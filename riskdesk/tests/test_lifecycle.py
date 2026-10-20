"""End-to-end vulnerability lifecycle: detect -> close -> reopen -> verify,
plus the decision, exception and ticket paths that run alongside it."""
from __future__ import annotations

import datetime as dt

import pytest
from sqlalchemy import create_engine, func, select, text, update

import app.sync as sync_mod
from app.connectors.base import NormalizedAsset, NormalizedRecord, NormalizedVuln
from app.models import (
    Adjudication, AssignmentRule, AuditEvent, Finding, FindingEvent, Ticket,
)

NOW = dt.datetime.now(dt.timezone.utc)


class StubConnector:
    def __init__(self, records, skipped=()):
        self.records = records
        self.skipped_categories = set(skipped)

    def configured(self):
        return True

    def fetch(self, limit=None):
        for i, r in enumerate(self.records):
            if limit and i >= limit:
                return
            yield r


def rec(fid, status="open", category="dependency", severity="high",
        last_seen=None, first=None):
    return NormalizedRecord(
        source_finding_id=fid, category=category,
        asset=NormalizedAsset(source_asset_id="org/repo", name="org/repo"),
        vuln=NormalizedVuln(canonical_id=f"GHSA-{fid}", severity=severity),
        severity=severity, status=status, last_seen=last_seen, first_detected=first,
    )


@pytest.fixture()
def sync(monkeypatch):
    def _run(records, skipped=(), limit=None):
        monkeypatch.setattr(sync_mod, "get_connector",
                            lambda source, demo=False: StubConnector(records, skipped))
        return sync_mod.run_sync("github", limit=limit, actor="tester")
    return _run


def _finding(db, fid) -> Finding:
    db.expire_all()
    return db.execute(select(Finding).where(Finding.source_finding_id == fid)).scalar_one()


def _age(db, fid, days=30):
    db.execute(update(Finding).where(Finding.source_finding_id == fid)
               .values(last_synced_at=NOW - dt.timedelta(days=days)))
    db.commit()


def _events(db, finding_id):
    return [e.event for e in db.execute(
        select(FindingEvent).where(FindingEvent.finding_id == finding_id)
        .order_by(FindingEvent.id)).scalars()]


# --- sync-driven transitions -------------------------------------------------

def test_old_source_timestamp_does_not_mark_stale(sync, db):
    """GitHub's updated_at can be months old on a live alert; that must not close it."""
    sync([rec("a", last_seen=NOW - dt.timedelta(days=200))])
    f = _finding(db, "a")
    assert f.status == "open"
    assert f.last_synced_at is not None
    assert f.closed_at is None


def test_unreported_finding_closes_as_stale(sync, db):
    sync([rec("a"), rec("b")])
    _age(db, "b")
    result = sync([rec("a")])
    f = _finding(db, "b")
    assert f.status == "stale"
    assert f.closed_at is not None
    assert result["stale"] == 1 and result["closed"] == 1
    assert _events(db, f.id) == ["stale"]


def test_stale_finding_reopens_when_reported_again(sync, db):
    sync([rec("a"), rec("b")])
    _age(db, "b")
    sync([rec("a")])
    result = sync([rec("a"), rec("b")])
    f = _finding(db, "b")
    assert f.status == "open"
    assert f.closed_at is None
    assert f.reopened_count == 1
    assert result["reopened"] == 1
    assert _events(db, f.id) == ["stale", "reopened"]


def test_source_reported_fix_closes_and_is_counted(sync, db):
    sync([rec("a")])
    result = sync([rec("a", status="fixed")])
    f = _finding(db, "a")
    assert f.status == "fixed"
    assert f.closed_at is not None
    assert result["closed"] == 1
    assert _events(db, f.id) == ["fixed"]


def test_verified_status_survives_source_fixed_report(sync, db, client):
    sync([rec("a")])
    sync([rec("a", status="fixed")])
    fid = _finding(db, "a").id
    assert client.post(f"/api/findings/{fid}/verify").status_code == 200
    sync([rec("a", status="fixed")])
    assert _finding(db, "a").status == "verified_fixed"


def test_partial_sync_does_not_mark_stale(sync, db):
    sync([rec("a"), rec("b")])
    _age(db, "b")
    result = sync([rec("a"), rec("b")], limit=1)
    assert _finding(db, "b").status == "open"
    assert result["stale"] == 0


def test_unread_category_is_not_marked_stale(sync, db):
    sync([rec("a"), rec("b", category="code_scanning")])
    _age(db, "a")
    _age(db, "b")
    sync([], skipped={"code_scanning"})
    assert _finding(db, "b").status == "open"
    assert _finding(db, "a").status == "stale"


# --- verification and timeline ----------------------------------------------

def test_verify_stale_finding_and_timeline(sync, db, client):
    sync([rec("a"), rec("b")])
    _age(db, "b")
    sync([rec("a")])
    fid = _finding(db, "b").id

    r = client.post(f"/api/findings/{fid}/verify", json={"note": "Patched in release 4.2"})
    assert r.status_code == 200
    f = _finding(db, "b")
    assert f.status == "verified_fixed" and f.verified_by

    events = client.get(f"/api/findings/{fid}/timeline").json()["events"]
    status_events = [e["event"] for e in events if e["kind"] == "status"]
    assert status_events == ["detected", "stale", "verified"]

    detail = client.get(f"/api/findings/{fid}").json()
    assert detail["status"] == "verified_fixed"
    assert detail["closed_at"] and detail["verified_by"]
    assert [e["event"] for e in detail["timeline"]][0] == "detected"


def test_verify_open_finding_rejected(client, seed_data):
    r = client.post(f"/api/findings/{seed_data['finding'].id}/verify")
    assert r.status_code == 422


def test_closed_findings_reachable_by_status_filter(sync, db, client):
    sync([rec("a"), rec("b")])
    sync([rec("a"), rec("b", status="fixed")])
    assert client.get("/api/findings").json()["total"] == 1
    r = client.get("/api/findings?status=fixed").json()
    assert r["total"] == 1 and r["findings"][0]["closed_at"]
    facets = client.get("/api/facets").json()
    assert facets["status"] == {"open": 1, "fixed": 1}


def test_closed_finding_is_not_overdue(db, client, seed_data):
    f = seed_data["finding"]
    f.first_detected = NOW - dt.timedelta(days=400)
    db.commit()
    assert client.get(f"/api/findings/{f.id}").json()["risk"]["sla_overdue"] is True
    f.status = "fixed"
    f.closed_at = NOW
    db.commit()
    assert client.get(f"/api/findings/{f.id}").json()["risk"]["sla_overdue"] is False


def test_lifecycle_metrics(sync, db, client):
    sync([rec("a", first=NOW - dt.timedelta(days=10))])
    sync([rec("a", status="fixed", first=NOW - dt.timedelta(days=10))])
    m = client.get("/api/lifecycle/metrics?days=30").json()
    assert m["closed_in_window"] == 1
    assert 9.5 <= m["mttr_days"] <= 10.5
    assert m["by_severity"]["high"]["closed_within_sla_pct"] == 100.0
    assert m["awaiting_verification"] == 1


# --- auto-assignment ----------------------------------------------------------

def test_assignment_does_not_duplicate_routing_decisions(db, seed_data):
    from app.assignment import evaluate_rules
    db.add(AssignmentRule(name="All high", severity="high", assign_to="team1"))
    db.commit()
    first = evaluate_rules(db, actor="tester")
    second = evaluate_rules(db, actor="tester")
    assert first["assigned"] == 1
    assert second["assigned"] == 0 and second["skipped_existing"] == 1
    assert db.execute(select(func.count()).select_from(Adjudication)).scalar() == 1


# --- decisions ----------------------------------------------------------------

JUSTIFICATION = "Compensating WAF rule blocks the vulnerable endpoint until the Q3 upgrade."


def _approved_acceptance(db, finding_id):
    from app.adjudication import create_decisions, decide
    adj = create_decisions(db, [finding_id], "accept_risk", JUSTIFICATION,
                           actor="admin1", approver="executive1")[0]
    return decide(db, adj.id, True, "executive1")


def test_renewal_keeps_predecessor_until_approved(db, seed_data):
    from app.adjudication import PolicyError, decide, renew
    old = _approved_acceptance(db, seed_data["finding"].id)

    new = renew(db, old.id, "admin1", JUSTIFICATION, NOW + dt.timedelta(days=60), "executive2")
    db.refresh(old)
    assert old.state == "approved"
    assert new.state == "pending_approval" and new.supersedes_id == old.id
    assert len(new.applications) == 1

    with pytest.raises(PolicyError):
        renew(db, old.id, "admin1", JUSTIFICATION, NOW + dt.timedelta(days=60), "executive2")

    decide(db, new.id, True, "executive2")
    db.refresh(old)
    assert old.state == "expired"


def test_revoke_rejects_dead_decision(db, seed_data):
    from app.adjudication import PolicyError, revoke
    adj = _approved_acceptance(db, seed_data["finding"].id)
    revoke(db, adj.id, "admin1", "Upgrade shipped, acceptance no longer needed")
    with pytest.raises(PolicyError):
        revoke(db, adj.id, "admin1", "Second revoke should not be allowed")


def test_scheduler_expires_lapsed_decisions(db, seed_data):
    from app import scheduler
    adj = _approved_acceptance(db, seed_data["finding"].id)
    adj.expires_at = NOW - dt.timedelta(days=1)
    db.commit()
    scheduler._last_expiry_check = None
    scheduler._maybe_expire_decisions(db, NOW)
    db.refresh(adj)
    assert adj.state == "expired"


# --- exceptions -----------------------------------------------------------------

def _exception(db, finding_id):
    from app.exceptions import create_exception
    return create_exception(db, "Test key in fixture repo", [finding_id], "accept_risk",
                            JUSTIFICATION, actor="team1")


def test_exception_approval_records_the_real_approver(db, seed_data):
    from app.exceptions import review_exception
    exc = review_exception(db, _exception(db, seed_data["finding"].id).id, "approved", "executive1")
    adj = db.get(Adjudication, exc.adjudication_id)
    assert adj.requested_by == "team1"
    assert adj.approved_by == "executive1"
    assert adj.state == "approved"


def test_exception_reviewed_by_non_approver_waits_for_approval(db, seed_data):
    from app.exceptions import review_exception
    exc = review_exception(db, _exception(db, seed_data["finding"].id).id, "approved", "security1")
    adj = db.get(Adjudication, exc.adjudication_id)
    assert adj.state == "pending_approval"
    assert adj.approved_by is None
    assert adj.approver not in ("security1", "team1")


# --- tickets ----------------------------------------------------------------------

def test_ticket_reopen_clears_resolution(client, db, seed_data):
    t = client.post("/api/tickets", json={"finding_ids": [seed_data["finding"].id],
                                          "provider": "manual"}).json()
    client.put(f"/api/tickets/{t['id']}", json={"status": "done"})
    assert db.get(Ticket, t["id"]).resolved_at is not None
    client.put(f"/api/tickets/{t['id']}", json={"status": "open"})
    db.expire_all()
    assert db.get(Ticket, t["id"]).resolved_at is None
    actions = {e.action for e in db.execute(select(AuditEvent)).scalars()}
    assert {"ticket.resolved", "ticket.reopened"} <= actions


def test_jira_done_category_counts_as_resolved(db, seed_data):
    from app.ticket_sync import apply_jira_fields
    t = Ticket(external_id="VULN-1", summary="x", created_by="admin1", status="open")
    db.add(t)
    db.commit()
    apply_jira_fields(db, t, {"status": {"name": "Done", "statusCategory": {"key": "done"}},
                              "resolution": None}, actor="tester")
    assert t.status == "done" and t.resolved_at is not None


def test_ticket_drift_in_metrics(client, db, seed_data):
    t = client.post("/api/tickets", json={"finding_ids": [seed_data["finding"].id],
                                          "provider": "manual"}).json()
    client.put(f"/api/tickets/{t['id']}", json={"status": "resolved"})
    m = client.get("/api/lifecycle/metrics").json()
    assert m["tickets"]["resolved_but_findings_open"] == 1


# --- schema migration ------------------------------------------------------------

def test_add_missing_columns_upgrades_existing_table(tmp_path):
    from app.db import add_missing_columns
    eng = create_engine(f"sqlite:///{tmp_path / 'old.db'}")
    with eng.begin() as c:
        c.execute(text("CREATE TABLE findings (id INTEGER PRIMARY KEY, source VARCHAR(16))"))
        c.execute(text("INSERT INTO findings (id, source) VALUES (1, 'wiz')"))
    added = add_missing_columns(eng)
    assert "findings.last_synced_at" in added
    assert "findings.reopened_count" in added
    with eng.connect() as c:
        assert c.execute(text("SELECT reopened_count FROM findings WHERE id = 1")).scalar() == 0
    assert add_missing_columns(eng) == []
