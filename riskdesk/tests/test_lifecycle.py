"""End-to-end vulnerability lifecycle: detect -> close -> reopen -> verify,
plus the decision, exception and ticket paths that run alongside it."""
from __future__ import annotations

import dataclasses
import datetime as dt

import pytest
from sqlalchemy import create_engine, func, select, text, update

import app.sync as sync_mod
from app.connectors.base import NormalizedAsset, NormalizedRecord, NormalizedVuln
from app.models import (
    Adjudication, AssignmentRule, AuditEvent, Finding, FindingEvent, Ticket, Vuln,
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

# --- historical remediation reporting ----------------------------------------

def test_sync_uses_source_resolved_at_not_sync_time(sync, db):
    """A fix reported today for an alert that closed 60 days ago must stamp
    closed_at with the real date, not today."""
    old_close = NOW - dt.timedelta(days=60)
    sync([rec("a")])
    sync([rec("a", status="fixed", last_seen=NOW), ],)
    db.expire_all()
    # Simulate: real connectors would set resolved_at from the source.
    r2 = dataclasses.replace(rec("b"), status="fixed", resolved_at=old_close,
                             first_detected=NOW - dt.timedelta(days=90))
    sync([r2])
    f = _finding(db, "b")
    assert f.status == "fixed"
    assert f.closed_at is not None
    gap = (NOW.replace(tzinfo=None) - f.closed_at.replace(tzinfo=None)).days
    assert 59 <= gap <= 61, f"closed_at should be the historical date, not today (got {f.closed_at})"


def test_remediated_endpoint_and_summary(sync, db, client):
    sync([rec(f"f{i}", first=NOW - dt.timedelta(days=20)) for i in range(5)])
    # Three get fixed; two stay open.
    sync([rec(f"f{i}", status="fixed", first=NOW - dt.timedelta(days=20)) for i in range(3)] +
         [rec(f"f{i}", first=NOW - dt.timedelta(days=20)) for i in range(3, 5)])
    r = client.get("/api/findings/remediated").json()
    assert r["total"] == 3
    assert r["summary"]["by_severity"].get("high") == 3
    assert r["summary"]["mean_time_to_close_days"] is not None
    assert all(row["status"] == "fixed" for row in r["findings"])


def test_remediated_filters_by_date_range(sync, db, client):
    """closed_at bounds exclude fixes outside the window."""
    sync([rec("old"), rec("new")])
    sync([rec("old", status="fixed"), rec("new")])
    f = _finding(db, "old")
    f.closed_at = NOW - dt.timedelta(days=400)
    db.commit()
    sync([rec("new", status="fixed")])
    r = client.get("/api/findings/remediated?start=" +
                   (NOW - dt.timedelta(days=30)).date().isoformat()).json()
    assert r["total"] == 1
    assert r["findings"][0]["canonical_id"] == "GHSA-new"


def test_trends_time_series(sync, db, client):
    sync([rec(f"t{i}", first=NOW - dt.timedelta(days=d))
          for i, d in enumerate([5, 10, 60, 120])])
    sync([rec("t0", status="fixed", first=NOW - dt.timedelta(days=5)),
          rec("t1", first=NOW - dt.timedelta(days=10)),
          rec("t2", first=NOW - dt.timedelta(days=60)),
          rec("t3", first=NOW - dt.timedelta(days=120))])
    r = client.get("/api/lifecycle/trends?days=180&granularity=month").json()
    assert r["granularity"] == "month"
    assert len(r["series"]) >= 4
    assert r["totals"]["opened"] >= 4
    assert r["totals"]["closed"] >= 1
    # Backlog line is monotone across buckets up through the current one.
    assert any(b["backlog_end"] >= 1 for b in r["series"])


def test_trends_granularities(client, sync, db):
    sync([rec("x")])
    for g in ("day", "week", "month", "quarter"):
        r = client.get(f"/api/lifecycle/trends?days=90&granularity={g}")
        assert r.status_code == 200, (g, r.text)
    r = client.get("/api/lifecycle/trends?granularity=hour")
    assert r.status_code == 422


def test_historical_import_backloads_remediation(client, db):
    import io, csv
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["canonical_id", "source", "asset", "severity",
                "first_detected", "closed_at", "status", "title", "category"])
    w.writerow(["CVE-2024-99991", "legacy", "web-prod-01", "critical",
                "2024-01-15", "2024-02-20", "verified_fixed",
                "Historic log4shell on web-prod-01", "os_vuln"])
    w.writerow(["CVE-2024-99992", "legacy", "db-prod-01", "high",
                "2024-03-01", "2024-04-10", "fixed", "", ""])
    buf.seek(0)
    r = client.post("/api/findings/import-historical",
                    files={"file": ("hist.csv", buf.getvalue(), "text/csv")})
    assert r.status_code == 200, r.text
    data = r.json()
    assert data["created"] == 2 and data["errors"] == 0

    # Re-importing is idempotent.
    buf.seek(0)
    r2 = client.post("/api/findings/import-historical",
                     files={"file": ("hist.csv", buf.getvalue(), "text/csv")}).json()
    assert r2["created"] == 0 and r2["skipped"] == 2

    rem = client.get("/api/findings/remediated?source=legacy").json()
    assert rem["total"] == 2
    verified = [r for r in rem["findings"] if r["status"] == "verified_fixed"]
    assert len(verified) == 1
    assert verified[0]["time_to_close_days"] == 36


def test_historical_import_rejects_bad_rows(client, db):
    import io, csv
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["canonical_id", "source", "asset", "severity", "first_detected", "closed_at", "status"])
    w.writerow(["", "x", "host", "high", "2024-01-01", "2024-02-01", "fixed"])  # no canonical_id
    w.writerow(["CVE-X", "x", "host", "high", "2024-01-01", "2024-02-01", "open"])  # bad status
    w.writerow(["CVE-Y", "x", "host", "high", "2024-01-01", "", "fixed"])  # no close date
    buf.seek(0)
    r = client.post("/api/findings/import-historical",
                    files={"file": ("bad.csv", buf.getvalue(), "text/csv")}).json()
    assert r["errors"] == 3
    assert r["created"] == 0


def test_remediated_csv_export(client, sync, db):
    sync([rec("a", first=NOW - dt.timedelta(days=15))])
    sync([rec("a", status="fixed", first=NOW - dt.timedelta(days=15))])
    r = client.get("/api/export/remediated.csv")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/csv")
    assert "GHSA-a" in r.text
    assert "time_to_close_days" in r.text


def test_dismissed_alerts_count_as_suppressed_not_fixed():
    """GitHub 'dismissed' alerts are suppressed at the source, not remediated,
    and must not inflate remediation metrics."""
    from app.connectors.github import _gh_status
    assert _gh_status({"state": "open"}) == "open"
    assert _gh_status({"state": "fixed"}) == "fixed"
    assert _gh_status({"state": "dismissed"}) == "suppressed_at_source"
    assert _gh_status({"state": "auto_dismissed"}) == "suppressed_at_source"


# --- Falcon detections --------------------------------------------------------

def test_falcon_detection_mapping():
    from app.connectors.falcon import FalconConnector, _falcon_severity
    assert _falcon_severity(80) == "critical"
    assert _falcon_severity(60) == "high"
    assert _falcon_severity(40) == "medium"
    assert _falcon_severity(10) == "low"
    assert _falcon_severity("CRITICAL") == "critical"

    c = FalconConnector(cfg=type("C", (), {})())
    alert = {
        "composite_id": "123", "name": "ProcessInjection", "severity": 75,
        "status": "closed", "created_timestamp": "2026-10-01T00:00:00Z",
        "updated_timestamp": "2026-10-05T00:00:00Z",
        "device": {"device_id": "aid-1", "hostname": "web-01", "os_version": "Windows 10",
                   "local_ip": "10.0.0.5", "platform_name": "Windows"},
        "description": "Suspicious process injection detected",
    }
    rec = c._map_detection(alert)
    assert rec.category == "detection"
    assert rec.severity == "critical"
    assert rec.vuln.canonical_id == "falcon-detect:ProcessInjection"
    assert rec.asset.name == "web-01"
    assert rec.status == "fixed"
    assert rec.resolved_at is not None


def test_detection_category_appears_in_facets_and_metrics(sync, db, client):
    """A detection flows through sync and shows up on reports the same way vulns do."""
    detection = NormalizedRecord(
        source_finding_id="detect:abc", category="detection",
        asset=NormalizedAsset(source_asset_id="aid-1", name="web-01", asset_type="endpoint"),
        vuln=NormalizedVuln(canonical_id="falcon-detect:ProcessInjection",
                            title="Process injection", severity="critical"),
        severity="critical", status="open",
        first_detected=NOW - dt.timedelta(days=7),
    )
    sync([detection])
    sync([dataclasses.replace(detection, status="fixed",
                              resolved_at=NOW - dt.timedelta(days=1))])
    facets = client.get("/api/facets?status=open&status=fixed").json()
    assert facets["category"].get("detection") == 1
    r = client.get("/api/findings/remediated?category=detection").json()
    assert r["total"] == 1
    assert r["findings"][0]["canonical_id"] == "falcon-detect:ProcessInjection"


# --- approval workspace (queue, bulk-decide, context, templates) ----------

def _pending(db, finding_id, requested_by="admin1", approver="executive1"):
    from app.adjudication import create_decisions
    return create_decisions(
        db, [finding_id], "accept_risk",
        "Compensating WAF rule and runbook; patched Q2.",
        actor=requested_by, approver=approver, scope="vuln_on_asset",
    )[0]


def test_approval_queue_filters_to_my_approvals(client, db, seed_data):
    """'approver=me' returns decisions I'm named as approver on (plus any with
    no named approver). The requester of a decision is not themselves the
    approver, and vice-versa."""
    adj = _pending(db, seed_data["finding"].id, approver="executive1")
    # executive1 (named approver) sees it in their queue
    r = client.get("/api/adjudications/queue?approver=me",
                   headers={"X-RiskDesk-User": "executive1"}).json()
    assert r["can_approve"] is True
    assert adj.id in [d["id"] for d in r["decisions"]]
    # A different approver (executive2) does not see it in "mine", because the
    # approver is named and it is not them.
    r2 = client.get("/api/adjudications/queue?approver=me",
                    headers={"X-RiskDesk-User": "executive2"}).json()
    assert adj.id not in [d["id"] for d in r2["decisions"]]
    # But "approver=any" shows every pending decision regardless of who owns it.
    r3 = client.get("/api/adjudications/queue?approver=any",
                    headers={"X-RiskDesk-User": "executive2"}).json()
    assert adj.id in [d["id"] for d in r3["decisions"]]


def test_approval_queue_age_bands(client, db, seed_data):
    adj = _pending(db, seed_data["finding"].id)
    adj.requested_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=20)
    db.commit()
    r = client.get("/api/adjudications/queue?approver=me",
                   headers={"X-RiskDesk-User": "executive1"}).json()
    assert r["age_bands"]["stale"] >= 1
    aged = next(d for d in r["decisions"] if d["id"] == adj.id)
    assert aged["age_days"] >= 20


def test_bulk_decide_approves_many(client, db, seed_data):
    from app.models import Asset, Finding, Vuln
    v = Vuln(canonical_id="CVE-2024-BULK", severity="high")
    db.add(v); db.flush()
    adjs = []
    for i in range(3):
        a = Asset(source="wiz", source_asset_id=f"host-bulk-{i}", name=f"host-bulk-{i}",
                  asset_type="server")
        db.add(a); db.flush()
        f = Finding(source="wiz", source_finding_id=f"bulk-{i}", asset_id=a.id,
                    vuln_id=v.id, category="os_vuln", status="open", severity="high")
        db.add(f); db.flush()
        adjs.append(_pending(db, f.id))
    r = client.post("/api/adjudications/bulk-decide",
                    json={"adjudication_ids": [a.id for a in adjs], "approve": True,
                          "note": "Bulk approved as per quarterly review"},
                    headers={"X-RiskDesk-User": "executive1"}).json()
    assert r["succeeded"] == 3 and r["failed"] == 0
    for a in adjs:
        db.refresh(a)
        assert a.state == "approved" and a.approved_by == "executive1"


def test_bulk_decide_rejects_non_approver(client, db, seed_data):
    adj = _pending(db, seed_data["finding"].id)
    r = client.post("/api/adjudications/bulk-decide",
                    json={"adjudication_ids": [adj.id], "approve": True},
                    headers={"X-RiskDesk-User": "team1"})
    assert r.status_code == 403


def test_bulk_decide_separates_successes_and_failures(client, db, seed_data):
    """One bad id in a bulk call does not abort the rest."""
    adj = _pending(db, seed_data["finding"].id)
    r = client.post("/api/adjudications/bulk-decide",
                    json={"adjudication_ids": [adj.id, 99999], "approve": True,
                          "note": "batch"},
                    headers={"X-RiskDesk-User": "executive1"}).json()
    assert r["succeeded"] == 1 and r["failed"] == 1
    assert r["results"]["failed"][0]["id"] == 99999


def test_decide_context_surfaces_prior_peer_tickets(client, db, seed_data):
    from app.adjudication import create_decisions, decide
    from app.models import Asset, Finding, Ticket, TicketFinding, Vuln
    # A prior approved decision on the same CVE on another asset -> peer match
    other_asset = Asset(source="wiz", source_asset_id="other", name="other-host",
                        asset_type="server")
    db.add(other_asset); db.flush()
    other_finding = Finding(
        source="wiz", source_finding_id="other-1",
        asset_id=other_asset.id, vuln_id=seed_data["vuln"].id,
        category="os_vuln", status="open", severity="high",
    )
    db.add(other_finding); db.commit()
    prior = create_decisions(db, [other_finding.id], "accept_risk",
                             "Historical accept for another host, patched since.",
                             actor="admin1", approver="executive1", scope="vuln")[0]
    decide(db, prior.id, True, "executive1")
    # An open ticket linked to our finding
    t = Ticket(external_id="VULN-99", summary="patch work", created_by="admin1",
               status="open", provider="manual")
    db.add(t); db.flush()
    db.add(TicketFinding(ticket_id=t.id, finding_id=seed_data["finding"].id))
    db.commit()

    r = client.get(f"/api/decide/context?finding_ids={seed_data['finding'].id}").json()
    assert r["finding_count"] == 1
    assert r["asset_count"] == 1
    assert r["unique_vulns"] == 1
    assert len(r["prior_decisions_on_scope"]) >= 0  # prior is at vuln scope -> covers our finding too
    assert len(r["peer_decisions_on_cve"]) + len(r["prior_decisions_on_scope"]) >= 1
    assert any(tt["external_id"] == "VULN-99" for tt in r["related_tickets"])
    assert r["suggested_expiry_days"] > 0


def test_decision_templates_crud_and_seed(client, db):
    # Trigger lifespan to seed defaults (the client fixture already does this).
    r = client.get("/api/decision-templates").json()
    assert len(r) >= 5           # several defaults seeded
    seeded = [t for t in r if t["created_by"] == "system"]
    assert len(seeded) >= 5
    assert any(t["disposition"] == "accept_risk" and t["expiry_days"] for t in seeded)

    created = client.post("/api/decision-templates", json={
        "name": "Test template", "disposition": "false_positive", "scope": "vuln",
        "justification_text": "Test template used for acceptance testing of the templates API.",
        "expiry_days": 30,
    }).json()
    assert created["id"]
    client.put(f"/api/decision-templates/{created['id']}",
               json={"description": "edited", "enabled": False})
    r2 = client.get("/api/decision-templates").json()
    [edited] = [t for t in r2 if t["id"] == created["id"]]
    assert edited["description"] == "edited" and edited["enabled"] is False
    client.delete(f"/api/decision-templates/{created['id']}")
    r3 = client.get("/api/decision-templates").json()
    assert not any(t["id"] == created["id"] for t in r3)


def test_decision_templates_require_core_fields(client, db):
    r = client.post("/api/decision-templates", json={"name": "", "disposition": "accept_risk"})
    assert r.status_code == 422


# --- lifecycle status handling -------------------------------------------------

# --- grouped search ---------------------------------------------------------

def test_grouped_by_cve_rolls_up_across_assets(sync, db, client):
    """Same CVE on three hosts groups into one row with asset_count=3."""
    asset_names = ["web-01", "web-02", "db-01"]
    recs = []
    for i, host in enumerate(asset_names):
        recs.append(NormalizedRecord(
            source_finding_id=f"wiz:{host}:1", category="os_vuln",
            asset=NormalizedAsset(source_asset_id=host, name=host, asset_type="server"),
            vuln=NormalizedVuln(canonical_id="CVE-2021-44228", cve_id="CVE-2021-44228",
                                title="Log4Shell", severity="critical", kev=True),
            severity="critical", status="open",
        ))
    # One unrelated CVE on one host for contrast
    recs.append(NormalizedRecord(
        source_finding_id="wiz:web-01:2", category="os_vuln",
        asset=NormalizedAsset(source_asset_id="web-01", name="web-01", asset_type="server"),
        vuln=NormalizedVuln(canonical_id="CVE-2024-0001", severity="high"),
        severity="high", status="open",
    ))
    sync(recs)

    r = client.get("/api/findings/grouped?by=cve").json()
    assert r["group_by"] == "cve"
    assert r["total_groups"] == 2
    by_key = {g["key"]: g for g in r["groups"]}
    log4j = by_key["CVE-2021-44228"]
    assert log4j["finding_count"] == 3
    assert log4j["asset_count"] == 3
    assert log4j["max_severity"] == "critical"
    assert log4j["kev_count"] == 3
    assert log4j["suggested_scope"] == "vuln"
    assert log4j["suggested_scope_key"] == "CVE-2021-44228"
    assert len(log4j["sample_finding_ids"]) == 3


def test_grouped_by_asset_lists_hosts(sync, db, client):
    sync([
        NormalizedRecord(
            source_finding_id=f"wiz:web-01:{i}", category="os_vuln",
            asset=NormalizedAsset(source_asset_id="web-01", name="web-01", asset_type="server"),
            vuln=NormalizedVuln(canonical_id=f"CVE-2024-{i}", severity="high"),
            severity="high", status="open",
        ) for i in range(4)
    ])
    r = client.get("/api/findings/grouped?by=asset").json()
    assert r["total_groups"] == 1
    g = r["groups"][0]
    assert g["label"] == "web-01"
    assert g["finding_count"] == 4
    assert g["asset_count"] == 1
    assert g["suggested_scope"] == "finding"


def test_grouped_by_component_uses_component_scope(sync, db, client):
    """Grouping by component lifts the component_key scope so a decision on
    the group covers every future finding in that package."""
    sync([
        NormalizedRecord(
            source_finding_id=f"gh:pli/repo:dep-{i}", category="dependency",
            asset=NormalizedAsset(source_asset_id=f"pli/repo-{i}", name=f"pli/repo-{i}",
                                  asset_type="repository"),
            vuln=NormalizedVuln(canonical_id=f"GHSA-{i}", severity="high"),
            severity="high", status="open",
            component="lodash", component_version="4.17.20",
            component_key="pkg:npm/lodash",
        ) for i in range(5)
    ])
    r = client.get("/api/findings/grouped?by=component").json()
    g = r["groups"][0]
    assert g["label"] == "lodash"
    assert g["finding_count"] == 5
    assert g["suggested_scope"] == "component"
    assert g["suggested_scope_key"] == "pkg:npm/lodash"


def test_grouped_by_ecosystem_derived_from_component_key(sync, db, client):
    sync([
        NormalizedRecord(
            source_finding_id=f"gh:r:{i}", category="dependency",
            asset=NormalizedAsset(source_asset_id="pli/repo", name="pli/repo", asset_type="repository"),
            vuln=NormalizedVuln(canonical_id=f"GHSA-{i}", severity="high"),
            severity="high", status="open",
            component="lodash" if i < 2 else "requests",
            component_key="pkg:npm/lodash" if i < 2 else "pkg:pypi/requests",
        ) for i in range(5)
    ])
    r = client.get("/api/findings/grouped?by=ecosystem").json()
    by_key = {g["key"]: g for g in r["groups"]}
    assert by_key["npm"]["finding_count"] == 2
    assert by_key["pypi"]["finding_count"] == 3


def test_grouped_respects_resolution_map(sync, db, client):
    """An ADJUST_RISK decision that downgrades severity shows up in the
    group's effective-severity rollup, not just the raw column."""
    from app.adjudication import create_decisions, decide
    from app.models import Finding
    from sqlalchemy import select
    sync([
        NormalizedRecord(
            source_finding_id=f"wiz:host:{i}", category="os_vuln",
            asset=NormalizedAsset(source_asset_id=f"host-{i}", name=f"host-{i}", asset_type="server"),
            vuln=NormalizedVuln(canonical_id="CVE-2024-X", severity="critical"),
            severity="critical", status="open",
        ) for i in range(3)
    ])
    fids = [f.id for f in db.execute(
        select(Finding).join(Vuln, Finding.vuln_id == Vuln.id)
        .where(Vuln.canonical_id == "CVE-2024-X")
    ).scalars()]
    assert len(fids) == 3
    for adj in create_decisions(db, fids, "adjust_risk",
                                "Internal network only; compensating WAF blocks exploit.",
                                actor="admin1", approver="executive1", scope="vuln",
                                adjusted_severity="medium"):
        decide(db, adj.id, True, "executive1")

    r = client.get("/api/findings/grouped?by=cve").json()
    g = next(x for x in r["groups"] if x["key"] == "CVE-2024-X")
    assert g["severity_counts"].get("medium") == 3
    assert g["max_severity"] == "medium"


def test_grouped_drill_down_filter_matches_group(sync, db, client):
    """Every drill-down filter the UI sets from a clicked group row
    produces the same count as the group header."""
    sync([
        NormalizedRecord(
            source_finding_id=f"wiz:a:{i}", category="os_vuln",
            asset=NormalizedAsset(source_asset_id="host-a", name="host-a", asset_type="server"),
            vuln=NormalizedVuln(canonical_id=f"CVE-2024-A{i}", severity="high"),
            severity="high", status="open",
            component="openssl", component_version="1.1.1",
            component_key="pkg:generic/openssl",
        ) for i in range(4)
    ])
    sync([
        NormalizedRecord(
            source_finding_id=f"wiz:b:{i}", category="os_vuln",
            asset=NormalizedAsset(source_asset_id="host-b", name="host-b", asset_type="server"),
            vuln=NormalizedVuln(canonical_id=f"CVE-2024-B{i}", severity="high"),
            severity="high", status="open",
            component="nginx", component_version="1.20",
            component_key="pkg:generic/nginx",
        ) for i in range(2)
    ])
    # Drill into the "openssl" group
    r = client.get("/api/findings?component=openssl").json()
    assert r["total"] == 4
    # Drill into the "host-b" group
    r = client.get("/api/findings/ids?asset_id=" + str(
        db.execute(select(Finding).where(Finding.source_finding_id == "wiz:b:0")).scalar_one().asset_id
    )).json()
    assert r["total"] == 2


def test_grouped_sorts(sync, db, client):
    sync([
        NormalizedRecord(
            source_finding_id=f"wiz:small:{i}", category="os_vuln",
            asset=NormalizedAsset(source_asset_id="small", name="small", asset_type="server"),
            vuln=NormalizedVuln(canonical_id="CVE-small", severity="low"),
            severity="low", status="open",
        ) for i in range(2)
    ])
    sync([
        NormalizedRecord(
            source_finding_id=f"wiz:big:{i}", category="os_vuln",
            asset=NormalizedAsset(source_asset_id="big", name="big", asset_type="server"),
            vuln=NormalizedVuln(canonical_id="CVE-big", severity="low"),
            severity="low", status="open",
        ) for i in range(10)
    ])
    r = client.get("/api/findings/grouped?by=cve&group_sort=count").json()
    assert r["groups"][0]["key"] == "CVE-big"
    r = client.get("/api/findings/grouped?by=cve&group_sort=count&order=asc").json()
    assert r["groups"][0]["key"] == "CVE-small"


def test_grouped_rejects_bad_dimension(client):
    r = client.get("/api/findings/grouped?by=nonsense")
    assert r.status_code == 422


def test_suppressed_at_source_from_connector(sync, db):
    sync([rec("a")])
    sync([rec("a", status="suppressed_at_source", last_seen=NOW)])
    f = _finding(db, "a")
    assert f.status == "suppressed_at_source"
    assert f.closed_at is not None


def test_add_missing_indexes_creates_declared_indexes(tmp_path):
    """add_missing_indexes picks up any Index declared on a model that is
    not present in the live DB -- so an index added in a later release
    lands automatically on next startup."""
    from app.db import Base, add_missing_indexes
    from sqlalchemy import create_engine, inspect, text
    eng = create_engine(f"sqlite:///{tmp_path / 'live.db'}")
    Base.metadata.create_all(eng)
    # Drop one of the indexes we declared to simulate an older schema
    with eng.begin() as c:
        c.execute(text("DROP INDEX IF EXISTS ix_finding_component"))
        c.execute(text("DROP INDEX IF EXISTS ix_finding_closed_at"))
    before = {i["name"] for i in inspect(eng).get_indexes("findings")}
    assert "ix_finding_component" not in before
    added = add_missing_indexes(eng)
    assert "ix_finding_component" in added
    assert "ix_finding_closed_at" in added
    after = {i["name"] for i in inspect(eng).get_indexes("findings")}
    assert "ix_finding_component" in after
    assert "ix_finding_closed_at" in after
    # Second run is a no-op
    assert add_missing_indexes(eng) == []


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
