"""Tests for finding routes."""
from __future__ import annotations

import datetime as dt

from app.models import Finding


def test_list_findings_empty(client):
    r = client.get("/api/findings")
    assert r.status_code == 200
    data = r.json()
    assert data["total"] == 0
    assert data["findings"] == []


def test_get_finding_not_found(client):
    r = client.get("/api/findings/999")
    assert r.status_code == 404


def test_get_finding_detail(client, seed_data):
    fid = seed_data["finding"].id
    r = client.get(f"/api/findings/{fid}")
    assert r.status_code == 200
    data = r.json()
    assert data["id"] == fid
    assert data["vuln"]["canonical_id"] == "CVE-2024-0001"


def test_verify_finding_wrong_status(client, seed_data):
    fid = seed_data["finding"].id
    r = client.post(f"/api/findings/{fid}/verify")
    assert r.status_code == 422
    assert "fixed" in r.json()["detail"].lower()


def test_verify_finding_success(client, seed_data, db):
    finding = seed_data["finding"]
    finding.status = "fixed"
    db.commit()
    r = client.post(f"/api/findings/{finding.id}/verify")
    assert r.status_code == 200
    data = r.json()
    assert data["status"] == "verified_fixed"

    db.refresh(finding)
    assert finding.status == "verified_fixed"
    assert finding.verified_by is not None
    assert finding.verified_at is not None


def test_dashboard(client, seed_data):
    r = client.get("/api/dashboard")
    assert r.status_code == 200
    data = r.json()
    assert "open_findings" in data
    assert data["open_findings"] >= 1


def test_rollup_caches_and_rebuilds_on_mark_stale(db, seed_data):
    """The materialized rollup should not recompute on every read."""
    from app import rollup
    from app.models import DashboardRollup

    first = rollup.get_rollup(db)
    row = db.get(DashboardRollup, 1)
    assert row is not None and row.stale is False
    stamp = row.generated_at

    # Second read: served from the cached row, no rebuild.
    rollup.get_rollup(db)
    db.refresh(row)
    assert row.generated_at == stamp

    # Mark stale, read again: rebuild happens and timestamp advances.
    rollup.mark_stale(db)
    db.refresh(row)
    assert row.stale is True
    rollup.get_rollup(db)
    db.refresh(row)
    assert row.stale is False
    assert row.generated_at >= stamp


def test_rollup_marked_stale_by_adjudication(db, seed_data):
    """Creating a decision must flip the rollup row to stale."""
    from app import rollup
    from app.adjudication import create_decisions
    from app.models import DashboardRollup

    rollup.get_rollup(db)
    row = db.get(DashboardRollup, 1)
    assert row.stale is False

    finding_id = seed_data["finding"].id
    create_decisions(
        db, finding_ids=[finding_id], disposition="accept_risk",
        justification="Documented residual risk for test coverage.",
        compensating_controls="Compensating control on file.",
        expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30),
        actor="executive1", approver="executive2",
    )
    db.refresh(row)
    assert row.stale is True


def test_meta(client):
    r = client.get("/api/meta")
    assert r.status_code == 200
    data = r.json()
    assert "dispositions" in data
    assert "severities" in data
