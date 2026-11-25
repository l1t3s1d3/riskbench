"""The five-bucket adjudication scheme."""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select

from app.buckets import BUCKETS, bucket_for_disposition, bucket_for_finding
from app.enums import Disposition
from app.models import Adjudication, Finding, Vuln, Asset


def test_bucket_map_covers_every_disposition():
    """Every current Disposition must map to a known bucket."""
    for d in Disposition:
        n = bucket_for_disposition(d.value)
        assert 0 <= n <= 4, f"{d.value} -> {n} outside 0..4"


def test_os_patches_map_to_bucket_1():
    assert bucket_for_disposition(Disposition.ROUTINE_FIX.value) == 1
    assert bucket_for_disposition(Disposition.FIX_IMMEDIATELY.value) == 1


def test_bucket_assignments_match_doc():
    assert bucket_for_disposition(None) == 0
    assert bucket_for_disposition(Disposition.COMPLEX_RESOLUTION.value) == 2
    assert bucket_for_disposition(Disposition.DEVELOPER_REVIEW.value) == 3
    for d in (Disposition.ACCEPT_RISK, Disposition.ADJUST_RISK, Disposition.FALSE_POSITIVE):
        assert bucket_for_disposition(d.value) == 4


def test_bucket_meta_lists_all_five():
    numbers = [b.number for b in BUCKETS]
    assert numbers == [0, 1, 2, 3, 4]


def test_bucket_for_finding_respects_expired_adj(db):
    """An expired adjudication must not keep the finding in its old bucket."""
    asset = Asset(source="falcon", source_asset_id="h", name="h", asset_type="server")
    vuln = Vuln(canonical_id="CVE-1", severity="high")
    db.add_all([asset, vuln])
    db.flush()
    f = Finding(source="falcon", source_finding_id="f", asset_id=asset.id,
                vuln_id=vuln.id, category="os_vuln", status="open", severity="high")
    db.add(f)
    db.flush()
    now = dt.datetime.now(dt.timezone.utc)
    adj = Adjudication(
        scope_type="finding", scope_key=str(f.id), scope_label="l",
        disposition=Disposition.ACCEPT_RISK.value, state="expired",
        justification="j" * 50, requested_by="a1", approver="a2",
        decided_at=now - dt.timedelta(days=200),
        expires_at=now - dt.timedelta(days=100),
    )
    db.add(adj)
    db.commit()
    assert bucket_for_finding(adj, now) == 0


def test_bucket_report_endpoint(client, seed_data):
    r = client.get("/api/buckets/report")
    assert r.status_code == 200
    data = r.json()
    assert "buckets" in data
    assert len(data["buckets"]) == 5
    assert data["buckets"][0]["number"] == 0


def test_findings_filter_by_bucket(client, seed_data):
    # The default-seeded finding is open and has no decision, so it's in bucket 0.
    r = client.get("/api/findings?bucket=0")
    assert r.status_code == 200
    assert r.json()["total"] >= 1
    r = client.get("/api/findings?bucket=4")
    assert r.status_code == 200
    assert r.json()["total"] == 0


def test_bucket_findings_endpoint(client, seed_data):
    r = client.get("/api/buckets/0/findings")
    assert r.status_code == 200
    data = r.json()
    assert data["bucket"] == 0
    assert data["total"] >= 1


def test_bucket_findings_rejects_unknown(client):
    r = client.get("/api/buckets/9/findings")
    assert r.status_code == 400


def test_dashboard_includes_bucket_counts(client, seed_data):
    r = client.get("/api/dashboard")
    data = r.json()
    assert "by_bucket" in data
    assert set(data["by_bucket"].keys()) == {"0", "1", "2", "3", "4"}


def test_review_suggest_returns_prior_decision(client, db, seed_data):
    from app.adjudication import create_decisions, decide
    f = seed_data["finding"]
    adjs = create_decisions(
        db, finding_ids=[f.id], disposition="accept_risk",
        justification="Documented residual risk; compensating network segmentation.",
        compensating_controls="Segmented VLAN with ACL.",
        expires_at=dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=30),
        actor="executive1", approver="executive2", scope="vuln",
    )
    for adj in adjs:
        decide(db, adj.id, True, "executive2")
    canonical = f.vuln.canonical_id
    r = client.get(f"/api/review/suggest?scope_type=vuln&scope_key={canonical}")
    assert r.status_code == 200
    s = r.json()["suggested"]
    assert s is not None
    assert s["disposition"] == "accept_risk"
