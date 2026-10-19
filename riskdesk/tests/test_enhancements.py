"""Tests for the eight new enhancements."""
from __future__ import annotations

import csv
import io

from app.models import Asset, AssetGroup, AuditEvent, Finding, Vuln


# --- 1. EPSS-based auto-prioritization -------------------------------------

def test_epss_kev_synergy_scoring(client, db):
    """When a vuln has both KEV and high EPSS, the synergy bonus applies."""
    asset = Asset(source="wiz", source_asset_id="a1", name="host1", asset_type="server")
    vuln = Vuln(
        canonical_id="CVE-2024-9999", cve_id="CVE-2024-9999",
        title="Test", severity="high", cvss_score=8.0,
        epss_score=0.85, epss_percentile=0.95, kev=True,
    )
    db.add_all([asset, vuln])
    db.flush()
    finding = Finding(
        source="wiz", source_finding_id="f-epss-1",
        asset_id=asset.id, vuln_id=vuln.id,
        category="os_vuln", status="open", severity="high",
    )
    db.add(finding)
    db.commit()

    r = client.get(f"/api/findings/{finding.id}")
    assert r.status_code == 200
    data = r.json()
    factor_names = [f["name"] for f in data["risk"]["factors"]]
    assert "KEV+EPSS synergy" in factor_names
    assert data["risk"]["priority"] == "P1"


def test_epss_auto_escalation(client, db):
    """KEV + EPSS >= 0.7 forces P1 even if score alone would be lower."""
    asset = Asset(source="wiz", source_asset_id="a2", name="host2", asset_type="server")
    vuln = Vuln(
        canonical_id="CVE-2024-8888", cve_id="CVE-2024-8888",
        title="Low CVSS but exploited", severity="medium", cvss_score=5.0,
        epss_score=0.72, kev=True,
    )
    db.add_all([asset, vuln])
    db.flush()
    finding = Finding(
        source="wiz", source_finding_id="f-epss-2",
        asset_id=asset.id, vuln_id=vuln.id,
        category="os_vuln", status="open", severity="medium",
    )
    db.add(finding)
    db.commit()

    r = client.get(f"/api/findings/{finding.id}")
    assert r.status_code == 200
    assert r.json()["risk"]["priority"] == "P1"


# --- 2. SLA breach notification --------------------------------------------

def test_sla_breaches_endpoint(client, seed_data):
    r = client.get("/api/sla/breaches")
    assert r.status_code == 200
    data = r.json()
    assert "total_overdue" in data
    assert "by_severity" in data
    assert "findings" in data
    assert data["notification_sent"] is False


# --- 3. Bulk adjudication from CSV -----------------------------------------

def test_bulk_csv_adjudication(client, seed_data, db):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["canonical_id", "disposition", "justification", "approver", "expires_at"])
    w.writerow(["CVE-2024-0001", "accept_risk",
                "Legacy system decommissioned by EOY per project plan",
                "executive1", "2025-12-31"])
    buf.seek(0)

    r = client.post(
        "/api/adjudications/bulk-csv",
        files={"file": ("decisions.csv", buf.getvalue(), "text/csv")},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["processed"] == 1
    assert data["succeeded"] == 1
    assert data["failed"] == 0


def test_bulk_csv_missing_canonical(client, seed_data, db):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["canonical_id", "disposition", "justification"])
    w.writerow(["", "accept_risk", "test"])
    buf.seek(0)

    r = client.post(
        "/api/adjudications/bulk-csv",
        files={"file": ("bad.csv", buf.getvalue(), "text/csv")},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["failed"] == 1
    assert data["results"][0]["error"] == "Missing canonical_id or disposition"


def test_bulk_csv_no_match(client, db):
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["canonical_id", "disposition", "justification"])
    w.writerow(["CVE-NONEXISTENT", "accept_risk", "test justification that is long enough for the policy"])
    buf.seek(0)

    r = client.post(
        "/api/adjudications/bulk-csv",
        files={"file": ("none.csv", buf.getvalue(), "text/csv")},
    )
    assert r.status_code == 200
    data = r.json()
    assert data["failed"] == 1


# --- 4. Asset grouping/tagging ---------------------------------------------

def test_asset_group_crud(client, db):
    r = client.post("/api/asset-groups", json={
        "name": "Production Servers",
        "business_unit": "Engineering",
        "criticality": "critical",
        "owner": "admin1",
    })
    assert r.status_code == 200
    gid = r.json()["id"]

    r = client.get("/api/asset-groups")
    assert r.status_code == 200
    assert r.json()["total"] >= 1

    r = client.put(f"/api/asset-groups/{gid}", json={"description": "Prod servers"})
    assert r.status_code == 200

    r = client.delete(f"/api/asset-groups/{gid}")
    assert r.status_code == 200


def test_asset_group_assign(client, seed_data, db):
    r = client.post("/api/asset-groups", json={
        "name": "Test Group", "business_unit": "QA"
    })
    gid = r.json()["id"]
    aid = seed_data["asset"].id

    r = client.post(f"/api/asset-groups/{gid}/assets", json={"asset_ids": [aid]})
    assert r.status_code == 200
    assert r.json()["assigned"] >= 1


def test_asset_group_duplicate_name(client, db):
    client.post("/api/asset-groups", json={"name": "UniqueGroup"})
    r = client.post("/api/asset-groups", json={"name": "UniqueGroup"})
    assert r.status_code == 409


# --- 5. Lifespan migration (verified by startup) ---------------------------

def test_app_starts_with_lifespan(client):
    """Verify the app starts normally with the lifespan context manager."""
    r = client.get("/api/meta")
    assert r.status_code == 200


# --- 6. Audit log pagination -----------------------------------------------

def test_audit_cursor_pagination(client, db):
    for i in range(5):
        db.add(AuditEvent(
            actor="admin1", action=f"test.action{i}",
            entity_type="test", entity_id=str(i),
            summary=f"Event {i}",
        ))
    db.commit()

    r = client.get("/api/audit?limit=2")
    assert r.status_code == 200
    data = r.json()
    assert len(data["events"]) == 2
    assert data["has_more"] is True
    assert data["cursor"] is not None

    r2 = client.get(f"/api/audit?limit=2&cursor={data['cursor']}")
    assert r2.status_code == 200
    data2 = r2.json()
    assert len(data2["events"]) == 2
    assert data2["events"][0]["id"] < data["events"][-1]["id"]


def test_audit_filter_by_action(client, db):
    db.add(AuditEvent(actor="admin1", action="sync", entity_type="source", summary="S"))
    db.add(AuditEvent(actor="admin1", action="finding.verify", entity_type="finding", summary="V"))
    db.commit()

    r = client.get("/api/audit?action=sync")
    assert r.status_code == 200
    events = r.json()["events"]
    assert all(e["action"] == "sync" for e in events)


# --- 7. OpenAPI schema documentation --------------------------------------

def test_openapi_schema_has_response_models(client):
    """Verify the OpenAPI schema includes typed response schemas."""
    r = client.get("/api/docs")
    assert r.status_code == 200

    r = client.get("/openapi.json")
    assert r.status_code == 200
    schema = r.json()
    assert "schemas" in schema.get("components", {})
    schema_names = set(schema["components"]["schemas"].keys())
    assert "DashboardOut" in schema_names
    assert "AuditPageOut" in schema_names
    assert "FindingListOut" in schema_names


# --- 8. SSE sync progress (structure test) ---------------------------------

def test_sync_progress_endpoint_exists(client):
    """The SSE endpoint should return without error for valid sources."""
    with client.stream("GET", "/api/sync/progress/wiz",
                       headers={"Accept": "text/event-stream"}) as r:
        assert r.status_code == 200
        first_line = next(r.iter_lines())
        assert "connected" in first_line or "event" in first_line


def test_sync_progress_bad_source(client):
    r = client.get("/api/sync/progress/invalid")
    assert r.status_code == 400


# --- 9. Wiz diagnostics / testing ------------------------------------------

def test_wiz_test_suite_unconfigured(client):
    """Test suite reports config failure when Wiz env vars are missing."""
    r = client.post("/api/wiz/test-suite")
    assert r.status_code == 200
    data = r.json()
    assert data["failed"] >= 1
    assert data["steps"][0]["step"] == "config"
    assert data["steps"][0]["status"] == "fail"
    # Remaining steps should be skipped
    assert data["skipped"] > 0


def test_wiz_query_templates(client):
    """Query templates endpoint returns a list of pre-built queries."""
    r = client.get("/api/wiz/query-templates")
    assert r.status_code == 200
    data = r.json()
    assert "templates" in data
    assert len(data["templates"]) >= 5
    names = [t["name"] for t in data["templates"]]
    assert "count_all" in names
    assert "full_sync_query" in names
    assert "introspect_root" in names
    for t in data["templates"]:
        assert "query" in t
        assert "label" in t


def test_wiz_dry_run_unconfigured(client):
    """Dry run gracefully reports when Wiz is not configured."""
    r = client.post("/api/wiz/dry-run")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "not configured" in data["error"].lower()


# --- 10. GitHub Advanced Security diagnostics --------------------------------

def test_github_test_suite_unconfigured(client):
    """Test suite reports config failure when GitHub env vars are missing."""
    r = client.post("/api/github/test-suite")
    assert r.status_code == 200
    data = r.json()
    assert data["failed"] >= 1
    assert data["steps"][0]["step"] == "config"
    assert data["steps"][0]["status"] == "fail"
    assert data["skipped"] > 0


def test_github_dry_run_unconfigured(client):
    """Dry run gracefully reports when GitHub is not configured."""
    r = client.post("/api/github/dry-run")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "not configured" in data["error"].lower()


def test_github_security_overview_unconfigured(client):
    """Security overview gracefully reports when GitHub is not configured."""
    r = client.get("/api/github/security-overview")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "not configured" in data["error"].lower()


def test_github_repos_unconfigured(client):
    """Repos endpoint returns 400 when GitHub is not configured."""
    r = client.get("/api/github/repos")
    assert r.status_code == 400


def test_github_query_unconfigured(client):
    """API explorer returns not-configured when GitHub is not set up."""
    r = client.post("/api/github/query", json={"path": "/orgs/test/dependabot/alerts"})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "not configured" in data["error"].lower()


def test_github_query_rejects_post_method(client):
    """API explorer rejects non-GET/HEAD methods for safety.
    When unconfigured, the not-configured check fires first."""
    r = client.post("/api/github/query", json={"method": "POST", "path": "/something"})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False


def test_github_query_requires_path(client):
    """API explorer requires a path parameter.
    When unconfigured, the not-configured check fires first."""
    r = client.post("/api/github/query", json={"method": "GET", "path": ""})
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False


def test_github_query_templates(client):
    """Query templates endpoint returns a list of pre-built API call templates."""
    r = client.get("/api/github/query-templates")
    assert r.status_code == 200
    data = r.json()
    assert "templates" in data
    assert len(data["templates"]) >= 5
    names = [t["name"] for t in data["templates"]]
    assert "dependabot_open" in names
    assert "secret_scanning_open" in names
    assert "rate_limit" in names
    for t in data["templates"]:
        assert "path" in t
        assert "label" in t
        assert "params" in t


# --- 11. CrowdStrike Falcon diagnostics ----------------------------------------

def test_falcon_test_suite_unconfigured(client):
    """Test suite reports config failure when Falcon env vars are missing."""
    r = client.post("/api/falcon/test-suite")
    assert r.status_code == 200
    data = r.json()
    assert data["failed"] >= 1
    assert data["steps"][0]["step"] == "config"
    assert data["steps"][0]["status"] == "fail"
    assert data["skipped"] > 0


def test_falcon_dry_run_unconfigured(client):
    """Dry run gracefully reports when Falcon is not configured."""
    r = client.post("/api/falcon/dry-run")
    assert r.status_code == 200
    data = r.json()
    assert data["ok"] is False
    assert "not configured" in data["error"].lower()


def test_falcon_query_templates(client):
    """Query templates endpoint returns a list of pre-built FQL templates."""
    r = client.get("/api/falcon/query-templates")
    assert r.status_code == 200
    data = r.json()
    assert "templates" in data
    assert len(data["templates"]) >= 5
    names = [t["name"] for t in data["templates"]]
    assert "all_open" in names
    assert "critical_open" in names
    assert "configured_filter" in names
    for t in data["templates"]:
        assert "filter" in t
        assert "label" in t
