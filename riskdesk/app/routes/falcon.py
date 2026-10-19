"""CrowdStrike Falcon Spotlight diagnostic routes.

Test-suite, dry-run, query-templates, and FQL explorer endpoints for
troubleshooting the Falcon Spotlight integration.
"""
from __future__ import annotations

import time
import traceback

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request

from ..api_queries import (
    FALCON_DEFAULT_FQL,
    FALCON_SPOTLIGHT_FACETS,
    FALCON_SPOTLIGHT_PATH,
    FALCON_TOKEN_PATH,
)
from ..config import reload_settings, settings
from ..connectors.falcon import FalconConnector
from .deps import current_user

router = APIRouter(prefix="/api/falcon", tags=["falcon"])


def _connector() -> FalconConnector:
    reload_settings()
    return FalconConnector()


def _summary(steps):
    passed = sum(1 for s in steps if s["status"] == "pass")
    failed = sum(1 for s in steps if s["status"] == "fail")
    skipped = sum(1 for s in steps if s["status"] == "skip")
    return {"steps": steps, "passed": passed, "failed": failed, "skipped": skipped}


# ---------------------------------------------------------------------------
#  Test suite — structured step-by-step diagnostic
# ---------------------------------------------------------------------------

@router.post("/test-suite")
def falcon_test_suite(request: Request):
    """Run a structured diagnostic against the CrowdStrike Falcon API.

    Steps: config -> auth -> scope check -> spotlight probe -> severity
    breakdown -> sample mapping.
    """
    c = _connector()
    steps: list[dict] = []

    def _step(name: str, description: str, fn):
        t0 = time.time()
        try:
            result = fn()
            elapsed = round(time.time() - t0, 2)
            steps.append({
                "step": name, "description": description,
                "status": "pass", "elapsed_s": elapsed, **result,
            })
            return True
        except Exception as exc:
            elapsed = round(time.time() - t0, 2)
            steps.append({
                "step": name, "description": description,
                "status": "fail", "elapsed_s": elapsed,
                "error": str(exc), "traceback": traceback.format_exc(),
            })
            return False

    def _skip(name: str, description: str, reason: str):
        steps.append({
            "step": name, "description": description,
            "status": "skip", "reason": reason,
        })

    remaining_steps = [
        ("auth", "Authenticate with OAuth2 client credentials"),
        ("scope", "Verify Spotlight vulnerabilities READ scope"),
        ("probe", "Probe Spotlight for vulnerability data"),
        ("filter_test", "Test the configured FQL filter"),
        ("severity_breakdown", "Count open findings by severity"),
        ("sample", "Fetch and map a sample vulnerability through the sync pipeline"),
    ]

    # Step 1: Config
    def check_config():
        cfg = c.cfg
        missing = []
        if not cfg.client_id:
            missing.append("FALCON_CLIENT_ID")
        if not cfg.client_secret:
            missing.append("FALCON_CLIENT_SECRET")
        if missing:
            raise RuntimeError(
                f"Missing required settings: {', '.join(missing)}. "
                "Set FALCON_CLIENT_ID and FALCON_CLIENT_SECRET in your .env file."
            )
        return {
            "config": {
                "base_url": cfg.base_url,
                "client_id_prefix": cfg.client_id[:8] + "..." if len(cfg.client_id) > 8 else "(set)",
                "member_cid": cfg.member_cid or "(none — single-CID mode)",
                "page_size": cfg.page_size,
                "filter_fql": cfg.filter_fql,
            },
        }

    ok = _step("config", "Verify environment variables are set", check_config)
    if not ok:
        for s in remaining_steps:
            _skip(s[0], s[1], "Configuration incomplete")
        return _summary(steps)

    # Step 2: Auth — get an OAuth2 token
    def check_auth():
        token = c._get_token()
        return {"token_preview": token[:12] + "..." if len(token) > 12 else "(obtained)"}

    remaining_steps = remaining_steps[1:]
    ok = _step("auth", "Authenticate with OAuth2 client credentials", check_auth)
    if not ok:
        for s in remaining_steps:
            _skip(s[0], s[1], "Authentication failed")
        return _summary(steps)

    # Step 3: Scope check — hit Spotlight with limit=1, no facets
    def check_scope():
        import httpx
        r = httpx.get(
            f"{c.cfg.base_url}{FALCON_SPOTLIGHT_PATH}",
            params={"filter": "status:!'closed'", "limit": 1},
            headers=c._headers(), timeout=30,
        )
        if r.status_code == 403:
            raise RuntimeError(
                "403 Forbidden — the API client lacks the 'Spotlight vulnerabilities: READ' "
                "scope. Add this scope in the CrowdStrike console under API Clients."
            )
        if r.status_code >= 400:
            raise RuntimeError(f"Spotlight returned HTTP {r.status_code}: {r.text[:300]}")
        meta = r.json().get("meta", {})
        pagination = meta.get("pagination", {})
        return {
            "total_matches": pagination.get("total"),
            "trace_id": meta.get("trace_id"),
        }

    remaining_steps = remaining_steps[1:]
    ok = _step("scope", "Verify Spotlight vulnerabilities READ scope", check_scope)
    if not ok:
        for s in remaining_steps:
            _skip(s[0], s[1], "Scope check failed")
        return _summary(steps)

    # Step 4: Probe with full facets
    def probe_spotlight():
        import httpx
        r = httpx.get(
            f"{c.cfg.base_url}{FALCON_SPOTLIGHT_PATH}",
            params={"filter": "status:!'closed'", "limit": 3,
                    "facet": FALCON_SPOTLIGHT_FACETS},
            headers=c._headers(), timeout=60,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:300]}")
        body = r.json()
        resources = body.get("resources") or []
        pagination = body.get("meta", {}).get("pagination", {})
        result = {
            "total": pagination.get("total"),
            "returned": len(resources),
        }
        if resources:
            sample = resources[0]
            result["sample"] = {
                "id": sample.get("id"),
                "cve": (sample.get("cve") or {}).get("id"),
                "severity": (sample.get("cve") or {}).get("severity"),
                "hostname": (sample.get("host_info") or {}).get("hostname"),
                "status": sample.get("status"),
            }
        else:
            result["note"] = "No open vulnerabilities found. This could be genuine or the FQL filter is too restrictive."
        return result

    _step("probe", "Probe Spotlight for vulnerability data (with facets)", probe_spotlight)

    # Step 5: Test the configured FQL filter
    def test_filter():
        import httpx
        fql = c.cfg.filter_fql
        r = httpx.get(
            f"{c.cfg.base_url}{FALCON_SPOTLIGHT_PATH}",
            params={"filter": fql, "limit": 1},
            headers=c._headers(), timeout=30,
        )
        if r.status_code == 400:
            raise RuntimeError(
                f"FQL filter rejected by Falcon: {r.text[:300]}. "
                "Check FALCON_FILTER_FQL syntax."
            )
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
        total = r.json().get("meta", {}).get("pagination", {}).get("total", 0)
        return {
            "fql": fql,
            "matching_count": total,
        }

    _step("filter_test", "Test the configured FQL filter", test_filter)

    # Step 6: Severity breakdown
    def severity_breakdown():
        import httpx
        counts = {}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            fql = f"cve.severity:'{sev}'+status:!'closed'"
            r = httpx.get(
                f"{c.cfg.base_url}{FALCON_SPOTLIGHT_PATH}",
                params={"filter": fql, "limit": 1},
                headers=c._headers(), timeout=20,
            )
            if r.status_code < 400:
                counts[sev] = r.json().get("meta", {}).get("pagination", {}).get("total", 0)
            else:
                counts[sev] = f"error:{r.status_code}"
        total_open = sum(v for v in counts.values() if isinstance(v, int))
        return {"by_severity": counts, "total_open": total_open}

    _step("severity_breakdown", "Count open findings by severity", severity_breakdown)

    # Step 7: Fetch and map a sample through the full pipeline
    def sample_mapping():
        import httpx
        r = httpx.get(
            f"{c.cfg.base_url}{FALCON_SPOTLIGHT_PATH}",
            params={"filter": c.cfg.filter_fql, "limit": 1,
                    "facet": FALCON_SPOTLIGHT_FACETS},
            headers=c._headers(), timeout=60,
        )
        if r.status_code >= 400:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
        resources = r.json().get("resources") or []
        if not resources:
            raise RuntimeError(
                "No resources returned with the configured filter. "
                "Try expanding the FQL filter or check the scope step."
            )
        item = resources[0]
        rec = c._map(item)
        if not rec:
            raise RuntimeError("Mapper returned None for the sample resource.")
        return {
            "raw_resource": item,
            "mapped": {
                "source_finding_id": rec.source_finding_id,
                "category": rec.category,
                "severity": rec.severity,
                "status": rec.status,
                "asset_name": rec.asset.name,
                "vuln_title": rec.vuln.title,
                "canonical_id": rec.vuln.canonical_id,
                "component": rec.component,
                "fix_available": rec.fix_available,
            },
        }

    _step("sample", "Fetch and map a sample vulnerability through the sync pipeline", sample_mapping)

    return _summary(steps)


# ---------------------------------------------------------------------------
#  Dry run — preview sync without writing to DB
# ---------------------------------------------------------------------------

@router.post("/dry-run")
def falcon_dry_run(request: Request, limit: int = Query(15, ge=1, le=50)):
    """Simulate a Falcon sync without writing to the database."""
    c = _connector()
    if not c.configured():
        return {"ok": False, "error": "Falcon connector is not configured."}

    try:
        c._get_token()
    except Exception as exc:
        return {"ok": False, "error": f"Authentication failed: {exc}",
                "traceback": traceback.format_exc()}

    import httpx
    records = []
    errors = []
    by_severity: dict[str, int] = {}
    raw_sample = None

    try:
        r = httpx.get(
            f"{c.cfg.base_url}{FALCON_SPOTLIGHT_PATH}",
            params={"filter": c.cfg.filter_fql,
                    "limit": min(limit, 50),
                    "facet": FALCON_SPOTLIGHT_FACETS},
            headers=c._headers(), timeout=90,
        )
        if r.status_code >= 400:
            return {"ok": False, "error": f"Spotlight HTTP {r.status_code}: {r.text[:300]}",
                    "traceback": traceback.format_exc()}
        body = r.json()
        resources = body.get("resources") or []
        total = body.get("meta", {}).get("pagination", {}).get("total", 0)

        for item in resources:
            if not raw_sample:
                raw_sample = item
            try:
                rec = c._map(item)
                if rec:
                    records.append({
                        "source_finding_id": rec.source_finding_id,
                        "category": rec.category,
                        "severity": rec.severity,
                        "status": rec.status,
                        "asset": {
                            "source_asset_id": rec.asset.source_asset_id,
                            "name": rec.asset.name,
                            "type": rec.asset.asset_type,
                            "os": rec.asset.os_name,
                            "ip": rec.asset.ip_address,
                        },
                        "vuln": {
                            "canonical_id": rec.vuln.canonical_id,
                            "cve_id": rec.vuln.cve_id,
                            "title": rec.vuln.title,
                            "severity": rec.vuln.severity,
                            "cvss_score": rec.vuln.cvss_score,
                            "kev": rec.vuln.kev,
                        },
                        "component": rec.component,
                        "fix_available": rec.fix_available,
                        "fix_version": rec.fix_version,
                    })
                    by_severity[rec.severity] = by_severity.get(rec.severity, 0) + 1
            except Exception as exc:
                errors.append({
                    "resource_id": item.get("id"),
                    "error": str(exc),
                })
    except Exception as exc:
        return {"ok": False, "error": f"Spotlight query failed: {exc}",
                "traceback": traceback.format_exc()}

    return {
        "ok": True,
        "total_in_falcon": total,
        "fetched": len(resources),
        "mapped": len(records),
        "mapping_errors": len(errors),
        "by_severity": by_severity,
        "records": records,
        "errors": errors[:10],
        "raw_sample": raw_sample,
    }


# ---------------------------------------------------------------------------
#  Query templates — pre-built FQL queries for common troubleshooting
# ---------------------------------------------------------------------------

@router.get("/query-templates")
def falcon_query_templates():
    """Return pre-built FQL query templates for Falcon Spotlight troubleshooting."""
    return {"templates": [
        {
            "name": "all_open",
            "label": "All open vulnerabilities",
            "description": "Base filter: everything not closed. Verifies the API client has Spotlight access.",
            "filter": "status:!'closed'",
            "facets": FALCON_SPOTLIGHT_FACETS,
            "limit": 5,
        },
        {
            "name": "critical_open",
            "label": "Open critical-severity CVEs",
            "description": "Critical CVEs that are still open.",
            "filter": "cve.severity:'CRITICAL'+status:!'closed'",
            "facets": FALCON_SPOTLIGHT_FACETS,
            "limit": 10,
        },
        {
            "name": "high_open",
            "label": "Open high-severity CVEs",
            "description": "High-severity CVEs that are still open.",
            "filter": "cve.severity:'HIGH'+status:!'closed'",
            "facets": FALCON_SPOTLIGHT_FACETS,
            "limit": 10,
        },
        {
            "name": "exploitable",
            "label": "Actively exploited vulnerabilities",
            "description": "CVEs with exploit_status >= 60 (known exploited in the wild — similar to CISA KEV).",
            "filter": "cve.exploit_status_string:'AVAILABLE'+status:!'closed'",
            "facets": FALCON_SPOTLIGHT_FACETS,
            "limit": 10,
        },
        {
            "name": "by_hostname",
            "label": "Vulnerabilities for a specific host",
            "description": "Replace HOSTNAME with a real hostname from your environment.",
            "filter": "host_info.hostname:'HOSTNAME'+status:!'closed'",
            "facets": FALCON_SPOTLIGHT_FACETS,
            "limit": 10,
        },
        {
            "name": "with_remediation",
            "label": "Vulnerabilities with available remediation",
            "description": "Only findings where Falcon suggests a patch or update.",
            "filter": "remediation.ids:*+status:!'closed'",
            "facets": ["cve", "host_info", "remediation"],
            "limit": 5,
        },
        {
            "name": "recent_24h",
            "label": "Findings created in the last 24 hours",
            "description": "New detections from the past day.",
            "filter": "created_timestamp:>'now-1d'+status:!'closed'",
            "facets": FALCON_SPOTLIGHT_FACETS,
            "limit": 10,
        },
        {
            "name": "windows_only",
            "label": "Windows endpoints only",
            "description": "Vulnerabilities on Windows hosts.",
            "filter": "host_info.platform:'Windows'+status:!'closed'",
            "facets": FALCON_SPOTLIGHT_FACETS,
            "limit": 5,
        },
        {
            "name": "configured_filter",
            "label": "Current configured filter",
            "description": "The FQL filter currently set in FALCON_FILTER_FQL. This is what the sync uses.",
            "filter": FALCON_DEFAULT_FQL,
            "facets": FALCON_SPOTLIGHT_FACETS,
            "limit": 5,
        },
    ]}
