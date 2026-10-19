"""Sync, schedule, and connector diagnostics routes."""
from __future__ import annotations

import asyncio
import datetime as dt
import json
import threading

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sse_starlette.sse import EventSourceResponse
from sqlalchemy import select

from ..api_queries import (
    QUERY_REGISTRY,
    WIZ_DIAG_CONFIG_PROBE,
    WIZ_DIAG_VULN_PROBE,
    WIZ_INTROSPECT_TYPES,
    WIZ_VULN_DEFAULT_FILTER,
    WIZ_VULN_FINDINGS,
)
from ..db import get_session
from ..models import AuditEvent, SyncRun, SyncSchedule
from ..schemas import QueryRegistryOut, ScheduleOut, SyncRunOut
from ..sync import get_connector, run_sync
from .deps import current_user

router = APIRouter(prefix="/api", tags=["sync"])


@router.post("/sync/{source}")
def trigger_sync(source: str, request: Request, demo: bool = False,
                 limit: int | None = None):
    if source not in ("wiz", "falcon", "github"):
        raise HTTPException(400, "Unknown source.")
    return run_sync(source, demo=demo, limit=limit, actor=current_user(request))


@router.get("/sync/check/{source}")
def check_source(source: str):
    if source not in ("wiz", "falcon", "github"):
        raise HTTPException(400, "Unknown source.")
    ok, message = get_connector(source).check()
    return {"source": source, "ok": ok, "message": message}


@router.get("/sync/diagnose/wiz")
def diagnose_wiz(request: Request):
    from ..connectors.wiz import WizConnector
    c = WizConnector()
    if not c.configured():
        return {"ok": False, "error": "Not configured"}
    results = {}
    try:
        c._get_token()
        results["auth"] = "ok"
    except Exception as exc:
        return {"ok": False, "auth": str(exc)}
    for type_name in WIZ_INTROSPECT_TYPES:
        try:
            fields = c.introspect(type_name)
            results[type_name] = fields if fields else "not found in schema"
        except Exception as exc:
            results[type_name] = f"error: {exc}"
    try:
        data = c.graphql(WIZ_DIAG_VULN_PROBE, {})
        block = data.get("vulnerabilityFindings") or {}
        results["vuln_probe"] = {
            "totalCount": block.get("totalCount"),
            "sample": (block.get("nodes") or [None])[0],
        }
    except Exception as exc:
        results["vuln_probe"] = f"error: {exc}"
    try:
        data = c.graphql(WIZ_DIAG_CONFIG_PROBE, {})
        block = data.get("configurationFindings") or {}
        results["config_probe"] = {
            "totalCount": block.get("totalCount"),
            "sample": (block.get("nodes") or [None])[0],
        }
    except Exception as exc:
        results["config_probe"] = f"error: {exc}"
    return {"ok": True, "diagnostics": results}


# --- Wiz test suite ----------------------------------------------------------

@router.post("/wiz/test-suite")
def wiz_test_suite(request: Request):
    """Run a structured, step-by-step diagnostic against the Wiz API.

    Each step builds on the previous one, so if auth fails, later steps are
    skipped. Returns a list of step results with pass/fail/skip status, timing,
    and actionable error details.
    """
    import time
    import traceback
    from ..connectors.wiz import WizConnector
    from ..config import reload_settings
    reload_settings()

    steps: list[dict] = []
    c = WizConnector()

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

    # Step 1: Configuration check
    def check_config():
        cfg = c.cfg
        fields = {
            "client_id": bool(cfg.client_id),
            "client_secret": bool(cfg.client_secret),
            "api_url": bool(cfg.api_url),
            "auth_url": cfg.auth_url,
            "audience": cfg.audience,
        }
        missing = [k for k, v in fields.items() if not v]
        if missing:
            raise RuntimeError(
                f"Missing required settings: {', '.join(missing)}. "
                "Set WIZ_CLIENT_ID, WIZ_CLIENT_SECRET, and WIZ_API_URL in your .env file."
            )
        return {
            "config": {
                "api_url": cfg.api_url,
                "auth_url": cfg.auth_url,
                "audience": cfg.audience,
                "page_size": cfg.page_size,
                "client_id_prefix": cfg.client_id[:8] + "..." if len(cfg.client_id) > 8 else "(set)",
            }
        }

    ok = _step("config", "Verify environment variables are set", check_config)
    if not ok:
        for s in [
            ("auth", "Authenticate with OAuth2 token"),
            ("connectivity", "Reach the GraphQL endpoint"),
            ("schema_vuln", "Validate VulnerabilityFinding schema fields"),
            ("schema_config", "Validate ConfigurationFinding schema fields"),
            ("probe_vuln", "Probe for vulnerability findings"),
            ("probe_vuln_unfiltered", "Probe without status filter"),
            ("probe_config", "Probe for configuration findings"),
            ("count_by_severity", "Count findings by severity"),
            ("sample_full", "Fetch a full sample record with all mapped fields"),
        ]:
            _skip(s[0], s[1], "Configuration incomplete")
        return {"steps": steps, "passed": 0, "failed": 1, "skipped": len(steps) - 1}

    # Step 2: Authentication
    def check_auth():
        token = c._get_token()
        return {"token_preview": token[:12] + "..." if len(token) > 12 else "(obtained)"}

    ok = _step("auth", "Authenticate with OAuth2 token", check_auth)
    if not ok:
        remaining = [
            ("connectivity", "Reach the GraphQL endpoint"),
            ("schema_vuln", "Validate VulnerabilityFinding schema fields"),
            ("schema_config", "Validate ConfigurationFinding schema fields"),
            ("probe_vuln", "Probe for vulnerability findings"),
            ("probe_vuln_unfiltered", "Probe without status filter"),
            ("probe_config", "Probe for configuration findings"),
            ("count_by_severity", "Count findings by severity"),
            ("sample_full", "Fetch a full sample record with all mapped fields"),
        ]
        for s in remaining:
            _skip(s[0], s[1], "Authentication failed")
        return {"steps": steps, "passed": 1, "failed": 1, "skipped": len(remaining)}

    # Step 3: Connectivity (minimal GraphQL query)
    def check_connectivity():
        data = c.graphql("query { __typename }", {})
        return {"response": data}

    ok = _step("connectivity", "Reach the GraphQL endpoint", check_connectivity)
    if not ok:
        remaining = [
            ("schema_vuln", "Validate VulnerabilityFinding schema fields"),
            ("schema_config", "Validate ConfigurationFinding schema fields"),
            ("probe_vuln", "Probe for vulnerability findings"),
            ("probe_vuln_unfiltered", "Probe without status filter"),
            ("probe_config", "Probe for configuration findings"),
            ("count_by_severity", "Count findings by severity"),
            ("sample_full", "Fetch a full sample record with all mapped fields"),
        ]
        for s in remaining:
            _skip(s[0], s[1], "GraphQL endpoint unreachable")
        return {"steps": steps, "passed": 2, "failed": 1, "skipped": len(remaining)}

    # Step 4: Schema validation — check the fields we query actually exist
    def check_schema_vuln():
        fields = c.introspect("VulnerabilityFinding")
        if not fields:
            raise RuntimeError(
                "Type 'VulnerabilityFinding' not found. Your tenant may use a different "
                "type name. Try introspecting 'Query' to see available root types."
            )
        field_names = {f.split(":")[0].strip() for f in fields}
        expected = {
            "id", "name", "CVSSSeverity", "score", "status", "vulnerableAsset",
            "firstDetectedAt", "lastDetectedAt", "remediation", "vendorSeverity",
        }
        missing = expected - field_names
        extra_useful = {"epssProbability", "epssPercentile", "hasCisaKevExploit",
                        "hasExploit", "detailedName", "fixedVersion"} & field_names
        result = {
            "total_fields": len(fields),
            "expected_present": sorted(expected & field_names),
            "extra_useful": sorted(extra_useful),
        }
        if missing:
            result["missing_fields"] = sorted(missing)
            result["warning"] = (
                f"Fields {sorted(missing)} are used by the sync query but not found "
                "on this tenant. The sync query will fail. Edit WIZ_VULN_FINDINGS "
                "in app/api_queries.py to match your schema."
            )
        return result

    _step("schema_vuln", "Validate VulnerabilityFinding schema fields", check_schema_vuln)

    def check_schema_config():
        fields = c.introspect("ConfigurationFinding")
        if not fields:
            raise RuntimeError(
                "Type 'ConfigurationFinding' not found. This is normal if your "
                "Wiz license does not include cloud security posture management (CSPM)."
            )
        field_names = {f.split(":")[0].strip() for f in fields}
        expected = {"id", "severity", "result", "rule", "resource"}
        missing = expected - field_names
        result = {"total_fields": len(fields)}
        if missing:
            result["missing_fields"] = sorted(missing)
            result["warning"] = f"Missing fields: {sorted(missing)}"
        return result

    _step("schema_config", "Validate ConfigurationFinding schema fields", check_schema_config)

    # Step 5: Data probes — does anything actually exist?
    def probe_vuln():
        data = c.graphql(
            "query { vulnerabilityFindings(first: 1, filterBy: {status: [OPEN, IN_PROGRESS]}) "
            "{ totalCount nodes { id name status vendorSeverity } } }", {}
        )
        block = data.get("vulnerabilityFindings") or {}
        total = block.get("totalCount", 0)
        sample = (block.get("nodes") or [None])[0]
        if total == 0:
            raise RuntimeError(
                "No OPEN/IN_PROGRESS vulnerability findings found. This could mean: "
                "(1) all findings are resolved, (2) the service account lacks the "
                "'read:vulnerabilities' scope, or (3) the account is scoped to a "
                "project/folder with no findings. Try the unfiltered probe next."
            )
        return {"total_count": total, "sample": sample}

    _step("probe_vuln", "Probe for vulnerability findings (OPEN/IN_PROGRESS)", probe_vuln)

    def probe_vuln_unfiltered():
        data = c.graphql(
            "query { vulnerabilityFindings(first: 3) "
            "{ totalCount nodes { id name status vendorSeverity } } }", {}
        )
        block = data.get("vulnerabilityFindings") or {}
        total = block.get("totalCount", 0)
        nodes = block.get("nodes") or []
        statuses = [n.get("status") for n in nodes]
        result = {"total_count": total, "sample_statuses": statuses}
        if total == 0:
            raise RuntimeError(
                "No vulnerability findings at all (even without filters). "
                "The service account likely lacks permissions, or this tenant "
                "has no vulnerability scanning enabled."
            )
        return result

    _step("probe_vuln_unfiltered", "Probe without status filter (any findings at all?)", probe_vuln_unfiltered)

    def probe_config():
        data = c.graphql(
            "query { configurationFindings(first: 1, filterBy: {result: [FAIL]}) "
            "{ totalCount nodes { id severity result } } }", {}
        )
        block = data.get("configurationFindings") or {}
        total = block.get("totalCount", 0)
        result = {"total_count": total}
        if total == 0:
            result["note"] = (
                "No FAIL configuration findings. Either CSPM is not enabled, "
                "all rules pass, or the service account lacks 'read:configurationFindings' scope."
            )
        return result

    _step("probe_config", "Probe for configuration findings (FAIL)", probe_config)

    # Step 6: Severity breakdown
    def count_by_severity():
        counts = {}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
            try:
                data = c.graphql(
                    "query($f: VulnerabilityFindingFilters) { "
                    "vulnerabilityFindings(first: 0, filterBy: $f) { totalCount } }",
                    {"f": {"status": ["OPEN", "IN_PROGRESS"], "vendorSeverity": [sev]}},
                )
                counts[sev] = (data.get("vulnerabilityFindings") or {}).get("totalCount", 0)
            except Exception:
                counts[sev] = "error"
        return {"by_severity": counts, "total_open": sum(v for v in counts.values() if isinstance(v, int))}

    _step("count_by_severity", "Count open findings by severity", count_by_severity)

    # Step 7: Fetch a full sample with the actual sync query fields
    def sample_full():
        data = c.graphql(WIZ_VULN_FINDINGS, {
            "filterBy": {"status": ["OPEN", "IN_PROGRESS"]},
            "first": 1, "after": None,
        })
        block = data.get("vulnerabilityFindings") or {}
        nodes = block.get("nodes") or []
        if not nodes:
            raise RuntimeError(
                "The full sync query returned no results. If the simple probe found "
                "data but this didn't, a field in the query may be causing an error. "
                "Check the schema_vuln step for missing fields."
            )
        node = nodes[0]
        mapped = None
        map_error = None
        try:
            rec = c._map_vuln(node)
            if rec:
                mapped = {
                    "source_finding_id": rec.source_finding_id,
                    "category": rec.category,
                    "severity": rec.severity,
                    "status": rec.status,
                    "asset_name": rec.asset.name,
                    "vuln_title": rec.vuln.title,
                    "canonical_id": rec.vuln.canonical_id,
                }
        except Exception as exc:
            map_error = str(exc)
        return {
            "raw_node": node,
            "mapped_record": mapped,
            "mapping_error": map_error,
        }

    _step("sample_full", "Fetch and map a full sample record using the sync query", sample_full)

    passed = sum(1 for s in steps if s["status"] == "pass")
    failed = sum(1 for s in steps if s["status"] == "fail")
    skipped = sum(1 for s in steps if s["status"] == "skip")
    return {"steps": steps, "passed": passed, "failed": failed, "skipped": skipped}


@router.get("/wiz/query-templates")
def wiz_query_templates():
    """Return pre-built query templates for common Wiz troubleshooting scenarios."""
    return {"templates": [
        {
            "name": "count_all",
            "label": "Count all vulnerability findings",
            "description": "Total count with no filter — verifies the service account can see data at all.",
            "query": "query {\n  vulnerabilityFindings(first: 0) {\n    totalCount\n  }\n}",
            "variables": {},
        },
        {
            "name": "count_open",
            "label": "Count open findings by status",
            "description": "How many findings are OPEN vs IN_PROGRESS vs RESOLVED.",
            "query": (
                "query($f: VulnerabilityFindingFilters) {\n"
                "  vulnerabilityFindings(first: 0, filterBy: $f) {\n"
                "    totalCount\n"
                "  }\n}"
            ),
            "variables": {"f": {"status": ["OPEN"]}},
            "variants": [
                {"label": "Open", "variables": {"f": {"status": ["OPEN"]}}},
                {"label": "In Progress", "variables": {"f": {"status": ["IN_PROGRESS"]}}},
                {"label": "Resolved", "variables": {"f": {"status": ["RESOLVED"]}}},
                {"label": "Open + In Progress", "variables": {"f": {"status": ["OPEN", "IN_PROGRESS"]}}},
            ],
        },
        {
            "name": "sample_vulns",
            "label": "Fetch 5 sample vulnerability findings",
            "description": "Minimal fields to verify data shape without risking schema drift.",
            "query": (
                "query {\n"
                "  vulnerabilityFindings(first: 5, filterBy: {status: [OPEN]}) {\n"
                "    totalCount\n"
                "    nodes {\n"
                "      id\n"
                "      name\n"
                "      status\n"
                "      vendorSeverity\n"
                "      score\n"
                "      firstDetectedAt\n"
                "    }\n"
                "    pageInfo { hasNextPage endCursor }\n"
                "  }\n}"
            ),
            "variables": {},
        },
        {
            "name": "sample_with_asset",
            "label": "Fetch findings with asset details",
            "description": "Includes the vulnerableAsset block to verify asset mapping works.",
            "query": (
                "query {\n"
                "  vulnerabilityFindings(first: 3, filterBy: {status: [OPEN]}) {\n"
                "    nodes {\n"
                "      id\n"
                "      name\n"
                "      vendorSeverity\n"
                "      vulnerableAsset {\n"
                "        ... on VulnerableAssetBase {\n"
                "          id name type cloudPlatform region\n"
                "        }\n"
                "      }\n"
                "    }\n"
                "  }\n}"
            ),
            "variables": {},
        },
        {
            "name": "full_sync_query",
            "label": "Full sync query (what the sync actually sends)",
            "description": "Exact query used by the sync engine. If this works, sync will work.",
            "query": WIZ_VULN_FINDINGS,
            "variables": {
                "filterBy": {"status": ["OPEN", "IN_PROGRESS"]},
                "first": 3, "after": None,
            },
        },
        {
            "name": "config_findings",
            "label": "Fetch configuration (CSPM) findings",
            "description": "Cloud misconfigurations. Requires CSPM entitlement.",
            "query": (
                "query {\n"
                "  configurationFindings(first: 3, filterBy: {result: [FAIL]}) {\n"
                "    totalCount\n"
                "    nodes {\n"
                "      id\n"
                "      severity\n"
                "      result\n"
                "      rule { id name shortName }\n"
                "      resource { id name type region }\n"
                "    }\n"
                "  }\n}"
            ),
            "variables": {},
        },
        {
            "name": "epss_kev",
            "label": "Findings with EPSS and KEV data",
            "description": "Verify EPSS/KEV fields are populated (needed for risk scoring).",
            "query": (
                "query {\n"
                "  vulnerabilityFindings(first: 5, filterBy: {status: [OPEN]}) {\n"
                "    nodes {\n"
                "      id\n"
                "      name\n"
                "      score\n"
                "      epssProbability\n"
                "      epssPercentile\n"
                "      hasCisaKevExploit\n"
                "      hasExploit\n"
                "      vendorSeverity\n"
                "    }\n"
                "  }\n}"
            ),
            "variables": {},
        },
        {
            "name": "introspect_root",
            "label": "Introspect the Query root type",
            "description": "Lists all top-level query fields available on your tenant.",
            "query": (
                "query {\n"
                "  __type(name: \"Query\") {\n"
                "    fields {\n"
                "      name\n"
                "      type { name kind }\n"
                "    }\n"
                "  }\n}"
            ),
            "variables": {},
        },
    ]}


@router.post("/wiz/dry-run")
def wiz_dry_run(request: Request, limit: int = 10):
    """Simulate a sync without writing to the database.

    Fetches up to `limit` records from Wiz, maps them through the connector,
    and returns what would have been imported — so you can verify the pipeline
    end-to-end before committing.
    """
    import traceback
    from ..connectors.wiz import WizConnector
    from ..config import reload_settings
    reload_settings()

    c = WizConnector()
    if not c.configured():
        return {"ok": False, "error": "Wiz connector is not configured."}
    try:
        c._get_token()
    except Exception as exc:
        return {"ok": False, "error": f"Authentication failed: {exc}",
                "traceback": traceback.format_exc()}

    records = []
    raw_nodes = []
    errors = []
    limit = min(limit, 50)
    seen = 0

    try:
        for node in c._paginate(WIZ_VULN_FINDINGS, "vulnerabilityFindings",
                                WIZ_VULN_DEFAULT_FILTER):
            raw_nodes.append(node)
            try:
                rec = c._map_vuln(node)
                if rec:
                    records.append({
                        "source_finding_id": rec.source_finding_id,
                        "category": rec.category,
                        "severity": rec.severity,
                        "source_severity": rec.source_severity,
                        "status": rec.status,
                        "asset": {
                            "source_asset_id": rec.asset.source_asset_id,
                            "name": rec.asset.name,
                            "type": rec.asset.asset_type,
                            "cloud_provider": rec.asset.cloud_provider,
                            "region": rec.asset.region,
                        },
                        "vuln": {
                            "canonical_id": rec.vuln.canonical_id,
                            "cve_id": rec.vuln.cve_id,
                            "title": rec.vuln.title,
                            "severity": rec.vuln.severity,
                            "cvss_score": rec.vuln.cvss_score,
                            "epss_score": rec.vuln.epss_score,
                            "kev": rec.vuln.kev,
                        },
                        "component": rec.component,
                        "fix_available": rec.fix_available,
                        "fix_version": rec.fix_version,
                    })
            except Exception as exc:
                errors.append({
                    "node_id": node.get("id"),
                    "error": str(exc),
                })
            seen += 1
            if seen >= limit:
                break
    except Exception as exc:
        return {
            "ok": False,
            "error": f"Query failed: {exc}",
            "traceback": traceback.format_exc(),
            "records_before_failure": len(records),
            "raw_nodes_fetched": len(raw_nodes),
        }

    severities = {}
    for r in records:
        sev = r["severity"]
        severities[sev] = severities.get(sev, 0) + 1

    return {
        "ok": True,
        "fetched": len(raw_nodes),
        "mapped": len(records),
        "mapping_errors": len(errors),
        "by_severity": severities,
        "records": records,
        "errors": errors[:10],
        "raw_sample": raw_nodes[0] if raw_nodes else None,
    }


@router.post("/wiz/query")
async def wiz_query(request: Request):
    import traceback
    from ..connectors.wiz import WizConnector
    from ..config import reload_settings
    reload_settings()
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body")
    query = body.get("query", "").strip()
    variables = body.get("variables") or {}
    if not query:
        raise HTTPException(400, "No query provided")
    c = WizConnector()
    if not c.configured():
        return {"ok": False, "error": "Wiz connector is not configured.",
                "debug": {"client_id": bool(c.cfg.client_id), "client_secret": bool(c.cfg.client_secret),
                          "api_url": c.cfg.api_url or "(empty)"}}
    try:
        c._get_token()
    except Exception as exc:
        return {"ok": False, "error": f"Wiz authentication failed: {exc}",
                "traceback": traceback.format_exc()}
    try:
        data = c.graphql(query, variables, attempts=2)
    except Exception as exc:
        return {"ok": False, "error": f"Wiz GraphQL error: {exc}",
                "traceback": traceback.format_exc()}
    return {"ok": True, "data": data}


@router.post("/wiz/introspect")
async def wiz_introspect_type(request: Request):
    import traceback
    from ..connectors.wiz import WizConnector
    from ..config import reload_settings
    reload_settings()
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body")
    type_name = body.get("type", "").strip()
    if not type_name:
        raise HTTPException(400, "No type name provided")
    c = WizConnector()
    if not c.configured():
        return {"ok": False, "error": "Wiz connector is not configured.",
                "debug": {"client_id": bool(c.cfg.client_id), "client_secret": bool(c.cfg.client_secret),
                          "api_url": c.cfg.api_url or "(empty)"}}
    try:
        fields = c.introspect(type_name)
    except Exception as exc:
        return {"ok": False, "error": f"Introspection failed: {exc}",
                "traceback": traceback.format_exc()}
    return {"ok": True, "type": type_name, "fields": fields}


@router.post("/wiz/import-file")
def wiz_import_file(request: Request, body: dict = Body(...), db=Depends(get_session)):
    from ..config import reload_settings
    reload_settings()
    actor = current_user(request)

    vuln_nodes = []
    config_nodes = []
    if "findings" in body:
        vuln_nodes = body["findings"]
    elif "data" in body:
        data = body["data"]
        vuln_nodes = (data.get("vulnerabilityFindings") or {}).get("nodes", [])
        config_nodes = (data.get("configurationFindings") or {}).get("nodes", [])
    else:
        vuln_nodes = body.get("nodes", [])

    if not vuln_nodes and not config_nodes:
        raise HTTPException(422, "No findings found in the uploaded data.")

    from ..connectors.wiz import WizConnector
    from ..sync import run_sync_from_records
    wiz = WizConnector()

    records = []
    errors = []
    for i, node in enumerate(vuln_nodes):
        try:
            rec = wiz._map_vuln(node)
            if rec:
                records.append(rec)
        except Exception as exc:
            errors.append({"index": i, "id": node.get("id"), "error": str(exc), "type": "vuln"})
    for i, node in enumerate(config_nodes):
        try:
            rec = wiz._map_config(node)
            if rec:
                records.append(rec)
        except Exception as exc:
            errors.append({"index": i, "id": node.get("id"), "error": str(exc), "type": "config"})

    if not records:
        return JSONResponse({
            "ok": False,
            "error": f"Could not map any of {len(vuln_nodes) + len(config_nodes)} nodes",
            "mapping_errors": errors[:20],
        }, status_code=422)

    result = run_sync_from_records(db, "wiz", records, actor=actor)
    result["mapping_errors"] = errors[:20]
    result["ok"] = True
    return result


@router.get("/sync/diagnose/falcon")
def diagnose_falcon(request: Request):
    """Diagnostic endpoint for CrowdStrike Falcon Spotlight."""
    from ..connectors.falcon import FalconConnector
    from ..api_queries import FALCON_SPOTLIGHT_PATH
    c = FalconConnector()
    if not c.configured():
        return {"ok": False, "error": "Not configured"}
    results = {}
    try:
        c._get_token()
        results["auth"] = "ok"
    except Exception as exc:
        return {"ok": False, "auth": str(exc)}
    try:
        import httpx
        r = httpx.get(
            f"{c.cfg.base_url}{FALCON_SPOTLIGHT_PATH}",
            params={"filter": c.cfg.filter_fql, "limit": 1,
                    "facet": ["cve", "host_info"]},
            headers=c._headers(), timeout=30,
        )
        if r.status_code == 403:
            results["spotlight"] = "error: API client lacks Spotlight vulnerabilities READ scope"
        elif r.status_code >= 400:
            results["spotlight"] = f"error: HTTP {r.status_code}"
        else:
            body = r.json()
            meta = body.get("meta", {}).get("pagination", {})
            sample = (body.get("resources") or [None])[0]
            results["spotlight_probe"] = {
                "total": meta.get("total"),
                "sample_id": sample.get("id") if sample else None,
                "sample_cve": (sample.get("cve") or {}).get("id") if sample else None,
                "sample_host": (sample.get("host_info") or {}).get("hostname") if sample else None,
            }
    except Exception as exc:
        results["spotlight_probe"] = f"error: {exc}"
    results["base_url"] = c.cfg.base_url
    results["filter_fql"] = c.cfg.filter_fql
    return {"ok": True, "diagnostics": results}


@router.post("/falcon/query")
async def falcon_query(request: Request):
    """Execute a Falcon Spotlight query with custom FQL filter."""
    import traceback
    from ..connectors.falcon import FalconConnector
    from ..api_queries import FALCON_SPOTLIGHT_PATH, FALCON_SPOTLIGHT_FACETS
    from ..config import reload_settings
    reload_settings()
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body")
    fql = body.get("filter", "").strip()
    limit = min(int(body.get("limit", 5)), 100)
    facets = body.get("facets", FALCON_SPOTLIGHT_FACETS)
    if not fql:
        raise HTTPException(400, "No FQL filter provided")
    c = FalconConnector()
    if not c.configured():
        return {"ok": False, "error": "Falcon connector is not configured.",
                "debug": {"client_id": bool(c.cfg.client_id),
                          "client_secret": bool(c.cfg.client_secret),
                          "base_url": c.cfg.base_url or "(empty)"}}
    try:
        c._get_token()
    except Exception as exc:
        return {"ok": False, "error": f"Falcon authentication failed: {exc}",
                "traceback": traceback.format_exc()}
    try:
        import httpx
        r = httpx.get(
            f"{c.cfg.base_url}{FALCON_SPOTLIGHT_PATH}",
            params={"filter": fql, "limit": limit, "facet": facets},
            headers=c._headers(), timeout=90,
        )
        if r.status_code >= 400:
            return {"ok": False, "error": f"Falcon Spotlight {r.status_code}: {r.text[:400]}",
                    "traceback": traceback.format_exc()}
        data = r.json()
    except Exception as exc:
        return {"ok": False, "error": f"Falcon Spotlight error: {exc}",
                "traceback": traceback.format_exc()}
    return {
        "ok": True,
        "meta": data.get("meta"),
        "resources": data.get("resources"),
        "errors": data.get("errors"),
    }


@router.get("/queries")
def list_queries():
    """Return the centralized query registry for all connectors."""
    return {"queries": QUERY_REGISTRY}


@router.get("/sync/runs")
def sync_runs(limit: int = 50, db=Depends(get_session)):
    rows = db.execute(
        select(SyncRun).order_by(SyncRun.started_at.desc()).limit(limit)
    ).scalars().all()
    return [{
        "id": r.id, "source": r.source, "status": r.status,
        "started_at": r.started_at.isoformat() if r.started_at else None,
        "finished_at": r.finished_at.isoformat() if r.finished_at else None,
        "assets": r.assets_upserted, "findings": r.findings_upserted,
        "new": r.findings_new, "closed": r.findings_closed,
        "error": r.error, "triggered_by": r.triggered_by,
    } for r in rows]


@router.get("/sync/runs/{run_id}")
def get_sync_run(run_id: int, db=Depends(get_session)):
    run = db.get(SyncRun, run_id)
    if run is None:
        raise HTTPException(404, "No such sync run.")
    delta = run.delta or {}
    return {
        "id": run.id, "source": run.source, "status": run.status,
        "started_at": run.started_at.isoformat() if run.started_at else None,
        "finished_at": run.finished_at.isoformat() if run.finished_at else None,
        "assets": run.assets_upserted, "findings": run.findings_upserted,
        "new": run.findings_new, "closed": run.findings_closed,
        "error": run.error, "triggered_by": run.triggered_by,
        "new_by_severity": delta.get("new_by_severity", {}),
    }


# --- sync schedules ---------------------------------------------------------

def _serialize_schedule(s: SyncSchedule) -> dict:
    return {
        "id": s.id, "source": s.source, "enabled": s.enabled,
        "interval_hours": s.interval_hours,
        "preferred_hour_utc": s.preferred_hour_utc,
        "last_run_at": s.last_run_at.isoformat() if s.last_run_at else None,
        "next_run_at": s.next_run_at.isoformat() if s.next_run_at else None,
        "last_status": s.last_status, "last_error": s.last_error,
        "limit": s.limit, "created_by": s.created_by,
        "updated_at": s.updated_at.isoformat() if s.updated_at else None,
    }


@router.get("/schedules")
def list_schedules(db=Depends(get_session)):
    rows = db.execute(select(SyncSchedule).order_by(SyncSchedule.source)).scalars().all()
    return [_serialize_schedule(s) for s in rows]


@router.post("/schedules")
def upsert_schedule(request: Request, body: dict = Body(...), db=Depends(get_session)):
    source = body.get("source")
    if source not in ("wiz", "falcon", "github"):
        raise HTTPException(400, "Unknown source.")
    row = db.execute(
        select(SyncSchedule).where(SyncSchedule.source == source)
    ).scalar_one_or_none()
    if row is None:
        row = SyncSchedule(source=source)
        db.add(row)
    row.enabled = bool(body.get("enabled", row.enabled))
    if "interval_hours" in body:
        val = max(1, min(int(body["interval_hours"]), 168))
        row.interval_hours = val
    if "preferred_hour_utc" in body:
        h = body["preferred_hour_utc"]
        row.preferred_hour_utc = int(h) % 24 if h is not None else None
    if "limit" in body:
        row.limit = int(body["limit"]) if body["limit"] else None
    row.created_by = current_user(request)
    now = dt.datetime.now(dt.timezone.utc)
    if row.enabled and row.next_run_at is None:
        from ..scheduler import _compute_next
        row.next_run_at = _compute_next(row, now)
    if not row.enabled:
        row.next_run_at = None
    db.commit()
    db.add(AuditEvent(
        actor=current_user(request), action="schedule.update",
        entity_type="schedule", entity_id=source,
        summary=f"Schedule {'enabled' if row.enabled else 'disabled'} for {source}: every {row.interval_hours}h",
    ))
    db.commit()
    return _serialize_schedule(row)


@router.delete("/schedules/{source}")
def delete_schedule(source: str, request: Request, db=Depends(get_session)):
    row = db.execute(
        select(SyncSchedule).where(SyncSchedule.source == source)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "No schedule for that source.")
    db.delete(row)
    db.commit()
    return {"deleted": source}


# --- SSE live sync progress -------------------------------------------------

_sync_subscribers: dict[str, list[asyncio.Queue]] = {}
_sub_lock = threading.Lock()


def _broadcast_sync_event(source: str, event: dict):
    """Push a progress event to all SSE subscribers for a source."""
    with _sub_lock:
        queues = _sync_subscribers.get(source, [])
        for q in queues:
            try:
                q.put_nowait(event)
            except asyncio.QueueFull:
                pass


@router.get("/sync/progress/{source}")
async def sync_progress_sse(source: str, request: Request):
    """SSE endpoint for live sync progress. Connect before triggering a sync."""
    if source not in ("wiz", "falcon", "github"):
        raise HTTPException(400, "Unknown source.")

    queue: asyncio.Queue = asyncio.Queue(maxsize=100)
    with _sub_lock:
        _sync_subscribers.setdefault(source, []).append(queue)

    async def event_generator():
        try:
            yield {"event": "connected", "data": json.dumps({"source": source})}
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=30.0)
                    yield {"event": event.get("type", "progress"), "data": json.dumps(event)}
                    if event.get("type") == "complete":
                        break
                except asyncio.TimeoutError:
                    yield {"event": "heartbeat", "data": json.dumps({"ts": dt.datetime.now(dt.timezone.utc).isoformat()})}
        finally:
            with _sub_lock:
                subs = _sync_subscribers.get(source, [])
                if queue in subs:
                    subs.remove(queue)

    return EventSourceResponse(event_generator())
