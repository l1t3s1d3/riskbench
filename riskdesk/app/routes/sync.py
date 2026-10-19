"""Sync, schedule, and connector diagnostics routes."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from ..api_queries import (
    QUERY_REGISTRY,
    WIZ_DIAG_CONFIG_PROBE,
    WIZ_DIAG_VULN_PROBE,
    WIZ_INTROSPECT_TYPES,
)
from ..db import get_session
from ..models import AuditEvent, SyncRun, SyncSchedule
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
