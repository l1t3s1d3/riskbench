from __future__ import annotations

import datetime as dt
import logging
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from sqlalchemy import func, select  # noqa: E402
from sqlalchemy.orm import joinedload  # noqa: E402

from . import adjudication as adj_service  # noqa: E402
from . import assignment as assign_service  # noqa: E402
from . import exceptions as exc_service  # noqa: E402
from . import compliance as compliance_svc  # noqa: E402
from . import correlation as corr_service  # noqa: E402
from . import enrichment as enrich_service  # noqa: E402
from . import reporting as report_service  # noqa: E402
from . import tokens as token_service  # noqa: E402
from . import connector_config as cc_service  # noqa: E402
from . import pipeline as pipeline_service  # noqa: E402
from .auth import (  # noqa: E402
    AUTH_MODE, COOKIE_NAME, authenticate, check_permission, create_session,
    create_user, get_session_user, has_permission, require_auth,
    require_role, seed_default_users, cleanup_expired_sessions,
    _hash_password,
)
from .config import settings  # noqa: E402
from .db import get_session, init_db  # noqa: E402
from .enums import (  # noqa: E402
    DISPOSITION_LABELS, Disposition, FindingCategory, ScopeType, Severity,
)
from .models import (  # noqa: E402
    Adjudication, AdjudicationApplication, ApiToken, Asset, AssetCorrelation,
    AssignmentRule, AuditEvent, ComplianceBenchmark, ComplianceCheck,
    ComplianceScan, ComplianceTarget, ConnectorConfig, ExceptionComment,
    ExceptionRequest, Finding, SavedView, SyncRun, SyncSchedule, Ticket,
    User, Vuln,
)
from .queries import (  # noqa: E402
    FindingFilter, _serialize_adj, build_pending_map, build_resolution_map,
    facets, search, serialize_finding,
)
from .risk import compute_risk, default_expiry, default_review_due  # noqa: E402
from .sync import get_connector, run_sync  # noqa: E402

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

STATIC = Path(__file__).resolve().parent / "static"

app = FastAPI(title="RiskDesk", version="1.0.0", docs_url="/api/docs")


@app.on_event("startup")
def _startup():
    init_db()
    from .db import SessionLocal
    db = SessionLocal()
    try:
        seed_default_users(db)
        cc_service.apply_all_from_db(db)
        n = adj_service.expire_lapsed(db)
        if n:
            logging.info("Expired %d lapsed decisions on startup", n)
        cleanup_expired_sessions(db)
    finally:
        db.close()
    from . import scheduler
    scheduler.start()


def current_user(request: Request) -> str:
    """Resolve the current user. Works in all auth modes + bearer tokens."""
    # Check for bearer token first
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        raw_token = auth_header[7:].strip()
        db = next(get_session())
        try:
            user, _ = token_service.validate_token(db, raw_token)
            if user:
                return user.username
        finally:
            db.close()
    if AUTH_MODE == "none":
        user = request.headers.get("X-RiskDesk-User") or settings.default_user
        return user if user in settings.users else settings.default_user
    db = next(get_session())
    try:
        u = get_session_user(db, request)
        return u.username if u else settings.default_user
    finally:
        db.close()


def current_user_obj(request: Request, db) -> User | None:
    """Get the full User object for the current request."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        user, _ = token_service.validate_token(db, auth_header[7:].strip())
        return user
    return get_session_user(db, request)


@app.exception_handler(adj_service.PolicyError)
def _policy_error(_request, exc: adj_service.PolicyError):
    return JSONResponse(status_code=422, content={"problems": exc.problems})


# --- meta -------------------------------------------------------------------

@app.get("/api/meta")
def meta(db=Depends(get_session), request: Request = None):
    demo_rows = db.execute(
        select(func.count()).select_from(Finding)
        .where(Finding.raw.contains('"demo": true'))
    ).scalar() or 0
    return {
        "org": settings.org_name,
        "users": settings.users,
        "approvers": settings.approvers,
        "current_user": current_user(request),
        "dispositions": [
            {"value": d.value, "label": DISPOSITION_LABELS[d],
             "is_risk_decision": d.value in {"accept_risk", "adjust_risk", "false_positive"}}
            for d in Disposition
        ],
        "severities": [s.value for s in Severity],
        "categories": [c.value for c in FindingCategory],
        "scopes": [
            {"value": ScopeType.FINDING.value, "label": "This finding only"},
            {"value": ScopeType.VULN_ON_ASSET.value, "label": "This vulnerability on this asset"},
            {"value": ScopeType.VULN.value, "label": "This vulnerability everywhere"},
            {"value": ScopeType.COMPONENT.value, "label": "This component or rule everywhere"},
        ],
        "policy": {
            "min_justification_chars": settings.policy.min_justification_chars,
            "max_acceptance_days": settings.policy.max_acceptance_days,
            "remediation_sla_days": settings.policy.remediation_sla_days,
            "require_separate_approver": settings.policy.require_separate_approver,
        },
        "connectors": {
            name: get_connector(name).configured()
            for name in ("wiz", "falcon", "github")
        },
        "demo_findings": demo_rows,
    }


# --- findings ---------------------------------------------------------------

def _filter_from_query(
    source: list[str] = Query(default=[]),
    severity: list[str] = Query(default=[]),
    status: list[str] = Query(default=["open"]),
    category: list[str] = Query(default=[]),
    disposition: list[str] = Query(default=[]),
    priority: list[str] = Query(default=[]),
    kev: bool = False,
    fixable: bool = False,
    overdue: bool = False,
    undecided: bool = False,
    q: str = "",
    asset: str = "",
    cve: str = "",
    sort: str = "risk",
    order: str = "desc",
) -> FindingFilter:
    return FindingFilter(
        sources=source, severities=severity, statuses=status, categories=category,
        dispositions=disposition, priorities=priority, kev_only=kev,
        fixable_only=fixable, overdue_only=overdue, undecided_only=undecided,
        q=q, asset=asset, cve=cve, sort=sort, order=order,
    )


@app.get("/api/findings")
def list_findings(f: FindingFilter = Depends(_filter_from_query),
                  page: int = 1, page_size: int = 50,
                  include_ids: bool = False, db=Depends(get_session)):
    result = search(db, f, page=page, page_size=min(page_size, 200))
    if not include_ids:
        result.pop("all_matching_ids", None)
    result["filter"] = f.as_dict()
    return result


@app.get("/api/findings/ids")
def matching_ids(f: FindingFilter = Depends(_filter_from_query), db=Depends(get_session)):
    """Every id matching the filter, for select-all-beyond-this-page."""
    result = search(db, f, page=1, page_size=1)
    return {"total": result["total"], "ids": result["all_matching_ids"]}


@app.get("/api/facets")
def get_facets(f: FindingFilter = Depends(_filter_from_query), db=Depends(get_session)):
    return facets(db, f)


@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: int, db=Depends(get_session)):
    obj = db.execute(
        select(Finding).options(joinedload(Finding.asset), joinedload(Finding.vuln))
        .where(Finding.id == finding_id)
    ).scalar_one_or_none()
    if obj is None:
        raise HTTPException(404, "No such finding.")

    resolution = build_resolution_map(db)
    pending = build_pending_map(db)
    adj = resolution.get(finding_id)
    risk = compute_risk(obj, adj, has_pending=finding_id in pending)
    payload = serialize_finding(obj, risk, adj)

    # Full decision history for this finding, including superseded ones.
    history = db.execute(
        select(Adjudication).join(AdjudicationApplication)
        .where(AdjudicationApplication.finding_id == finding_id)
        .order_by(Adjudication.requested_at.desc())
    ).unique().scalars().all()
    payload["decision_history"] = [_serialize_adj(a) for a in history]
    payload["raw"] = obj.raw
    return payload


# --- adjudication -----------------------------------------------------------

@app.post("/api/adjudications/preview")
def preview_scope(body: dict = Body(...), db=Depends(get_session)):
    """Show what a bulk decision will actually cover before it is recorded."""
    finding_ids = body.get("finding_ids") or []
    scope = body.get("scope") or ScopeType.FINDING.value
    plans = adj_service.plan_scope(db, finding_ids, scope)
    return {
        "selected": len(finding_ids),
        "decisions_to_create": len(plans),
        "plans": [
            {"scope_type": p.scope_type, "scope_key": p.scope_key,
             "scope_label": p.scope_label, "selected_in_scope": len(p.finding_ids),
             "coverage": p.coverage_note}
            for p in plans[:200]
        ],
        "truncated": len(plans) > 200,
    }


@app.post("/api/adjudications")
def create_adjudication(request: Request, body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    created = adj_service.create_decisions(
        db,
        finding_ids=body.get("finding_ids") or [],
        disposition=body["disposition"],
        justification=body.get("justification", ""),
        actor=actor,
        scope=body.get("scope") or ScopeType.FINDING.value,
        approver=body.get("approver"),
        expires_at=_parse_date(body.get("expires_at")),
        review_due=_parse_date(body.get("review_due")),
        adjusted_severity=body.get("adjusted_severity"),
        adjusted_priority=body.get("adjusted_priority"),
        assigned_to=body.get("assigned_to"),
        remediation_due=_parse_date(body.get("remediation_due")),
        compensating_controls=body.get("compensating_controls"),
        scope_filter=body.get("filter"),
    )
    return {"created": len(created), "adjudications": [_serialize_adj(a) for a in created]}


@app.get("/api/adjudications")
def list_adjudications(state: list[str] = Query(default=[]),
                       disposition: list[str] = Query(default=[]),
                       scope_type: list[str] = Query(default=[]),
                       due_within_days: int | None = None,
                       q: str = "",
                       page: int = 1, page_size: int = 50,
                       db=Depends(get_session)):
    stmt = select(Adjudication)
    if state:
        stmt = stmt.where(Adjudication.state.in_(state))
    if disposition:
        stmt = stmt.where(Adjudication.disposition.in_(disposition))
    if scope_type:
        stmt = stmt.where(Adjudication.scope_type.in_(scope_type))
    if q:
        term = f"%{q}%"
        stmt = stmt.where(Adjudication.scope_label.ilike(term) |
                          Adjudication.justification.ilike(term) |
                          Adjudication.scope_key.ilike(term))
    if due_within_days is not None:
        horizon = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=due_within_days)
        stmt = stmt.where(
            ((Adjudication.expires_at.isnot(None)) & (Adjudication.expires_at <= horizon)) |
            ((Adjudication.review_due.isnot(None)) & (Adjudication.review_due <= horizon))
        )

    rows = db.execute(stmt.order_by(Adjudication.requested_at.desc())).unique().scalars().all()
    total = len(rows)
    start = max(0, (page - 1) * page_size)
    return {
        "total": total, "page": page, "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
        "adjudications": [_serialize_adj(a) for a in rows[start:start + page_size]],
    }


@app.get("/api/adjudications/{adj_id}")
def get_adjudication(adj_id: int, db=Depends(get_session)):
    a = db.get(Adjudication, adj_id)
    if a is None:
        raise HTTPException(404, "No such decision.")
    payload = _serialize_adj(a)
    fids = [x.finding_id for x in a.applications]
    objs = db.execute(
        select(Finding).options(joinedload(Finding.asset), joinedload(Finding.vuln))
        .where(Finding.id.in_(fids[:500]))
    ).scalars().all()
    payload["findings"] = [{
        "id": o.id, "source": o.source, "asset": o.asset.name,
        "vuln": o.vuln.canonical_id, "severity": o.severity,
        "status": o.status, "component": o.component,
    } for o in objs]
    payload["findings_truncated"] = len(fids) > 500
    payload["audit"] = [{
        "ts": e.ts.isoformat(), "actor": e.actor, "action": e.action,
        "summary": e.summary, "detail": e.detail,
    } for e in db.execute(
        select(AuditEvent).where(AuditEvent.entity_type == "adjudication",
                                 AuditEvent.entity_id == str(adj_id))
        .order_by(AuditEvent.ts.asc())
    ).scalars().all()]
    return payload


@app.post("/api/adjudications/{adj_id}/decision")
def decide_adjudication(adj_id: int, request: Request, body: dict = Body(...),
                        db=Depends(get_session)):
    a = adj_service.decide(db, adj_id, approve=bool(body.get("approve")),
                           actor=current_user(request), note=body.get("note"))
    return _serialize_adj(a)


@app.post("/api/adjudications/{adj_id}/revoke")
def revoke_adjudication(adj_id: int, request: Request, body: dict = Body(...),
                        db=Depends(get_session)):
    a = adj_service.revoke(db, adj_id, actor=current_user(request),
                           reason=body.get("reason", ""))
    return _serialize_adj(a)


@app.post("/api/adjudications/{adj_id}/renew")
def renew_adjudication(adj_id: int, request: Request, body: dict = Body(...),
                       db=Depends(get_session)):
    expires = _parse_date(body.get("expires_at"))
    if expires is None:
        raise HTTPException(422, "A renewal needs a new expiry date.")
    a = adj_service.renew(db, adj_id, actor=current_user(request),
                          justification=body.get("justification", ""),
                          expires_at=expires, approver=body.get("approver"))
    return _serialize_adj(a)


@app.get("/api/adjudications/defaults/suggest")
def suggest_defaults(disposition: str, severity: str = "high"):
    exp = default_expiry(disposition, severity)
    return {
        "expires_at": exp.date().isoformat() if exp else None,
        "review_due": default_review_due(severity).date().isoformat(),
        "max_days": settings.policy.max_acceptance_days.get(severity),
    }


# --- dashboard --------------------------------------------------------------

@app.get("/api/dashboard")
def dashboard(db=Depends(get_session)):
    now = dt.datetime.now(dt.timezone.utc)
    resolution = build_resolution_map(db)

    rows = db.execute(
        select(Finding.id, Finding.severity, Finding.source, Finding.first_detected,
               Vuln.kev)
        .join(Vuln, Finding.vuln_id == Vuln.id)
        .where(Finding.status == "open")
    ).all()

    by_severity: dict[str, int] = {}
    by_source: dict[str, int] = {}
    by_disposition: dict[str, int] = {}
    overdue = 0
    kev_open = 0

    for fid, sev, source, first_detected, kev in rows:
        adj = resolution.get(fid)
        eff = sev
        disp = adj.disposition if adj else "none"
        if adj and adj.disposition == Disposition.ADJUST_RISK.value and adj.adjusted_severity:
            eff = adj.adjusted_severity
        by_severity[eff] = by_severity.get(eff, 0) + 1
        by_source[source] = by_source.get(source, 0) + 1
        by_disposition[disp] = by_disposition.get(disp, 0) + 1
        if kev:
            kev_open += 1
        if disp not in ("accept_risk", "false_positive"):
            fd = first_detected or now
            if fd.tzinfo is None:
                fd = fd.replace(tzinfo=dt.timezone.utc)
            days = settings.policy.remediation_sla_days.get(eff, 90)
            if kev:
                days = min(days, settings.policy.kev_sla_days)
            if fd + dt.timedelta(days=days) < now:
                overdue += 1

    pending = db.execute(
        select(func.count()).select_from(Adjudication)
        .where(Adjudication.state == "pending_approval")
    ).scalar() or 0

    horizon = now + dt.timedelta(days=30)
    expiring = db.execute(
        select(func.count()).select_from(Adjudication)
        .where(Adjudication.state == "approved",
               Adjudication.expires_at.isnot(None),
               Adjudication.expires_at <= horizon)
    ).scalar() or 0
    review_due = db.execute(
        select(func.count()).select_from(Adjudication)
        .where(Adjudication.state == "approved",
               Adjudication.review_due.isnot(None),
               Adjudication.review_due <= now)
    ).scalar() or 0

    runs = db.execute(
        select(SyncRun).order_by(SyncRun.started_at.desc()).limit(6)
    ).scalars().all()

    return {
        "open_findings": len(rows),
        "unique_vulns": db.execute(select(func.count()).select_from(Vuln)).scalar(),
        "assets": db.execute(select(func.count()).select_from(Asset)).scalar(),
        "by_severity": by_severity,
        "by_source": by_source,
        "by_disposition": by_disposition,
        "overdue": overdue,
        "kev_open": kev_open,
        "undecided": by_disposition.get("none", 0),
        "pending_approvals": pending,
        "expiring_30d": expiring,
        "review_overdue": review_due,
        "recent_syncs": [{
            "id": r.id, "source": r.source, "status": r.status,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "findings": r.findings_upserted, "new": r.findings_new,
            "closed": r.findings_closed, "error": r.error,
        } for r in runs],
    }


# --- sync -------------------------------------------------------------------

@app.post("/api/sync/{source}")
def trigger_sync(source: str, request: Request, demo: bool = False,
                 limit: int | None = None):
    if source not in ("wiz", "falcon", "github"):
        raise HTTPException(400, "Unknown source.")
    return run_sync(source, demo=demo, limit=limit, actor=current_user(request))


@app.get("/api/sync/check/{source}")
def check_source(source: str):
    if source not in ("wiz", "falcon", "github"):
        raise HTTPException(400, "Unknown source.")
    ok, message = get_connector(source).check()
    return {"source": source, "ok": ok, "message": message}


@app.get("/api/sync/diagnose/wiz")
def diagnose_wiz(request: Request):
    """Run diagnostic queries against Wiz to check schema compatibility."""
    from .connectors.wiz import WizConnector
    c = WizConnector()
    if not c.configured():
        return {"ok": False, "error": "Not configured"}
    results = {}
    try:
        c._get_token()
        results["auth"] = "ok"
    except Exception as exc:
        return {"ok": False, "auth": str(exc)}
    for type_name in ("VulnerabilityFinding", "ConfigurationFinding",
                      "VulnerableAssetBase", "VulnerableAssetVirtualMachine"):
        try:
            fields = c.introspect(type_name)
            results[type_name] = fields if fields else "not found in schema"
        except Exception as exc:
            results[type_name] = f"error: {exc}"
    try:
        data = c.graphql(
            "query { vulnerabilityFindings(first: 1) { totalCount nodes { id name status } } }",
            {},
        )
        block = data.get("vulnerabilityFindings") or {}
        results["vuln_probe"] = {
            "totalCount": block.get("totalCount"),
            "sample": (block.get("nodes") or [None])[0],
        }
    except Exception as exc:
        results["vuln_probe"] = f"error: {exc}"
    try:
        data = c.graphql(
            "query { configurationFindings(first: 1) { totalCount nodes { id severity result } } }",
            {},
        )
        block = data.get("configurationFindings") or {}
        results["config_probe"] = {
            "totalCount": block.get("totalCount"),
            "sample": (block.get("nodes") or [None])[0],
        }
    except Exception as exc:
        results["config_probe"] = f"error: {exc}"
    return {"ok": True, "diagnostics": results}


@app.post("/api/wiz/query")
async def wiz_query(request: Request):
    """Execute an arbitrary GraphQL query against the connected Wiz tenant."""
    import traceback
    from .connectors.wiz import WizConnector
    from .config import reload_settings
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
        return {"ok": False, "error": "Wiz connector is not configured. Set credentials in Sources → Wiz.",
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


@app.post("/api/wiz/introspect")
async def wiz_introspect_type(request: Request):
    """Introspect a Wiz GraphQL type to discover available fields."""
    import traceback
    from .connectors.wiz import WizConnector
    from .config import reload_settings
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


@app.get("/api/sync/runs")
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


@app.get("/api/schedules")
def list_schedules(db=Depends(get_session)):
    rows = db.execute(select(SyncSchedule).order_by(SyncSchedule.source)).scalars().all()
    return [_serialize_schedule(s) for s in rows]


@app.post("/api/schedules")
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
    # Compute next run
    now = dt.datetime.now(dt.timezone.utc)
    if row.enabled and row.next_run_at is None:
        from .scheduler import _compute_next
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


@app.delete("/api/schedules/{source}")
def delete_schedule(source: str, request: Request, db=Depends(get_session)):
    row = db.execute(
        select(SyncSchedule).where(SyncSchedule.source == source)
    ).scalar_one_or_none()
    if row is None:
        raise HTTPException(404, "No schedule for that source.")
    db.delete(row)
    db.commit()
    return {"deleted": source}


@app.get("/api/sync/runs/{run_id}")
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


# --- assignment rules -------------------------------------------------------

def _serialize_rule(r: AssignmentRule) -> dict:
    return {
        "id": r.id, "name": r.name, "description": r.description,
        "enabled": r.enabled, "priority": r.priority,
        "source": r.source, "severity": r.severity, "category": r.category,
        "asset_pattern": r.asset_pattern, "component_pattern": r.component_pattern,
        "environment": r.environment, "kev_only": r.kev_only,
        "fix_available_only": r.fix_available_only,
        "assign_to": r.assign_to, "disposition": r.disposition,
        "remediation_days": r.remediation_days,
        "justification_template": r.justification_template,
        "created_by": r.created_by,
        "created_at": r.created_at.isoformat() if r.created_at else None,
        "updated_at": r.updated_at.isoformat() if r.updated_at else None,
    }


@app.get("/api/rules")
def list_rules(db=Depends(get_session)):
    rows = db.execute(
        select(AssignmentRule).order_by(AssignmentRule.priority.asc())
    ).scalars().all()
    return [_serialize_rule(r) for r in rows]


@app.post("/api/rules")
def create_rule(request: Request, body: dict = Body(...), db=Depends(get_session)):
    if not body.get("name"):
        raise HTTPException(422, "Name is required.")
    if not body.get("assign_to"):
        raise HTTPException(422, "assign_to is required.")
    if body.get("assign_to") not in settings.users:
        raise HTTPException(422, f"{body['assign_to']} is not on the user roster.")
    disp = body.get("disposition", "fix_immediately")
    if disp not in ("fix_immediately", "complex_resolution", "developer_review"):
        raise HTTPException(422, "Disposition must be a routing type: fix_immediately, complex_resolution, or developer_review.")
    rule = AssignmentRule(
        name=body["name"],
        description=body.get("description"),
        enabled=body.get("enabled", True),
        priority=body.get("priority", 100),
        source=body.get("source"),
        severity=body.get("severity"),
        category=body.get("category"),
        asset_pattern=body.get("asset_pattern"),
        component_pattern=body.get("component_pattern"),
        environment=body.get("environment"),
        kev_only=body.get("kev_only", False),
        fix_available_only=body.get("fix_available_only", False),
        assign_to=body["assign_to"],
        disposition=disp,
        remediation_days=body.get("remediation_days"),
        justification_template=body.get("justification_template"),
        created_by=current_user(request),
    )
    db.add(rule)
    db.commit()
    db.add(AuditEvent(
        actor=current_user(request), action="rule.create",
        entity_type="rule", entity_id=str(rule.id),
        summary=f"Assignment rule created: {rule.name} → {rule.assign_to}",
    ))
    db.commit()
    return _serialize_rule(rule)


@app.put("/api/rules/{rule_id}")
def update_rule(rule_id: int, request: Request, body: dict = Body(...),
                db=Depends(get_session)):
    rule = db.get(AssignmentRule, rule_id)
    if rule is None:
        raise HTTPException(404, "No such rule.")
    for field in ("name", "description", "enabled", "priority", "source", "severity",
                  "category", "asset_pattern", "component_pattern", "environment",
                  "kev_only", "fix_available_only", "assign_to", "disposition",
                  "remediation_days", "justification_template"):
        if field in body:
            setattr(rule, field, body[field])
    if rule.assign_to not in settings.users:
        raise HTTPException(422, f"{rule.assign_to} is not on the user roster.")
    db.commit()
    db.add(AuditEvent(
        actor=current_user(request), action="rule.update",
        entity_type="rule", entity_id=str(rule.id),
        summary=f"Assignment rule updated: {rule.name}",
    ))
    db.commit()
    return _serialize_rule(rule)


@app.delete("/api/rules/{rule_id}")
def delete_rule(rule_id: int, request: Request, db=Depends(get_session)):
    rule = db.get(AssignmentRule, rule_id)
    if rule is None:
        raise HTTPException(404, "No such rule.")
    db.delete(rule)
    db.add(AuditEvent(
        actor=current_user(request), action="rule.delete",
        entity_type="rule", entity_id=str(rule_id),
        summary=f"Assignment rule deleted: {rule.name}",
    ))
    db.commit()
    return {"deleted": rule_id}


@app.post("/api/rules/preview")
def preview_rules(rule_id: int | None = None, db=Depends(get_session)):
    return assign_service.preview_rules(db, rule_id=rule_id)


@app.post("/api/rules/run")
def run_assignment(request: Request, body: dict = Body(default={}),
                   db=Depends(get_session)):
    source = body.get("source")
    dry_run = body.get("dry_run", False)
    result = assign_service.evaluate_rules(
        db, source=source, actor=current_user(request), dry_run=dry_run
    )
    return result


# --- audit and export -------------------------------------------------------

@app.get("/api/audit")
def audit(limit: int = 200, action: list[str] = Query(default=[]),
          entity_id: str = "", db=Depends(get_session)):
    stmt = select(AuditEvent)
    if action:
        stmt = stmt.where(AuditEvent.action.in_(action))
    if entity_id:
        stmt = stmt.where(AuditEvent.entity_id == entity_id)
    rows = db.execute(stmt.order_by(AuditEvent.ts.desc()).limit(limit)).scalars().all()
    return [{
        "id": e.id, "ts": e.ts.isoformat(), "actor": e.actor, "action": e.action,
        "entity_type": e.entity_type, "entity_id": e.entity_id,
        "summary": e.summary, "detail": e.detail,
    } for e in rows]


@app.get("/api/export/register.csv")
def export_register(db=Depends(get_session)):
    """The risk register as CSV -- what you hand to an auditor or paste into a
    steering deck."""
    import csv
    import io

    rows = db.execute(select(Adjudication).order_by(Adjudication.requested_at.desc())).unique().scalars().all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "id", "disposition", "state", "scope_type", "scope_key", "scope_label",
        "findings_at_decision", "adjusted_severity", "adjusted_priority",
        "justification", "compensating_controls", "requested_by", "requested_at",
        "approver", "approved_by", "decided_at", "decision_note",
        "review_due", "expires_at",
    ])
    for a in rows:
        w.writerow([
            a.id, a.disposition, a.state, a.scope_type, a.scope_key, a.scope_label,
            len(a.applications), a.adjusted_severity or "", a.adjusted_priority or "",
            (a.justification or "").replace("\n", " "),
            (a.compensating_controls or "").replace("\n", " "),
            a.requested_by, a.requested_at.isoformat() if a.requested_at else "",
            a.approver or "", a.approved_by or "",
            a.decided_at.isoformat() if a.decided_at else "",
            (a.decision_note or "").replace("\n", " "),
            a.review_due.isoformat() if a.review_due else "",
            a.expires_at.isoformat() if a.expires_at else "",
        ])
    buf.seek(0)
    stamp = dt.date.today().isoformat()
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="risk-register-{stamp}.csv"'},
    )


@app.get("/api/export/findings.csv")
def export_findings(f: FindingFilter = Depends(_filter_from_query), db=Depends(get_session)):
    import csv
    import io

    result = search(db, f, page=1, page_size=100000)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "finding_id", "source", "source_finding_id", "category", "vuln", "cve",
        "title", "asset", "asset_type", "cloud_account", "environment",
        "component", "location", "base_severity", "effective_severity",
        "priority", "score", "kev", "cvss", "fix_available", "fix_version",
        "first_detected", "sla_due", "sla_overdue", "disposition",
        "decision_state", "decision_expires", "justification",
    ])
    for x in result["findings"]:
        d = x.get("decision") or {}
        w.writerow([
            x["id"], x["source"], x["source_finding_id"], x["category"],
            x["vuln"]["canonical_id"], x["vuln"]["cve_id"] or "",
            (x["vuln"]["title"] or "").replace("\n", " "),
            x["asset"]["name"], x["asset"]["type"] or "",
            x["asset"]["cloud_account"] or "", x["asset"]["environment"] or "",
            x["component"] or "", x["location"] or "",
            x["risk"]["base_severity"], x["risk"]["effective_severity"],
            x["risk"]["priority"], x["risk"]["score"],
            x["vuln"]["kev"], x["vuln"]["cvss_score"] or "",
            x["fix_available"], x["fix_version"] or "",
            x["first_detected"] or "", x["risk"]["sla_due"] or "",
            x["risk"]["sla_overdue"], d.get("disposition", ""),
            d.get("state", ""), d.get("expires_at", "") or "",
            (d.get("justification") or "").replace("\n", " "),
        ])
    buf.seek(0)
    stamp = dt.date.today().isoformat()
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="findings-{stamp}.csv"'},
    )


def _parse_date(value) -> dt.datetime | None:
    if not value:
        return None
    if isinstance(value, dt.datetime):
        return value
    s = str(value)
    try:
        if len(s) == 10:
            return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        parsed = dt.datetime.fromisoformat(s)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        raise HTTPException(422, f"Could not read the date '{value}'. Use YYYY-MM-DD.")


# --- authentication ---------------------------------------------------------

@app.post("/api/auth/login")
def login(request: Request, body: dict = Body(...), db=Depends(get_session)):
    if AUTH_MODE == "none":
        return {"ok": True, "user": body.get("username"), "role": "admin",
                "auth_mode": "none", "message": "Auth is disabled. Everyone is admin."}
    username = (body.get("username") or "").strip().lower()
    password = body.get("password") or ""
    user = authenticate(db, username, password)
    if not user:
        raise HTTPException(401, "Invalid username or password.")
    token = create_session(db, user, request)
    response = JSONResponse({
        "ok": True, "user": user.username, "display_name": user.display_name,
        "role": user.role, "team": user.team, "auth_mode": AUTH_MODE,
    })
    response.set_cookie(
        COOKIE_NAME, token, httponly=True, samesite="lax",
        max_age=int(dt.timedelta(hours=12).total_seconds()),
        secure=request.url.scheme == "https",
    )
    return response


@app.post("/api/auth/logout")
def logout(request: Request, db=Depends(get_session)):
    from .models import Session as SessModel
    token = request.cookies.get(COOKIE_NAME)
    if token:
        sess = db.execute(select(SessModel).where(SessModel.token == token)).scalar_one_or_none()
        if sess:
            db.delete(sess)
            db.commit()
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE_NAME)
    return response


@app.get("/api/auth/me")
def auth_me(request: Request, db=Depends(get_session)):
    user = get_session_user(db, request)
    if not user:
        return {"authenticated": False, "auth_mode": AUTH_MODE}
    return {
        "authenticated": True, "auth_mode": AUTH_MODE,
        "username": user.username, "display_name": user.display_name,
        "role": user.role, "team": user.team, "email": user.email,
        "permissions": {p: has_permission(user, p) for p in [
            "submit_exception", "review_exception", "create_adjudication",
            "manage_rules", "manage_users", "run_sync",
        ]},
    }


@app.post("/api/auth/change-password")
def change_password(request: Request, body: dict = Body(...), db=Depends(get_session)):
    user = get_session_user(db, request)
    if not user:
        raise HTTPException(401, "Not authenticated.")
    new_pw = body.get("new_password", "")
    if len(new_pw) < 8:
        raise HTTPException(422, "Password must be at least 8 characters.")
    user.password_hash = _hash_password(new_pw)
    db.commit()
    return {"ok": True}


# --- user management --------------------------------------------------------

@app.get("/api/users")
def list_users(request: Request, db=Depends(get_session)):
    rows = db.execute(select(User).order_by(User.username)).scalars().all()
    return [{
        "id": u.id, "username": u.username, "display_name": u.display_name,
        "email": u.email, "role": u.role, "team": u.team, "active": u.active,
        "auth_method": u.auth_method,
        "last_login": u.last_login.isoformat() if u.last_login else None,
    } for u in rows]


@app.post("/api/users")
def create_user_api(request: Request, body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    # In none mode, anyone can create. In auth modes, need manage_users.
    if AUTH_MODE != "none":
        user_obj = get_session_user(db, request)
        if not user_obj:
            raise HTTPException(401)
        check_permission(user_obj, "manage_users")
    try:
        user = create_user(
            db,
            username=(body.get("username") or "").strip().lower(),
            password=body.get("password"),
            display_name=body.get("display_name"),
            email=body.get("email"),
            role=body.get("role", "team"),
            team=body.get("team"),
            auth_method=body.get("auth_method", "local"),
        )
    except ValueError as e:
        raise HTTPException(422, str(e))
    return {"id": user.id, "username": user.username, "role": user.role}


@app.put("/api/users/{user_id}")
def update_user_api(user_id: int, request: Request, body: dict = Body(...),
                    db=Depends(get_session)):
    if AUTH_MODE != "none":
        actor_obj = get_session_user(db, request)
        if not actor_obj:
            raise HTTPException(401)
        check_permission(actor_obj, "manage_users")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found.")
    for field in ("display_name", "email", "role", "team", "active", "auth_method"):
        if field in body:
            setattr(user, field, body[field])
    if "password" in body and body["password"]:
        user.password_hash = _hash_password(body["password"])
    db.commit()
    return {"ok": True, "username": user.username, "role": user.role}


# --- exception requests -----------------------------------------------------

@app.exception_handler(exc_service.ExceptionError)
def _exception_error(_request, exc: exc_service.ExceptionError):
    return JSONResponse(status_code=422, content={"detail": exc.message})


@app.get("/api/exceptions")
def list_exceptions(
    status: list[str] = Query(default=[]),
    submitted_by: str = "",
    reviewer: str = "",
    q: str = "",
    page: int = 1, page_size: int = 50,
    db=Depends(get_session), request: Request = None,
):
    stmt = select(ExceptionRequest)
    if status:
        stmt = stmt.where(ExceptionRequest.status.in_(status))
    if submitted_by:
        stmt = stmt.where(ExceptionRequest.submitted_by == submitted_by)
    if reviewer:
        stmt = stmt.where(ExceptionRequest.assigned_reviewer == reviewer)
    if q:
        term = f"%{q}%"
        stmt = stmt.where(
            ExceptionRequest.title.ilike(term) |
            ExceptionRequest.justification.ilike(term) |
            ExceptionRequest.scope_label.ilike(term)
        )
    rows = db.execute(stmt.order_by(ExceptionRequest.created_at.desc())).scalars().all()
    total = len(rows)
    start = max(0, (page - 1) * page_size)
    return {
        "total": total, "page": page,
        "exceptions": [exc_service.serialize_exception(e) for e in rows[start:start + page_size]],
    }


@app.post("/api/exceptions")
def submit_exception(request: Request, body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    user_obj = current_user_obj(request, db)
    exc = exc_service.create_exception(
        db,
        title=body.get("title", ""),
        finding_ids=body.get("finding_ids", []),
        requested_disposition=body.get("requested_disposition", ""),
        justification=body.get("justification", ""),
        actor=actor,
        scope=body.get("scope", "finding"),
        business_impact=body.get("business_impact"),
        compensating_controls=body.get("compensating_controls"),
        adjusted_severity=body.get("adjusted_severity"),
        requested_duration_days=body.get("requested_duration_days"),
        submitter_team=user_obj.team if user_obj else body.get("submitter_team"),
        submitter_email=user_obj.email if user_obj else body.get("submitter_email"),
    )
    return exc_service.serialize_exception(exc)


@app.get("/api/exceptions/{exc_id}")
def get_exception(exc_id: int, request: Request, db=Depends(get_session)):
    exc = db.get(ExceptionRequest, exc_id)
    if not exc:
        raise HTTPException(404, "Exception not found.")
    comments = db.execute(
        select(ExceptionComment)
        .where(ExceptionComment.exception_id == exc_id)
        .order_by(ExceptionComment.created_at.asc())
    ).scalars().all()
    user_obj = current_user_obj(request, db)
    is_security = user_obj and user_obj.role in ("security", "admin")
    return exc_service.serialize_exception(exc, comments, include_internal=is_security)


@app.post("/api/exceptions/{exc_id}/assign")
def assign_exception_reviewer(exc_id: int, request: Request,
                              body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    exc = exc_service.assign_reviewer(db, exc_id, body.get("reviewer", ""), actor)
    return exc_service.serialize_exception(exc)


@app.post("/api/exceptions/{exc_id}/review")
def review_exception(exc_id: int, request: Request,
                     body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    exc = exc_service.review_exception(
        db, exc_id,
        decision=body.get("decision", ""),
        actor=actor,
        note=body.get("note"),
        expires_at=_parse_date(body.get("expires_at")),
        approver=body.get("approver"),
    )
    return exc_service.serialize_exception(exc)


@app.post("/api/exceptions/{exc_id}/request-info")
def request_exception_info(exc_id: int, request: Request,
                           body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    exc = exc_service.request_info(db, exc_id, body.get("message", ""), actor)
    return exc_service.serialize_exception(exc)


@app.post("/api/exceptions/{exc_id}/respond")
def respond_to_exception_info(exc_id: int, request: Request,
                              body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    exc = exc_service.respond_to_info(db, exc_id, body.get("message", ""), actor)
    return exc_service.serialize_exception(exc)


@app.post("/api/exceptions/{exc_id}/comment")
def comment_on_exception(exc_id: int, request: Request,
                         body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    exc_service.add_comment(
        db, exc_id, body.get("body", ""), actor,
        is_internal=bool(body.get("is_internal")),
    )
    return {"ok": True}


@app.post("/api/exceptions/{exc_id}/withdraw")
def withdraw_exception(exc_id: int, request: Request, db=Depends(get_session)):
    actor = current_user(request)
    exc = exc_service.withdraw_exception(db, exc_id, actor)
    return exc_service.serialize_exception(exc)


# --- compliance -------------------------------------------------------------

@app.get("/api/compliance")
def compliance_summary(db=Depends(get_session)):
    return compliance_svc.get_compliance_summary(db)


@app.post("/api/compliance/import")
async def import_compliance(request: Request, db=Depends(get_session)):
    """Import a CIS or STIG benchmark CSV. Accepts multipart file upload."""
    from starlette.datastructures import UploadFile
    form = await request.form()
    file = form.get("file")
    if not file or not hasattr(file, "read"):
        raise HTTPException(400, "Upload a CSV file as 'file' in a multipart form.")
    content = await file.read()
    filename = getattr(file, "filename", "upload.csv")
    actor = current_user(request)

    try:
        scans = compliance_svc.parse_file(content, filename)
    except Exception as exc:
        raise HTTPException(422, f"Could not parse the file: {exc}")

    if not scans:
        raise HTTPException(422, "No benchmark results found in the file.")

    results = []
    for parsed in scans:
        r = compliance_svc.import_scan(db, parsed, actor=actor)
        results.append(r)
        db.add(AuditEvent(
            actor=actor, action="compliance.import",
            entity_type="scan", entity_id=str(r["scan_id"]),
            summary=(f"Imported {r['framework'].upper()} scan: {r['benchmark']} "
                     f"({r['host_count']} hosts, {r['score_percent']}% compliance)"),
            detail=r,
        ))
    db.commit()
    return {"imported": len(results), "scans": results}


@app.get("/api/compliance/scans/{scan_id}")
def compliance_scan_detail(scan_id: int, db=Depends(get_session)):
    detail = compliance_svc.get_scan_detail(db, scan_id)
    if not detail:
        raise HTTPException(404, "Scan not found.")
    return detail


@app.get("/api/compliance/hosts/{hostname}")
def compliance_host(hostname: str, db=Depends(get_session)):
    return compliance_svc.get_host_compliance(db, hostname)


@app.get("/api/compliance/scans")
def list_compliance_scans(db=Depends(get_session)):
    scans = db.execute(
        select(ComplianceScan).order_by(ComplianceScan.scan_date.desc()).limit(100)
    ).scalars().all()
    return [{
        "id": s.id, "benchmark_id": s.benchmark_id,
        "scan_date": s.scan_date.isoformat() if s.scan_date else None,
        "source_file": s.source_file, "imported_by": s.imported_by,
        "total_pass": s.total_pass, "total_fail": s.total_fail,
        "total_manual": s.total_manual, "score_percent": s.score_percent,
        "host_count": s.host_count,
    } for s in scans]


# --- saved views ------------------------------------------------------------

@app.get("/api/views")
def list_views(request: Request, db=Depends(get_session)):
    actor = current_user(request)
    rows = db.execute(
        select(SavedView).where(
            (SavedView.owner == actor) | (SavedView.shared.is_(True))
        ).order_by(SavedView.pinned.desc(), SavedView.name)
    ).scalars().all()
    return [{
        "id": v.id, "name": v.name, "description": v.description,
        "filters": v.filters, "owner": v.owner, "shared": v.shared,
        "pinned": v.pinned, "is_mine": v.owner == actor,
    } for v in rows]


@app.post("/api/views")
def create_view(request: Request, body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    v = SavedView(
        name=body.get("name", "Untitled"),
        description=body.get("description"),
        filters=body.get("filters", {}),
        owner=actor,
        shared=body.get("shared", False),
        pinned=body.get("pinned", False),
    )
    db.add(v)
    db.commit()
    return {"id": v.id, "name": v.name}


@app.put("/api/views/{view_id}")
def update_view(view_id: int, request: Request, body: dict = Body(...),
                db=Depends(get_session)):
    v = db.get(SavedView, view_id)
    if not v:
        raise HTTPException(404)
    if v.owner != current_user(request):
        raise HTTPException(403, "You can only edit your own views.")
    for field in ("name", "description", "filters", "shared", "pinned"):
        if field in body:
            setattr(v, field, body[field])
    db.commit()
    return {"ok": True}


@app.delete("/api/views/{view_id}")
def delete_view(view_id: int, request: Request, db=Depends(get_session)):
    v = db.get(SavedView, view_id)
    if not v:
        raise HTTPException(404)
    if v.owner != current_user(request):
        raise HTTPException(403)
    db.delete(v)
    db.commit()
    return {"deleted": view_id}


# --- asset correlation ------------------------------------------------------

@app.get("/api/correlations")
def list_correlations(q: str = "", db=Depends(get_session)):
    return corr_service.get_correlations(db, q=q or None)


@app.post("/api/correlations/auto")
def auto_correlate(request: Request, body: dict = Body(default={}),
                   db=Depends(get_session)):
    method = body.get("method", "hostname")
    dry_run = body.get("dry_run", False)
    return corr_service.auto_correlate(db, method=method, dry_run=dry_run)


@app.post("/api/correlations")
def create_correlation(request: Request, body: dict = Body(...),
                       db=Depends(get_session)):
    actor = current_user(request)
    corr = corr_service.create_manual_correlation(
        db,
        canonical_name=body.get("canonical_name", ""),
        asset_ids=body.get("asset_ids", []),
        actor=actor,
        environment=body.get("environment"),
        data_classification=body.get("data_classification"),
        owner=body.get("owner"),
        notes=body.get("notes"),
    )
    return {"id": corr.id, "canonical_name": corr.canonical_name}


@app.get("/api/correlations/stats")
def correlation_stats(db=Depends(get_session)):
    return corr_service.get_deduplicated_counts(db)


@app.delete("/api/correlations/{corr_id}")
def delete_correlation(corr_id: int, request: Request, db=Depends(get_session)):
    corr = db.get(AssetCorrelation, corr_id)
    if not corr:
        raise HTTPException(404)
    db.delete(corr)
    db.commit()
    return {"deleted": corr_id}


# --- enrichment (EPSS + KEV) -----------------------------------------------

@app.post("/api/enrich")
def run_enrichment(request: Request, db=Depends(get_session)):
    return enrich_service.enrich_all(db)


@app.post("/api/enrich/epss")
def run_epss(request: Request, db=Depends(get_session)):
    return enrich_service.enrich_epss(db)


@app.post("/api/enrich/kev")
def run_kev(request: Request, db=Depends(get_session)):
    return enrich_service.enrich_kev(db)


# --- API tokens -------------------------------------------------------------

@app.get("/api/tokens")
def list_tokens(request: Request, db=Depends(get_session)):
    user = current_user_obj(request, db)
    if not user:
        raise HTTPException(401)
    return token_service.list_tokens(db, user.id)


@app.post("/api/tokens")
def create_token(request: Request, body: dict = Body(...), db=Depends(get_session)):
    user = current_user_obj(request, db)
    if not user:
        raise HTTPException(401)
    name = body.get("name", "API Token")
    scopes = body.get("scopes")
    expires_days = body.get("expires_days")
    token, plaintext = token_service.create_token(
        db, user, name, scopes=scopes, expires_days=expires_days
    )
    return {
        "id": token.id, "name": token.name, "prefix": token.token_prefix,
        "token": plaintext,  # shown exactly once
        "message": "Copy this token now. It cannot be retrieved again.",
    }


@app.delete("/api/tokens/{token_id}")
def revoke_token(token_id: int, request: Request, db=Depends(get_session)):
    user = current_user_obj(request, db)
    if not user:
        raise HTTPException(401)
    ok = token_service.revoke_token(db, token_id, user.id)
    if not ok:
        raise HTTPException(404)
    return {"revoked": token_id}


# --- connector configuration (admin) ---------------------------------------

@app.get("/api/config/sources")
def list_source_configs(request: Request, db=Depends(get_session)):
    """Get all source configurations with sensitive fields masked."""
    result = {}
    for source in ("wiz", "falcon", "github", "jira"):
        result[source] = {
            "config": cc_service.get_config_display(db, source),
            "fields": cc_service.get_field_definitions(source),
        }
    return result


@app.get("/api/config/sources/{source}")
def get_source_config(source: str, request: Request, db=Depends(get_session)):
    if source not in ("wiz", "falcon", "github", "jira"):
        raise HTTPException(400)
    return {
        "config": cc_service.get_config_display(db, source),
        "fields": cc_service.get_field_definitions(source),
    }


@app.post("/api/config/sources/{source}")
def save_source_config(source: str, request: Request, body: dict = Body(...),
                       db=Depends(get_session)):
    if source not in ("wiz", "falcon", "github", "jira"):
        raise HTTPException(400)
    actor = current_user(request)
    config = body.get("config", {})
    result = cc_service.save_config(db, source, config, actor)
    db.add(AuditEvent(
        actor=actor, action="config.update",
        entity_type="connector", entity_id=source,
        summary=f"Connector config updated for {source}",
    ))
    db.commit()
    return {"config": result}


# --- reporting --------------------------------------------------------------

@app.get("/api/report")
def executive_report(db=Depends(get_session)):
    return report_service.generate_executive_summary(db)


@app.get("/api/report/pptx")
def executive_report_pptx(db=Depends(get_session)):
    try:
        pptx_bytes = report_service.generate_report_pptx(db)
    except RuntimeError as e:
        raise HTTPException(422, str(e))
    stamp = dt.date.today().isoformat()
    return StreamingResponse(
        iter([pptx_bytes]),
        media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        headers={"Content-Disposition": f'attachment; filename="security-report-{stamp}.pptx"'},
    )


# --- compliance targets -----------------------------------------------------

@app.get("/api/compliance/targets")
def list_targets(db=Depends(get_session)):
    rows = db.execute(
        select(ComplianceTarget).order_by(ComplianceTarget.target_date)
    ).scalars().all()
    return [{
        "id": t.id, "benchmark_id": t.benchmark_id,
        "target_percent": t.target_percent,
        "target_date": t.target_date.isoformat() if t.target_date else None,
        "baseline_percent": t.baseline_percent,
        "baseline_date": t.baseline_date.isoformat() if t.baseline_date else None,
        "description": t.description,
    } for t in rows]


@app.post("/api/compliance/targets")
def set_target(request: Request, body: dict = Body(...), db=Depends(get_session)):
    bm_id = body.get("benchmark_id")
    if not bm_id:
        raise HTTPException(422, "benchmark_id is required.")
    bm = db.get(ComplianceBenchmark, bm_id)
    if not bm:
        raise HTTPException(404, "Benchmark not found.")

    existing = db.execute(
        select(ComplianceTarget).where(ComplianceTarget.benchmark_id == bm_id)
    ).scalar_one_or_none()
    if existing:
        existing.target_percent = body.get("target_percent", existing.target_percent)
        if body.get("target_date"):
            existing.target_date = _parse_date(body["target_date"])
        if body.get("baseline_percent") is not None:
            existing.baseline_percent = body["baseline_percent"]
        if body.get("baseline_date"):
            existing.baseline_date = _parse_date(body["baseline_date"])
        existing.description = body.get("description", existing.description)
        db.commit()
        return {"id": existing.id}

    target = ComplianceTarget(
        benchmark_id=bm_id,
        target_percent=body.get("target_percent", 100),
        target_date=_parse_date(body.get("target_date")),
        baseline_percent=body.get("baseline_percent"),
        baseline_date=_parse_date(body.get("baseline_date")),
        description=body.get("description"),
        created_by=current_user(request),
    )
    db.add(target)
    db.commit()
    return {"id": target.id}


# --- pipeline integration ---------------------------------------------------

@app.post("/api/pipeline/import")
def pipeline_import(request: Request, body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    return pipeline_service.import_pipeline_scan(db, body, actor=actor)


@app.get("/api/pipeline/containers")
def list_pipeline_containers(request: Request):
    return pipeline_service.get_container_status()


@app.post("/api/pipeline/containers/{service}/{action}")
def manage_pipeline_container(service: str, action: str, request: Request):
    return pipeline_service.manage_container(action, service)


# --- tickets / Jira integration ---------------------------------------------

def _serialize_ticket(t: Ticket) -> dict:
    return {
        "id": t.id,
        "external_id": t.external_id,
        "external_url": t.external_url,
        "provider": t.provider,
        "project_key": t.project_key,
        "issue_type": t.issue_type,
        "summary": t.summary,
        "description": t.description,
        "status": t.status,
        "priority": t.priority,
        "assignee": t.assignee,
        "reporter": t.reporter,
        "finding_ids": t.finding_ids or [],
        "vuln_ids": t.vuln_ids or [],
        "finding_count": t.finding_count or 0,
        "severity": t.severity,
        "created_by": t.created_by,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "updated_at": t.updated_at.isoformat() if t.updated_at else None,
        "resolved_at": t.resolved_at.isoformat() if t.resolved_at else None,
        "synced_at": t.synced_at.isoformat() if t.synced_at else None,
    }


@app.get("/api/tickets")
def list_tickets(
    status: str | None = None, finding_id: int | None = None,
    db=Depends(get_session),
):
    q = select(Ticket).order_by(Ticket.created_at.desc())
    if status:
        q = q.where(Ticket.status == status)
    rows = db.execute(q).scalars().all()
    result = [_serialize_ticket(t) for t in rows]
    if finding_id:
        result = [t for t in result if finding_id in (t["finding_ids"] or [])]
    return result


@app.get("/api/tickets/{ticket_id}")
def get_ticket(ticket_id: int, db=Depends(get_session)):
    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404)
    return _serialize_ticket(t)


@app.post("/api/tickets")
def create_ticket(request: Request, body: dict = Body(...), db=Depends(get_session)):
    """Create a ticket record. If Jira is configured, also creates the Jira issue."""
    actor = current_user(request)
    finding_ids = body.get("finding_ids", [])
    if not finding_ids:
        raise HTTPException(422, "finding_ids is required")

    findings = db.execute(
        select(Finding).options(joinedload(Finding.vuln), joinedload(Finding.asset))
        .where(Finding.id.in_(finding_ids))
    ).unique().scalars().all()
    if not findings:
        raise HTTPException(404, "No matching findings")

    severities = [f.severity for f in findings]
    sev_order = ["critical", "high", "medium", "low", "info"]
    highest = min(severities, key=lambda s: sev_order.index(s) if s in sev_order else 99)
    vuln_ids = list({f.vuln.canonical_id for f in findings if f.vuln})

    summary = body.get("summary") or _auto_summary(findings)
    description = body.get("description") or _auto_description(findings)

    jira_config = cc_service.get_config(db, "jira")
    external_id = ""
    external_url = ""
    provider = body.get("provider", "jira")
    project_key = body.get("project_key") or jira_config.get("project_key", "")
    issue_type = body.get("issue_type") or jira_config.get("issue_type", "Bug")

    if provider == "jira" and jira_config.get("url") and jira_config.get("api_token"):
        try:
            jira_result = _create_jira_issue(
                jira_config, summary, description,
                project_key=project_key, issue_type=issue_type,
                priority=body.get("priority"),
                assignee=body.get("assignee"),
            )
            external_id = jira_result["key"]
            external_url = jira_result["url"]
        except Exception as exc:
            return JSONResponse({"ok": False, "error": f"Jira API error: {exc}"}, status_code=502)
    elif provider == "manual":
        external_id = body.get("external_id", f"MANUAL-{dt.datetime.now().strftime('%Y%m%d%H%M%S')}")
        external_url = body.get("external_url", "")
    else:
        external_id = f"DRAFT-{dt.datetime.now().strftime('%Y%m%d%H%M%S')}"

    ticket = Ticket(
        external_id=external_id,
        external_url=external_url,
        provider=provider,
        project_key=project_key,
        issue_type=issue_type,
        summary=summary,
        description=description,
        status="open",
        priority=body.get("priority", _sev_to_priority(highest)),
        assignee=body.get("assignee"),
        reporter=actor,
        finding_ids=finding_ids,
        vuln_ids=vuln_ids,
        finding_count=len(findings),
        severity=highest,
        created_by=actor,
    )
    db.add(ticket)
    db.add(AuditEvent(
        actor=actor, action="ticket.create",
        entity_type="ticket", entity_id=external_id,
        summary=f"Created ticket {external_id} for {len(findings)} findings",
    ))
    db.commit()
    return _serialize_ticket(ticket)


@app.put("/api/tickets/{ticket_id}")
def update_ticket(ticket_id: int, request: Request, body: dict = Body(...),
                  db=Depends(get_session)):
    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404)
    actor = current_user(request)
    for field in ("status", "assignee", "priority", "external_id", "external_url"):
        if field in body:
            setattr(t, field, body[field])
    if body.get("status") in ("resolved", "closed"):
        t.resolved_at = dt.datetime.now(dt.timezone.utc)
    t.synced_at = dt.datetime.now(dt.timezone.utc)
    db.add(AuditEvent(
        actor=actor, action="ticket.update",
        entity_type="ticket", entity_id=t.external_id,
        summary=f"Updated ticket {t.external_id}: {', '.join(body.keys())}",
    ))
    db.commit()
    return _serialize_ticket(t)


@app.post("/api/tickets/{ticket_id}/sync")
def sync_ticket_status(ticket_id: int, request: Request, db=Depends(get_session)):
    """Pull latest status from Jira for this ticket."""
    t = db.get(Ticket, ticket_id)
    if not t:
        raise HTTPException(404)
    if t.provider != "jira":
        return {"ok": True, "message": "Only Jira tickets can be synced"}
    jira_config = cc_service.get_config(db, "jira")
    if not jira_config.get("url") or not jira_config.get("api_token"):
        raise HTTPException(422, "Jira not configured")
    try:
        issue = _fetch_jira_issue(jira_config, t.external_id)
        fields = issue.get("fields", {})
        t.status = (fields.get("status", {}).get("name", "open")).lower().replace(" ", "_")
        t.assignee = (fields.get("assignee") or {}).get("displayName")
        t.priority = (fields.get("priority") or {}).get("name")
        resolution = fields.get("resolution")
        if resolution and not t.resolved_at:
            t.resolved_at = dt.datetime.now(dt.timezone.utc)
        t.synced_at = dt.datetime.now(dt.timezone.utc)
        db.commit()
        return {"ok": True, "ticket": _serialize_ticket(t)}
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)


@app.get("/api/tickets/for-finding/{finding_id}")
def tickets_for_finding(finding_id: int, db=Depends(get_session)):
    """Find all tickets that cover a specific finding."""
    rows = db.execute(select(Ticket).order_by(Ticket.created_at.desc())).scalars().all()
    return [_serialize_ticket(t) for t in rows if finding_id in (t.finding_ids or [])]


def _create_jira_issue(config: dict, summary: str, description: str, *,
                       project_key: str, issue_type: str,
                       priority: str | None = None,
                       assignee: str | None = None) -> dict:
    import httpx, base64
    auth = base64.b64encode(f"{config['email']}:{config['api_token']}".encode()).decode()
    url = config["url"].rstrip("/")
    payload: dict = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type},
        }
    }
    if priority:
        payload["fields"]["priority"] = {"name": priority}
    if assignee:
        payload["fields"]["assignee"] = {"accountId": assignee}
    r = httpx.post(
        f"{url}/rest/api/2/issue",
        json=payload,
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
        timeout=30,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"Jira {r.status_code}: {r.text[:300]}")
    data = r.json()
    return {"key": data["key"], "url": f"{url}/browse/{data['key']}"}


def _fetch_jira_issue(config: dict, issue_key: str) -> dict:
    import httpx, base64
    auth = base64.b64encode(f"{config['email']}:{config['api_token']}".encode()).decode()
    url = config["url"].rstrip("/")
    r = httpx.get(
        f"{url}/rest/api/2/issue/{issue_key}",
        headers={"Authorization": f"Basic {auth}"},
        timeout=30,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"Jira {r.status_code}: {r.text[:300]}")
    return r.json()


def _auto_summary(findings) -> str:
    vulns = {f.vuln.canonical_id for f in findings if f.vuln}
    assets = {f.asset.name for f in findings if f.asset}
    if len(vulns) == 1:
        v = list(vulns)[0]
        return f"[{findings[0].severity.upper()}] {v} on {len(assets)} asset(s)"
    return f"[{findings[0].severity.upper()}] {len(vulns)} vulnerabilities on {len(assets)} asset(s)"


def _auto_description(findings) -> str:
    lines = ["Vulnerability findings from RiskDesk:\n"]
    by_vuln: dict = {}
    for f in findings:
        vid = f.vuln.canonical_id if f.vuln else "unknown"
        by_vuln.setdefault(vid, []).append(f)
    for vid, flist in list(by_vuln.items())[:20]:
        sev = flist[0].severity
        title = flist[0].vuln.title if flist[0].vuln else vid
        lines.append(f"* *{vid}* ({sev}) - {title}")
        for f in flist[:5]:
            asset = f.asset.name if f.asset else "unknown"
            comp = f.component or ""
            lines.append(f"  - {asset} {comp}")
        if len(flist) > 5:
            lines.append(f"  - ...and {len(flist) - 5} more")
    lines.append(f"\nTotal findings: {len(findings)}")
    return "\n".join(lines)


def _sev_to_priority(severity: str) -> str:
    return {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P4"}.get(severity, "P3")


# --- Wiz file import (alternative to GraphQL sync) -------------------------

@app.post("/api/wiz/import-file")
def wiz_import_file(request: Request, body: dict = Body(...), db=Depends(get_session)):
    """Import Wiz findings from a JSON export (Wiz Reports or manual export).

    Accepts the body format:
      { "findings": [ { ... raw Wiz node ... }, ... ] }
    or the Wiz Reports CSV-to-JSON format:
      { "data": { "vulnerabilityFindings": { "nodes": [...] } } }
    """
    from .config import reload_settings
    reload_settings()
    actor = current_user(request)

    nodes = []
    if "findings" in body:
        nodes = body["findings"]
    elif "data" in body:
        data = body["data"]
        for key in ("vulnerabilityFindings", "configurationFindings"):
            block = data.get(key, {})
            nodes.extend(block.get("nodes", []))
    else:
        nodes = body.get("nodes", [])

    if not nodes:
        raise HTTPException(422, "No findings found in the uploaded data. "
                            "Expected 'findings', 'data.vulnerabilityFindings.nodes', or 'nodes' key.")

    from .connectors.wiz import WizConnector
    from .sync import run_sync_from_records
    wiz = WizConnector()

    records = []
    errors = []
    for i, node in enumerate(nodes):
        try:
            rec = wiz._map_vuln(node)
            if rec:
                records.append(rec)
        except Exception as exc:
            errors.append({"index": i, "id": node.get("id"), "error": str(exc)})

    if not records:
        return JSONResponse({
            "ok": False,
            "error": f"Could not map any of {len(nodes)} nodes to findings",
            "mapping_errors": errors[:20],
        }, status_code=422)

    result = run_sync_from_records(db, "wiz", records, actor=actor)
    result["mapping_errors"] = errors[:20]
    result["ok"] = True
    return result


# --- static UI --------------------------------------------------------------

app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
