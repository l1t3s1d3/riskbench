"""Findings, facets, dashboard, and CSV export routes."""
from __future__ import annotations

import csv
import datetime as dt
import io

from fastapi import APIRouter, Depends, Query, Request, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import joinedload

from ..config import settings
from ..db import get_session
from ..enums import Disposition, FindingCategory, ScopeType, Severity, DISPOSITION_LABELS
from ..models import (
    Adjudication, AdjudicationApplication, Asset, Finding, SyncRun, Vuln,
)
from ..queries import (
    FindingFilter, _serialize_adj, build_pending_map, build_resolution_map,
    facets as get_facets, search, serialize_finding,
)
from ..risk import compute_risk, default_expiry, default_review_due
from ..schemas import (
    AuditPageOut, BulkAdjudicationOut, DashboardOut,
    FindingDetailOut, FindingListOut, FindingIdsOut,
    MetaOut, SLABreachReportOut, VerifyOut,
)
from ..sync import get_connector
from .deps import current_user

router = APIRouter(prefix="/api", tags=["findings"])


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


@router.get("/meta", response_model=MetaOut)
def meta(request: Request, db=Depends(get_session)):
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


@router.get("/findings", response_model=FindingListOut)
def list_findings(f: FindingFilter = Depends(_filter_from_query),
                  page: int = 1, page_size: int = 50,
                  include_ids: bool = False, db=Depends(get_session)):
    result = search(db, f, page=page, page_size=min(page_size, 200))
    if not include_ids:
        result.pop("all_matching_ids", None)
    result["filter"] = f.as_dict()
    return result


@router.get("/findings/ids", response_model=FindingIdsOut)
def matching_ids(f: FindingFilter = Depends(_filter_from_query), db=Depends(get_session)):
    result = search(db, f, page=1, page_size=1)
    return {"total": result["total"], "ids": result["all_matching_ids"]}


@router.get("/facets")
def facets_endpoint(f: FindingFilter = Depends(_filter_from_query), db=Depends(get_session)):
    return get_facets(db, f)


@router.get("/findings/{finding_id}")
def get_finding(finding_id: int, db=Depends(get_session)):
    from fastapi import HTTPException
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

    history = db.execute(
        select(Adjudication).join(AdjudicationApplication)
        .where(AdjudicationApplication.finding_id == finding_id)
        .order_by(Adjudication.requested_at.desc())
    ).unique().scalars().all()
    payload["decision_history"] = [_serialize_adj(a) for a in history]
    payload["raw"] = obj.raw
    return payload


@router.post("/findings/{finding_id}/verify", response_model=VerifyOut)
def verify_finding(finding_id: int, request: Request, db=Depends(get_session)):
    """Mark a fixed finding as verified fixed."""
    from fastapi import HTTPException
    from ..models import AuditEvent
    obj = db.get(Finding, finding_id)
    if obj is None:
        raise HTTPException(404, "No such finding.")
    if obj.status != "fixed":
        raise HTTPException(422, f"Finding must be in 'fixed' status to verify (currently '{obj.status}').")
    actor = current_user(request)
    obj.status = "verified_fixed"
    obj.verified_by = actor
    obj.verified_at = dt.datetime.now(dt.timezone.utc)
    db.add(AuditEvent(
        actor=actor, action="finding.verify",
        entity_type="finding", entity_id=str(finding_id),
        summary=f"Finding #{finding_id} verified as fixed",
    ))
    db.commit()
    return {"ok": True, "finding_id": finding_id, "status": "verified_fixed"}


@router.get("/dashboard", response_model=DashboardOut)
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


@router.get("/audit", response_model=AuditPageOut)
def audit(limit: int = 100, cursor: int | None = None,
          action: list[str] = Query(default=[]),
          actor_filter: str = "",
          entity_type: str = "",
          entity_id: str = "", db=Depends(get_session)):
    from ..models import AuditEvent
    limit = min(limit, 500)
    stmt = select(AuditEvent)
    if cursor is not None:
        stmt = stmt.where(AuditEvent.id < cursor)
    if action:
        stmt = stmt.where(AuditEvent.action.in_(action))
    if actor_filter:
        stmt = stmt.where(AuditEvent.actor == actor_filter)
    if entity_type:
        stmt = stmt.where(AuditEvent.entity_type == entity_type)
    if entity_id:
        stmt = stmt.where(AuditEvent.entity_id == entity_id)

    count_stmt = select(func.count()).select_from(AuditEvent)
    if action:
        count_stmt = count_stmt.where(AuditEvent.action.in_(action))
    if actor_filter:
        count_stmt = count_stmt.where(AuditEvent.actor == actor_filter)
    if entity_type:
        count_stmt = count_stmt.where(AuditEvent.entity_type == entity_type)
    if entity_id:
        count_stmt = count_stmt.where(AuditEvent.entity_id == entity_id)
    total = db.execute(count_stmt).scalar() or 0

    rows = db.execute(stmt.order_by(AuditEvent.id.desc()).limit(limit + 1)).scalars().all()
    has_more = len(rows) > limit
    rows = rows[:limit]
    next_cursor = rows[-1].id if rows and has_more else None

    return {
        "events": [{
            "id": e.id, "ts": e.ts.isoformat(), "actor": e.actor, "action": e.action,
            "entity_type": e.entity_type, "entity_id": e.entity_id,
            "summary": e.summary, "detail": e.detail,
        } for e in rows],
        "total": total,
        "cursor": next_cursor,
        "has_more": has_more,
    }


@router.get("/export/register.csv")
def export_register(db=Depends(get_session)):
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


@router.get("/sla/breaches", response_model=SLABreachReportOut)
def sla_breaches(notify: bool = False, db=Depends(get_session)):
    """Check all open findings for SLA breaches. Pass notify=true to send alerts."""
    from ..notifications import check_sla_breaches, send_sla_notifications
    if notify:
        return send_sla_notifications(db)
    report = check_sla_breaches(db)
    report["notification_sent"] = False
    return report


@router.post("/adjudications/bulk-csv", response_model=BulkAdjudicationOut)
async def bulk_adjudicate_csv(request: Request, file: UploadFile = File(...),
                              db=Depends(get_session)):
    """Import adjudications from a CSV file.

    Expected columns: canonical_id, disposition, justification, approver,
    scope (optional, default 'vuln'), expires_at (optional),
    adjusted_severity (optional), compensating_controls (optional).
    """
    from ..models import AuditEvent
    from .. import adjudication as adj_svc

    actor = current_user(request)
    content = await file.read()
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = content.decode("latin-1")

    reader = csv.DictReader(io.StringIO(text))
    results: list[dict] = []
    succeeded = 0
    failed = 0

    for row_num, row in enumerate(reader, start=2):
        canonical_id = (row.get("canonical_id") or "").strip()
        disposition = (row.get("disposition") or "").strip()
        justification = (row.get("justification") or "").strip()
        approver = (row.get("approver") or "").strip() or None
        scope = (row.get("scope") or "vuln").strip()
        expires_str = (row.get("expires_at") or "").strip()
        adjusted_severity = (row.get("adjusted_severity") or "").strip() or None
        compensating = (row.get("compensating_controls") or "").strip() or None

        if not canonical_id or not disposition:
            results.append({
                "row": row_num, "status": "error", "canonical_id": canonical_id,
                "finding_ids": [], "error": "Missing canonical_id or disposition",
            })
            failed += 1
            continue

        findings = db.execute(
            select(Finding).join(Vuln, Finding.vuln_id == Vuln.id)
            .where(Vuln.canonical_id == canonical_id, Finding.status == "open")
        ).scalars().all()

        if not findings:
            results.append({
                "row": row_num, "status": "skipped", "canonical_id": canonical_id,
                "finding_ids": [], "error": "No open findings match this canonical_id",
            })
            failed += 1
            continue

        fids = [f.id for f in findings]
        expires_at = None
        if expires_str:
            from .deps import parse_date
            try:
                expires_at = parse_date(expires_str)
            except Exception:
                results.append({
                    "row": row_num, "status": "error", "canonical_id": canonical_id,
                    "finding_ids": fids, "error": f"Bad expires_at: {expires_str}",
                })
                failed += 1
                continue

        try:
            created = adj_svc.create_decisions(
                db, finding_ids=fids, disposition=disposition,
                justification=justification, actor=actor, scope=scope,
                approver=approver, expires_at=expires_at,
                adjusted_severity=adjusted_severity,
                compensating_controls=compensating,
            )
            results.append({
                "row": row_num, "status": "ok", "canonical_id": canonical_id,
                "finding_ids": fids, "error": None,
            })
            succeeded += 1
        except Exception as exc:
            results.append({
                "row": row_num, "status": "error", "canonical_id": canonical_id,
                "finding_ids": fids, "error": str(exc),
            })
            failed += 1

    db.add(AuditEvent(
        actor=actor, action="adjudication.bulk_csv",
        entity_type="adjudication", entity_id="bulk",
        summary=f"Bulk CSV import: {succeeded} succeeded, {failed} failed out of {succeeded + failed} rows",
    ))
    db.commit()

    return {
        "ok": failed == 0,
        "processed": succeeded + failed,
        "succeeded": succeeded,
        "failed": failed,
        "results": results[:500],
    }


@router.get("/export/findings.csv")
def export_findings(f: FindingFilter = Depends(_filter_from_query), db=Depends(get_session)):
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
