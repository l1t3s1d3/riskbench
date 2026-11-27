"""Findings, facets, dashboard, and CSV export routes."""
from __future__ import annotations

import csv
import datetime as dt
import io

from fastapi import APIRouter, Body, Depends, Query, Request, UploadFile, File
from fastapi.responses import StreamingResponse
from sqlalchemy import func, select
from sqlalchemy.orm import joinedload

from ..buckets import bucket_for_disposition as _bucket_for, bucket_meta as _bucket_meta
from ..config import settings
from ..db import get_session
from ..enums import (
    DISPOSITION_LABELS, VERIFIABLE_STATUSES, Disposition, FindingCategory, ScopeType, Severity,
)
from ..lifecycle import finding_timeline, lifecycle_metrics, record_event
from ..models import (
    Adjudication, AdjudicationApplication, Asset, Finding, SyncRun, Vuln,
)
from ..queries import (
    FindingFilter, _serialize_adj, build_pending_map, build_resolution_map,
    facets as get_facets, search, serialize_finding,
)
from ..risk import compute_risk, sla_status
from ..schemas import (
    AuditPageOut, BulkAdjudicationOut, DashboardOut,
    FindingDetailOut, FindingListOut, FindingIdsOut,
    MetaOut, SLABreachReportOut, VerifyOut,
)
from ..sync import get_connector
from .deps import current_user, parse_date

router = APIRouter(prefix="/api", tags=["findings"])


def _filter_from_query(
    source: list[str] = Query(default=[]),
    severity: list[str] = Query(default=[]),
    status: list[str] = Query(default=["open"]),
    category: list[str] = Query(default=[]),
    disposition: list[str] = Query(default=[]),
    priority: list[str] = Query(default=[]),
    bucket: list[int] = Query(default=[]),
    kev: bool = False,
    fixable: bool = False,
    overdue: bool = False,
    undecided: bool = False,
    q: str = "",
    asset: str = "",
    cve: str = "",
    asset_id: int | None = None,
    component: str = "",
    component_version: str = "",
    owner: str = "",
    business_unit: str = "",
    asset_type: str = "",
    asset_group_id: int | None = None,
    ecosystem: str = "",
    sort: str = "risk",
    order: str = "desc",
) -> FindingFilter:
    return FindingFilter(
        sources=source, severities=severity, statuses=status, categories=category,
        dispositions=disposition, priorities=priority, buckets=bucket, kev_only=kev,
        fixable_only=fixable, overdue_only=overdue, undecided_only=undecided,
        q=q, asset=asset, cve=cve,
        asset_id=asset_id, component=component, component_version=component_version,
        owner=owner, business_unit=business_unit, asset_type=asset_type,
        asset_group_id=asset_group_id, ecosystem=ecosystem,
        sort=sort, order=order,
    )


@router.get("/meta", response_model=MetaOut)
def meta(request: Request, db=Depends(get_session)):
    demo_rows = db.execute(
        select(func.count()).select_from(Finding).where(Finding.is_demo.is_(True))
    ).scalar() or 0
    return {
        "org": settings.org_name,
        "users": settings.users,
        "approvers": settings.approvers,
        "current_user": current_user(request),
        "dispositions": [
            {"value": d.value, "label": DISPOSITION_LABELS[d],
             "is_risk_decision": d.value in {"accept_risk", "adjust_risk", "false_positive"},
             "bucket": _bucket_for(d.value)}
            for d in Disposition
        ],
        "buckets": _bucket_meta(),
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


@router.get("/findings/grouped")
def list_grouped(
    by: str = Query(..., pattern="^(cve|asset|component|component_version|asset_type|owner|business_unit|ecosystem)$"),
    group_sort: str = Query("count", pattern="^(count|severity|score|assets|label)$"),
    page: int = 1,
    page_size: int = Query(50, ge=1, le=500),
    f: FindingFilter = Depends(_filter_from_query),
    db=Depends(get_session),
):
    """One row per group (CVE / asset / component / etc.) with aggregates and
    sample finding IDs. Use the usual filter params to narrow the universe
    before grouping. `group_sort` is count (default) / severity / score /
    assets / label."""
    from ..queries import grouped_search
    result = grouped_search(db, f, by=by, page=page, page_size=page_size, sort=group_sort)
    result["filter"] = f.as_dict()
    return result


@router.get("/findings/remediated")
def list_remediated(
    start: str | None = None,
    end: str | None = None,
    severity: list[str] = Query(default=[]),
    source: list[str] = Query(default=[]),
    category: list[str] = Query(default=[]),
    status: list[str] = Query(default=[]),
    verified_only: bool = False,
    page: int = 1,
    page_size: int = Query(100, ge=1, le=500),
    db=Depends(get_session),
):
    """List remediated findings for historical reporting. Default scope is
    every closed finding; narrow with start/end dates and the usual filters."""
    from ..lifecycle import remediated_findings
    return remediated_findings(
        db,
        start=parse_date(start), end=parse_date(end),
        severity=severity or None, source=source or None,
        category=category or None, status=status or None,
        include_verified_only=verified_only,
        page=page, page_size=page_size,
    )


@router.post("/findings/import-historical")
async def import_historical_findings(
    request: Request, file: UploadFile = File(...), db=Depends(get_session),
):
    """Backload remediated findings from a CSV so prior remediation history is
    reportable. Required columns: canonical_id, source, asset, severity,
    first_detected, closed_at, status. Optional: cve_id, title, category,
    component, component_version, source_finding_id, asset_type."""
    from ..lifecycle import import_historical
    actor = current_user(request)
    content = await file.read()
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        text = content.decode("latin-1")
    reader = csv.DictReader(io.StringIO(text))
    rows = list(reader)
    if not rows:
        from fastapi import HTTPException
        raise HTTPException(422, "CSV has no data rows.")
    return import_historical(db, rows, actor)


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
    payload["timeline"] = finding_timeline(db, obj)
    payload["raw"] = obj.raw
    return payload


@router.get("/findings/{finding_id}/timeline")
def get_finding_timeline(finding_id: int, db=Depends(get_session)):
    from fastapi import HTTPException
    obj = db.get(Finding, finding_id)
    if obj is None:
        raise HTTPException(404, "No such finding.")
    return {"finding_id": finding_id, "status": obj.status, "events": finding_timeline(db, obj)}


@router.get("/lifecycle/metrics")
def get_lifecycle_metrics(days: int = Query(90, ge=1, le=730), db=Depends(get_session)):
    """Remediation flow over a window: opened vs closed, time to close, SLA
    attainment at closure, reopens, verification backlog, ticket drift."""
    return lifecycle_metrics(db, days=days)


@router.get("/lifecycle/trends")
def get_lifecycle_trends(
    days: int = Query(365, ge=7, le=1825),
    granularity: str = Query("week", pattern="^(day|week|month|quarter)$"),
    db=Depends(get_session),
):
    """Time series of findings opened, closed, and remaining backlog, bucketed
    by day/week/month/quarter. Backs the trend chart in the Activity tab."""
    from ..lifecycle import lifecycle_trends
    return lifecycle_trends(db, days=days, granularity=granularity)


@router.get("/export/remediated.csv")
def export_remediated(
    start: str | None = None,
    end: str | None = None,
    severity: list[str] = Query(default=[]),
    source: list[str] = Query(default=[]),
    category: list[str] = Query(default=[]),
    db=Depends(get_session),
):
    """CSV export of remediated findings for audit/compliance evidence."""
    from ..lifecycle import remediated_findings
    data = remediated_findings(
        db, start=parse_date(start), end=parse_date(end),
        severity=severity or None, source=source or None,
        category=category or None, page=1, page_size=100000,
    )
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([
        "finding_id", "source", "canonical_id", "cve_id", "title", "asset",
        "asset_type", "category", "severity", "effective_severity", "status",
        "component", "component_version", "first_detected", "closed_at",
        "time_to_close_days", "closed_within_sla", "sla_due", "reopened_count",
        "verified_by", "verified_at", "fix_version",
    ])
    for r in data["findings"]:
        w.writerow([
            r["finding_id"], r["source"], r["canonical_id"], r["cve_id"] or "",
            (r["title"] or "").replace("\n", " "), r["asset"],
            r["asset_type"] or "", r["category"], r["severity"],
            r["effective_severity"], r["status"], r["component"] or "",
            r["component_version"] or "", r["first_detected"] or "",
            r["closed_at"] or "", r["time_to_close_days"] if r["time_to_close_days"] is not None else "",
            r["closed_within_sla"], r["sla_due"] or "", r["reopened_count"],
            r["verified_by"] or "", r["verified_at"] or "", r["fix_version"] or "",
        ])
    buf.seek(0)
    stamp = dt.date.today().isoformat()
    return StreamingResponse(
        iter([buf.getvalue()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="remediated-{stamp}.csv"'},
    )


@router.post("/findings/{finding_id}/verify", response_model=VerifyOut)
def verify_finding(finding_id: int, request: Request, body: dict | None = Body(default=None),
                   db=Depends(get_session)):
    """Confirm a closed finding (fixed by the source, or stale) is really fixed."""
    from fastapi import HTTPException
    from ..models import AuditEvent
    obj = db.get(Finding, finding_id)
    if obj is None:
        raise HTTPException(404, "No such finding.")
    if obj.status not in VERIFIABLE_STATUSES:
        raise HTTPException(
            422, f"Only fixed or stale findings can be verified (currently '{obj.status}').")
    actor = current_user(request)
    note = ((body or {}).get("note") or "").strip() or None
    now = dt.datetime.now(dt.timezone.utc)
    prev = obj.status
    obj.status = "verified_fixed"
    obj.verified_by = actor
    obj.verified_at = now
    if obj.closed_at is None:
        obj.closed_at = now
    record_event(db, obj, "verified", "verified_fixed", actor, from_status=prev, ts=now, note=note)
    db.add(AuditEvent(
        actor=actor, action="finding.verify",
        entity_type="finding", entity_id=str(finding_id),
        summary=f"Finding #{finding_id} verified as fixed (was {prev})",
        detail={"note": note},
    ))
    db.commit()
    from ..cache import invalidate_all
    invalidate_all()
    from ..rollup import mark_stale
    mark_stale(db)
    return {"ok": True, "finding_id": finding_id, "status": "verified_fixed"}


@router.get("/dashboard", response_model=DashboardOut)
def dashboard(db=Depends(get_session)):
    from ..rollup import get_rollup, live_extras
    now = dt.datetime.now(dt.timezone.utc)
    payload = get_rollup(db, now)
    payload.update(live_extras(db, now))
    return payload


# --- bucket reporting & bulk review ----------------------------------------

@router.get("/buckets/report")
def buckets_report(top_n: int = 10, db=Depends(get_session)):
    """Per-bucket breakdown: counts, age stats, top CVEs/owners, over-cap items."""
    from ..buckets_report import bucket_report
    return bucket_report(db, top_n=top_n)


@router.get("/buckets/report.csv")
def buckets_report_csv(db=Depends(get_session)):
    """Per-bucket breakdown as CSV for executive reporting."""
    from ..buckets_report import bucket_report
    data = bucket_report(db, top_n=0)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["bucket", "title", "count", "kev", "severity_critical",
                "severity_high", "severity_medium", "severity_low",
                "median_age_days", "p90_age_days", "max_age_days",
                "max_days_cap", "over_cap_count"])
    for b in data["buckets"]:
        sev = b["severities"]
        w.writerow([
            b["number"], b["title"], b["count"], b["kev"],
            sev.get("critical", 0), sev.get("high", 0),
            sev.get("medium", 0), sev.get("low", 0),
            b["age"]["median_days"], b["age"]["p90_days"], b["age"]["max_days"],
            b["max_days"] or "", b["over_cap_count"],
        ])
    buf.seek(0)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%d")
    return StreamingResponse(
        iter([buf.read()]), media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="bucket-report-{stamp}.csv"'},
    )


@router.get("/buckets/trend")
def buckets_trend(weeks: int = 8, db=Depends(get_session)):
    """Weekly history of bucket counts."""
    from ..buckets_report import bucket_trend
    return bucket_trend(db, weeks=weeks)


@router.get("/buckets/{bucket_number}/findings")
def buckets_findings(bucket_number: int,
                     page: int = 1, page_size: int = 50,
                     db=Depends(get_session)):
    """List findings currently sitting in a given bucket."""
    from ..buckets import bucket_for_finding, BUCKETS
    if not any(b.number == bucket_number for b in BUCKETS):
        from fastapi import HTTPException
        raise HTTPException(400, f"Unknown bucket {bucket_number}")
    resolution = build_resolution_map(db)
    # Load open findings in one query, then filter in Python so bucket
    # membership stays consistent with the rest of the API.
    rows = db.execute(
        select(Finding).options(joinedload(Finding.asset), joinedload(Finding.vuln))
        .where(Finding.status == "open")
        .order_by(Finding.first_detected.asc())
    ).unique().scalars().all()
    hits = [f for f in rows if bucket_for_finding(resolution.get(f.id)) == bucket_number]
    total = len(hits)
    start = (page - 1) * page_size
    page_items = hits[start:start + page_size]
    pending = build_pending_map(db)
    out = []
    for f in page_items:
        adj = resolution.get(f.id)
        risk = compute_risk(f, adj, has_pending=f.id in pending)
        out.append(serialize_finding(f, risk, adj))
    return {"bucket": bucket_number, "total": total, "page": page,
            "page_size": page_size, "findings": out}


@router.get("/review/bundles")
def review_bundles(limit: int = 20, db=Depends(get_session)):
    """Smart bundles: undecided groups with a suggested disposition."""
    from ..bulk_review import smart_bundles
    return {"bundles": smart_bundles(db, limit=limit)}


@router.get("/review/intake")
def review_intake(limit: int = 100, db=Depends(get_session)):
    """Bucket-0 findings sorted oldest-first, grouped by owner."""
    from ..bulk_review import intake_queue
    return intake_queue(db, limit=limit)


@router.get("/review/suggest")
def review_suggest(scope_type: str, scope_key: str, db=Depends(get_session)):
    """Pre-fill hint for a decision form, pulled from the most recent
    approved decision at this scope. Returns `{"suggested": null}` when
    the team has not decided this scope before."""
    from ..bulk_review import suggest_for_scope
    return {"suggested": suggest_for_scope(db, scope_type, scope_key)}


@router.post("/review/scope-promotion")
def review_scope_promotion(body: dict = Body(...), db=Depends(get_session)):
    """Given a selection of finding IDs, suggest broader scopes the
    reviewer could record the decision at. Each suggestion reports the
    number of distinct scope keys, total coverage, extras beyond the
    selection, and warnings when promotion sweeps in heterogeneous
    siblings.

    Body: `{"finding_ids": [1, 2, 3, ...]}` (or `{"ids": [...]}`).
    """
    from ..scope_promotion import suggest_scope_promotions
    ids = body.get("finding_ids") or body.get("ids") or []
    return suggest_scope_promotions(db, ids)


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
