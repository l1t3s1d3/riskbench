"""Adjudication and assignment rule routes."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from .. import adjudication as adj_service
from .. import assignment as assign_service
from ..config import settings
from ..db import get_session
from ..enums import ScopeType
from ..models import (
    Adjudication, AdjudicationApplication, AssignmentRule, AuditEvent, Finding,
)
from ..queries import _serialize_adj
from ..risk import default_expiry, default_review_due
from .deps import current_user, parse_date

router = APIRouter(prefix="/api", tags=["adjudications"])


@router.post("/adjudications/preview")
def preview_scope(body: dict = Body(...), db=Depends(get_session)):
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


@router.post("/adjudications")
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
        expires_at=parse_date(body.get("expires_at")),
        review_due=parse_date(body.get("review_due")),
        adjusted_severity=body.get("adjusted_severity"),
        adjusted_priority=body.get("adjusted_priority"),
        assigned_to=body.get("assigned_to"),
        remediation_due=parse_date(body.get("remediation_due")),
        compensating_controls=body.get("compensating_controls"),
        scope_filter=body.get("filter"),
    )
    return {"created": len(created), "adjudications": [_serialize_adj(a) for a in created]}


@router.get("/adjudications")
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


@router.get("/adjudications/defaults/suggest")
def suggest_defaults(disposition: str, severity: str = "high"):
    exp = default_expiry(disposition, severity)
    return {
        "expires_at": exp.date().isoformat() if exp else None,
        "review_due": default_review_due(severity).date().isoformat(),
        "max_days": settings.policy.max_acceptance_days.get(severity),
    }


@router.get("/adjudications/{adj_id}")
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


@router.post("/adjudications/{adj_id}/decision")
def decide_adjudication(adj_id: int, request: Request, body: dict = Body(...),
                        db=Depends(get_session)):
    a = adj_service.decide(db, adj_id, approve=bool(body.get("approve")),
                           actor=current_user(request), note=body.get("note"))
    return _serialize_adj(a)


@router.post("/adjudications/{adj_id}/revoke")
def revoke_adjudication(adj_id: int, request: Request, body: dict = Body(...),
                        db=Depends(get_session)):
    a = adj_service.revoke(db, adj_id, actor=current_user(request),
                           reason=body.get("reason", ""))
    return _serialize_adj(a)


@router.post("/adjudications/{adj_id}/renew")
def renew_adjudication(adj_id: int, request: Request, body: dict = Body(...),
                       db=Depends(get_session)):
    expires = parse_date(body.get("expires_at"))
    if expires is None:
        raise HTTPException(422, "A renewal needs a new expiry date.")
    a = adj_service.renew(db, adj_id, actor=current_user(request),
                          justification=body.get("justification", ""),
                          expires_at=expires, approver=body.get("approver"))
    return _serialize_adj(a)


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


@router.get("/rules")
def list_rules(db=Depends(get_session)):
    rows = db.execute(
        select(AssignmentRule).order_by(AssignmentRule.priority.asc())
    ).scalars().all()
    return [_serialize_rule(r) for r in rows]


@router.post("/rules")
def create_rule(request: Request, body: dict = Body(...), db=Depends(get_session)):
    if not body.get("name"):
        raise HTTPException(422, "Name is required.")
    if not body.get("assign_to"):
        raise HTTPException(422, "assign_to is required.")
    if body.get("assign_to") not in settings.users:
        raise HTTPException(422, f"{body['assign_to']} is not on the user roster.")
    disp = body.get("disposition", "fix_immediately")
    if disp not in ("fix_immediately", "complex_resolution", "developer_review"):
        raise HTTPException(422, "Disposition must be a routing type.")
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


@router.put("/rules/{rule_id}")
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


@router.delete("/rules/{rule_id}")
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


@router.post("/rules/preview")
def preview_rules(rule_id: int | None = None, db=Depends(get_session)):
    return assign_service.preview_rules(db, rule_id=rule_id)


@router.post("/rules/run")
def run_assignment(request: Request, body: dict = Body(default={}),
                   db=Depends(get_session)):
    source = body.get("source")
    dry_run = body.get("dry_run", False)
    return assign_service.evaluate_rules(
        db, source=source, actor=current_user(request), dry_run=dry_run
    )
