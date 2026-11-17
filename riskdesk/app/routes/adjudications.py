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


# ---------------------------------------------------------------------------
#  Approval queue + bulk decide
# ---------------------------------------------------------------------------

@router.get("/adjudications/queue")
def approval_queue(request: Request, approver: str = "me",
                   max_age_days: int | None = None,
                   db=Depends(get_session)):
    """Decisions currently awaiting approval. `approver=me` filters to the
    current user (named as approver on the request, or empty — any approver
    on the roster can act). Enriches each row with age-in-days so the UI can
    sort and group by stale pending."""
    from ..models import Adjudication
    me = current_user(request)
    stmt = select(Adjudication).where(
        Adjudication.state == "pending_approval"
    )
    if approver == "me":
        # Pending decisions I can act on: either I'm the named approver,
        # or no approver was named and I'm on the roster.
        if me not in settings.approvers:
            return {"total": 0, "me": me, "can_approve": False, "decisions": []}
        stmt = stmt.where(
            (Adjudication.approver == me) | (Adjudication.approver.is_(None))
        )
    elif approver and approver != "any":
        stmt = stmt.where(Adjudication.approver == approver)

    rows = db.execute(stmt.order_by(Adjudication.requested_at.asc())).unique().scalars().all()
    now = dt.datetime.now(dt.timezone.utc)

    enriched = []
    for a in rows:
        req_at = a.requested_at
        if req_at and req_at.tzinfo is None:
            req_at = req_at.replace(tzinfo=dt.timezone.utc)
        age_days = (now - req_at).days if req_at else 0
        if max_age_days is not None and age_days < max_age_days:
            continue
        can_approve = (
            me in settings.approvers
            and a.requested_by != me
            and (not settings.policy.require_separate_approver or a.requested_by != me)
        )
        enriched.append({
            **_serialize_adj(a),
            "age_days": age_days,
            "can_approve": can_approve,
        })

    # Age bands for group tabs. Match the lifecycle vocabulary.
    bands = {"new": 0, "aging": 0, "stale": 0}
    for e in enriched:
        if e["age_days"] >= 14:
            bands["stale"] += 1
        elif e["age_days"] >= 3:
            bands["aging"] += 1
        else:
            bands["new"] += 1

    # Convenience group counts for the UI
    by_requester: dict[str, int] = {}
    by_disposition: dict[str, int] = {}
    by_scope_type: dict[str, int] = {}
    for e in enriched:
        by_requester[e["requested_by"]] = by_requester.get(e["requested_by"], 0) + 1
        by_disposition[e["disposition"]] = by_disposition.get(e["disposition"], 0) + 1
        by_scope_type[e["scope_type"]] = by_scope_type.get(e["scope_type"], 0) + 1

    return {
        "total": len(enriched),
        "me": me,
        "can_approve": me in settings.approvers,
        "age_bands": bands,
        "by_requester": by_requester,
        "by_disposition": by_disposition,
        "by_scope_type": by_scope_type,
        "decisions": enriched,
    }


@router.post("/adjudications/bulk-decide")
def bulk_decide(request: Request, body: dict = Body(...), db=Depends(get_session)):
    """Approve or reject many pending decisions in one call. A shared note
    is applied to each. Rejection of one does not abort the rest; the
    response reports per-item success or error."""
    ids = body.get("adjudication_ids") or []
    approve = bool(body.get("approve"))
    note = (body.get("note") or "").strip() or None
    if not ids:
        raise HTTPException(422, "adjudication_ids is required")
    actor = current_user(request)
    if actor not in settings.approvers:
        raise HTTPException(403, f"{actor} is not on the approver roster.")

    succeeded, failed = [], []
    for adj_id in ids:
        try:
            a = adj_service.decide(db, int(adj_id), approve=approve, actor=actor, note=note)
            succeeded.append({"id": a.id, "state": a.state})
        except adj_service.PolicyError as exc:
            failed.append({"id": adj_id, "error": "; ".join(exc.problems)})
        except Exception as exc:
            failed.append({"id": adj_id, "error": str(exc)})
    return {
        "ok": not failed,
        "processed": len(ids),
        "succeeded": len(succeeded),
        "failed": len(failed),
        "results": {"succeeded": succeeded, "failed": failed},
        "action": "approve" if approve else "reject",
    }


# ---------------------------------------------------------------------------
#  Decide context — prior/peer decisions, asset context, vuln signals
# ---------------------------------------------------------------------------

@router.get("/decide/context")
def decide_context(finding_ids: list[int] = Query(default=[]),
                   db=Depends(get_session)):
    """Everything the approver should see without clicking away: aggregate
    asset facts, vuln exploitation signals, prior decisions on this exact
    scope, peer decisions on the same CVE across other findings, and open
    tickets touching any of these findings."""
    from ..models import (
        Adjudication, AdjudicationApplication, Asset, Finding, Ticket,
        TicketFinding, Vuln,
    )
    if not finding_ids:
        raise HTTPException(422, "finding_ids is required")

    findings = db.execute(
        select(Finding).options(joinedload(Finding.asset), joinedload(Finding.vuln))
        .where(Finding.id.in_(finding_ids))
    ).unique().scalars().all()
    if not findings:
        raise HTTPException(404, "No findings matched")

    # ---- asset context (aggregated) -----------------------------------------
    envs: dict[str, int] = {}
    owners: dict[str, int] = {}
    bus: dict[str, int] = {}
    internet_counts = {"true": 0, "false": 0, "unknown": 0}
    classifications: dict[str, int] = {}
    asset_ids = set()
    for f in findings:
        a = f.asset
        if not a:
            continue
        asset_ids.add(a.id)
        envs[a.environment or "unknown"] = envs.get(a.environment or "unknown", 0) + 1
        if a.owner:
            owners[a.owner] = owners.get(a.owner, 0) + 1
        if a.business_unit:
            bus[a.business_unit] = bus.get(a.business_unit, 0) + 1
        key = "true" if a.internet_facing is True else "false" if a.internet_facing is False else "unknown"
        internet_counts[key] += 1
        if a.data_classification:
            classifications[a.data_classification] = classifications.get(a.data_classification, 0) + 1

    # ---- vuln context (aggregated) ------------------------------------------
    vulns = {f.vuln.canonical_id: f.vuln for f in findings if f.vuln}
    max_epss = max((v.epss_score for v in vulns.values() if v.epss_score is not None), default=None)
    max_cvss = max((v.cvss_score for v in vulns.values() if v.cvss_score is not None), default=None)
    kev_count = sum(1 for v in vulns.values() if v.kev)
    fix_available_count = sum(1 for f in findings if f.fix_available)
    canonicals = sorted(vulns.keys())

    # ---- prior decisions on same scope keys ---------------------------------
    # Build the possible scope keys from the findings, then look up every
    # approved or expired decision that matches any of them. This shows the
    # history across the organisation, not just on these specific findings.
    from ..risk import scope_keys_for_finding
    scope_pairs = set()
    for f in findings:
        for st, sk in scope_keys_for_finding(f):
            scope_pairs.add((st, sk))

    # Also peer decisions on the same canonical_id (vuln scope) on OTHER findings
    peer_canonicals = canonicals
    prior = db.execute(
        select(Adjudication).where(
            Adjudication.state.in_(["approved", "expired", "revoked", "pending_approval"])
        ).order_by(Adjudication.requested_at.desc())
    ).scalars().all()
    scope_matches = []
    peer_matches = []
    for a in prior:
        if (a.scope_type, a.scope_key) in scope_pairs:
            scope_matches.append(_short_adj(a))
            continue
        # peer: same vuln across other findings
        if a.scope_type == "vuln" and a.scope_key in peer_canonicals:
            peer_matches.append(_short_adj(a))
        elif a.scope_type == "vuln_on_asset":
            canonical = a.scope_key.split("::", 1)[0]
            if canonical in peer_canonicals:
                peer_matches.append(_short_adj(a))

    # ---- related tickets ----------------------------------------------------
    tickets = db.execute(
        select(Ticket).options(joinedload(Ticket.ticket_findings))
        .join(TicketFinding, TicketFinding.ticket_id == Ticket.id)
        .where(TicketFinding.finding_id.in_(finding_ids))
    ).unique().scalars().all()
    ticket_rows = [{
        "id": t.id, "external_id": t.external_id, "external_url": t.external_url,
        "status": t.status, "summary": t.summary,
    } for t in tickets]

    # ---- suggested expiry ---------------------------------------------------
    worst_sev = None
    for sev in ("critical", "high", "medium", "low", "info"):
        if any(f.severity == sev for f in findings):
            worst_sev = sev
            break
    kev_present = kev_count > 0
    suggested_days = settings.policy.max_acceptance_days.get(worst_sev or "high", 180)
    if kev_present:
        suggested_days = min(suggested_days, settings.policy.kev_sla_days * 2)

    return {
        "finding_count": len(findings),
        "asset_count": len(asset_ids),
        "unique_vulns": len(vulns),
        "canonical_ids": canonicals[:20],
        "worst_severity": worst_sev,
        "suggested_expiry_days": suggested_days,
        "asset_context": {
            "environments": envs,
            "owners": dict(sorted(owners.items(), key=lambda x: -x[1])[:10]),
            "business_units": dict(sorted(bus.items(), key=lambda x: -x[1])[:10]),
            "internet_facing": internet_counts,
            "data_classifications": classifications,
        },
        "vuln_context": {
            "max_cvss": max_cvss,
            "max_epss": max_epss,
            "kev_count": kev_count,
            "fix_available_count": fix_available_count,
        },
        "prior_decisions_on_scope": scope_matches[:20],
        "peer_decisions_on_cve": peer_matches[:20],
        "related_tickets": ticket_rows,
    }


def _short_adj(a):
    """Compact adj representation for the context panel."""
    return {
        "id": a.id, "disposition": a.disposition, "state": a.state,
        "scope_type": a.scope_type, "scope_key": a.scope_key,
        "scope_label": a.scope_label,
        "justification": (a.justification or "")[:240],
        "requested_by": a.requested_by,
        "approved_by": a.approved_by,
        "requested_at": a.requested_at.isoformat() if a.requested_at else None,
        "decided_at": a.decided_at.isoformat() if a.decided_at else None,
        "expires_at": a.expires_at.isoformat() if a.expires_at else None,
        "adjusted_severity": a.adjusted_severity,
    }


# ---------------------------------------------------------------------------
#  Decision templates
# ---------------------------------------------------------------------------

def _serialize_template(t) -> dict:
    return {
        "id": t.id, "name": t.name, "description": t.description,
        "disposition": t.disposition, "scope": t.scope,
        "justification_text": t.justification_text,
        "compensating_controls": t.compensating_controls,
        "adjusted_severity": t.adjusted_severity,
        "adjusted_priority": t.adjusted_priority,
        "expiry_days": t.expiry_days,
        "remediation_days": t.remediation_days,
        "enabled": t.enabled,
        "created_by": t.created_by,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "updated_at": t.updated_at.isoformat() if t.updated_at else None,
    }


@router.get("/decision-templates")
def list_templates(enabled_only: bool = False, db=Depends(get_session)):
    from ..models import DecisionTemplate
    stmt = select(DecisionTemplate).order_by(DecisionTemplate.name)
    if enabled_only:
        stmt = stmt.where(DecisionTemplate.enabled.is_(True))
    rows = db.execute(stmt).scalars().all()
    return [_serialize_template(t) for t in rows]


@router.post("/decision-templates")
def create_template(request: Request, body: dict = Body(...), db=Depends(get_session)):
    from ..models import DecisionTemplate
    required = ("name", "disposition", "justification_text")
    missing = [k for k in required if not body.get(k)]
    if missing:
        raise HTTPException(422, f"Missing: {', '.join(missing)}")
    if body["disposition"] not in {d["value"] for d in _disposition_values()}:
        raise HTTPException(422, "Unknown disposition.")
    t = DecisionTemplate(
        name=body["name"].strip(),
        description=body.get("description"),
        disposition=body["disposition"],
        scope=body.get("scope", "finding"),
        justification_text=body["justification_text"],
        compensating_controls=body.get("compensating_controls"),
        adjusted_severity=body.get("adjusted_severity"),
        adjusted_priority=body.get("adjusted_priority"),
        expiry_days=body.get("expiry_days"),
        remediation_days=body.get("remediation_days"),
        enabled=bool(body.get("enabled", True)),
        created_by=current_user(request),
    )
    db.add(t)
    db.commit()
    return _serialize_template(t)


@router.put("/decision-templates/{tid}")
def update_template(tid: int, body: dict = Body(...), db=Depends(get_session)):
    from ..models import DecisionTemplate
    t = db.get(DecisionTemplate, tid)
    if t is None:
        raise HTTPException(404, "No such template.")
    for field in ("name", "description", "disposition", "scope", "justification_text",
                  "compensating_controls", "adjusted_severity", "adjusted_priority",
                  "expiry_days", "remediation_days", "enabled"):
        if field in body:
            setattr(t, field, body[field])
    db.commit()
    return _serialize_template(t)


@router.delete("/decision-templates/{tid}")
def delete_template(tid: int, db=Depends(get_session)):
    from ..models import DecisionTemplate
    t = db.get(DecisionTemplate, tid)
    if t is None:
        raise HTTPException(404, "No such template.")
    db.delete(t)
    db.commit()
    return {"deleted": tid}


def _disposition_values():
    from ..enums import Disposition, DISPOSITION_LABELS
    return [{"value": d.value, "label": DISPOSITION_LABELS[d]} for d in Disposition]


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
