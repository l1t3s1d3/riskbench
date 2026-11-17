"""Adjudication service.

Creating a decision has three parts:

  1. Work out which findings the person means (a selection, or every finding
     matching the filter they are looking at).
  2. Work out what scope to record it against. Choosing the scope well is what
     makes a bulk decision durable: an accept on CVE-2021-44228 recorded at
     `vuln` scope keeps covering that CVE when Wiz reports it on a new host
     next month, whereas 4,000 finding-scoped rows would not.
  3. Check it against policy, record it, and write the audit trail.

Nothing here silently changes a risk posture. A risk decision starts as
`pending_approval` and does not affect any score until someone on the approver
roster decides on it.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from sqlalchemy import select

from .config import settings
from .cache import invalidate_all as invalidate_cache
from .enums import (
    RISK_DECISION_DISPOSITIONS, Disposition, AdjudicationState, ScopeType,
)
from .models import (
    Adjudication, AdjudicationApplication, AuditEvent, Finding, Vuln, utcnow,
)
from .risk import default_expiry, default_review_due, validate_decision


class PolicyError(Exception):
    def __init__(self, problems: list[str]):
        self.problems = problems
        super().__init__("; ".join(problems))


@dataclass
class ScopePlan:
    scope_type: str
    scope_key: str
    scope_label: str
    finding_ids: list[int]
    coverage_note: str


def plan_scope(db, finding_ids: list[int], requested_scope: str) -> list[ScopePlan]:
    """Group the selected findings into the scopes a decision will be recorded at.

    A bulk action over mixed CVEs at `vuln` scope produces one decision per
    CVE rather than one giant decision, so the register stays reviewable and a
    single CVE can later be revoked without unpicking everything else.
    """
    findings = db.execute(
        select(Finding).where(Finding.id.in_(finding_ids))
    ).scalars().all()
    if not findings:
        return []

    scope = ScopeType(requested_scope)
    groups: dict[tuple[str, str, str], list[int]] = {}

    for f in findings:
        if scope == ScopeType.FINDING:
            key = (ScopeType.FINDING.value, str(f.id),
                   f"{f.vuln.canonical_id} on {f.asset.name}")
        elif scope == ScopeType.VULN_ON_ASSET:
            key = (ScopeType.VULN_ON_ASSET.value, f"{f.vuln.canonical_id}::{f.asset_id}",
                   f"{f.vuln.canonical_id} on {f.asset.name}")
        elif scope == ScopeType.VULN:
            key = (ScopeType.VULN.value, f.vuln.canonical_id,
                   f"{f.vuln.canonical_id} (all assets)")
        elif scope == ScopeType.COMPONENT:
            if not f.component_key:
                # Fall back rather than silently dropping the finding.
                key = (ScopeType.FINDING.value, str(f.id),
                       f"{f.vuln.canonical_id} on {f.asset.name} (no component key)")
            else:
                key = (ScopeType.COMPONENT.value, f.component_key,
                       f"{f.component_key} (all findings)")
        else:
            raise ValueError(f"Unsupported scope {requested_scope}")
        groups.setdefault(key, []).append(f.id)

    plans = []
    for (stype, skey, label), ids in groups.items():
        plans.append(ScopePlan(
            scope_type=stype, scope_key=skey, scope_label=label,
            finding_ids=ids,
            coverage_note=_coverage_note(db, stype, skey, len(ids)),
        ))
    return plans


def _coverage_note(db, scope_type: str, scope_key: str, selected: int) -> str:
    """Tell the person how far past their selection this decision will reach."""
    if scope_type == ScopeType.FINDING.value:
        return "Covers this one finding."
    if scope_type == ScopeType.VULN_ON_ASSET.value:
        return "Covers this vulnerability on this asset, including future re-detections."
    if scope_type == ScopeType.VULN.value:
        total = db.execute(
            select(Finding.id).join(Vuln).where(Vuln.canonical_id == scope_key,
                                                Finding.status == "open")
        ).scalars().all()
        extra = len(total) - selected
        base = f"Covers all {len(total)} open findings for {scope_key}, and any reported later."
        if extra > 0:
            base += f" That is {extra} beyond your selection."
        return base
    if scope_type == ScopeType.COMPONENT.value:
        total = db.execute(
            select(Finding.id).where(Finding.component_key == scope_key,
                                     Finding.status == "open")
        ).scalars().all()
        extra = len(total) - selected
        base = f"Covers all {len(total)} open findings for {scope_key}, and any reported later."
        if extra > 0:
            base += f" That is {extra} beyond your selection."
        return base
    return ""


def create_decisions(
    db,
    finding_ids: list[int],
    disposition: str,
    justification: str,
    actor: str,
    scope: str = ScopeType.FINDING.value,
    approver: str | None = None,
    expires_at: dt.datetime | None = None,
    review_due: dt.datetime | None = None,
    adjusted_severity: str | None = None,
    adjusted_priority: str | None = None,
    assigned_to: str | None = None,
    remediation_due: dt.datetime | None = None,
    compensating_controls: str | None = None,
    scope_filter: dict | None = None,
) -> list[Adjudication]:
    disp = Disposition(disposition)
    plans = plan_scope(db, finding_ids, scope)
    if not plans:
        raise PolicyError(["No findings matched the selection."])

    if disp == Disposition.ADJUST_RISK and not (adjusted_severity or adjusted_priority):
        raise PolicyError(["An adjust-risk decision must set a new severity or priority."])

    # Severity drives the default expiry and review windows, so derive it from
    # the findings in scope rather than a global default.
    sample_sev = _dominant_severity(db, finding_ids)
    if expires_at is None:
        expires_at = default_expiry(disp.value, adjusted_severity or sample_sev)
    if review_due is None and disp in RISK_DECISION_DISPOSITIONS:
        review_due = default_review_due(adjusted_severity or sample_sev)

    problems = validate_decision(disp.value, justification, expires_at, actor, approver)
    if problems:
        raise PolicyError(problems)

    is_risk_decision = disp in RISK_DECISION_DISPOSITIONS
    state = (AdjudicationState.PENDING_APPROVAL.value if is_risk_decision
             else AdjudicationState.APPROVED.value)

    created: list[Adjudication] = []
    for plan in plans:
        adj = Adjudication(
            scope_type=plan.scope_type,
            scope_key=plan.scope_key,
            scope_label=plan.scope_label,
            scope_filter=scope_filter,
            disposition=disp.value,
            state=state,
            justification=justification.strip(),
            compensating_controls=compensating_controls,
            adjusted_severity=adjusted_severity,
            adjusted_priority=adjusted_priority,
            assigned_to=assigned_to,
            remediation_due=remediation_due,
            requested_by=actor,
            approver=approver,
            review_due=review_due,
            expires_at=expires_at,
        )
        # Routing decisions take effect immediately; record who set them.
        if not is_risk_decision:
            adj.approved_by = actor
            adj.decided_at = utcnow()
        db.add(adj)
        db.flush()

        for fid in plan.finding_ids:
            db.add(AdjudicationApplication(adjudication_id=adj.id, finding_id=fid))

        db.add(AuditEvent(
            actor=actor, action="adjudication.create",
            entity_type="adjudication", entity_id=str(adj.id),
            summary=(f"{disp.value} on {plan.scope_label} "
                     f"({len(plan.finding_ids)} findings selected) -> {state}"),
            detail={
                "scope_type": plan.scope_type, "scope_key": plan.scope_key,
                "finding_ids": plan.finding_ids[:2000],
                "selected_count": len(plan.finding_ids),
                "coverage": plan.coverage_note,
                "expires_at": expires_at.isoformat() if expires_at else None,
                "approver": approver, "filter": scope_filter,
            },
        ))
        created.append(adj)

    db.commit()
    invalidate_cache()
    return created


def decide(db, adjudication_id: int, approve: bool, actor: str,
           note: str | None = None) -> Adjudication:
    adj = db.get(Adjudication, adjudication_id)
    if adj is None:
        raise PolicyError(["No such decision."])
    if adj.state != AdjudicationState.PENDING_APPROVAL.value:
        raise PolicyError([f"This decision is {adj.state}, not awaiting approval."])
    if actor not in settings.approvers:
        raise PolicyError([f"{actor} is not on the approver roster."])
    if settings.policy.require_separate_approver and actor == adj.requested_by:
        raise PolicyError(["The approver must be someone other than the requester."])

    adj.state = (AdjudicationState.APPROVED.value if approve
                 else AdjudicationState.REJECTED.value)
    adj.approved_by = actor
    adj.decided_at = utcnow()
    adj.decision_note = note

    db.add(AuditEvent(
        actor=actor, action="adjudication.approve" if approve else "adjudication.reject",
        entity_type="adjudication", entity_id=str(adj.id),
        summary=f"{'Approved' if approve else 'Rejected'} {adj.disposition} on {adj.scope_label}",
        detail={"note": note, "requested_by": adj.requested_by,
                "expires_at": adj.expires_at.isoformat() if adj.expires_at else None},
    ))

    if approve and adj.supersedes_id:
        prev = db.get(Adjudication, adj.supersedes_id)
        if prev is not None and prev.state == AdjudicationState.APPROVED.value:
            prev.state = AdjudicationState.EXPIRED.value
            db.add(AuditEvent(
                actor=actor, action="adjudication.superseded",
                entity_type="adjudication", entity_id=str(prev.id),
                summary=f"Superseded by renewal #{adj.id} on {prev.scope_label}",
                detail={"renewal_id": adj.id},
            ))
    db.commit()
    invalidate_cache()
    return adj


def revoke(db, adjudication_id: int, actor: str, reason: str) -> Adjudication:
    adj = db.get(Adjudication, adjudication_id)
    if adj is None:
        raise PolicyError(["No such decision."])
    if adj.state not in (AdjudicationState.APPROVED.value,
                         AdjudicationState.PENDING_APPROVAL.value):
        raise PolicyError([f"This decision is {adj.state}; only live or pending decisions can be revoked."])
    if len((reason or "").strip()) < 10:
        raise PolicyError(["Give a reason for revoking."])
    adj.state = AdjudicationState.REVOKED.value
    adj.decision_note = ((adj.decision_note or "") + f"\nRevoked by {actor}: {reason}").strip()
    db.add(AuditEvent(
        actor=actor, action="adjudication.revoke",
        entity_type="adjudication", entity_id=str(adj.id),
        summary=f"Revoked {adj.disposition} on {adj.scope_label}",
        detail={"reason": reason},
    ))
    db.commit()
    invalidate_cache()
    return adj


def renew(db, adjudication_id: int, actor: str, justification: str,
          expires_at: dt.datetime, approver: str | None) -> Adjudication:
    """Re-argue an expiring decision. Creates a fresh record rather than
    editing the old one, so the history of what was accepted when survives.
    The old decision stays in force until the renewal is approved."""
    old = db.get(Adjudication, adjudication_id)
    if old is None:
        raise PolicyError(["No such decision."])
    if old.state not in (AdjudicationState.APPROVED.value, AdjudicationState.EXPIRED.value):
        raise PolicyError([f"This decision is {old.state}; only approved or expired decisions can be renewed."])
    already = db.execute(
        select(Adjudication.id).where(
            Adjudication.supersedes_id == old.id,
            Adjudication.state == AdjudicationState.PENDING_APPROVAL.value)
    ).scalar()
    if already:
        raise PolicyError([f"Renewal #{already} is already awaiting approval."])

    problems = validate_decision(old.disposition, justification, expires_at, actor, approver)
    if problems:
        raise PolicyError(problems)

    finding_ids = [a.finding_id for a in old.applications]
    new = Adjudication(
        scope_type=old.scope_type, scope_key=old.scope_key, scope_label=old.scope_label,
        scope_filter=old.scope_filter, disposition=old.disposition,
        state=AdjudicationState.PENDING_APPROVAL.value,
        justification=justification.strip(),
        compensating_controls=old.compensating_controls,
        adjusted_severity=old.adjusted_severity, adjusted_priority=old.adjusted_priority,
        assigned_to=old.assigned_to, remediation_due=old.remediation_due,
        requested_by=actor, approver=approver,
        expires_at=expires_at,
        review_due=default_review_due(
            old.adjusted_severity or (_dominant_severity(db, finding_ids) if finding_ids else "high")),
        supersedes_id=old.id,
    )
    db.add(new)
    db.flush()
    for fid in finding_ids:
        db.add(AdjudicationApplication(adjudication_id=new.id, finding_id=fid))
    db.add(AuditEvent(
        actor=actor, action="adjudication.renew",
        entity_type="adjudication", entity_id=str(new.id),
        summary=f"Renewal of #{old.id} requested for {old.scope_label}",
        detail={"previous_id": old.id, "expires_at": expires_at.isoformat()},
    ))
    db.commit()
    invalidate_cache()
    return new


def expire_lapsed(db, actor: str = "system") -> int:
    """Move approved decisions past their expiry into `expired`.

    Risk returns to the finding automatically when this runs, which is the
    point: an acceptance nobody renewed should stop suppressing the finding.
    """
    now = utcnow()
    rows = db.execute(
        select(Adjudication).where(
            Adjudication.state == AdjudicationState.APPROVED.value,
            Adjudication.expires_at.isnot(None),
            Adjudication.expires_at < now,
        )
    ).scalars().all()
    for adj in rows:
        adj.state = AdjudicationState.EXPIRED.value
        db.add(AuditEvent(
            actor=actor, action="adjudication.expire",
            entity_type="adjudication", entity_id=str(adj.id),
            summary=f"{adj.disposition} on {adj.scope_label} lapsed; risk is live again",
            detail={"expired_at": adj.expires_at.isoformat()},
        ))
    if rows:
        db.commit()
        invalidate_cache()
    return len(rows)


def _dominant_severity(db, finding_ids: list[int]) -> str:
    from .enums import Severity
    rows = db.execute(
        select(Finding.severity).where(Finding.id.in_(finding_ids[:5000]))
    ).scalars().all()
    if not rows:
        return "medium"
    return max(rows, key=lambda s: Severity(s).rank if s in Severity._value2member_map_ else 0)
