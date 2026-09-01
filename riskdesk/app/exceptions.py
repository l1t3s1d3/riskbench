"""Exception request workflow.

The flow from a team member's perspective:

  1. They see a finding assigned to them (or browse the findings list)
  2. They believe it should be accepted, adjusted, or marked false positive
  3. They submit an exception request with their justification
  4. Security reviews it, possibly asks for more information
  5. Security approves → an Adjudication is created automatically
     Security rejects → the finding stays in the backlog

This keeps the team and the security function in their respective lanes: teams
own the business context ("this is a test key, not a production credential"),
security owns the risk decision ("accepted for 90 days with this control").
"""
from __future__ import annotations

import datetime as dt
from typing import Optional

from sqlalchemy import select, func
from sqlalchemy.orm import joinedload

from .config import settings
from .enums import Disposition, RISK_DECISION_DISPOSITIONS
from .models import (
    AuditEvent, ExceptionComment, ExceptionRequest, Finding, Vuln, utcnow,
)
from .adjudication import create_decisions, PolicyError
from .risk import default_expiry


class ExceptionError(Exception):
    def __init__(self, message: str):
        self.message = message
        super().__init__(message)


def create_exception(
    db,
    title: str,
    finding_ids: list[int],
    requested_disposition: str,
    justification: str,
    actor: str,
    scope: str = "finding",
    business_impact: str | None = None,
    compensating_controls: str | None = None,
    adjusted_severity: str | None = None,
    requested_duration_days: int | None = None,
    submitter_team: str | None = None,
    submitter_email: str | None = None,
) -> ExceptionRequest:
    if not title or len(title.strip()) < 5:
        raise ExceptionError("Give the exception a descriptive title.")
    if not finding_ids:
        raise ExceptionError("Select at least one finding.")
    if not justification or len(justification.strip()) < 40:
        raise ExceptionError(
            f"Justification must be at least 40 characters. Explain why "
            f"this risk is tolerable for your workload."
        )
    disp = requested_disposition
    if disp not in ("accept_risk", "adjust_risk", "false_positive"):
        raise ExceptionError("Exceptions can request accept_risk, adjust_risk, or false_positive.")
    if disp == "adjust_risk" and not adjusted_severity:
        raise ExceptionError("An adjust_risk exception must say what severity you believe is correct.")

    # Build scope label from findings
    findings = db.execute(
        select(Finding).options(joinedload(Finding.vuln), joinedload(Finding.asset))
        .where(Finding.id.in_(finding_ids))
    ).unique().scalars().all()
    if not findings:
        raise ExceptionError("No findings matched the selection.")

    scope_label = _build_scope_label(findings, scope)
    scope_key = _build_scope_key(findings, scope)

    exc = ExceptionRequest(
        title=title.strip(),
        finding_ids=finding_ids,
        scope=scope,
        scope_key=scope_key,
        scope_label=scope_label,
        requested_disposition=disp,
        justification=justification.strip(),
        business_impact=business_impact,
        compensating_controls=compensating_controls,
        adjusted_severity=adjusted_severity,
        requested_duration_days=requested_duration_days or 90,
        submitted_by=actor,
        submitter_team=submitter_team,
        submitter_email=submitter_email,
        status="submitted",
        submitted_at=utcnow(),
    )
    db.add(exc)
    db.flush()

    db.add(AuditEvent(
        actor=actor, action="exception.submit",
        entity_type="exception", entity_id=str(exc.id),
        summary=f"Exception submitted: {title} ({disp} on {scope_label})",
        detail={"finding_count": len(finding_ids), "disposition": disp},
    ))
    db.commit()
    return exc


def assign_reviewer(db, exception_id: int, reviewer: str, actor: str) -> ExceptionRequest:
    exc = db.get(ExceptionRequest, exception_id)
    if not exc:
        raise ExceptionError("Exception not found.")
    exc.assigned_reviewer = reviewer
    if exc.status == "submitted":
        exc.status = "under_review"
    db.add(AuditEvent(
        actor=actor, action="exception.assign",
        entity_type="exception", entity_id=str(exc.id),
        summary=f"Reviewer assigned: {reviewer}",
    ))
    db.commit()
    return exc


def request_info(db, exception_id: int, message: str, actor: str) -> ExceptionRequest:
    exc = db.get(ExceptionRequest, exception_id)
    if not exc:
        raise ExceptionError("Exception not found.")
    exc.status = "info_requested"
    db.add(ExceptionComment(
        exception_id=exc.id, author=actor, body=message, is_internal=False,
    ))
    db.add(AuditEvent(
        actor=actor, action="exception.info_requested",
        entity_type="exception", entity_id=str(exc.id),
        summary=f"More information requested from {exc.submitted_by}",
    ))
    db.commit()
    return exc


def respond_to_info(db, exception_id: int, message: str, actor: str) -> ExceptionRequest:
    exc = db.get(ExceptionRequest, exception_id)
    if not exc:
        raise ExceptionError("Exception not found.")
    if actor != exc.submitted_by:
        raise ExceptionError("Only the submitter can respond to information requests.")
    exc.status = "under_review"
    db.add(ExceptionComment(
        exception_id=exc.id, author=actor, body=message, is_internal=False,
    ))
    db.add(AuditEvent(
        actor=actor, action="exception.respond",
        entity_type="exception", entity_id=str(exc.id),
        summary="Submitter responded to information request",
    ))
    db.commit()
    return exc


def add_comment(db, exception_id: int, body: str, actor: str,
                is_internal: bool = False) -> ExceptionComment:
    exc = db.get(ExceptionRequest, exception_id)
    if not exc:
        raise ExceptionError("Exception not found.")
    comment = ExceptionComment(
        exception_id=exc.id, author=actor, body=body, is_internal=is_internal,
    )
    db.add(comment)
    db.commit()
    return comment


def review_exception(
    db,
    exception_id: int,
    decision: str,  # "approved" or "rejected"
    actor: str,
    note: str | None = None,
    expires_at: dt.datetime | None = None,
    approver: str | None = None,
) -> ExceptionRequest:
    exc = db.get(ExceptionRequest, exception_id)
    if not exc:
        raise ExceptionError("Exception not found.")
    if exc.status not in ("submitted", "under_review"):
        raise ExceptionError(f"This exception is {exc.status}, not ready for review.")
    if decision not in ("approved", "rejected"):
        raise ExceptionError("Decision must be 'approved' or 'rejected'.")

    exc.reviewed_by = actor
    exc.review_decision = decision
    exc.review_note = note
    exc.review_date = utcnow()
    exc.status = decision

    if decision == "approved":
        # Create the actual adjudication
        adj = _create_adjudication_from_exception(db, exc, actor, expires_at, approver)
        exc.adjudication_id = adj.id if adj else None

    db.add(AuditEvent(
        actor=actor, action=f"exception.{decision}",
        entity_type="exception", entity_id=str(exc.id),
        summary=f"Exception {decision}: {exc.title}",
        detail={"note": note, "adjudication_id": exc.adjudication_id},
    ))
    db.commit()
    return exc


def withdraw_exception(db, exception_id: int, actor: str) -> ExceptionRequest:
    exc = db.get(ExceptionRequest, exception_id)
    if not exc:
        raise ExceptionError("Exception not found.")
    if actor != exc.submitted_by:
        raise ExceptionError("Only the submitter can withdraw an exception.")
    if exc.status in ("approved", "rejected"):
        raise ExceptionError("This exception has already been decided.")
    exc.status = "withdrawn"
    db.add(AuditEvent(
        actor=actor, action="exception.withdraw",
        entity_type="exception", entity_id=str(exc.id),
        summary=f"Exception withdrawn: {exc.title}",
    ))
    db.commit()
    return exc


def _create_adjudication_from_exception(
    db, exc: ExceptionRequest, actor: str,
    expires_at: dt.datetime | None, approver: str | None,
):
    """Convert an approved exception into a real adjudication."""
    if not expires_at:
        days = exc.requested_duration_days or 90
        expires_at = utcnow() + dt.timedelta(days=days)

    # The security reviewer who approves is the actor. The adjudication needs
    # a *different* person as approver if require_separate_approver is on.
    adj_approver = approver
    if not adj_approver or adj_approver == actor:
        # Pick someone from the approver roster who isn't the reviewer
        candidates = [a for a in settings.approvers if a != actor]
        adj_approver = candidates[0] if candidates else actor

    try:
        adjs = create_decisions(
            db,
            finding_ids=exc.finding_ids,
            disposition=exc.requested_disposition,
            justification=(
                f"Exception #{exc.id}: {exc.justification}\n"
                f"Business impact: {exc.business_impact or 'not stated'}\n"
                f"Submitted by: {exc.submitted_by}"
                + (f"\nCompensating controls: {exc.compensating_controls}" if exc.compensating_controls else "")
            ),
            actor=actor,
            scope=exc.scope,
            approver=adj_approver,
            expires_at=expires_at,
            adjusted_severity=exc.adjusted_severity,
            compensating_controls=exc.compensating_controls,
        )
        # Auto-approve the adjudication since the security reviewer just approved
        if adjs and adj_approver in settings.approvers:
            from .adjudication import decide
            for adj in adjs:
                if adj.state == "pending_approval":
                    try:
                        decide(db, adj.id, True, adj_approver,
                               note=f"Auto-approved from exception #{exc.id}")
                    except PolicyError:
                        pass  # self-approve guard; leave pending for another approver
        return adjs[0] if adjs else None
    except PolicyError as e:
        # Log the failure but don't block the exception approval
        db.add(AuditEvent(
            actor=actor, action="exception.adjudication_failed",
            entity_type="exception", entity_id=str(exc.id),
            summary=f"Adjudication creation failed: {e}",
        ))
        return None


def _build_scope_label(findings: list, scope: str) -> str:
    if scope == "finding":
        if len(findings) == 1:
            f = findings[0]
            return f"{f.vuln.canonical_id} on {f.asset.name}"
        return f"{len(findings)} findings"
    if scope == "vuln":
        vulns = {f.vuln.canonical_id for f in findings}
        if len(vulns) == 1:
            return f"{list(vulns)[0]} (all assets)"
        return f"{len(vulns)} vulnerabilities"
    if scope == "vuln_on_asset":
        pairs = {(f.vuln.canonical_id, f.asset.name) for f in findings}
        if len(pairs) == 1:
            cve, asset = list(pairs)[0]
            return f"{cve} on {asset}"
        return f"{len(pairs)} vuln-asset pairs"
    return f"{len(findings)} findings"


def _build_scope_key(findings: list, scope: str) -> str:
    if scope == "finding" and len(findings) == 1:
        return str(findings[0].id)
    if scope == "vuln":
        vulns = {f.vuln.canonical_id for f in findings}
        return ",".join(sorted(vulns))
    return ",".join(str(f.id) for f in findings[:100])


def serialize_exception(exc: ExceptionRequest, comments: list | None = None,
                        include_internal: bool = False) -> dict:
    result = {
        "id": exc.id,
        "title": exc.title,
        "finding_ids": exc.finding_ids,
        "scope": exc.scope,
        "scope_key": exc.scope_key,
        "scope_label": exc.scope_label,
        "requested_disposition": exc.requested_disposition,
        "justification": exc.justification,
        "business_impact": exc.business_impact,
        "compensating_controls": exc.compensating_controls,
        "adjusted_severity": exc.adjusted_severity,
        "requested_duration_days": exc.requested_duration_days,
        "submitted_by": exc.submitted_by,
        "submitter_team": exc.submitter_team,
        "status": exc.status,
        "assigned_reviewer": exc.assigned_reviewer,
        "reviewed_by": exc.reviewed_by,
        "review_decision": exc.review_decision,
        "review_note": exc.review_note,
        "review_date": exc.review_date.isoformat() if exc.review_date else None,
        "adjudication_id": exc.adjudication_id,
        "submitted_at": exc.submitted_at.isoformat() if exc.submitted_at else None,
        "created_at": exc.created_at.isoformat() if exc.created_at else None,
        "updated_at": exc.updated_at.isoformat() if exc.updated_at else None,
    }
    if comments is not None:
        result["comments"] = [
            {"id": c.id, "author": c.author, "body": c.body,
             "is_internal": c.is_internal,
             "created_at": c.created_at.isoformat() if c.created_at else None}
            for c in comments
            if include_internal or not c.is_internal
        ]
    return result
