"""Routine-fix auto-tagging.

An OS patch that is still inside its severity SLA is routine work: it
belongs in the normal monthly patching pipeline, not in anyone's
adjudication queue. This module labels those findings with a
`routine_fix` adjudication so they fall out of the "undecided" bucket
without hiding them.

The tag:
  * Is scoped to the individual finding (per-host patches).
  * Carries an expiry set to the SLA due date, so if the fix never
    lands, the tag lapses and the finding reappears as undecided for
    someone to act on.
  * Is left in place once applied even if the finding slips past SLA
    (the `expire_lapsed` sweep will retire it as normal).
  * Only attaches to findings that have no other scoped decision.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import select

from .enums import AdjudicationState, Disposition, FindingCategory, ScopeType
from .models import (
    Adjudication, AdjudicationApplication, AuditEvent, Finding, Vuln, utcnow,
)
from .queries import build_resolution_map
from .risk import sla_status


AUTO_ACTOR = "system:routine-fix"


def _findings_under_scope(db, scope_type: str, scope_key: str) -> list[int]:
    """Return every finding_id that falls under a scope key, used to retire
    the broadest possible set of routine_fix tags when a human decision at
    a coarser scope lands."""
    from .enums import ScopeType
    if scope_type == ScopeType.FINDING.value:
        try:
            return [int(scope_key)]
        except ValueError:
            return []
    if scope_type == ScopeType.VULN.value:
        return list(db.execute(
            select(Finding.id).join(Vuln, Finding.vuln_id == Vuln.id)
            .where(Vuln.canonical_id == scope_key)
        ).scalars())
    if scope_type == ScopeType.VULN_ON_ASSET.value:
        try:
            canonical, asset_id = scope_key.split("::", 1)
            asset_id_i = int(asset_id)
        except ValueError:
            return []
        return list(db.execute(
            select(Finding.id).join(Vuln, Finding.vuln_id == Vuln.id)
            .where(Vuln.canonical_id == canonical, Finding.asset_id == asset_id_i)
        ).scalars())
    if scope_type == ScopeType.COMPONENT.value:
        return list(db.execute(
            select(Finding.id).where(Finding.component_key == scope_key)
        ).scalars())
    return []


def retire_for_scope(db, scope_type: str, scope_key: str, actor: str = AUTO_ACTOR) -> int:
    """Retire routine_fix tags on every finding under a given scope."""
    return retire_for_findings(db, _findings_under_scope(db, scope_type, scope_key), actor)


def retire_for_findings(db, finding_ids: list[int], actor: str = AUTO_ACTOR) -> int:
    """Expire any still-approved auto routine_fix adjudications attached to
    these findings. Call this whenever a human decision supersedes the
    auto tag, so the human's decision becomes the governing resolution.

    Does not commit; caller owns the transaction.
    """
    if not finding_ids:
        return 0
    rows = db.execute(
        select(Adjudication).join(AdjudicationApplication,
                                   AdjudicationApplication.adjudication_id == Adjudication.id)
        .where(Adjudication.state == AdjudicationState.APPROVED.value,
               Adjudication.disposition == Disposition.ROUTINE_FIX.value,
               Adjudication.requested_by == AUTO_ACTOR,
               AdjudicationApplication.finding_id.in_(finding_ids))
    ).unique().scalars().all()
    for adj in rows:
        adj.state = AdjudicationState.EXPIRED.value
        db.add(AuditEvent(
            actor=actor, action="adjudication.routine_fix_superseded",
            entity_type="adjudication", entity_id=str(adj.id),
            summary=f"Auto routine-fix on {adj.scope_label} retired; a human decision now applies",
            detail={"superseded_by_actor": actor},
        ))
    return len(rows)
AUTO_JUSTIFICATION = (
    "Automatically tagged: this OS finding is still inside its severity SLA, "
    "so it belongs in the standard patching cadence. If this needs faster "
    "handling, replace the tag with an explicit decision."
)


def auto_tag_routine_fixes(db, now: dt.datetime | None = None) -> int:
    """Attach a routine_fix adjudication to every un-adjudicated OS finding
    that is still within its SLA. Returns the number tagged.

    Safe to call repeatedly: findings that already carry any approved
    scoped decision are skipped, and ones that are overdue are left
    alone so their lateness stays visible.
    """
    now = now or utcnow()
    resolution = build_resolution_map(db, now)

    rows = db.execute(
        select(Finding.id, Finding.severity, Finding.first_detected, Vuln.kev)
        .join(Vuln, Finding.vuln_id == Vuln.id)
        .where(Finding.category == FindingCategory.OS_VULN.value,
               Finding.status == "open")
    ).all()

    tagged = 0
    for fid, sev, first_detected, kev in rows:
        if fid in resolution:
            continue
        due, overdue = sla_status(first_detected, sev, bool(kev), None, now)
        if overdue or due is None:
            continue

        adj = Adjudication(
            scope_type=ScopeType.FINDING.value,
            scope_key=str(fid),
            scope_label=f"Routine patch for finding #{fid}",
            disposition=Disposition.ROUTINE_FIX.value,
            state=AdjudicationState.APPROVED.value,
            justification=AUTO_JUSTIFICATION,
            requested_by=AUTO_ACTOR,
            approver=None,
            approved_by=AUTO_ACTOR,
            decided_at=now,
            expires_at=due,
        )
        db.add(adj)
        db.flush()
        db.add(AdjudicationApplication(adjudication_id=adj.id, finding_id=fid))
        db.add(AuditEvent(
            actor=AUTO_ACTOR, action="adjudication.auto_routine_fix",
            entity_type="adjudication", entity_id=str(adj.id),
            summary=f"Auto-tagged finding #{fid} as routine fix (SLA due {due.isoformat()})",
            detail={"finding_id": fid, "severity": sev, "sla_due": due.isoformat()},
        ))
        tagged += 1

    if tagged:
        db.commit()
        from .cache import invalidate_all
        invalidate_all()
        from .rollup import mark_stale
        mark_stale(db)
    return tagged
