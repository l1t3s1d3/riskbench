"""Bulk-review helpers for decision-makers.

Three patterns the UI drives from this module:

  1. Smart bundles — groups of undecided (bucket 0) findings that share
     a scope key the team has decided on before. Each bundle carries a
     suggested disposition (pulled from the most recent approved
     decision at that scope) so a reviewer can apply the same call to
     the fresh batch with one action.

  2. Suggestion for a single scope — given a candidate scope (vuln,
     vuln_on_asset, or component), return the latest approved decision
     against it, if any, so the "create decision" form can pre-fill.

  3. Oldest-first intake queue — bucket-0 findings ordered by age,
     grouped by owner, for a reviewer who wants to drive intake to
     zero without hunting for stragglers.
"""
from __future__ import annotations

import datetime as dt
from collections import defaultdict
from typing import Optional

from sqlalchemy import func, select

from .buckets import bucket_for_finding
from .enums import AdjudicationState, Disposition, ScopeType
from .models import Adjudication, Asset, Finding, Vuln
from .queries import build_resolution_map


def suggest_for_scope(db, scope_type: str, scope_key: str) -> Optional[dict]:
    """Return the most recent approved decision at this scope, as a
    serializable hint for pre-filling a decision form."""
    stmt = (
        select(Adjudication)
        .where(Adjudication.scope_type == scope_type,
               Adjudication.scope_key == scope_key,
               Adjudication.state == AdjudicationState.APPROVED.value)
        .order_by(Adjudication.decided_at.desc().nulls_last())
        .limit(1)
    )
    adj = db.execute(stmt).scalars().first()
    if adj is None:
        return None
    return {
        "disposition": adj.disposition,
        "justification": adj.justification,
        "compensating_controls": adj.compensating_controls,
        "adjusted_severity": adj.adjusted_severity,
        "approver": adj.approver,
        "decided_at": adj.decided_at.isoformat() if adj.decided_at else None,
        "requested_by": adj.requested_by,
    }


def smart_bundles(db, limit: int = 20, now: dt.datetime | None = None) -> list[dict]:
    """Bucket-0 findings grouped by a shared scope key the team has
    already decided on. Each bundle is actionable in one click.

    Groups by vuln (CVE) first because that's the broadest reach, then
    component, then no prior decision. Each bundle carries the suggested
    disposition the team used last time.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    resolution = build_resolution_map(db, now)

    # Load only bucket-0 open findings so we don't bundle items that are
    # already in a decided bucket.
    rows = db.execute(
        select(Finding.id, Finding.component_key, Finding.severity,
               Vuln.canonical_id, Asset.owner, Asset.name)
        .join(Vuln, Finding.vuln_id == Vuln.id)
        .join(Asset, Finding.asset_id == Asset.id)
        .where(Finding.status == "open")
    ).all()

    undecided = [r for r in rows if r[0] not in resolution]
    if not undecided:
        return []

    # Group twice: by canonical_id (vuln scope), by component_key (component scope).
    by_vuln: dict[str, list] = defaultdict(list)
    by_component: dict[str, list] = defaultdict(list)
    for fid, ckey, sev, canonical, owner, asset in undecided:
        if canonical:
            by_vuln[canonical].append((fid, sev, owner, asset))
        if ckey:
            by_component[ckey].append((fid, sev, owner, asset))

    bundles: list[dict] = []
    for canonical, items in by_vuln.items():
        if len(items) < 2:
            continue
        hint = suggest_for_scope(db, ScopeType.VULN.value, canonical)
        if hint is None:
            continue
        bundles.append(_bundle(items, ScopeType.VULN.value, canonical,
                                canonical, hint, "prior vuln decision"))

    seen_fids = {fid for b in bundles for fid in b["finding_ids"]}

    for ckey, items in by_component.items():
        pending = [i for i in items if i[0] not in seen_fids]
        if len(pending) < 2:
            continue
        hint = suggest_for_scope(db, ScopeType.COMPONENT.value, ckey)
        if hint is None:
            continue
        bundles.append(_bundle(pending, ScopeType.COMPONENT.value, ckey,
                                ckey, hint, "prior component decision"))
        seen_fids.update(i[0] for i in pending)

    bundles.sort(key=lambda b: b["count"], reverse=True)
    return bundles[:limit]


def _bundle(items, scope_type, scope_key, label, hint, basis) -> dict:
    severities: dict[str, int] = {}
    owners: dict[str, int] = {}
    for fid, sev, owner, asset in items:
        severities[sev] = severities.get(sev, 0) + 1
        if owner:
            owners[owner] = owners.get(owner, 0) + 1
    return {
        "scope_type": scope_type,
        "scope_key": scope_key,
        "label": label,
        "basis": basis,
        "count": len(items),
        "finding_ids": [i[0] for i in items],
        "severities": severities,
        "owners": owners,
        "suggested": hint,
    }


def intake_queue(db, limit: int = 100, now: dt.datetime | None = None) -> dict:
    """Bucket-0 findings ordered by age (oldest first), grouped by owner.

    Returned as:
      {"by_owner": [{"owner": str, "count": int, "findings": [...]}, ...],
       "total": int, "oldest_age_days": float}
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    resolution = build_resolution_map(db, now)
    rows = db.execute(
        select(Finding.id, Finding.severity, Finding.first_detected,
               Vuln.canonical_id, Asset.owner, Asset.name, Vuln.kev)
        .join(Vuln, Finding.vuln_id == Vuln.id)
        .join(Asset, Finding.asset_id == Asset.id)
        .where(Finding.status == "open")
        .order_by(Finding.first_detected.asc())
    ).all()

    by_owner: dict[str, list[dict]] = defaultdict(list)
    total = 0
    oldest = 0.0
    for fid, sev, first_detected, canonical, owner, asset, kev in rows:
        if fid in resolution:
            continue
        total += 1
        age = _age_days(first_detected, now)
        oldest = max(oldest, age)
        by_owner[owner or "(unassigned)"].append({
            "finding_id": fid, "severity": sev, "cve": canonical,
            "asset": asset, "age_days": round(age, 1), "kev": bool(kev),
        })
    owner_list = [
        {"owner": o, "count": len(items), "findings": items[:limit]}
        for o, items in sorted(by_owner.items(), key=lambda kv: -len(kv[1]))
    ]
    return {"by_owner": owner_list, "total": total, "oldest_age_days": round(oldest, 1)}


def _age_days(anchor: dt.datetime | None, now: dt.datetime) -> float:
    if anchor is None:
        return 0.0
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=dt.timezone.utc)
    return max(0.0, (now - anchor).total_seconds() / 86400.0)
