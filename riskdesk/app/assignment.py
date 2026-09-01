"""Assignment engine.

Evaluates assignment rules against findings and routes work automatically.

Rules fire in priority order (lowest number first). Each finding matches at
most one rule -- first match wins. When a rule fires it can:

  1. Set `assigned_to` on the finding (always).
  2. Create a routing adjudication (fix_immediately, complex_resolution, or
     developer_review) so the assignment appears in the register alongside
     risk decisions rather than being invisible metadata.

The engine is called after every sync, and can also be re-run manually against
existing findings.

Assignment rules are routing, not risk, decisions. They take effect immediately
and do NOT go through the approval gate. If a finding already has an active
adjudication (risk decision), the assignment rule does not overwrite it --
risk decisions outrank routing.
"""
from __future__ import annotations

import datetime as dt
import logging
from typing import Optional

from sqlalchemy import select, and_
from sqlalchemy.orm import joinedload

from .config import settings
from .enums import ROUTING_DISPOSITIONS, Disposition
from .models import (
    AssignmentRule, Asset, AuditEvent, Finding, Vuln, utcnow,
)

log = logging.getLogger(__name__)


def evaluate_rules(db, source: str | None = None,
                   finding_ids: list[int] | None = None,
                   actor: str = "system",
                   dry_run: bool = False) -> dict:
    """Run assignment rules against findings.

    Args:
        source: limit to findings from this source (typical after a sync)
        finding_ids: limit to specific findings (manual re-evaluation)
        dry_run: return what would happen without writing anything

    Returns a summary dict.
    """
    rules = db.execute(
        select(AssignmentRule)
        .where(AssignmentRule.enabled.is_(True))
        .order_by(AssignmentRule.priority.asc())
    ).scalars().all()

    if not rules:
        return {"evaluated": 0, "matched": 0, "assigned": 0, "skipped_existing": 0,
                "rules_fired": {}, "dry_run": dry_run}

    # Load findings to evaluate
    stmt = (
        select(Finding)
        .options(joinedload(Finding.asset), joinedload(Finding.vuln))
        .where(Finding.status == "open")
    )
    if source:
        stmt = stmt.where(Finding.source == source)
    if finding_ids:
        stmt = stmt.where(Finding.id.in_(finding_ids))

    findings = db.execute(stmt).unique().scalars().all()

    # Load existing active adjudications to avoid overwriting risk decisions
    from .queries import build_resolution_map
    resolution = build_resolution_map(db)

    stats = {"evaluated": len(findings), "matched": 0, "assigned": 0,
             "skipped_existing": 0, "rules_fired": {}, "dry_run": dry_run,
             "assignments": []}

    for f in findings:
        existing = resolution.get(f.id)
        # Risk decisions (accept, adjust, false positive) outrank assignment rules
        if existing and existing.disposition not in (
            d.value for d in ROUTING_DISPOSITIONS
        ):
            stats["skipped_existing"] += 1
            continue

        matched_rule = _match(f, rules)
        if matched_rule is None:
            continue

        stats["matched"] += 1
        rule_name = matched_rule.name
        stats["rules_fired"][rule_name] = stats["rules_fired"].get(rule_name, 0) + 1

        if dry_run:
            stats["assignments"].append({
                "finding_id": f.id,
                "vuln": f.vuln.canonical_id if f.vuln else None,
                "asset": f.asset.name if f.asset else None,
                "rule": rule_name,
                "assign_to": matched_rule.assign_to,
            })
            continue

        _apply_rule(db, f, matched_rule, actor, existing)
        stats["assigned"] += 1

    if not dry_run and stats["assigned"] > 0:
        db.add(AuditEvent(
            actor=actor, action="assignment.run",
            entity_type="source", entity_id=source or "manual",
            summary=(f"Auto-assignment: {stats['assigned']} findings assigned "
                     f"across {len(stats['rules_fired'])} rules"),
            detail={k: v for k, v in stats.items() if k != "assignments"},
        ))
        db.commit()

    return stats


def _match(finding: Finding, rules: list[AssignmentRule]) -> AssignmentRule | None:
    """First matching rule wins."""
    for rule in rules:
        if _rule_matches(finding, rule):
            return rule
    return None


def _rule_matches(f: Finding, r: AssignmentRule) -> bool:
    """Every non-null criterion must match (AND logic)."""
    if r.source and f.source != r.source:
        return False
    if r.severity:
        allowed = {s.strip().lower() for s in r.severity.split(",")}
        if f.severity not in allowed:
            return False
    if r.category:
        allowed = {c.strip().lower() for c in r.category.split(",")}
        if f.category not in allowed:
            return False
    if r.asset_pattern:
        if not _like(f.asset.name if f.asset else "", r.asset_pattern):
            return False
    if r.component_pattern:
        if not _like(f.component or "", r.component_pattern):
            return False
    if r.environment:
        asset_env = (f.asset.environment if f.asset else None) or "unknown"
        if asset_env != r.environment:
            return False
    if r.kev_only:
        if not (f.vuln and f.vuln.kev):
            return False
    if r.fix_available_only:
        if not f.fix_available:
            return False
    return True


def _like(value: str, pattern: str) -> bool:
    """Python equivalent of SQL LIKE with % wildcards, case-insensitive."""
    import re
    val = value.lower()
    pat = pattern.lower()
    # Escape regex special chars except %, then convert % to .*
    regex = ""
    for ch in pat:
        if ch == "%":
            regex += ".*"
        elif ch in r"\.^$+?{}[]|()":
            regex += "\\" + ch
        else:
            regex += ch
    return bool(re.fullmatch(regex, val))


def _apply_rule(db, finding: Finding, rule: AssignmentRule,
                actor: str, existing_adj) -> None:
    """Set assigned_to on the finding and optionally create a routing decision."""
    from .adjudication import create_decisions, PolicyError

    # If there is already a routing decision from a *different* rule or manual
    # action, don't pile on -- just update the assignment field.
    finding.assigned_to_rule = rule.id if hasattr(finding, 'assigned_to_rule') else None

    # Create a routing decision so it shows in the register
    disp = rule.disposition or Disposition.FIX_IMMEDIATELY.value
    if disp not in (d.value for d in ROUTING_DISPOSITIONS):
        disp = Disposition.FIX_IMMEDIATELY.value

    justification = rule.justification_template or (
        f"Auto-assigned by rule '{rule.name}': {rule.description or 'criteria match'}"
    )

    due = None
    if rule.remediation_days:
        base = finding.first_detected or utcnow()
        if base.tzinfo is None:
            base = base.replace(tzinfo=dt.timezone.utc)
        due = base + dt.timedelta(days=rule.remediation_days)

    try:
        create_decisions(
            db,
            finding_ids=[finding.id],
            disposition=disp,
            justification=justification,
            actor=actor,
            scope="finding",
            assigned_to=rule.assign_to,
            remediation_due=due,
        )
    except PolicyError:
        # Routing decisions shouldn't fail policy, but if they do, still set
        # the assignment on the finding itself.
        pass


def preview_rules(db, rule_id: int | None = None) -> dict:
    """Show what each rule would match right now, without changing anything."""
    rules = db.execute(
        select(AssignmentRule)
        .where(AssignmentRule.enabled.is_(True))
        .order_by(AssignmentRule.priority.asc())
    ).scalars().all()
    if rule_id:
        rules = [r for r in rules if r.id == rule_id]

    findings = db.execute(
        select(Finding)
        .options(joinedload(Finding.asset), joinedload(Finding.vuln))
        .where(Finding.status == "open")
    ).unique().scalars().all()

    result = []
    claimed: set[int] = set()
    for rule in rules:
        matches = []
        for f in findings:
            if f.id in claimed:
                continue
            if _rule_matches(f, rule):
                matches.append({
                    "finding_id": f.id,
                    "vuln": f.vuln.canonical_id if f.vuln else None,
                    "asset": f.asset.name if f.asset else None,
                    "severity": f.severity,
                    "category": f.category,
                })
                claimed.add(f.id)
        result.append({
            "rule_id": rule.id,
            "rule_name": rule.name,
            "assign_to": rule.assign_to,
            "match_count": len(matches),
            "sample": matches[:20],
        })

    return {
        "total_open": len(findings),
        "total_matched": len(claimed),
        "unmatched": len(findings) - len(claimed),
        "rules": result,
    }
