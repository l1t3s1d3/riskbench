"""Scope-promotion suggestions.

When a reviewer has a selection of findings in hand, this module says
"you could record this as N broader-scoped decisions instead of 500
finding-scoped ones". It inspects the selection for each candidate
scope (vuln, vuln_on_asset, component) and asks:

  * How many distinct scope keys would this collapse to?
  * How many *other* open findings does each key cover that weren't in
    the selection? (the "extras" — promotion brings them along)
  * Are those extras safe to promote — same severity, same disposition
    status, same owner? Or does promotion sweep in heterogeneous rows
    the reviewer should see first?

The output is a ranked list of suggestions with enough context for a
confirmation screen.
"""
from __future__ import annotations

import datetime as dt
from collections import defaultdict
from typing import Iterable

from sqlalchemy import select
from sqlalchemy.orm import joinedload

from .enums import ScopeType
from .models import Adjudication, AdjudicationApplication, Asset, Finding, Vuln
from .queries import build_resolution_map


_PROMOTABLE_SCOPES = (
    ScopeType.VULN_ON_ASSET,
    ScopeType.VULN,
    ScopeType.COMPONENT,
)


def _scope_key(f: Finding, scope: ScopeType) -> str | None:
    if scope == ScopeType.FINDING:
        return str(f.id)
    if scope == ScopeType.VULN_ON_ASSET:
        if f.vuln is None:
            return None
        return f"{f.vuln.canonical_id}::{f.asset_id}"
    if scope == ScopeType.VULN:
        return f.vuln.canonical_id if f.vuln else None
    if scope == ScopeType.COMPONENT:
        return f.component_key or None
    return None


def _label_for(scope: ScopeType, key: str, sample_finding: Finding) -> str:
    if scope == ScopeType.FINDING:
        return f"{sample_finding.vuln.canonical_id} on {sample_finding.asset.name}"
    if scope == ScopeType.VULN_ON_ASSET:
        return f"{sample_finding.vuln.canonical_id} on {sample_finding.asset.name}"
    if scope == ScopeType.VULN:
        return f"{key} (all assets)"
    if scope == ScopeType.COMPONENT:
        return f"{key} (all findings)"
    return key


def suggest_scope_promotions(
    db, finding_ids: Iterable[int], now: dt.datetime | None = None
) -> dict:
    """Return per-scope promotion suggestions for a selection.

    For each candidate scope (vuln_on_asset, vuln, component) it reports
    the distinct keys the selection collapses to, the total open
    findings each key would govern, and warnings when promotion would
    cover heterogeneous siblings the reviewer did not pick.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    fid_list = list(dict.fromkeys(int(x) for x in finding_ids))
    if not fid_list:
        return {"selection": {"count": 0}, "suggestions": []}

    selected = db.execute(
        select(Finding)
        .options(joinedload(Finding.asset), joinedload(Finding.vuln))
        .where(Finding.id.in_(fid_list))
    ).unique().scalars().all()
    if not selected:
        return {"selection": {"count": 0}, "suggestions": []}

    selected_ids = {f.id for f in selected}
    by_id = {f.id: f for f in selected}

    resolution = build_resolution_map(db, now)

    suggestions: list[dict] = []
    for scope in _PROMOTABLE_SCOPES:
        key_plans = _plans_for_scope(db, scope, selected, selected_ids, by_id, resolution)
        if not key_plans:
            continue
        coverage = sum(p["coverage_total"] for p in key_plans)
        extras = sum(p["extra_beyond_selection"] for p in key_plans)
        warnings = _aggregate_warnings(key_plans)
        clean = all(p["extra_beyond_selection"] == 0 for p in key_plans)
        suggestions.append({
            "scope_type": scope.value,
            "key_count": len(key_plans),
            "coverage_total": coverage,
            "selection_count": len(selected_ids),
            "extra_beyond_selection": extras,
            "clean": clean,
            "summary": _summary_line(scope, key_plans, coverage, extras),
            "warnings": warnings,
            "plans": key_plans,
        })

    # Always offer finding-scope as the conservative baseline so the UI
    # can show "or keep it per-finding" without a special case.
    suggestions.append({
        "scope_type": ScopeType.FINDING.value,
        "key_count": len(selected_ids),
        "coverage_total": len(selected_ids),
        "selection_count": len(selected_ids),
        "extra_beyond_selection": 0,
        "clean": True,
        "summary": (f"Keep it per-finding: {len(selected_ids)} finding-scoped "
                    f"decisions, one per instance."),
        "warnings": [],
        "plans": [],
    })

    suggestions.sort(key=_rank)
    return {
        "selection": {"count": len(selected_ids), "ids_truncated": fid_list[:5000]},
        "suggestions": suggestions,
    }


def _plans_for_scope(db, scope: ScopeType, selected: list[Finding],
                      selected_ids: set[int], by_id: dict[int, Finding],
                      resolution: dict[int, Adjudication]) -> list[dict]:
    """Build the per-key plan list for one scope type."""
    grouped: dict[str, list[Finding]] = defaultdict(list)
    for f in selected:
        k = _scope_key(f, scope)
        if k:
            grouped[k].append(f)
    if not grouped:
        return []

    # Pull every open finding that matches these keys so we can report
    # the extras promotion would sweep in.
    coverage = _coverage_for_keys(db, scope, list(grouped.keys()))

    plans: list[dict] = []
    for key, selected_here in grouped.items():
        cov = coverage.get(key, [])
        extra_ids = [fid for fid in cov if fid not in selected_ids]
        warnings = _plan_warnings(db, scope, key, selected_here, extra_ids, resolution)
        sample = selected_here[0]
        plans.append({
            "scope_key": key,
            "label": _label_for(scope, key, sample),
            "selected_count": len(selected_here),
            "coverage_total": len(cov),
            "extra_beyond_selection": len(extra_ids),
            "extra_ids_sample": extra_ids[:50],
            "warnings": warnings,
        })
    plans.sort(key=lambda p: p["coverage_total"], reverse=True)
    return plans


def _coverage_for_keys(db, scope: ScopeType, keys: list[str]) -> dict[str, list[int]]:
    """Return {scope_key: [finding_ids]} for every open finding under each key."""
    if scope == ScopeType.VULN:
        rows = db.execute(
            select(Finding.id, Vuln.canonical_id)
            .join(Vuln, Finding.vuln_id == Vuln.id)
            .where(Vuln.canonical_id.in_(keys), Finding.status == "open")
        ).all()
        out: dict[str, list[int]] = defaultdict(list)
        for fid, k in rows:
            out[k].append(fid)
        return out
    if scope == ScopeType.VULN_ON_ASSET:
        # Split keys into (canonical, asset_id) pairs for an efficient query.
        pairs = []
        for k in keys:
            try:
                c, a = k.split("::", 1)
                pairs.append((c, int(a)))
            except ValueError:
                continue
        if not pairs:
            return {}
        canonicals = list({c for c, _ in pairs})
        asset_ids = list({a for _, a in pairs})
        rows = db.execute(
            select(Finding.id, Vuln.canonical_id, Finding.asset_id)
            .join(Vuln, Finding.vuln_id == Vuln.id)
            .where(Vuln.canonical_id.in_(canonicals),
                   Finding.asset_id.in_(asset_ids),
                   Finding.status == "open")
        ).all()
        want = set(pairs)
        out = defaultdict(list)
        for fid, c, a in rows:
            if (c, a) in want:
                out[f"{c}::{a}"].append(fid)
        return out
    if scope == ScopeType.COMPONENT:
        rows = db.execute(
            select(Finding.id, Finding.component_key)
            .where(Finding.component_key.in_(keys), Finding.status == "open")
        ).all()
        out = defaultdict(list)
        for fid, k in rows:
            out[k].append(fid)
        return out
    return {}


def _plan_warnings(db, scope, key, selected_here, extra_ids,
                   resolution) -> list[str]:
    """Flag reasons promotion might surprise the reviewer."""
    warnings: list[str] = []
    if not extra_ids:
        return warnings
    extras = db.execute(
        select(Finding.id, Finding.severity, Finding.category, Finding.asset_id,
               Asset.owner, Asset.business_unit, Asset.environment)
        .join(Asset, Finding.asset_id == Asset.id)
        .where(Finding.id.in_(extra_ids))
    ).all()

    sel_sev = {f.severity for f in selected_here}
    sel_owner = {f.asset.owner for f in selected_here if f.asset.owner}
    sel_bu = {f.asset.business_unit for f in selected_here if f.asset.business_unit}
    sel_env = {f.asset.environment for f in selected_here if f.asset.environment}

    extras_sev = {r.severity for r in extras}
    extras_owner = {r.owner for r in extras if r.owner}
    extras_bu = {r.business_unit for r in extras if r.business_unit}
    extras_env = {r.environment for r in extras if r.environment}

    if extras_sev - sel_sev:
        warnings.append(
            f"Covers {len(extras)} extra findings with other severities "
            f"({', '.join(sorted(extras_sev - sel_sev))}).")
    if extras_owner - sel_owner:
        warnings.append(
            f"Covers assets owned by other teams ({', '.join(sorted(extras_owner - sel_owner))}).")
    if extras_bu - sel_bu:
        warnings.append(
            f"Covers other business units ({', '.join(sorted(extras_bu - sel_bu))}).")
    if extras_env - sel_env:
        warnings.append(
            f"Spans other environments ({', '.join(sorted(extras_env - sel_env))}).")

    decided_extras = [r.id for r in extras if r.id in resolution]
    if decided_extras:
        warnings.append(
            f"{len(decided_extras)} of the extras already carry a more specific "
            f"decision (those keep theirs; the new decision does not override them).")
    return warnings


def _aggregate_warnings(plans: list[dict]) -> list[str]:
    seen: list[str] = []
    for p in plans:
        for w in p["warnings"]:
            if w not in seen:
                seen.append(w)
    return seen[:6]


def _summary_line(scope: ScopeType, plans, coverage, extras) -> str:
    n = len(plans)
    if scope == ScopeType.VULN:
        base = f"Record as {n} vuln-scoped decision{'s' if n != 1 else ''}"
    elif scope == ScopeType.VULN_ON_ASSET:
        base = f"Record as {n} vuln-on-asset decision{'s' if n != 1 else ''}"
    elif scope == ScopeType.COMPONENT:
        base = f"Record as {n} component-scoped decision{'s' if n != 1 else ''}"
    else:
        base = f"Record as {n} decisions"
    if extras:
        return f"{base}, covering {coverage:,} open findings ({extras:,} beyond your selection)."
    return f"{base}, covering exactly your {coverage:,} selected findings."


def _rank(suggestion: dict) -> tuple:
    """Prefer clean matches, then fewer plans, then broader coverage."""
    clean_penalty = 0 if suggestion["clean"] else 1
    return (
        clean_penalty,
        suggestion["key_count"],
        -suggestion["coverage_total"],
    )
