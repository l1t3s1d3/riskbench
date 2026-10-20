"""Finding queries.

The awkward part of this application is that the most interesting attributes
of a finding -- its effective severity and its disposition -- are not columns.
They are the result of resolving scope-based decisions, so they cannot be
filtered or sorted in SQL directly.

The approach here: resolve every active decision onto finding ids in a handful
of set-based queries, then filter and sort against lightweight tuples in
memory, and only hydrate full ORM objects for the page being displayed. At the
scale this runs at (tens of thousands of findings, hundreds of decisions) that
is a few milliseconds and it keeps precedence logic in one readable place
rather than smeared across a correlated subquery.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

from sqlalchemy import func, or_, select
from sqlalchemy.orm import joinedload

from .enums import CLOSED_STATUSES, SCOPE_PRECEDENCE, Disposition, ScopeType, Severity
from .models import Adjudication, Asset, Finding, Vuln, utcnow
from .risk import compute_risk, sla_status


@dataclass
class FindingFilter:
    sources: list[str] = field(default_factory=list)
    severities: list[str] = field(default_factory=list)     # effective severity
    statuses: list[str] = field(default_factory=lambda: ["open"])
    categories: list[str] = field(default_factory=list)
    dispositions: list[str] = field(default_factory=list)   # "none" for undecided
    priorities: list[str] = field(default_factory=list)
    kev_only: bool = False
    fixable_only: bool = False
    overdue_only: bool = False
    undecided_only: bool = False
    q: str = ""
    asset: str = ""
    cve: str = ""
    sort: str = "risk"          # risk | severity | age | asset | cve
    order: str = "desc"

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v not in ([], "", False)}


def build_resolution_map(db, now: dt.datetime | None = None) -> dict[int, Adjudication]:
    """finding_id -> the decision that governs it, honouring scope precedence.

    Built least-specific first so more specific scopes overwrite. Both approved
    and pending decisions are loaded, but pending ones are kept in a separate
    map so they never influence risk.
    """
    now = now or utcnow()
    adjs = db.execute(
        select(Adjudication).where(Adjudication.state == "approved")
    ).scalars().all()
    active = [a for a in adjs if a.is_active(now)]
    if not active:
        return {}

    by_scope: dict[str, list[Adjudication]] = {s.value: [] for s in ScopeType}
    for a in active:
        by_scope.setdefault(a.scope_type, []).append(a)

    resolved: dict[int, Adjudication] = {}

    # Least specific first: component -> vuln -> vuln_on_asset -> finding.
    for scope in reversed(SCOPE_PRECEDENCE):
        group = by_scope.get(scope.value) or []
        if not group:
            continue
        keys = [a.scope_key for a in group]
        lookup = {a.scope_key: a for a in group}

        if scope == ScopeType.COMPONENT:
            rows = db.execute(
                select(Finding.id, Finding.component_key)
                .where(Finding.component_key.in_(keys))
            ).all()
            for fid, ckey in rows:
                resolved[fid] = lookup[ckey]

        elif scope == ScopeType.VULN:
            rows = db.execute(
                select(Finding.id, Vuln.canonical_id)
                .join(Vuln, Finding.vuln_id == Vuln.id)
                .where(Vuln.canonical_id.in_(keys))
            ).all()
            for fid, canonical in rows:
                resolved[fid] = lookup[canonical]

        elif scope == ScopeType.VULN_ON_ASSET:
            rows = db.execute(
                select(Finding.id, Vuln.canonical_id, Finding.asset_id)
                .join(Vuln, Finding.vuln_id == Vuln.id)
            ).all()
            for fid, canonical, asset_id in rows:
                hit = lookup.get(f"{canonical}::{asset_id}")
                if hit is not None:
                    resolved[fid] = hit

        elif scope == ScopeType.FINDING:
            for a in group:
                try:
                    resolved[int(a.scope_key)] = a
                except ValueError:
                    continue

    return resolved


def build_pending_map(db) -> dict[int, int]:
    """finding_id -> count of pending decisions touching it, via the
    application records captured when the request was raised."""
    from .models import AdjudicationApplication
    rows = db.execute(
        select(AdjudicationApplication.finding_id, func.count())
        .join(Adjudication, Adjudication.id == AdjudicationApplication.adjudication_id)
        .where(Adjudication.state == "pending_approval")
        .group_by(AdjudicationApplication.finding_id)
    ).all()
    return {fid: n for fid, n in rows}


def _base_query(f: FindingFilter):
    stmt = select(
        Finding.id, Finding.severity, Finding.first_detected, Finding.source,
        Finding.fix_available, Vuln.kev, Vuln.cvss_score, Vuln.canonical_id,
        Asset.name, Finding.status,
    ).join(Vuln, Finding.vuln_id == Vuln.id).join(Asset, Finding.asset_id == Asset.id)

    if f.statuses:
        stmt = stmt.where(Finding.status.in_(f.statuses))
    if f.sources:
        stmt = stmt.where(Finding.source.in_(f.sources))
    if f.categories:
        stmt = stmt.where(Finding.category.in_(f.categories))
    if f.kev_only:
        stmt = stmt.where(Vuln.kev.is_(True))
    if f.fixable_only:
        stmt = stmt.where(Finding.fix_available.is_(True))
    if f.asset:
        stmt = stmt.where(Asset.name.ilike(f"%{f.asset}%"))
    if f.cve:
        stmt = stmt.where(Vuln.canonical_id.ilike(f"%{f.cve}%"))
    if f.q:
        term = f"%{f.q}%"
        stmt = stmt.where(or_(
            Vuln.canonical_id.ilike(term), Vuln.title.ilike(term),
            Asset.name.ilike(term), Finding.component.ilike(term),
            Finding.location.ilike(term),
        ))
    return stmt


@dataclass
class Row:
    id: int
    severity: str
    effective_severity: str
    disposition: str | None
    priority: str
    score: float
    first_detected: dt.datetime | None
    asset_name: str
    canonical_id: str
    sort_key: tuple


def search(db, f: FindingFilter, page: int = 1, page_size: int = 50) -> dict:
    """Returns a page of hydrated findings plus the full matching id set.

    The id set matters: bulk actions operate on "everything matching this
    filter", not just the visible page, so the caller needs it.
    """
    resolution = build_resolution_map(db)
    pending = build_pending_map(db)
    now = utcnow()

    candidates = db.execute(_base_query(f)).all()

    rows: list[Row] = []
    for (fid, sev, first_detected, source, fix_available,
         kev, cvss, canonical, asset_name, status) in candidates:
        adj = resolution.get(fid)
        eff_sev = sev
        disp = None
        if adj is not None:
            disp = adj.disposition
            if adj.disposition == Disposition.ADJUST_RISK.value and adj.adjusted_severity:
                eff_sev = adj.adjusted_severity

        if f.severities and eff_sev not in f.severities:
            continue
        if f.undecided_only and adj is not None:
            continue
        if f.dispositions:
            want_none = "none" in f.dispositions
            if disp is None and not want_none:
                continue
            if disp is not None and disp not in f.dispositions:
                continue

        # Lightweight priority proxy for sorting; the page recomputes the real
        # score with the full factor breakdown.
        proxy = _proxy_score(eff_sev, kev, cvss, fix_available, disp)
        priority = ("P4" if disp in (Disposition.ACCEPT_RISK.value,
                                     Disposition.FALSE_POSITIVE.value)
                    else "P1" if proxy >= 80 else "P2" if proxy >= 60
                    else "P3" if proxy >= 35 else "P4")
        if f.priorities and priority not in f.priorities:
            continue

        if f.overdue_only:
            if status in CLOSED_STATUSES:
                continue
            _due, overdue = sla_status(first_detected, eff_sev, bool(kev), adj, now)
            if not overdue:
                continue

        rows.append(Row(
            id=fid, severity=sev, effective_severity=eff_sev, disposition=disp,
            priority=priority, score=proxy, first_detected=first_detected,
            asset_name=asset_name, canonical_id=canonical, sort_key=(),
        ))

    rows = _sort(rows, f)
    total = len(rows)
    start = max(0, (page - 1) * page_size)
    page_rows = rows[start:start + page_size]
    page_ids = [r.id for r in page_rows]

    hydrated = []
    if page_ids:
        objs = db.execute(
            select(Finding)
            .options(joinedload(Finding.asset), joinedload(Finding.vuln))
            .where(Finding.id.in_(page_ids))
        ).scalars().all()
        by_id = {o.id: o for o in objs}
        for fid in page_ids:
            obj = by_id.get(fid)
            if obj is None:
                continue
            adj = resolution.get(fid)
            risk = compute_risk(obj, adj, has_pending=fid in pending, now=now)
            hydrated.append(serialize_finding(obj, risk, adj))

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
        "findings": hydrated,
        "all_matching_ids": [r.id for r in rows],
    }


def _proxy_score(sev: str, kev: bool, cvss: float | None,
                 fix_available: bool, disp: str | None) -> float:
    base = {"critical": 70.0, "high": 55.0, "medium": 35.0, "low": 18.0, "info": 5.0}.get(sev, 5.0)
    if kev:
        base += 20
    if fix_available:
        base += 5
    if cvss:
        base += min(cvss / 10.0 * 3, 3)
    return round(min(base, 100.0), 1)


def _sort(rows: list[Row], f: FindingFilter) -> list[Row]:
    reverse = f.order != "asc"
    if f.sort == "severity":
        rows.sort(key=lambda r: (Severity(r.effective_severity).rank, r.score), reverse=reverse)
    elif f.sort == "age":
        far = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc)
        rows.sort(key=lambda r: (r.first_detected.replace(tzinfo=dt.timezone.utc)
                                 if r.first_detected and r.first_detected.tzinfo is None
                                 else (r.first_detected or far)), reverse=not reverse)
    elif f.sort == "asset":
        rows.sort(key=lambda r: r.asset_name.lower(), reverse=reverse)
    elif f.sort == "cve":
        rows.sort(key=lambda r: r.canonical_id, reverse=reverse)
    else:  # risk
        rows.sort(key=lambda r: (r.score, Severity(r.effective_severity).rank), reverse=reverse)
    return rows


def serialize_finding(f: Finding, risk, adj: Adjudication | None) -> dict:
    return {
        "id": f.id,
        "source": f.source,
        "source_finding_id": f.source_finding_id,
        "category": f.category,
        "status": f.status,
        "component": f.component,
        "component_version": f.component_version,
        "component_key": f.component_key,
        "location": f.location,
        "fix_available": f.fix_available,
        "fix_version": f.fix_version,
        "first_detected": _iso(f.first_detected),
        "last_seen": _iso(f.last_seen),
        "last_synced_at": _iso(f.last_synced_at),
        "closed_at": _iso(f.closed_at),
        "reopened_count": f.reopened_count or 0,
        "verified_by": f.verified_by,
        "verified_at": _iso(f.verified_at),
        "source_url": f.source_url,
        "source_severity": f.source_severity,
        "asset": {
            "id": f.asset.id, "name": f.asset.name, "type": f.asset.asset_type,
            "os": f.asset.os_name, "ip": f.asset.ip_address,
            "cloud_provider": f.asset.cloud_provider, "cloud_account": f.asset.cloud_account,
            "region": f.asset.region, "environment": f.asset.environment,
            "internet_facing": f.asset.internet_facing,
            "data_classification": f.asset.data_classification,
            "owner": f.asset.owner, "business_unit": f.asset.business_unit,
            "tags": f.asset.tags or {},
        },
        "vuln": {
            "canonical_id": f.vuln.canonical_id, "cve_id": f.vuln.cve_id,
            "title": f.vuln.title, "description": f.vuln.description,
            "cvss_score": f.vuln.cvss_score, "cvss_vector": f.vuln.cvss_vector,
            "epss_score": f.vuln.epss_score, "kev": f.vuln.kev,
            "published_at": _iso(f.vuln.published_at),
            "remediation": f.vuln.remediation, "references": f.vuln.references or [],
        },
        "risk": {
            "base_severity": risk.base_severity,
            "effective_severity": risk.effective_severity,
            "adjusted": risk.adjusted,
            "priority": risk.priority,
            "score": risk.score,
            "sla_due": _iso(risk.sla_due),
            "sla_overdue": risk.sla_overdue,
            "unknown_inputs": risk.unknown_inputs,
            "factors": [{"name": x.name, "applied": x.applied,
                         "points": x.points, "note": x.note} for x in risk.factors],
        },
        "decision": _serialize_adj(adj) if adj else None,
        "has_pending": risk.has_pending,
        "is_demo": bool((f.raw or {}).get("demo")),
    }


def _serialize_adj(a: Adjudication) -> dict:
    return {
        "id": a.id, "scope_type": a.scope_type, "scope_key": a.scope_key,
        "scope_label": a.scope_label, "disposition": a.disposition, "state": a.state,
        "justification": a.justification, "compensating_controls": a.compensating_controls,
        "adjusted_severity": a.adjusted_severity, "adjusted_priority": a.adjusted_priority,
        "assigned_to": a.assigned_to, "remediation_due": _iso(a.remediation_due),
        "requested_by": a.requested_by, "requested_at": _iso(a.requested_at),
        "approver": a.approver, "approved_by": a.approved_by,
        "decided_at": _iso(a.decided_at), "decision_note": a.decision_note,
        "review_due": _iso(a.review_due), "expires_at": _iso(a.expires_at),
        "applied_count": len(a.applications),
        "scope_filter": a.scope_filter,
        "supersedes_id": a.supersedes_id,
    }


def facets(db, f: FindingFilter) -> dict:
    """Counts for the filter rail, computed against the same filter minus the
    dimension being counted, so a facet never shows zero for a value you could
    still pick."""
    resolution = build_resolution_map(db)

    def counts(exclude: str) -> dict:
        g = FindingFilter(**{**f.__dict__})
        setattr(g, exclude, [] if isinstance(getattr(g, exclude), list) else False)
        rows = db.execute(_base_query(g)).all()
        out: dict[str, int] = {}
        for (fid, sev, _fd, source, _fa, _kev, _cvss, _cid, _an, _st) in rows:
            adj = resolution.get(fid)
            eff = sev
            if adj and adj.disposition == Disposition.ADJUST_RISK.value and adj.adjusted_severity:
                eff = adj.adjusted_severity
            if exclude == "severities":
                out[eff] = out.get(eff, 0) + 1
            elif exclude == "sources":
                out[source] = out.get(source, 0) + 1
            elif exclude == "dispositions":
                key = adj.disposition if adj else "none"
                out[key] = out.get(key, 0) + 1
        return out

    cat_rows = db.execute(
        _base_query(FindingFilter(**{**f.__dict__, "categories": []}))
        .with_only_columns(Finding.category, func.count())
        .group_by(Finding.category)
    ).all()
    status_rows = db.execute(
        _base_query(FindingFilter(**{**f.__dict__, "statuses": []}))
        .with_only_columns(Finding.status, func.count())
        .group_by(Finding.status)
    ).all()

    return {
        "severity": counts("severities"),
        "source": counts("sources"),
        "disposition": counts("dispositions"),
        "category": {c: n for c, n in cat_rows},
        "status": {s: n for s, n in status_rows},
    }


def _iso(value: dt.datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.isoformat()
