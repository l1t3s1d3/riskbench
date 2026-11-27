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
    buckets: list[int] = field(default_factory=list)        # 0..4, filters by bucket
    kev_only: bool = False
    fixable_only: bool = False
    overdue_only: bool = False
    undecided_only: bool = False
    q: str = ""
    asset: str = ""                     # asset name ilike match (text search)
    cve: str = ""                       # canonical_id ilike match (text search)
    # Exact-match drill-down filters, used when the user clicks a row in a
    # grouped view: they must match exactly so the resulting list matches the
    # group header's counts.
    asset_id: int | None = None
    component: str = ""
    component_version: str = ""
    owner: str = ""
    business_unit: str = ""
    asset_type: str = ""
    asset_group_id: int | None = None
    ecosystem: str = ""                 # matches Finding.component_key prefix pkg:<ecosystem>/
    sort: str = "risk"          # risk | severity | age | asset | cve
    order: str = "desc"

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items()
                if v not in ([], "", False, None)}


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


def _apply_filters(stmt, f: FindingFilter):
    """SQL WHERE clauses shared between the list view, the facet counts, and
    the grouped view. Any filter understood by one is understood by all."""
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
    if f.asset_id is not None:
        stmt = stmt.where(Finding.asset_id == f.asset_id)
    if f.component:
        stmt = stmt.where(Finding.component == f.component)
    if f.component_version:
        stmt = stmt.where(Finding.component_version == f.component_version)
    if f.owner:
        stmt = stmt.where(Asset.owner == f.owner)
    if f.business_unit:
        stmt = stmt.where(Asset.business_unit == f.business_unit)
    if f.asset_type:
        stmt = stmt.where(Asset.asset_type == f.asset_type)
    if f.asset_group_id is not None:
        stmt = stmt.where(Asset.asset_group_id == f.asset_group_id)
    if f.ecosystem:
        stmt = stmt.where(Finding.component_key.like(f"pkg:{f.ecosystem}/%"))
    if f.q:
        term = f"%{f.q}%"
        stmt = stmt.where(or_(
            Vuln.canonical_id.ilike(term), Vuln.title.ilike(term),
            Asset.name.ilike(term), Finding.component.ilike(term),
            Finding.location.ilike(term),
        ))
    return stmt


def _base_query(f: FindingFilter):
    stmt = select(
        Finding.id, Finding.severity, Finding.first_detected, Finding.source,
        Finding.fix_available, Vuln.kev, Vuln.cvss_score, Vuln.canonical_id,
        Asset.name, Finding.status,
    ).join(Vuln, Finding.vuln_id == Vuln.id).join(Asset, Finding.asset_id == Asset.id)
    return _apply_filters(stmt, f)


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


from .cache import cached


@cached("search")
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
        if f.buckets:
            from .buckets import bucket_for_finding
            if bucket_for_finding(adj, now) not in f.buckets:
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
        "is_demo": bool(f.is_demo or (f.raw or {}).get("demo")),
        "bucket": _bucket_number(f, adj),
    }


def _bucket_number(f: Finding, adj: Adjudication | None) -> int:
    from .buckets import bucket_for_finding
    if f.status != "open":
        return bucket_for_finding(adj)  # same mapping, callers can ignore closed
    return bucket_for_finding(adj)


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


@cached("facets")
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


# ---------------------------------------------------------------------------
#  Grouped search: one row per CVE / asset / component / etc., with aggregates
#  and sample finding ids so bulk actions (decide / ticket / assign) work on
#  the whole group.
# ---------------------------------------------------------------------------

GROUPABLE = (
    "cve", "asset", "component", "component_version",
    "asset_type", "owner", "business_unit", "ecosystem",
)

# For each group dimension, the scope type a bulk decision on the group
# should default to. Scopes are the vocabulary adjudications already use:
# "vuln" survives across future re-detections of that CVE, "component"
# survives across future findings in the same package, "finding" is
# per-instance (used when the group has no durable scope).
GROUP_SCOPE_SUGGESTION = {
    "cve": "vuln",
    "component": "component",       # only when component_key is present
    "asset": "finding",
    "component_version": "finding",
    "asset_type": "finding",
    "owner": "finding",
    "business_unit": "finding",
    "ecosystem": "finding",
}


def _group_cols():
    """Columns needed to build a group row. Superset of _base_query for the
    aggregates and labels the UI needs."""
    return select(
        Finding.id, Finding.severity, Finding.status, Finding.source,
        Finding.first_detected, Finding.closed_at, Finding.component,
        Finding.component_version, Finding.component_key,
        Finding.fix_available, Finding.fix_version, Finding.asset_id,
        Vuln.kev, Vuln.cvss_score, Vuln.canonical_id, Vuln.cve_id, Vuln.title,
        Asset.name, Asset.asset_type, Asset.owner, Asset.business_unit,
    ).join(Vuln, Finding.vuln_id == Vuln.id).join(Asset, Finding.asset_id == Asset.id)


def _group_key(by: str, row) -> tuple[str, str] | None:
    """Return (key, label) for this row's group, or None to drop the row
    (e.g. grouping by owner when the asset has no owner set)."""
    if by == "cve":
        return row.canonical_id, (row.cve_id or row.canonical_id)
    if by == "asset":
        return str(row.asset_id), row.name
    if by == "component":
        if not row.component:
            return None
        return row.component, row.component
    if by == "component_version":
        if not row.component:
            return None
        key = f"{row.component}\u0001{row.component_version or ''}"
        label = f"{row.component} {row.component_version}" if row.component_version else row.component
        return key, label
    if by == "asset_type":
        if not row.asset_type:
            return None
        return row.asset_type, row.asset_type
    if by == "owner":
        if not row.owner:
            return None
        return row.owner, row.owner
    if by == "business_unit":
        if not row.business_unit:
            return None
        return row.business_unit, row.business_unit
    if by == "ecosystem":
        # component_key is normalised as pkg:<ecosystem>/<name>. Anything that
        # doesn't fit (CodeQL rule keys, Wiz rule keys) is dropped from the
        # ecosystem rollup because it has no package manager.
        ck = row.component_key or ""
        if not ck.startswith("pkg:") or "/" not in ck[4:]:
            return None
        eco = ck[4:].split("/", 1)[0]
        return eco, eco
    raise ValueError(f"Unknown group dimension: {by}")


@cached("grouped_search")
def grouped_search(db, f: FindingFilter, by: str,
                   page: int = 1, page_size: int = 50,
                   sort: str = "count") -> dict:
    """One row per group. Aggregates respect the resolution map, so a decision
    that adjusted severity is reflected in the group's effective-severity
    counts, and accepted / false-positive findings sort down."""
    if by not in GROUPABLE:
        raise ValueError(f"by must be one of {GROUPABLE}")

    resolution = build_resolution_map(db)
    now = utcnow()
    stmt = _apply_filters(_group_cols(), f)
    rows = db.execute(stmt).all()

    groups: dict[str, dict] = {}
    for row in rows:
        gk = _group_key(by, row)
        if gk is None:
            continue
        key, label = gk

        adj = resolution.get(row.id)
        eff_sev = row.severity
        disp = None
        if adj is not None:
            disp = adj.disposition
            if adj.disposition == Disposition.ADJUST_RISK.value and adj.adjusted_severity:
                eff_sev = adj.adjusted_severity

        # Apply the same post-resolution filters that search() applies, so
        # grouped counts and the drilled-down list agree.
        if f.severities and eff_sev not in f.severities:
            continue
        if f.undecided_only and adj is not None:
            continue
        if f.dispositions:
            want_none = "none" in f.dispositions
            key_disp = disp if disp is not None else "none"
            if key_disp not in f.dispositions and not (disp is None and want_none):
                continue

        g = groups.get(key)
        if g is None:
            g = groups[key] = {
                "key": key, "label": label,
                "finding_count": 0,
                "asset_ids": set(),
                "sources": set(),
                "severity_counts": {},         # effective severity rollup
                "status_counts": {},
                "disposition_counts": {},
                "kev_count": 0,
                "fix_available_count": 0,
                "max_score": 0.0,
                "oldest_open_detected": None,
                "newest_detected": None,
                "sample_titles": set(),
                "sample_finding_ids": [],
                # Per-dimension extras used by the UI
                "canonical_id": row.canonical_id if by == "cve" else None,
                "cve_id": row.cve_id if by == "cve" else None,
                "title": row.title if by == "cve" else None,
                "component_key": row.component_key if by in ("component", "component_version") else None,
                "asset_type": row.asset_type if by == "asset" else None,
                "component": row.component if by == "component_version" else None,
                "component_version": row.component_version if by == "component_version" else None,
                "fix_versions": set(),
            }
        g["finding_count"] += 1
        g["asset_ids"].add(row.asset_id)
        g["sources"].add(row.source)
        g["severity_counts"][eff_sev] = g["severity_counts"].get(eff_sev, 0) + 1
        g["status_counts"][row.status] = g["status_counts"].get(row.status, 0) + 1
        g["disposition_counts"][disp or "none"] = g["disposition_counts"].get(disp or "none", 0) + 1
        if row.kev:
            g["kev_count"] += 1
        if row.fix_available:
            g["fix_available_count"] += 1
            if row.fix_version:
                g["fix_versions"].add(row.fix_version)
        proxy = _proxy_score(eff_sev, bool(row.kev), row.cvss_score, row.fix_available, disp)
        if proxy > g["max_score"]:
            g["max_score"] = proxy
        fd = row.first_detected
        if fd is not None:
            if fd.tzinfo is None:
                fd = fd.replace(tzinfo=dt.timezone.utc)
            if g["newest_detected"] is None or fd > g["newest_detected"]:
                g["newest_detected"] = fd
            if row.status == "open" and (g["oldest_open_detected"] is None or fd < g["oldest_open_detected"]):
                g["oldest_open_detected"] = fd
        if len(g["sample_finding_ids"]) < 500:
            g["sample_finding_ids"].append(row.id)
        if row.title and len(g["sample_titles"]) < 3:
            g["sample_titles"].add(row.title)

    # Serialise, compute max severity, and attach the scope suggestion
    result_rows = []
    for g in groups.values():
        max_sev = _max_severity(g["severity_counts"])
        suggested_scope = GROUP_SCOPE_SUGGESTION[by]
        suggested_scope_key = None
        if suggested_scope == "vuln" and by == "cve":
            suggested_scope_key = g["canonical_id"]
        elif suggested_scope == "component":
            # Only usable when a component_key is normalised (pkg:...), otherwise
            # fall back to per-finding scope so decisions still work.
            if g["component_key"]:
                suggested_scope_key = g["component_key"]
            else:
                suggested_scope = "finding"
        result_rows.append({
            "key": g["key"],
            "label": g["label"],
            "finding_count": g["finding_count"],
            "asset_count": len(g["asset_ids"]),
            "sources": sorted(g["sources"]),
            "max_severity": max_sev,
            "severity_counts": g["severity_counts"],
            "status_counts": g["status_counts"],
            "disposition_counts": g["disposition_counts"],
            "kev_count": g["kev_count"],
            "fix_available_count": g["fix_available_count"],
            "fix_versions": sorted(g["fix_versions"])[:5],
            "max_score": round(g["max_score"], 1),
            "oldest_open_detected": _iso(g["oldest_open_detected"]),
            "newest_detected": _iso(g["newest_detected"]),
            "sample_titles": sorted(g["sample_titles"]),
            "sample_finding_ids": g["sample_finding_ids"],
            "canonical_id": g["canonical_id"],
            "cve_id": g["cve_id"],
            "title": g["title"],
            "component": g["component"] or (g["label"] if by == "component" else None),
            "component_version": g["component_version"],
            "component_key": g["component_key"],
            "asset_type": g["asset_type"],
            "suggested_scope": suggested_scope,
            "suggested_scope_key": suggested_scope_key,
        })

    # Sort
    def _sortkey(r):
        rank = Severity(r["max_severity"]).rank if r["max_severity"] in Severity._value2member_map_ else 0
        if sort == "severity":
            return (rank, r["max_score"], r["finding_count"])
        if sort == "assets":
            return (r["asset_count"], rank, r["finding_count"])
        if sort == "score":
            return (r["max_score"], rank, r["finding_count"])
        if sort == "label":
            return (-ord(r["label"][:1].lower()) if r["label"] else 0,)
        # default: count
        return (r["finding_count"], rank, r["max_score"])

    reverse = f.order != "asc" and sort != "label"
    result_rows.sort(key=_sortkey, reverse=reverse)
    if sort == "label":
        result_rows.sort(key=lambda r: (r["label"] or "").lower(), reverse=(f.order != "asc"))

    total = len(result_rows)
    start = max(0, (page - 1) * page_size)
    return {
        "group_by": by,
        "total_groups": total,
        "total_findings": sum(r["finding_count"] for r in result_rows),
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
        "groups": result_rows[start:start + page_size],
    }


def _max_severity(sev_counts: dict) -> str:
    """The worst severity present in the group's effective-severity rollup."""
    for sev in ("critical", "high", "medium", "low", "info"):
        if sev_counts.get(sev):
            return sev
    return "info"


def _iso(value: dt.datetime | None) -> str | None:
    if value is None:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.timezone.utc)
    return value.isoformat()
