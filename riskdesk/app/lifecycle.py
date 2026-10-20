"""Finding lifecycle.

A finding moves through:

    detected -> open -> fixed (source says so) | stale (source stopped reporting)
                     -> verified_fixed (a person confirmed the fix)
    any closed state -> open again = reopened (a regression, counted)

Every transition after first detection is written to FindingEvent, so the
history of a vulnerability survives status overwrites. The timeline merges
those events with the decisions, exceptions and tickets that touched it.
"""
from __future__ import annotations

import datetime as dt
import statistics

from sqlalchemy import func, select, tuple_
from sqlalchemy.orm import joinedload

from .enums import CLOSED_STATUSES, Disposition, FindingStatus
from .models import (
    Adjudication, AuditEvent, ExceptionRequest, Finding, FindingEvent, Ticket,
    TicketFinding, Vuln, utcnow,
)
from .risk import AdjudicationIndex, scope_keys_for_finding, sla_status
from .ticket_sync import TICKET_CLOSED_STATUSES


def record_event(db, finding: Finding, event: str, to_status: str | None, actor: str,
                 from_status: str | None = None, sync_run_id: int | None = None,
                 note: str | None = None, ts: dt.datetime | None = None) -> FindingEvent:
    ev = FindingEvent(
        finding_id=finding.id, ts=ts or utcnow(), event=event,
        from_status=from_status, to_status=to_status, actor=actor,
        sync_run_id=sync_run_id, note=note,
    )
    db.add(ev)
    return ev


def apply_reported_status(db, row: Finding, reported: str, is_new: bool, now: dt.datetime,
                          actor: str, sync_run_id: int | None,
                          resolved_at: dt.datetime | None = None) -> str | None:
    """Apply the status a source reported. Returns "fixed" or "reopened" when the
    report closed or reopened the finding, else None. `resolved_at` is the
    source's own close timestamp; it anchors closed_at and the lifecycle event
    so historical fixes are recorded on their real date, not today."""
    prev = row.status
    close_ts = resolved_at or now
    if is_new:
        row.status = reported
        if reported in CLOSED_STATUSES:
            row.closed_at = close_ts
            # Backfill a close event so the timeline shows when the fix landed,
            # not just that the finding was detected and closed in the same sync.
            if resolved_at is not None:
                record_event(db, row, "fixed", reported, actor, from_status="open",
                             sync_run_id=sync_run_id, ts=close_ts,
                             note="Imported from source as already resolved")
        return None

    if reported == FindingStatus.OPEN.value:
        if prev in CLOSED_STATUSES:
            row.status = reported
            row.closed_at = None
            row.reopened_count = (row.reopened_count or 0) + 1
            row.verified_by = None
            row.verified_at = None
            record_event(db, row, "reopened", reported, actor, from_status=prev,
                         sync_run_id=sync_run_id, ts=now,
                         note="Source reported the finding again after it was closed")
            return "reopened"
        row.status = reported
        return None

    if reported in (FindingStatus.FIXED.value, FindingStatus.SUPPRESSED_AT_SOURCE.value):
        if prev == FindingStatus.VERIFIED_FIXED.value:
            return None  # a human already verified; the source agreeing changes nothing
        if prev == reported:
            # Already in this state; still update closed_at if we learned a real date.
            if resolved_at is not None and (row.closed_at is None or close_ts < row.closed_at):
                row.closed_at = close_ts
            return None
        row.status = reported
        if row.closed_at is None or (resolved_at is not None and close_ts < row.closed_at):
            row.closed_at = close_ts
        note = ("Source suppressed the finding" if reported == "suppressed_at_source"
                else "Source reported the finding resolved")
        record_event(db, row, "fixed" if reported == "fixed" else "suppressed",
                     reported, actor, from_status=prev,
                     sync_run_id=sync_run_id, ts=close_ts, note=note)
        return "fixed" if prev not in CLOSED_STATUSES else None

    if prev != reported:
        row.status = reported
        if reported in CLOSED_STATUSES and row.closed_at is None:
            row.closed_at = close_ts
        record_event(db, row, "status_change", reported, actor, from_status=prev,
                     sync_run_id=sync_run_id, ts=close_ts)
    return None


# ---------------------------------------------------------------------------
#  Timeline
# ---------------------------------------------------------------------------

def finding_timeline(db, finding: Finding, now: dt.datetime | None = None) -> list[dict]:
    """Everything that happened to one finding, oldest first."""
    now = now or utcnow()
    items: list[dict] = []

    def add(ts, kind, event, summary, actor=None, **extra):
        if ts is None:
            return
        items.append({"ts": _iso(ts), "kind": kind, "event": event,
                      "summary": summary, "actor": actor, **extra})

    add(finding.first_detected, "status", "detected",
        f"First detected by {finding.source}", finding.source)

    for ev in db.execute(
        select(FindingEvent).where(FindingEvent.finding_id == finding.id)
        .order_by(FindingEvent.ts)
    ).scalars():
        add(ev.ts, "status", ev.event, _event_summary(ev, finding, now), ev.actor,
            from_status=ev.from_status, to_status=ev.to_status, note=ev.note)

    # Decisions recorded at any scope that covers this finding, in any state.
    keys = scope_keys_for_finding(finding)
    adjs = db.execute(
        select(Adjudication).where(
            tuple_(Adjudication.scope_type, Adjudication.scope_key).in_(keys))
    ).scalars().all()
    if adjs:
        by_id = {a.id: a for a in adjs}
        for e in db.execute(
            select(AuditEvent).where(AuditEvent.entity_type == "adjudication",
                                     AuditEvent.entity_id.in_([str(i) for i in by_id]))
            .order_by(AuditEvent.ts)
        ).scalars():
            a = by_id.get(int(e.entity_id))
            add(e.ts, "decision", e.action, e.summary, e.actor,
                adjudication_id=a.id if a else None,
                disposition=a.disposition if a else None,
                scope_type=a.scope_type if a else None)

    tickets = db.execute(
        select(Ticket).join(TicketFinding).where(TicketFinding.finding_id == finding.id)
    ).unique().scalars().all()
    for t in tickets:
        add(t.created_at, "ticket", "ticket.create",
            f"Ticket {t.external_id} opened: {t.summary[:120]}", t.created_by,
            ticket_id=t.id, external_id=t.external_id, external_url=t.external_url)
        if t.resolved_at:
            add(t.resolved_at, "ticket", "ticket.resolved",
                f"Ticket {t.external_id} resolved ({t.status})", t.assignee,
                ticket_id=t.id, external_id=t.external_id, external_url=t.external_url)

    for x in db.execute(
        select(ExceptionRequest).where(ExceptionRequest.status != "draft")
    ).scalars():
        if finding.id not in (x.finding_ids or []):
            continue
        add(x.submitted_at or x.created_at, "exception", "exception.submit",
            f"Exception #{x.id} requested: {x.requested_disposition} — {x.title}",
            x.submitted_by, exception_id=x.id)
        if x.review_date and x.review_decision:
            add(x.review_date, "exception", f"exception.{x.review_decision}",
                f"Exception #{x.id} {x.review_decision}", x.reviewed_by, exception_id=x.id)

    items.sort(key=lambda i: i["ts"])
    return items


def _event_summary(ev: FindingEvent, finding: Finding, now: dt.datetime) -> str:
    if ev.event == "fixed":
        return "Closed: the source reported it resolved" + _closure_age(finding, ev.ts)
    if ev.event == "stale":
        return ("Closed as stale: the source stopped reporting it (presumed remediated)"
                + _closure_age(finding, ev.ts))
    if ev.event == "reopened":
        return f"Reopened: reported again after being {ev.from_status}"
    if ev.event == "verified":
        return "Fix verified" + (f" — {ev.note}" if ev.note else "")
    return f"Status changed {ev.from_status} → {ev.to_status}"


def _closure_age(finding: Finding, closed: dt.datetime) -> str:
    first = _aware(finding.first_detected)
    if first is None:
        return ""
    return f", {(_aware(closed) - first).days} days after detection"


# ---------------------------------------------------------------------------
#  Metrics
# ---------------------------------------------------------------------------

def lifecycle_metrics(db, days: int = 90, now: dt.datetime | None = None) -> dict:
    now = now or utcnow()
    start = now - dt.timedelta(days=days)

    status_counts = dict(db.execute(
        select(Finding.status, func.count()).group_by(Finding.status)
    ).all())

    index = AdjudicationIndex.load(db, now=now)
    closed_rows = db.execute(
        select(Finding).join(Vuln, Finding.vuln_id == Vuln.id)
        .where(Finding.closed_at.isnot(None), Finding.closed_at >= start)
    ).scalars().all()

    per_sev: dict[str, dict] = {}
    for f in closed_rows:
        adj = index.resolve(f)
        eff = (adj.adjusted_severity if adj is not None and adj.adjusted_severity
               and adj.disposition == Disposition.ADJUST_RISK.value else f.severity)
        closed = _aware(f.closed_at)
        first = _aware(f.first_detected) or closed
        due, _ = sla_status(f.first_detected, eff, bool(f.vuln and f.vuln.kev), adj, now)
        bucket = per_sev.setdefault(eff, {"closed": 0, "ages": [], "within_sla": 0, "with_sla": 0})
        bucket["closed"] += 1
        bucket["ages"].append(max(0.0, (closed - first).total_seconds() / 86400))
        if due is not None:
            bucket["with_sla"] += 1
            if closed <= due:
                bucket["within_sla"] += 1

    by_severity = {}
    all_ages: list[float] = []
    within = with_sla = 0
    for sev, b in per_sev.items():
        all_ages.extend(b["ages"])
        within += b["within_sla"]
        with_sla += b["with_sla"]
        by_severity[sev] = {
            "closed": b["closed"],
            "mttr_days": round(statistics.mean(b["ages"]), 1),
            "median_days": round(statistics.median(b["ages"]), 1),
            "closed_within_sla_pct": _pct(b["within_sla"], b["with_sla"]),
        }

    def _count_events(name):
        return db.execute(
            select(func.count()).select_from(FindingEvent)
            .where(FindingEvent.event == name, FindingEvent.ts >= start)
        ).scalar() or 0

    opened = db.execute(
        select(func.count()).select_from(Finding).where(Finding.first_detected >= start)
    ).scalar() or 0

    return {
        "window_days": days,
        "generated_at": now.isoformat(),
        "status_counts": status_counts,
        "opened_in_window": opened,
        "closed_in_window": len(closed_rows),
        "net_change": opened - len(closed_rows),
        "mttr_days": round(statistics.mean(all_ages), 1) if all_ages else None,
        "median_days_to_close": round(statistics.median(all_ages), 1) if all_ages else None,
        "closed_within_sla_pct": _pct(within, with_sla),
        "by_severity": by_severity,
        "reopened_in_window": _count_events("reopened"),
        "verified_in_window": _count_events("verified"),
        "stale_in_window": _count_events("stale"),
        "awaiting_verification": sum(status_counts.get(s, 0) for s in
                                     (FindingStatus.FIXED.value, FindingStatus.STALE.value)),
        "findings_ever_reopened": db.execute(
            select(func.count()).select_from(Finding).where(Finding.reopened_count > 0)
        ).scalar() or 0,
        "tickets": _ticket_drift(db),
    }


def _ticket_drift(db) -> dict:
    """Tickets whose state disagrees with their findings: resolved while the
    scanner still sees the vuln, or still open after every finding closed."""
    rows = db.execute(
        select(Ticket.id, Ticket.external_id, Ticket.status, Ticket.resolved_at, Finding.status)
        .join(TicketFinding, TicketFinding.ticket_id == Ticket.id)
        .join(Finding, Finding.id == TicketFinding.finding_id)
    ).all()
    tickets: dict[int, dict] = {}
    for tid, ext, tstatus, resolved_at, fstatus in rows:
        t = tickets.setdefault(tid, {"id": tid, "external_id": ext, "status": tstatus,
                                     "resolved": resolved_at is not None or tstatus in TICKET_CLOSED_STATUSES,
                                     "open_findings": 0, "closed_findings": 0})
        if fstatus in CLOSED_STATUSES:
            t["closed_findings"] += 1
        else:
            t["open_findings"] += 1
    resolved_still_open = [t for t in tickets.values() if t["resolved"] and t["open_findings"]]
    open_all_closed = [t for t in tickets.values()
                       if not t["resolved"] and not t["open_findings"] and t["closed_findings"]]
    return {
        "resolved_but_findings_open": len(resolved_still_open),
        "open_but_findings_closed": len(open_all_closed),
        "resolved_but_findings_open_sample": resolved_still_open[:20],
        "open_but_findings_closed_sample": open_all_closed[:20],
    }


def _pct(n: int, d: int) -> float | None:
    return round(100.0 * n / d, 1) if d else None


# ---------------------------------------------------------------------------
#  Historical reporting
# ---------------------------------------------------------------------------

GRANULARITIES = {
    "day": dt.timedelta(days=1),
    "week": dt.timedelta(days=7),
    "month": dt.timedelta(days=30),
    "quarter": dt.timedelta(days=90),
}


def _bucket_start(ts: dt.datetime, granularity: str) -> dt.datetime:
    ts = _aware(ts)
    if granularity == "day":
        return ts.replace(hour=0, minute=0, second=0, microsecond=0)
    if granularity == "week":
        start = ts.replace(hour=0, minute=0, second=0, microsecond=0)
        return start - dt.timedelta(days=start.weekday())  # Monday
    if granularity == "month":
        return ts.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    if granularity == "quarter":
        q = (ts.month - 1) // 3 * 3 + 1
        return ts.replace(month=q, day=1, hour=0, minute=0, second=0, microsecond=0)
    raise ValueError(f"Unknown granularity: {granularity}")


def _next_bucket(ts: dt.datetime, granularity: str) -> dt.datetime:
    if granularity == "month":
        return (ts.replace(day=28) + dt.timedelta(days=4)).replace(day=1)
    if granularity == "quarter":
        base = (ts.replace(day=28) + dt.timedelta(days=4)).replace(day=1)
        for _ in range(2):
            base = (base.replace(day=28) + dt.timedelta(days=4)).replace(day=1)
        return base
    return ts + GRANULARITIES[granularity]


def lifecycle_trends(db, days: int = 365, granularity: str = "week",
                     now: dt.datetime | None = None) -> dict:
    """Time series of findings opened, closed, and backlog over `days`,
    bucketed by `granularity`. The backlog line is the running count of
    findings in an open status at the end of each bucket, computed by
    walking forward from the known baseline."""
    now = now or utcnow()
    if granularity not in GRANULARITIES:
        raise ValueError(f"granularity must be one of {sorted(GRANULARITIES)}")
    start = _bucket_start(now - dt.timedelta(days=days), granularity)

    # One-shot pass: pull everything in the window, bucket in Python.
    rows = db.execute(
        select(Finding.first_detected, Finding.closed_at, Finding.severity, Finding.source)
    ).all()

    buckets: dict[dt.datetime, dict] = {}

    def _bucket(ts):
        b = _bucket_start(ts, granularity)
        return buckets.setdefault(b, {"opened": 0, "closed": 0,
                                      "opened_by_severity": {}, "closed_by_severity": {}})

    # Baseline: count findings that were already open at the window start
    # (first_detected < start AND (closed_at is null OR closed_at >= start)).
    baseline_open = 0
    for first, closed, sev, _source in rows:
        first_aw = _aware(first)
        closed_aw = _aware(closed)
        if first_aw is None:
            continue
        if first_aw < start and (closed_aw is None or closed_aw >= start):
            baseline_open += 1
        if first_aw >= start:
            b = _bucket(first_aw)
            b["opened"] += 1
            b["opened_by_severity"][sev] = b["opened_by_severity"].get(sev, 0) + 1
        if closed_aw is not None and closed_aw >= start:
            b = _bucket(closed_aw)
            b["closed"] += 1
            b["closed_by_severity"][sev] = b["closed_by_severity"].get(sev, 0) + 1

    series: list[dict] = []
    cur = start
    backlog = baseline_open
    while cur <= now:
        info = buckets.get(cur, {"opened": 0, "closed": 0,
                                 "opened_by_severity": {}, "closed_by_severity": {}})
        backlog = backlog + info["opened"] - info["closed"]
        series.append({
            "bucket_start": _iso(cur),
            "opened": info["opened"],
            "closed": info["closed"],
            "backlog_end": max(0, backlog),
            "opened_by_severity": info["opened_by_severity"],
            "closed_by_severity": info["closed_by_severity"],
        })
        cur = _next_bucket(cur, granularity)

    totals = {"opened": sum(b["opened"] for b in series),
              "closed": sum(b["closed"] for b in series)}
    return {
        "window_days": days,
        "granularity": granularity,
        "start": _iso(start),
        "end": _iso(now),
        "baseline_open_at_start": baseline_open,
        "series": series,
        "totals": totals,
    }


def remediated_findings(
    db,
    start: dt.datetime | None = None,
    end: dt.datetime | None = None,
    severity: list[str] | None = None,
    source: list[str] | None = None,
    category: list[str] | None = None,
    status: list[str] | None = None,
    include_verified_only: bool = False,
    page: int = 1,
    page_size: int = 100,
) -> dict:
    """List remediated (closed) findings for historical reporting and audit.

    Defaults to every closed finding, newest fix first. Pass `start`/`end` to
    scope to a reporting period (e.g. a quarter), or `include_verified_only`
    to count only fixes a person signed off."""
    now = utcnow()
    wanted_status = set(status or [])
    if include_verified_only:
        wanted_status = {"verified_fixed"}
    elif not wanted_status:
        wanted_status = {s for s in CLOSED_STATUSES}

    stmt = (
        select(Finding)
        .where(Finding.status.in_(wanted_status), Finding.closed_at.isnot(None))
    )
    if start:
        stmt = stmt.where(Finding.closed_at >= start)
    if end:
        stmt = stmt.where(Finding.closed_at <= end)
    if severity:
        stmt = stmt.where(Finding.severity.in_(severity))
    if source:
        stmt = stmt.where(Finding.source.in_(source))
    if category:
        stmt = stmt.where(Finding.category.in_(category))

    all_rows = db.execute(
        stmt.options(joinedload(Finding.asset), joinedload(Finding.vuln))
        .order_by(Finding.closed_at.desc())
    ).unique().scalars().all()

    index = AdjudicationIndex.load(db, now=now)

    def _row(f: Finding) -> dict:
        adj = index.resolve(f)
        eff = f.severity
        if adj is not None and adj.disposition == Disposition.ADJUST_RISK.value and adj.adjusted_severity:
            eff = adj.adjusted_severity
        due, _ = sla_status(f.first_detected, eff, bool(f.vuln and f.vuln.kev), adj, now)
        closed = _aware(f.closed_at)
        first = _aware(f.first_detected) or closed
        time_to_close = (closed - first).days if (closed and first) else None
        return {
            "finding_id": f.id,
            "source": f.source,
            "canonical_id": f.vuln.canonical_id if f.vuln else None,
            "cve_id": f.vuln.cve_id if f.vuln else None,
            "title": f.vuln.title if f.vuln else None,
            "asset": f.asset.name if f.asset else None,
            "asset_type": f.asset.asset_type if f.asset else None,
            "severity": f.severity,
            "effective_severity": eff,
            "category": f.category,
            "status": f.status,
            "component": f.component,
            "component_version": f.component_version,
            "first_detected": _iso(f.first_detected),
            "closed_at": _iso(f.closed_at),
            "time_to_close_days": time_to_close,
            "reopened_count": f.reopened_count or 0,
            "verified_by": f.verified_by,
            "verified_at": _iso(f.verified_at),
            "sla_due": _iso(due),
            "closed_within_sla": (due is not None and closed is not None and closed <= due),
            "fix_version": f.fix_version,
        }

    total = len(all_rows)
    offset = max(0, (page - 1) * page_size)
    rows = [_row(f) for f in all_rows[offset:offset + page_size]]

    # Aggregates across every row that matched the filter, not just the page.
    by_severity: dict[str, int] = {}
    by_source: dict[str, int] = {}
    by_month: dict[str, int] = {}
    within_sla = with_sla = 0
    ttc_values: list[int] = []
    for f in all_rows:
        by_severity[f.severity] = by_severity.get(f.severity, 0) + 1
        by_source[f.source] = by_source.get(f.source, 0) + 1
        closed = _aware(f.closed_at)
        if closed:
            key = closed.strftime("%Y-%m")
            by_month[key] = by_month.get(key, 0) + 1
            first = _aware(f.first_detected) or closed
            ttc_values.append((closed - first).days)
            adj = index.resolve(f)
            eff = (adj.adjusted_severity if adj and adj.adjusted_severity
                   and adj.disposition == Disposition.ADJUST_RISK.value else f.severity)
            due, _ = sla_status(f.first_detected, eff, bool(f.vuln and f.vuln.kev), adj, now)
            if due is not None:
                with_sla += 1
                if closed <= due:
                    within_sla += 1

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "pages": max(1, (total + page_size - 1) // page_size),
        "findings": rows,
        "summary": {
            "by_severity": by_severity,
            "by_source": by_source,
            "by_month": dict(sorted(by_month.items())),
            "mean_time_to_close_days": round(statistics.mean(ttc_values), 1) if ttc_values else None,
            "median_time_to_close_days": round(statistics.median(ttc_values), 1) if ttc_values else None,
            "closed_within_sla_pct": _pct(within_sla, with_sla),
            "closed_within_sla": within_sla,
            "measurable_against_sla": with_sla,
        },
    }


def import_historical(db, rows: list[dict], actor: str) -> dict:
    """Backload remediated findings from CSV/JSON.

    Each row must carry: canonical_id, source, asset, severity, first_detected,
    closed_at, status (one of fixed/verified_fixed/stale/suppressed_at_source).
    Optional: cve_id, title, category, component, source_finding_id.
    Rows are keyed on (source, source_finding_id), so re-running the import is
    idempotent."""
    from .enums import normalize_severity
    from .models import Asset, AuditEvent, Vuln

    results: list[dict] = []
    created = 0
    skipped = 0
    errors = 0

    for i, row in enumerate(rows, start=1):
        try:
            canonical = (row.get("canonical_id") or "").strip()
            source = (row.get("source") or "manual").strip()
            asset_name = (row.get("asset") or "").strip()
            status = (row.get("status") or "fixed").strip()
            first = _parse_date(row.get("first_detected"))
            closed = _parse_date(row.get("closed_at"))
            if not canonical:
                raise ValueError("canonical_id is required")
            if not asset_name:
                raise ValueError("asset is required")
            if closed is None:
                raise ValueError("closed_at is required (this is the historical fix date)")
            if status not in CLOSED_STATUSES:
                raise ValueError(f"status must be one of {sorted(CLOSED_STATUSES)}")
            source_finding_id = (row.get("source_finding_id") or
                                 f"historical:{source}:{canonical}:{asset_name}")

            # Idempotency: an existing row keeps its id, closed_at is updated
            # to the earliest reported close date.
            existing = db.execute(
                select(Finding).where(Finding.source == source,
                                      Finding.source_finding_id == source_finding_id)
            ).scalar_one_or_none()
            if existing is not None:
                skipped += 1
                results.append({"row": i, "status": "exists", "finding_id": existing.id})
                continue

            asset = db.execute(
                select(Asset).where(Asset.source == source, Asset.source_asset_id == asset_name)
            ).scalar_one_or_none()
            if asset is None:
                asset = Asset(source=source, source_asset_id=asset_name, name=asset_name,
                              asset_type=(row.get("asset_type") or None))
                db.add(asset)
                db.flush()

            vuln = db.execute(
                select(Vuln).where(Vuln.canonical_id == canonical)
            ).scalar_one_or_none()
            sev = normalize_severity(row.get("severity")).value
            if vuln is None:
                vuln = Vuln(canonical_id=canonical,
                            cve_id=(row.get("cve_id") or None),
                            title=(row.get("title") or canonical),
                            severity=sev)
                db.add(vuln)
                db.flush()

            finding = Finding(
                source=source, source_finding_id=source_finding_id,
                asset_id=asset.id, vuln_id=vuln.id,
                category=(row.get("category") or "os_vuln"),
                status=status, severity=sev,
                source_severity=row.get("source_severity"),
                component=row.get("component"),
                component_version=row.get("component_version"),
                first_detected=first or closed,
                last_seen=closed, last_synced_at=closed,
                closed_at=closed,
                verified_by=(actor if status == "verified_fixed" else None),
                verified_at=(closed if status == "verified_fixed" else None),
                raw={"imported": True, "imported_by": actor,
                     "imported_at": utcnow().isoformat()},
            )
            db.add(finding)
            db.flush()
            record_event(db, finding, "fixed", status, actor, from_status="open",
                         ts=closed, note="Historical import")
            created += 1
            results.append({"row": i, "status": "created", "finding_id": finding.id})
        except Exception as exc:
            errors += 1
            results.append({"row": i, "status": "error", "error": str(exc)})

    if created:
        db.add(AuditEvent(
            actor=actor, action="finding.import_historical",
            entity_type="finding", entity_id="bulk",
            summary=f"Historical import: {created} created, {skipped} already existed, {errors} failed",
            detail={"created": created, "skipped": skipped, "errors": errors},
        ))
    db.commit()
    return {
        "ok": errors == 0,
        "processed": len(rows),
        "created": created,
        "skipped": skipped,
        "errors": errors,
        "results": results[:500],
    }


def _parse_date(value) -> dt.datetime | None:
    if value is None or value == "":
        return None
    if isinstance(value, dt.datetime):
        return _aware(value)
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        return _aware(dt.datetime.fromisoformat(s))
    except ValueError:
        # Date-only (YYYY-MM-DD)
        try:
            return dt.datetime.strptime(s, "%Y-%m-%d").replace(tzinfo=dt.timezone.utc)
        except ValueError:
            raise ValueError(f"Could not parse date: {value!r}")


def _aware(value: dt.datetime | None) -> dt.datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def _iso(value: dt.datetime | None) -> str | None:
    v = _aware(value)
    return v.isoformat() if v else None
