"""Materialized dashboard rollup.

The dashboard endpoint walks every open finding and resolves adjudication
per-row to derive effective severity, overdue, and KEV counts. That loop
is O(open findings) and hurts at scale.

This module caches the result in a single-row table. Reads return the
cached row when fresh; writes mark it stale. The next read rebuilds.

Pair this with :func:`app.cache.invalidate_all` at the same mutation
sites so the in-process TTL cache and the materialized row stay in sync.
"""
from __future__ import annotations

import datetime as dt

from sqlalchemy import func, select

from .buckets import BUCKETS, bucket_for_finding
from .enums import Disposition
from .models import (
    Adjudication, Asset, DashboardRollup, Finding, SyncRun, Vuln,
)
from .queries import build_resolution_map
from .risk import sla_status


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _get_or_create(db) -> DashboardRollup:
    row = db.get(DashboardRollup, 1)
    if row is None:
        row = DashboardRollup(id=1, stale=True, data={})
        db.add(row)
        db.flush()
    return row


def mark_stale(db) -> None:
    """Flag the rollup for rebuild on the next read.

    Commits its own write so callers can treat this as fire-and-forget
    after their own commit has already landed.
    """
    row = _get_or_create(db)
    if not row.stale:
        row.stale = True
        db.commit()


def _compute(db, now: dt.datetime) -> dict:
    resolution = build_resolution_map(db)

    rows = db.execute(
        select(Finding.id, Finding.severity, Finding.source, Finding.first_detected,
               Vuln.kev)
        .join(Vuln, Finding.vuln_id == Vuln.id)
        .where(Finding.status == "open")
    ).all()

    by_severity: dict[str, int] = {}
    by_source: dict[str, int] = {}
    by_disposition: dict[str, int] = {}
    by_bucket: dict[str, int] = {str(b.number): 0 for b in BUCKETS}
    bucket_aging_breach: dict[str, int] = {str(b.number): 0 for b in BUCKETS if b.max_days}
    overdue = 0
    kev_open = 0

    for fid, sev, source, first_detected, kev in rows:
        adj = resolution.get(fid)
        eff = sev
        disp = adj.disposition if adj else "none"
        if adj and adj.disposition == Disposition.ADJUST_RISK.value and adj.adjusted_severity:
            eff = adj.adjusted_severity
        by_severity[eff] = by_severity.get(eff, 0) + 1
        by_source[source] = by_source.get(source, 0) + 1
        by_disposition[disp] = by_disposition.get(disp, 0) + 1
        bucket_num = bucket_for_finding(adj, now)
        by_bucket[str(bucket_num)] = by_bucket.get(str(bucket_num), 0) + 1
        # Aging breach: bucket 0 anchors on first_detected; bucket 3 on
        # when the governing decision landed (decided_at or requested_at).
        max_days = next((b.max_days for b in BUCKETS if b.number == bucket_num), None)
        if max_days:
            anchor = first_detected
            if bucket_num != 0 and adj is not None:
                anchor = adj.decided_at or adj.requested_at or first_detected
            if _age_days(anchor, now) > max_days:
                bucket_aging_breach[str(bucket_num)] = (
                    bucket_aging_breach.get(str(bucket_num), 0) + 1
                )
        if kev:
            kev_open += 1
        if sla_status(first_detected, eff, bool(kev), adj, now)[1]:
            overdue += 1

    unique_vulns = db.execute(select(func.count()).select_from(Vuln)).scalar() or 0
    assets = db.execute(select(func.count()).select_from(Asset)).scalar() or 0

    return {
        "open_findings": len(rows),
        "unique_vulns": unique_vulns,
        "assets": assets,
        "by_severity": by_severity,
        "by_source": by_source,
        "by_disposition": by_disposition,
        "by_bucket": by_bucket,
        "bucket_aging_breach": bucket_aging_breach,
        "overdue": overdue,
        "kev_open": kev_open,
        "undecided": by_bucket.get("0", 0),
    }


def _age_days(anchor: dt.datetime | None, now: dt.datetime) -> float:
    if anchor is None:
        return 0.0
    if anchor.tzinfo is None:
        anchor = anchor.replace(tzinfo=dt.timezone.utc)
    return max(0.0, (now - anchor).total_seconds() / 86400.0)


def get_rollup(db, now: dt.datetime | None = None) -> dict:
    """Return the materialized dashboard payload.

    Rebuilds on-demand when the singleton row is missing or marked stale.
    Volatile fields (pending approvals, expiring soon, recent syncs)
    are not cached here -- the dashboard endpoint computes them with
    cheap COUNT queries and splices them on top.
    """
    now = now or _now()
    row = _get_or_create(db)
    if row.stale or not row.data:
        row.data = _compute(db, now)
        row.generated_at = now
        row.stale = False
        db.commit()
    return dict(row.data)


def rebuild(db, now: dt.datetime | None = None) -> dict:
    """Force a rebuild of the rollup (used by tests and admin recompute)."""
    row = _get_or_create(db)
    row.stale = True
    return get_rollup(db, now)


def live_extras(db, now: dt.datetime | None = None) -> dict:
    """Small, cheap counts that change too often to materialize."""
    now = now or _now()
    pending = db.execute(
        select(func.count()).select_from(Adjudication)
        .where(Adjudication.state == "pending_approval")
    ).scalar() or 0
    horizon = now + dt.timedelta(days=30)
    expiring = db.execute(
        select(func.count()).select_from(Adjudication)
        .where(Adjudication.state == "approved",
               Adjudication.expires_at.isnot(None),
               Adjudication.expires_at > now,
               Adjudication.expires_at <= horizon)
    ).scalar() or 0
    review_due = db.execute(
        select(func.count()).select_from(Adjudication)
        .where(Adjudication.state == "approved",
               Adjudication.review_due.isnot(None),
               Adjudication.review_due <= now)
    ).scalar() or 0
    runs = db.execute(
        select(SyncRun).order_by(SyncRun.started_at.desc()).limit(6)
    ).scalars().all()
    return {
        "pending_approvals": pending,
        "expiring_30d": expiring,
        "review_overdue": review_due,
        "recent_syncs": [{
            "id": r.id, "source": r.source, "status": r.status,
            "started_at": r.started_at.isoformat() if r.started_at else None,
            "findings": r.findings_upserted, "new": r.findings_new,
            "closed": r.findings_closed, "error": r.error,
        } for r in runs],
    }
