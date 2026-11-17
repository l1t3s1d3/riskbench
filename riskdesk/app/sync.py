"""Sync engine.

Owns every write that comes from a connector. Upserts are keyed on
(source, source_finding_id) so re-running a sync is idempotent.

Findings the source stops reporting are not deleted. They are marked `stale`
after a grace window and keep their adjudication history, because "this
finding disappeared" and "someone accepted this risk" are different facts and
an auditor will eventually ask about both.
"""
from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass

from sqlalchemy import func, select

from .config import settings
from .connectors.base import NormalizedRecord
from .db import SessionLocal
from .models import Asset, AuditEvent, Finding, SyncRun, Vuln, utcnow

log = logging.getLogger(__name__)

BATCH = 500


def _notify_progress(source: str, stats: dict, new_by_severity: dict):
    """Push a progress event to SSE subscribers (no-op if none connected)."""
    try:
        from .routes.sync import _broadcast_sync_event
        _broadcast_sync_event(source, {
            "type": "progress",
            "source": source,
            "findings": stats.get("findings", 0),
            "new": stats.get("new", 0),
            "assets": stats.get("assets", 0),
            "new_by_severity": new_by_severity,
        })
    except Exception:
        pass


def _notify_complete(source: str, result: dict):
    """Push a completion event to SSE subscribers."""
    try:
        from .routes.sync import _broadcast_sync_event
        _broadcast_sync_event(source, {
            "type": "complete",
            "source": source,
            "status": result.get("status", "unknown"),
            "findings": result.get("findings", 0),
            "new": result.get("new", 0),
            "closed": result.get("closed", 0),
            "error": result.get("error"),
        })
    except Exception:
        pass


def get_connector(source: str, demo: bool = False):
    from .connectors.demo import DemoConnector
    if demo:
        return DemoConnector(source)
    if source == "wiz":
        from .connectors.wiz import WizConnector
        return WizConnector()
    if source == "falcon":
        from .connectors.falcon import FalconConnector
        return FalconConnector()
    if source == "github":
        from .connectors.github import GitHubConnector
        return GitHubConnector()
    raise ValueError(f"Unknown source: {source}")


def run_sync(source: str, demo: bool = False, limit: int | None = None,
             actor: str = "system") -> dict:
    db = SessionLocal()
    run = SyncRun(source=source, triggered_by=actor, status="running")
    db.add(run)
    db.commit()

    started = utcnow()
    stats = {"assets": 0, "findings": 0, "new": 0, "closed": 0, "reopened": 0, "stale": 0}
    new_severity: dict[str, int] = {}      # severity -> count of new findings
    new_ids: list[int] = []                # ids of newly created findings
    asset_cache: dict[tuple[str, str], int] = {}
    vuln_cache: dict[str, int] = {}
    stale_skipped_reason = None

    try:
        connector = get_connector(source, demo=demo)
        if not demo and not connector.configured():
            raise RuntimeError(
                f"{source} is not configured. Set its credentials in .env, or run "
                f"with demo data to explore the interface."
            )

        ctx = _SyncContext(started=started, actor=actor, run_id=run.id)
        pending = 0
        for rec in connector.fetch(limit=limit):
            asset_id = _upsert_asset(db, source, rec, asset_cache, stats)
            vuln_id = _upsert_vuln(db, rec, vuln_cache)
            fid, is_new = _upsert_finding(db, source, rec, asset_id, vuln_id, stats, ctx)
            if is_new:
                new_severity[rec.severity] = new_severity.get(rec.severity, 0) + 1
                new_ids.append(fid)
            pending += 1
            if pending >= BATCH:
                db.commit()
                _notify_progress(source, stats, new_severity)
                pending = 0
        db.commit()

        # Only a complete pull can say what the source stopped reporting.
        if limit:
            stale_skipped_reason = f"partial sync (limit={limit})"
        elif demo:
            stale_skipped_reason = "demo data"
        else:
            skipped = set(getattr(connector, "skipped_categories", set()))
            stats["stale"] = _mark_stale(db, source, started, ctx, exclude_categories=skipped)
            stats["closed"] += stats["stale"]
            if skipped:
                stale_skipped_reason = f"not read this run: {', '.join(sorted(skipped))}"
        db.commit()

        run.status = "ok"
    except Exception as exc:
        db.rollback()
        run = db.get(SyncRun, run.id)
        run.status = "error"
        run.error = f"{type(exc).__name__}: {exc}"
        log.exception("Sync failed for %s", source)
    finally:
        run = db.get(SyncRun, run.id)
        run.finished_at = utcnow()
        run.assets_upserted = stats["assets"]
        run.findings_upserted = stats["findings"]
        run.findings_new = stats["new"]
        run.findings_closed = stats["closed"]
        run.delta = {
            "new_by_severity": new_severity,
            "new_ids_sample": new_ids[:500],
            "reopened": stats["reopened"],
            "stale": stats["stale"],
            "stale_check_skipped": stale_skipped_reason,
        }
        db.add(AuditEvent(
            actor=actor, action="sync", entity_type="source", entity_id=source,
            summary=(f"Sync {run.status}: {stats['findings']} findings "
                     f"({stats['new']} new, {stats['closed']} closed, "
                     f"{stats['reopened']} reopened)"
                     + (" [demo data]" if demo else "")),
            detail={**stats, "demo": demo, "error": run.error,
                    "new_by_severity": new_severity,
                    "stale_check_skipped": stale_skipped_reason},
        ))
        db.commit()

        # Auto-assignment, for findings this run created only.
        assign_stats = None
        if run.status == "ok" and new_ids and not demo:
            try:
                from .assignment import evaluate_rules
                assign_stats = evaluate_rules(
                    db, source=source, finding_ids=new_ids, actor=actor
                )
            except Exception:
                log.exception("Auto-assignment after %s sync failed", source)

        result = {
            "run_id": run.id, "source": source, "status": run.status,
            "error": run.error, **stats, "demo": demo,
            "new_by_severity": new_severity,
            "auto_assigned": assign_stats.get("assigned", 0) if assign_stats else 0,
        }
        _notify_complete(source, result)
        # A completed sync changes counts, severities, and often decision
        # coverage. Flush the TTL cache so the next page load sees fresh data.
        from .cache import invalidate_all
        invalidate_all()
        db.close()
    return result


def _upsert_asset(db, source: str, rec: NormalizedRecord, cache: dict, stats: dict) -> int:
    key = (source, rec.asset.source_asset_id)
    if key in cache:
        return cache[key]

    row = db.execute(
        select(Asset).where(Asset.source == source,
                            Asset.source_asset_id == rec.asset.source_asset_id)
    ).scalar_one_or_none()

    a = rec.asset
    if row is None:
        row = Asset(source=source, source_asset_id=a.source_asset_id)
        db.add(row)
        stats["assets"] += 1

    row.name = a.name or row.name
    row.asset_type = a.asset_type or row.asset_type
    row.os_name = a.os_name or row.os_name
    row.ip_address = a.ip_address or row.ip_address
    row.cloud_provider = a.cloud_provider or row.cloud_provider
    row.cloud_account = a.cloud_account or row.cloud_account
    row.region = a.region or row.region
    row.owner = a.owner or row.owner
    if a.tags:
        row.tags = a.tags
    # Only overwrite enrichment fields when the source actually asserted a value.
    if a.environment is not None:
        row.environment = a.environment
    if a.internet_facing is not None:
        row.internet_facing = a.internet_facing
    if a.data_classification is not None:
        row.data_classification = a.data_classification
    row.last_seen = utcnow()

    db.flush()
    cache[key] = row.id
    return row.id


def _upsert_vuln(db, rec: NormalizedRecord, cache: dict) -> int:
    v = rec.vuln
    if v.canonical_id in cache:
        return cache[v.canonical_id]

    row = db.execute(
        select(Vuln).where(Vuln.canonical_id == v.canonical_id)
    ).scalar_one_or_none()
    if row is None:
        row = Vuln(canonical_id=v.canonical_id)
        db.add(row)

    row.cve_id = v.cve_id or row.cve_id
    row.title = v.title or row.title
    row.description = v.description or row.description
    if v.cvss_score is not None:
        row.cvss_score = v.cvss_score
    row.cvss_vector = v.cvss_vector or row.cvss_vector
    # Vulns are shared across sources; keep the highest severity anyone reports.
    from .enums import Severity
    try:
        if row.severity is None or Severity(v.severity).rank > Severity(row.severity).rank:
            row.severity = v.severity
    except ValueError:
        row.severity = v.severity
    if v.epss_score is not None:
        row.epss_score = v.epss_score
        row.epss_percentile = v.epss_percentile
    row.kev = bool(row.kev or v.kev)
    row.published_at = v.published_at or row.published_at
    row.remediation = v.remediation or row.remediation
    if v.references:
        row.references = v.references

    db.flush()
    cache[v.canonical_id] = row.id
    return row.id


@dataclass
class _SyncContext:
    started: dt.datetime
    actor: str
    run_id: int | None


def _upsert_finding(db, source: str, rec: NormalizedRecord,
                    asset_id: int, vuln_id: int, stats: dict,
                    ctx: _SyncContext) -> tuple[int, bool]:
    from .lifecycle import apply_reported_status

    row = db.execute(
        select(Finding).where(Finding.source == source,
                              Finding.source_finding_id == rec.source_finding_id)
    ).scalar_one_or_none()
    is_new = row is None
    if is_new:
        row = Finding(source=source, source_finding_id=rec.source_finding_id,
                      first_detected=rec.first_detected or ctx.started,
                      reopened_count=0)
        db.add(row)
        stats["new"] += 1

    row.asset_id = asset_id
    row.vuln_id = vuln_id
    row.category = rec.category
    row.component = rec.component
    row.component_version = rec.component_version
    row.component_key = rec.component_key
    row.location = rec.location
    row.source_severity = rec.source_severity
    row.severity = rec.severity
    row.fix_available = rec.fix_available
    row.fix_version = rec.fix_version
    row.last_seen = rec.last_seen or ctx.started
    row.last_synced_at = ctx.started
    row.source_url = rec.source_url
    row.raw = rec.raw
    db.flush()  # events need row.id

    transition = apply_reported_status(
        db, row, rec.status, is_new, utcnow(),
        actor=f"sync:{source}", sync_run_id=ctx.run_id,
        resolved_at=rec.resolved_at,
    )
    if transition == "fixed":
        stats["closed"] += 1
    elif transition == "reopened":
        stats["reopened"] += 1

    stats["findings"] += 1
    db.flush()
    return row.id, is_new


def run_sync_from_records(caller_db, source: str, records: list[NormalizedRecord],
                          actor: str = "system") -> dict:
    """Import pre-mapped NormalizedRecords (e.g. from a file upload).

    Uses its own DB session to avoid corrupting the caller's session on error.
    """
    db = SessionLocal()
    run = SyncRun(source=source, triggered_by=actor, status="running")
    db.add(run)
    db.commit()

    stats = {"assets": 0, "findings": 0, "new": 0, "closed": 0, "reopened": 0}
    new_severity: dict[str, int] = {}
    asset_cache: dict[tuple[str, str], int] = {}
    vuln_cache: dict[str, int] = {}
    ctx = _SyncContext(started=utcnow(), actor=actor, run_id=run.id)

    try:
        pending = 0
        for rec in records:
            asset_id = _upsert_asset(db, source, rec, asset_cache, stats)
            vuln_id = _upsert_vuln(db, rec, vuln_cache)
            fid, is_new = _upsert_finding(db, source, rec, asset_id, vuln_id, stats, ctx)
            if is_new:
                new_severity[rec.severity] = new_severity.get(rec.severity, 0) + 1
            pending += 1
            if pending >= BATCH:
                db.commit()
                pending = 0
        db.commit()
        run.status = "ok"
    except Exception as exc:
        db.rollback()
        run = db.get(SyncRun, run.id)
        run.status = "error"
        run.error = f"{type(exc).__name__}: {exc}"
        log.exception("File import sync failed for %s", source)
    finally:
        run = db.get(SyncRun, run.id)
        run.finished_at = utcnow()
        run.assets_upserted = stats["assets"]
        run.findings_upserted = stats["findings"]
        run.findings_new = stats["new"]
        run.findings_closed = stats["closed"]
        run.delta = {"new_by_severity": new_severity}
        db.add(AuditEvent(
            actor=actor, action="sync.file_import", entity_type="source",
            entity_id=source,
            summary=f"File import: {stats['findings']} findings ({stats['new']} new)",
        ))
        db.commit()

        result = {
            "run_id": run.id, "source": source, "status": run.status,
            "error": run.error, **stats,
            "new_by_severity": new_severity,
        }
        from .cache import invalidate_all
        invalidate_all()
        db.close()
    return result


def _mark_stale(db, source: str, run_started: dt.datetime, ctx: _SyncContext,
                exclude_categories: set[str] | None = None) -> int:
    """Close open findings this source stopped reporting, as `stale`.

    Deliberately conservative: a finding must go unreported by RiskDesk syncs
    for the full grace window before it changes state, so one truncated sync
    does not silently close a backlog. Measured against last_synced_at, not the
    source's own timestamp (rows from before that column existed fall back to
    last_seen until their next sync).
    """
    from .lifecycle import record_event

    cutoff = run_started - dt.timedelta(days=settings.stale_after_days)
    stmt = select(Finding).where(
        Finding.source == source, Finding.status == "open",
        func.coalesce(Finding.last_synced_at, Finding.last_seen) < cutoff,
    )
    if exclude_categories:
        stmt = stmt.where(Finding.category.notin_(exclude_categories))
    now = utcnow()
    rows = db.execute(stmt).scalars().all()
    for f in rows:
        f.status = "stale"
        f.closed_at = now
        record_event(db, f, "stale", "stale", f"sync:{source}", from_status="open",
                     sync_run_id=ctx.run_id, ts=now,
                     note=f"Not reported for {settings.stale_after_days}+ days")
    return len(rows)
