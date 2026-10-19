"""Background scheduler.

A single daemon thread that wakes every 60 seconds, checks which sources are
due for a sync, and runs them. This is deliberately simple -- no APScheduler
dependency, no distributed locking, no retry queue. It is correct for a single
instance, which is how this application runs.

If you move to multiple instances, replace this with a proper scheduler or a
cron-based approach and disable the background thread via
RISKDESK_SCHEDULER_ENABLED=0.
"""
from __future__ import annotations

import datetime as dt
import logging
import os
import threading
import time

from sqlalchemy import select

from .db import SessionLocal
from .models import AuditEvent, SyncSchedule, utcnow

log = logging.getLogger(__name__)

_thread: threading.Thread | None = None
_stop = threading.Event()

TICK_SECONDS = 60


def start():
    """Start the background scheduler. Idempotent."""
    global _thread
    if os.getenv("RISKDESK_SCHEDULER_ENABLED", "1") == "0":
        log.info("Scheduler disabled by RISKDESK_SCHEDULER_ENABLED=0")
        return
    if _thread is not None and _thread.is_alive():
        return
    _stop.clear()
    _thread = threading.Thread(target=_loop, daemon=True, name="riskdesk-scheduler")
    _thread.start()
    log.info("Background scheduler started (tick every %ds)", TICK_SECONDS)


def stop():
    _stop.set()
    if _thread is not None:
        _thread.join(timeout=10)


def _loop():
    while not _stop.is_set():
        try:
            _tick()
        except Exception:
            log.exception("Scheduler tick failed")
        _stop.wait(TICK_SECONDS)


def _tick():
    db = SessionLocal()
    try:
        now = utcnow()
        schedules = db.execute(
            select(SyncSchedule).where(SyncSchedule.enabled.is_(True))
        ).scalars().all()

        for sched in schedules:
            if _is_due(sched, now):
                _run_scheduled(db, sched, now)

        _maybe_sync_tickets(db, now)
    finally:
        db.close()


_last_ticket_sync: dt.datetime | None = None
TICKET_SYNC_INTERVAL_HOURS = 1


def _maybe_sync_tickets(db, now: dt.datetime):
    """Sync open Jira tickets at most once per TICKET_SYNC_INTERVAL_HOURS."""
    global _last_ticket_sync
    if _last_ticket_sync is not None:
        elapsed = (now - _last_ticket_sync).total_seconds() / 3600
        if elapsed < TICKET_SYNC_INTERVAL_HOURS:
            return
    try:
        from .ticket_sync import sync_open_jira_tickets
        result = sync_open_jira_tickets(db, actor="scheduler:ticket_sync")
        _last_ticket_sync = now
        if result.get("synced", 0) > 0:
            log.info("Ticket sync: %d tickets synced", result["synced"])
    except Exception:
        log.exception("Scheduled ticket sync failed")


def _is_due(sched: SyncSchedule, now: dt.datetime) -> bool:
    """Check whether this schedule should fire now."""
    if sched.next_run_at is not None:
        next_run = sched.next_run_at
        if next_run.tzinfo is None:
            next_run = next_run.replace(tzinfo=dt.timezone.utc)
        return now >= next_run

    # No next_run_at set yet -- due immediately if never run, or if the
    # interval has elapsed since the last run.
    if sched.last_run_at is None:
        return True
    last = sched.last_run_at
    if last.tzinfo is None:
        last = last.replace(tzinfo=dt.timezone.utc)
    return now >= last + dt.timedelta(hours=sched.interval_hours)


def _compute_next(sched: SyncSchedule, now: dt.datetime) -> dt.datetime:
    """When this schedule should fire next."""
    base = now + dt.timedelta(hours=sched.interval_hours)
    if sched.preferred_hour_utc is not None:
        # Snap to the preferred hour on the next qualifying day.
        candidate = base.replace(
            hour=sched.preferred_hour_utc, minute=0, second=0, microsecond=0
        )
        if candidate <= now:
            candidate += dt.timedelta(days=1)
        return candidate
    return base


def _run_scheduled(db, sched: SyncSchedule, now: dt.datetime):
    """Execute one scheduled sync."""
    from .sync import get_connector, run_sync
    from .assignment import evaluate_rules

    source = sched.source
    connector = get_connector(source)
    if not connector.configured():
        log.warning("Scheduled sync for %s skipped: not configured", source)
        sched.last_status = "skipped"
        sched.last_error = "Source not configured"
        sched.next_run_at = _compute_next(sched, now)
        db.commit()
        return

    log.info("Scheduled sync starting for %s", source)
    sched.last_run_at = now
    sched.last_status = "running"
    sched.last_error = None
    db.commit()

    try:
        result = run_sync(source, demo=False, limit=sched.limit,
                          actor=f"scheduler:{sched.created_by or 'system'}")

        sched.last_status = result.get("status", "error")
        sched.last_error = result.get("error")

        # Run assignment rules against new findings
        if result.get("status") == "ok" and result.get("new", 0) > 0:
            try:
                assign_result = evaluate_rules(
                    db, source=source,
                    actor=f"scheduler:{sched.created_by or 'system'}"
                )
                log.info("Auto-assignment after %s sync: %d assigned",
                         source, assign_result.get("assigned", 0))
            except Exception:
                log.exception("Auto-assignment failed after %s sync", source)

        log.info("Scheduled sync for %s finished: %s", source, sched.last_status)
    except Exception as exc:
        sched.last_status = "error"
        sched.last_error = f"{type(exc).__name__}: {exc}"
        log.exception("Scheduled sync for %s failed", source)

    sched.next_run_at = _compute_next(sched, now)

    db.add(AuditEvent(
        actor="scheduler", action="sync.scheduled",
        entity_type="source", entity_id=source,
        summary=f"Scheduled sync: {sched.last_status}",
        detail={"interval_hours": sched.interval_hours,
                "next_run": sched.next_run_at.isoformat() if sched.next_run_at else None,
                "error": sched.last_error},
    ))
    db.commit()
