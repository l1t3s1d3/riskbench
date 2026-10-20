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
                          actor: str, sync_run_id: int | None) -> str | None:
    """Apply the status a source reported. Returns "fixed" or "reopened" when the
    report closed or reopened the finding, else None."""
    prev = row.status
    if is_new:
        row.status = reported
        if reported in CLOSED_STATUSES:
            row.closed_at = now
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

    if reported == FindingStatus.FIXED.value:
        if prev == FindingStatus.VERIFIED_FIXED.value:
            return None  # a human already verified; the source agreeing changes nothing
        if prev == FindingStatus.FIXED.value:
            return None
        row.status = reported
        if row.closed_at is None:
            row.closed_at = now
        record_event(db, row, "fixed", reported, actor, from_status=prev,
                     sync_run_id=sync_run_id, ts=now, note="Source reported the finding resolved")
        return "fixed" if prev not in CLOSED_STATUSES else None

    if prev != reported:
        row.status = reported
        if reported in CLOSED_STATUSES and row.closed_at is None:
            row.closed_at = now
        record_event(db, row, "status_change", reported, actor, from_status=prev,
                     sync_run_id=sync_run_id, ts=now)
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


def _aware(value: dt.datetime | None) -> dt.datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


def _iso(value: dt.datetime | None) -> str | None:
    v = _aware(value)
    return v.isoformat() if v else None
