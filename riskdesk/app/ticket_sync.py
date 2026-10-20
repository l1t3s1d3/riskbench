"""Periodic Jira ticket status sync.

Called by the scheduler and by the manual sync-all endpoint.
Fetches current status for all open Jira tickets and updates local records.
"""
from __future__ import annotations

import datetime as dt
import logging
import re

import httpx

from sqlalchemy import select
from sqlalchemy.orm import joinedload

from . import connector_config as cc_service
from .models import AuditEvent, Ticket, TicketFinding, utcnow

log = logging.getLogger(__name__)

_JIRA_KEY_RE = re.compile(r'^[A-Z][A-Z0-9_]+-\d+$')

# Local statuses that mean the ticket is finished. Jira workflows name their
# final state differently, so Jira closure is read from resolution/statusCategory.
TICKET_CLOSED_STATUSES = {"resolved", "closed", "done", "won't_fix", "wont_fix", "fixed"}

# Keep re-checking resolved tickets this long so a reopen in Jira is noticed.
REOPEN_WATCH_DAYS = 30


def set_ticket_status(db, ticket: Ticket, new_status: str, actor: str,
                      closed: bool | None = None) -> bool:
    """Apply a status change, keep resolved_at consistent, and audit it.
    `closed` overrides the status-name check (Jira resolution). Returns True if changed."""
    is_closed = closed if closed is not None else new_status in TICKET_CLOSED_STATUSES
    old_status = ticket.status
    was_closed = ticket.resolved_at is not None
    ticket.status = new_status
    if is_closed and not was_closed:
        ticket.resolved_at = utcnow()
    elif not is_closed and was_closed:
        ticket.resolved_at = None
    if old_status == new_status and is_closed == was_closed:
        return False
    action = ("ticket.resolved" if is_closed and not was_closed
              else "ticket.reopened" if was_closed and not is_closed
              else "ticket.status")
    db.add(AuditEvent(
        actor=actor, action=action, entity_type="ticket", entity_id=ticket.external_id,
        summary=f"Ticket {ticket.external_id}: {old_status} → {new_status}",
        detail={"ticket_id": ticket.id, "from": old_status, "to": new_status},
    ))
    return True


def sync_open_jira_tickets(db, *, actor: str = "scheduler") -> dict:
    """Sync status for open (and recently resolved) Jira tickets."""
    jira_config = cc_service.get_config(db, "jira")
    if not jira_config.get("url") or not jira_config.get("api_token"):
        return {"ok": False, "error": "Jira not configured", "synced": 0}

    watch_from = utcnow() - dt.timedelta(days=REOPEN_WATCH_DAYS)
    open_tickets = db.execute(
        select(Ticket)
        .options(joinedload(Ticket.ticket_findings))
        .where(Ticket.provider == "jira",
               (Ticket.resolved_at.is_(None)) | (Ticket.resolved_at >= watch_from))
    ).unique().scalars().all()

    if not open_tickets:
        return {"ok": True, "synced": 0, "message": "No open Jira tickets to sync"}

    synced = 0
    errors = []

    for ticket in open_tickets:
        if not _JIRA_KEY_RE.match(ticket.external_id):
            errors.append({"ticket_id": ticket.id, "error": f"Invalid key: {ticket.external_id}"})
            continue
        try:
            sync_one(db, ticket, jira_config, actor=actor)
            synced += 1
        except Exception as exc:
            log.warning("Failed to sync ticket %s: %s", ticket.external_id, exc)
            errors.append({"ticket_id": ticket.id, "external_id": ticket.external_id, "error": str(exc)})

    db.add(AuditEvent(
        actor=actor, action="ticket.sync_all",
        entity_type="ticket", entity_id="all",
        summary=f"Synced {synced} Jira tickets, {len(errors)} errors",
    ))
    db.commit()

    return {"ok": True, "synced": synced, "errors": errors[:20], "total_open": len(open_tickets)}


def sync_one(db, ticket: Ticket, jira_config: dict, actor: str = "scheduler") -> None:
    """Fetch current Jira status for a single ticket and update the local record."""
    import base64

    if not _JIRA_KEY_RE.match(ticket.external_id or ""):
        raise ValueError(f"Invalid Jira issue key: {ticket.external_id!r}")
    auth = base64.b64encode(
        f"{jira_config['email']}:{jira_config['api_token']}".encode()
    ).decode()
    url = jira_config["url"].rstrip("/")

    r = httpx.get(
        f"{url}/rest/api/2/issue/{ticket.external_id}",
        headers={"Authorization": f"Basic {auth}"},
        timeout=30,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"Jira {r.status_code}: {r.text[:300]}")
    apply_jira_fields(db, ticket, r.json().get("fields", {}), actor)


def apply_jira_fields(db, ticket: Ticket, fields: dict, actor: str) -> None:
    status = fields.get("status") or {}
    new_status = (status.get("name") or "open").lower().replace(" ", "_")
    category = ((status.get("statusCategory") or {}).get("key") or "").lower()
    closed = bool(fields.get("resolution")) or category == "done"
    set_ticket_status(db, ticket, new_status, actor, closed=closed)
    ticket.assignee = (fields.get("assignee") or {}).get("displayName")
    ticket.priority = (fields.get("priority") or {}).get("name")
    ticket.synced_at = utcnow()
