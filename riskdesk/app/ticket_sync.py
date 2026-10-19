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


def sync_open_jira_tickets(db, *, actor: str = "scheduler") -> dict:
    """Sync status for all open Jira tickets. Returns a summary dict."""
    jira_config = cc_service.get_config(db, "jira")
    if not jira_config.get("url") or not jira_config.get("api_token"):
        return {"ok": False, "error": "Jira not configured", "synced": 0}

    open_tickets = db.execute(
        select(Ticket)
        .options(joinedload(Ticket.ticket_findings))
        .where(Ticket.provider == "jira", Ticket.status.notin_(["resolved", "closed"]))
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
            _sync_one(db, ticket, jira_config)
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


def _sync_one(db, ticket: Ticket, jira_config: dict) -> None:
    """Fetch current Jira status for a single ticket and update the local record."""
    import base64

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

    fields = r.json().get("fields", {})
    new_status = (fields.get("status", {}).get("name", "open")).lower().replace(" ", "_")
    ticket.status = new_status
    ticket.assignee = (fields.get("assignee") or {}).get("displayName")
    ticket.priority = (fields.get("priority") or {}).get("name")

    resolution = fields.get("resolution")
    if resolution and not ticket.resolved_at:
        ticket.resolved_at = dt.datetime.now(dt.timezone.utc)

    ticket.synced_at = dt.datetime.now(dt.timezone.utc)
