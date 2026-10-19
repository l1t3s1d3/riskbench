"""Ticket and Jira integration routes."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from .. import connector_config as cc_service
from ..db import get_session
from ..models import AuditEvent, Finding, Ticket, TicketFinding
from .deps import current_user

router = APIRouter(prefix="/api", tags=["tickets"])


def _serialize_ticket(t: Ticket) -> dict:
    finding_ids = [tf.finding_id for tf in t.ticket_findings] if t.ticket_findings else []
    return {
        "id": t.id,
        "external_id": t.external_id,
        "external_url": t.external_url,
        "provider": t.provider,
        "project_key": t.project_key,
        "issue_type": t.issue_type,
        "summary": t.summary,
        "description": t.description,
        "status": t.status,
        "priority": t.priority,
        "assignee": t.assignee,
        "reporter": t.reporter,
        "finding_ids": finding_ids,
        "vuln_ids": t.vuln_ids or [],
        "finding_count": t.finding_count or 0,
        "severity": t.severity,
        "created_by": t.created_by,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "updated_at": t.updated_at.isoformat() if t.updated_at else None,
        "resolved_at": t.resolved_at.isoformat() if t.resolved_at else None,
        "synced_at": t.synced_at.isoformat() if t.synced_at else None,
    }


@router.get("/tickets")
def list_tickets(
    status: str | None = None, finding_id: int | None = None,
    db=Depends(get_session),
):
    q = select(Ticket).options(joinedload(Ticket.ticket_findings))
    if status:
        q = q.where(Ticket.status == status)
    if finding_id:
        q = q.join(TicketFinding).where(TicketFinding.finding_id == finding_id)
    rows = db.execute(q.order_by(Ticket.created_at.desc())).unique().scalars().all()
    return [_serialize_ticket(t) for t in rows]


@router.get("/tickets/for-finding/{finding_id}")
def tickets_for_finding(finding_id: int, db=Depends(get_session)):
    rows = db.execute(
        select(Ticket)
        .join(TicketFinding)
        .where(TicketFinding.finding_id == finding_id)
        .options(joinedload(Ticket.ticket_findings))
        .order_by(Ticket.created_at.desc())
    ).unique().scalars().all()
    return [_serialize_ticket(t) for t in rows]


@router.get("/tickets/{ticket_id}")
def get_ticket(ticket_id: int, db=Depends(get_session)):
    t = db.execute(
        select(Ticket).options(joinedload(Ticket.ticket_findings))
        .where(Ticket.id == ticket_id)
    ).unique().scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    return _serialize_ticket(t)


@router.post("/tickets")
def create_ticket(request: Request, body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    finding_ids = body.get("finding_ids", [])
    if not finding_ids:
        raise HTTPException(422, "finding_ids is required")

    findings = db.execute(
        select(Finding).options(joinedload(Finding.vuln), joinedload(Finding.asset))
        .where(Finding.id.in_(finding_ids))
    ).unique().scalars().all()
    if not findings:
        raise HTTPException(404, "No matching findings")

    severities = [f.severity for f in findings]
    sev_order = ["critical", "high", "medium", "low", "info"]
    highest = min(severities, key=lambda s: sev_order.index(s) if s in sev_order else 99)
    vuln_ids = list({f.vuln.canonical_id for f in findings if f.vuln})

    summary = body.get("summary") or _auto_summary(findings)
    description = body.get("description") or _auto_description(findings)

    jira_config = cc_service.get_config(db, "jira")
    external_id = ""
    external_url = ""
    provider = body.get("provider", "jira")
    project_key = body.get("project_key") or jira_config.get("project_key", "")
    issue_type = body.get("issue_type") or jira_config.get("issue_type", "Bug")

    if provider == "jira" and jira_config.get("url") and jira_config.get("api_token"):
        try:
            jira_result = _create_jira_issue(
                jira_config, summary, description,
                project_key=project_key, issue_type=issue_type,
                priority=body.get("priority"),
                assignee=body.get("assignee"),
            )
            external_id = jira_result["key"]
            external_url = jira_result["url"]
        except Exception as exc:
            return JSONResponse({"ok": False, "error": f"Jira API error: {exc}"}, status_code=502)
    elif provider == "manual":
        external_id = body.get("external_id", f"MANUAL-{dt.datetime.now().strftime('%Y%m%d%H%M%S')}")
        external_url = body.get("external_url", "")
    else:
        external_id = f"DRAFT-{dt.datetime.now().strftime('%Y%m%d%H%M%S')}"

    ticket = Ticket(
        external_id=external_id,
        external_url=external_url,
        provider=provider,
        project_key=project_key,
        issue_type=issue_type,
        summary=summary,
        description=description,
        status="open",
        priority=body.get("priority", _sev_to_priority(highest)),
        assignee=body.get("assignee"),
        reporter=actor,
        vuln_ids=vuln_ids,
        finding_count=len(findings),
        severity=highest,
        created_by=actor,
    )
    db.add(ticket)
    db.flush()

    for fid in finding_ids:
        db.add(TicketFinding(ticket_id=ticket.id, finding_id=fid))

    db.add(AuditEvent(
        actor=actor, action="ticket.create",
        entity_type="ticket", entity_id=external_id,
        summary=f"Created ticket {external_id} for {len(findings)} findings",
    ))
    db.commit()
    db.refresh(ticket)
    return _serialize_ticket(ticket)


@router.put("/tickets/{ticket_id}")
def update_ticket(ticket_id: int, request: Request, body: dict = Body(...),
                  db=Depends(get_session)):
    t = db.execute(
        select(Ticket).options(joinedload(Ticket.ticket_findings))
        .where(Ticket.id == ticket_id)
    ).unique().scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    actor = current_user(request)
    for field in ("status", "assignee", "priority", "external_id", "external_url"):
        if field in body:
            setattr(t, field, body[field])
    if body.get("status") in ("resolved", "closed"):
        t.resolved_at = dt.datetime.now(dt.timezone.utc)
    db.add(AuditEvent(
        actor=actor, action="ticket.update",
        entity_type="ticket", entity_id=t.external_id,
        summary=f"Updated ticket {t.external_id}: {', '.join(body.keys())}",
    ))
    db.commit()
    return _serialize_ticket(t)


@router.post("/tickets/{ticket_id}/sync")
def sync_ticket_status(ticket_id: int, request: Request, db=Depends(get_session)):
    t = db.execute(
        select(Ticket).options(joinedload(Ticket.ticket_findings))
        .where(Ticket.id == ticket_id)
    ).unique().scalar_one_or_none()
    if not t:
        raise HTTPException(404)
    if t.provider != "jira":
        return {"ok": True, "message": "Only Jira tickets can be synced"}
    jira_config = cc_service.get_config(db, "jira")
    if not jira_config.get("url") or not jira_config.get("api_token"):
        raise HTTPException(422, "Jira not configured")
    try:
        issue = _fetch_jira_issue(jira_config, t.external_id)
        fields = issue.get("fields", {})
        t.status = (fields.get("status", {}).get("name", "open")).lower().replace(" ", "_")
        t.assignee = (fields.get("assignee") or {}).get("displayName")
        t.priority = (fields.get("priority") or {}).get("name")
        resolution = fields.get("resolution")
        if resolution and not t.resolved_at:
            t.resolved_at = dt.datetime.now(dt.timezone.utc)
        t.synced_at = dt.datetime.now(dt.timezone.utc)
        db.commit()
        return {"ok": True, "ticket": _serialize_ticket(t)}
    except Exception as exc:
        return JSONResponse({"ok": False, "error": str(exc)}, status_code=502)


@router.post("/tickets/sync-all")
def sync_all_tickets(request: Request, db=Depends(get_session)):
    """Sync status for all open Jira tickets."""
    from ..ticket_sync import sync_open_jira_tickets
    result = sync_open_jira_tickets(db, actor=current_user(request))
    return result


def _create_jira_issue(config: dict, summary: str, description: str, *,
                       project_key: str, issue_type: str,
                       priority: str | None = None,
                       assignee: str | None = None) -> dict:
    import httpx, base64
    auth = base64.b64encode(f"{config['email']}:{config['api_token']}".encode()).decode()
    url = config["url"].rstrip("/")
    payload: dict = {
        "fields": {
            "project": {"key": project_key},
            "summary": summary,
            "description": description,
            "issuetype": {"name": issue_type},
        }
    }
    if priority:
        payload["fields"]["priority"] = {"name": priority}
    if assignee:
        payload["fields"]["assignee"] = {"accountId": assignee}
    r = httpx.post(
        f"{url}/rest/api/2/issue",
        json=payload,
        headers={"Authorization": f"Basic {auth}", "Content-Type": "application/json"},
        timeout=30,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"Jira {r.status_code}: {r.text[:300]}")
    data = r.json()
    return {"key": data["key"], "url": f"{url}/browse/{data['key']}"}


def _fetch_jira_issue(config: dict, issue_key: str) -> dict:
    import re, httpx, base64
    if not re.match(r'^[A-Z][A-Z0-9_]+-\d+$', issue_key):
        raise ValueError(f"Invalid Jira issue key: {issue_key!r}")
    auth = base64.b64encode(f"{config['email']}:{config['api_token']}".encode()).decode()
    url = config["url"].rstrip("/")
    r = httpx.get(
        f"{url}/rest/api/2/issue/{issue_key}",
        headers={"Authorization": f"Basic {auth}"},
        timeout=30,
    )
    if r.status_code >= 400:
        raise RuntimeError(f"Jira {r.status_code}: {r.text[:300]}")
    return r.json()


def _auto_summary(findings) -> str:
    vulns = {f.vuln.canonical_id for f in findings if f.vuln}
    assets = {f.asset.name for f in findings if f.asset}
    if len(vulns) == 1:
        v = list(vulns)[0]
        return f"[{findings[0].severity.upper()}] {v} on {len(assets)} asset(s)"
    return f"[{findings[0].severity.upper()}] {len(vulns)} vulnerabilities on {len(assets)} asset(s)"


def _auto_description(findings) -> str:
    lines = ["Vulnerability findings from RiskDesk:\n"]
    by_vuln: dict = {}
    for f in findings:
        vid = f.vuln.canonical_id if f.vuln else "unknown"
        by_vuln.setdefault(vid, []).append(f)
    for vid, flist in list(by_vuln.items())[:20]:
        sev = flist[0].severity
        title = flist[0].vuln.title if flist[0].vuln else vid
        lines.append(f"* *{vid}* ({sev}) - {title}")
        for f in flist[:5]:
            asset = f.asset.name if f.asset else "unknown"
            comp = f.component or ""
            lines.append(f"  - {asset} {comp}")
        if len(flist) > 5:
            lines.append(f"  - ...and {len(flist) - 5} more")
    lines.append(f"\nTotal findings: {len(findings)}")
    return "\n".join(lines)


def _sev_to_priority(severity: str) -> str:
    return {"critical": "P1", "high": "P2", "medium": "P3", "low": "P4", "info": "P4"}.get(severity, "P3")
