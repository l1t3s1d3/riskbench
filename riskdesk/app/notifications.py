"""SLA breach notification dispatcher.

Sends alerts when findings go overdue via Slack webhook and/or email.
Configure with environment variables:
  RISKDESK_SLACK_WEBHOOK   - Slack incoming webhook URL
  RISKDESK_SMTP_HOST       - SMTP server hostname
  RISKDESK_SMTP_PORT       - SMTP port (default 587)
  RISKDESK_EMAIL_FROM      - Sender address
  RISKDESK_EMAIL_TO        - Comma-separated recipient list
"""
from __future__ import annotations

import logging
import smtplib
from email.message import EmailMessage

import httpx
from sqlalchemy import select
from sqlalchemy.orm import joinedload

from .config import settings
from .models import Asset, Finding, Vuln, utcnow
from .queries import build_resolution_map
from .enums import Disposition
from .risk import compute_risk, sla_status

log = logging.getLogger(__name__)


def check_sla_breaches(db) -> dict:
    """Scan open findings for SLA breaches and return a summary."""
    now = utcnow()
    resolution = build_resolution_map(db, now)

    rows = db.execute(
        select(Finding)
        .options(joinedload(Finding.asset), joinedload(Finding.vuln))
        .where(Finding.status == "open")
    ).scalars().all()

    overdue: list[dict] = []
    by_severity: dict[str, int] = {}
    by_priority: dict[str, int] = {}

    for f in rows:
        adj = resolution.get(f.id)
        if adj and adj.disposition in (
            Disposition.ACCEPT_RISK.value, Disposition.FALSE_POSITIVE.value
        ):
            continue

        eff_sev = f.severity
        if adj and adj.disposition == Disposition.ADJUST_RISK.value and adj.adjusted_severity:
            eff_sev = adj.adjusted_severity

        due, is_overdue = sla_status(f.first_detected, eff_sev,
                                     bool(f.vuln and f.vuln.kev), adj, now)
        if not is_overdue:
            continue

        days_over = (now - due).days
        risk = compute_risk(f, adj, now=now)

        overdue.append({
            "finding_id": f.id,
            "canonical_id": f.vuln.canonical_id if f.vuln else "unknown",
            "asset_name": f.asset.name if f.asset else "unknown",
            "severity": eff_sev,
            "priority": risk.priority,
            "sla_due": due.isoformat(),
            "days_overdue": days_over,
            "disposition": adj.disposition if adj else None,
        })
        by_severity[eff_sev] = by_severity.get(eff_sev, 0) + 1
        by_priority[risk.priority] = by_priority.get(risk.priority, 0) + 1

    overdue.sort(key=lambda x: (-x["days_overdue"], x["severity"]))

    return {
        "total_overdue": len(overdue),
        "by_severity": by_severity,
        "by_priority": by_priority,
        "findings": overdue[:500],
    }


def send_sla_notifications(db) -> dict:
    """Check for SLA breaches and notify if any exist."""
    report = check_sla_breaches(db)
    if report["total_overdue"] == 0:
        return {**report, "notification_sent": False}

    cfg = settings.notifications
    sent = False

    if cfg.slack_webhook_url:
        try:
            _send_slack(cfg.slack_webhook_url, report)
            sent = True
        except Exception:
            log.exception("Slack SLA notification failed")

    if cfg.email_smtp_host and cfg.email_from and cfg.email_to:
        try:
            _send_email(cfg, report)
            sent = True
        except Exception:
            log.exception("Email SLA notification failed")

    return {**report, "notification_sent": sent}


def _send_slack(webhook_url: str, report: dict):
    sev_line = ", ".join(f"{k}: {v}" for k, v in sorted(report["by_severity"].items()))
    pri_line = ", ".join(f"{k}: {v}" for k, v in sorted(report["by_priority"].items()))

    top = report["findings"][:10]
    finding_lines = "\n".join(
        f"  - `{f['canonical_id']}` on *{f['asset_name']}* "
        f"({f['severity']}, {f['priority']}) — {f['days_overdue']}d overdue"
        for f in top
    )

    text = (
        f":warning: *RiskDesk SLA Breach Report*\n"
        f"*{report['total_overdue']}* findings are past their remediation SLA.\n\n"
        f"*By severity:* {sev_line}\n"
        f"*By priority:* {pri_line}\n\n"
        f"*Top overdue findings:*\n{finding_lines}"
    )
    if report["total_overdue"] > 10:
        text += f"\n  _…and {report['total_overdue'] - 10} more_"

    httpx.post(webhook_url, json={"text": text}, timeout=30)
    log.info("Slack SLA notification sent (%d overdue)", report["total_overdue"])


def _send_email(cfg, report: dict):
    msg = EmailMessage()
    msg["Subject"] = f"[RiskDesk] {report['total_overdue']} findings past SLA"
    msg["From"] = cfg.email_from
    msg["To"] = ", ".join(cfg.email_to)

    sev_line = ", ".join(f"{k}: {v}" for k, v in sorted(report["by_severity"].items()))
    pri_line = ", ".join(f"{k}: {v}" for k, v in sorted(report["by_priority"].items()))

    top = report["findings"][:25]
    rows = "\n".join(
        f"  {f['canonical_id']:30s}  {f['asset_name']:30s}  "
        f"{f['severity']:10s}  {f['priority']:4s}  {f['days_overdue']}d overdue"
        for f in top
    )

    body = (
        f"RiskDesk SLA Breach Report\n"
        f"{'=' * 40}\n\n"
        f"Total overdue findings: {report['total_overdue']}\n"
        f"By severity: {sev_line}\n"
        f"By priority: {pri_line}\n\n"
        f"Top overdue findings:\n{rows}\n"
    )
    if report["total_overdue"] > 25:
        body += f"\n  …and {report['total_overdue'] - 25} more\n"

    msg.set_content(body)
    with smtplib.SMTP(cfg.email_smtp_host, cfg.email_smtp_port) as s:
        s.ehlo()
        if cfg.email_smtp_port != 25:
            s.starttls()
        s.send_message(msg)

    log.info("Email SLA notification sent to %s (%d overdue)",
             cfg.email_to, report["total_overdue"])
