"""Seed a handful of starter decision templates on first startup.

Templates are the house pattern for the 80% of decisions that share a shape
(accept on lab, false-positive on vendor-signed binary, adjust for internal
network). An operator can edit or delete them freely; this seed only runs
when the table is empty, so edits are never clobbered by a restart.
"""
from __future__ import annotations

import logging

from sqlalchemy import select

from .models import DecisionTemplate

log = logging.getLogger(__name__)


SEEDS = [
    {
        "name": "Accept — lab / non-production",
        "description": "Standard acceptance for development or lab environments where exposure is contained.",
        "disposition": "accept_risk",
        "scope": "vuln_on_asset",
        "justification_text": (
            "Asset is in a lab / non-production environment with no customer "
            "data and no production dependencies. Exposure is contained; "
            "scheduled for remediation during the next quarterly maintenance "
            "window. Risk is accepted for the stated period."
        ),
        "expiry_days": 90,
    },
    {
        "name": "Accept — compensating WAF rule",
        "description": "Exploit path is blocked by a WAF rule; the vulnerability itself is not patched.",
        "disposition": "accept_risk",
        "scope": "vuln",
        "justification_text": (
            "Known exploit path for this vulnerability is blocked by an "
            "active WAF rule / IPS signature. No observed attempts in logs "
            "for the acceptance window. Patch pending in vendor backlog; "
            "rule will stay in force until the patch ships."
        ),
        "compensating_controls": "WAF rule (ID: FILL-IN) blocking known exploit path",
        "expiry_days": 180,
    },
    {
        "name": "False positive — vendor-signed binary",
        "description": "Scanner flagged a legitimate vendor binary as vulnerable; verified not affected.",
        "disposition": "false_positive",
        "scope": "vuln_on_asset",
        "justification_text": (
            "Binary is vendor-signed and matches the published hash for a "
            "patched version. The scanner's version match is incorrect "
            "because the vendor backports security fixes without bumping the "
            "version string. Verified by comparing file hash against vendor "
            "advisory."
        ),
        "expiry_days": 365,
    },
    {
        "name": "False positive — code path unreachable",
        "description": "Vulnerable code exists in a dependency but the affected API is never called.",
        "disposition": "false_positive",
        "scope": "vuln",
        "justification_text": (
            "Dependency contains the vulnerable code path, but the affected "
            "function / API is not invoked from this codebase. Verified by "
            "static analysis and grep of call sites. Documented for future "
            "re-review if usage patterns change."
        ),
        "expiry_days": 180,
    },
    {
        "name": "Adjust — internal network only, medium",
        "description": "Vulnerability requires network access that only internal admins have.",
        "disposition": "adjust_risk",
        "scope": "vuln_on_asset",
        "justification_text": (
            "Exploit requires authenticated access to an internal management "
            "interface that is network-segmented and accessible only to "
            "operations staff from jump hosts. Treating as medium severity "
            "for prioritisation while patch is scheduled."
        ),
        "adjusted_severity": "medium",
        "expiry_days": 180,
    },
    {
        "name": "Fix immediately — critical production",
        "description": "Routing: critical vuln on production that needs immediate work.",
        "disposition": "fix_immediately",
        "scope": "finding",
        "justification_text": (
            "Critical vulnerability on production asset. Owning team to "
            "patch or mitigate within the remediation window below."
        ),
        "remediation_days": 7,
    },
    {
        "name": "Complex resolution — architectural change",
        "description": "Routing: vuln requires a redesign, not a patch.",
        "disposition": "complex_resolution",
        "scope": "finding",
        "justification_text": (
            "Fix requires architectural change (library replacement, API "
            "migration, data model update). Owning team to scope the work "
            "and propose a plan; interim compensating controls to be "
            "documented in a follow-up decision."
        ),
        "remediation_days": 90,
    },
    {
        "name": "Developer review — needs context",
        "description": "Routing: owning engineer should triage before security decides.",
        "disposition": "developer_review",
        "scope": "finding",
        "justification_text": (
            "Needs owning developer to confirm whether the vulnerable code "
            "path is used and whether a fix is straightforward. Security "
            "will adjudicate based on the developer's response."
        ),
        "remediation_days": 14,
    },
]


def seed_defaults(db) -> int:
    """Seed starter templates if none exist. Returns the number inserted."""
    existing = db.execute(select(DecisionTemplate.id).limit(1)).scalar()
    if existing is not None:
        return 0
    for t in SEEDS:
        db.add(DecisionTemplate(created_by="system", **t))
    db.commit()
    log.info("Seeded %d default decision templates", len(SEEDS))
    return len(SEEDS)
