"""Risk engine.

Two jobs:

1. Scope resolution -- given a finding, which approved decision governs it?
   Decisions attach to scopes, not rows, so one "accept risk" on CVE-2021-1234
   covers every current and future finding for that CVE until it expires.

2. Effective risk -- what the finding's severity and priority are *after* any
   approved adjustment, plus a transparent breakdown of what fed the priority.

The breakdown is deliberately explicit about missing inputs. EPSS, verified
internet exposure and data classification are not currently wired to a feed;
the engine reports those factors as "not applied - no data" rather than
silently defaulting them, so a priority number is never more confident than
the data behind it.
"""
from __future__ import annotations

import datetime as dt
from collections import defaultdict
from dataclasses import dataclass, field

from .config import settings
from .enums import CLOSED_STATUSES, SCOPE_PRECEDENCE, Disposition, ScopeType, Severity
from .models import Adjudication, Finding, utcnow


# --- Scope keys -------------------------------------------------------------

def scope_keys_for_finding(finding: Finding) -> list[tuple[str, str]]:
    """Every scope key that could govern this finding, most specific first."""
    keys: list[tuple[str, str]] = [(ScopeType.FINDING.value, str(finding.id))]
    canonical = finding.vuln.canonical_id if finding.vuln else None
    if canonical:
        keys.append((ScopeType.VULN_ON_ASSET.value, f"{canonical}::{finding.asset_id}"))
        keys.append((ScopeType.VULN.value, canonical))
    if finding.component_key:
        keys.append((ScopeType.COMPONENT.value, finding.component_key))
    return keys


class AdjudicationIndex:
    """In-memory index of approved decisions, keyed by scope.

    There are orders of magnitude fewer decisions than findings, so loading all
    active ones once per request is far cheaper than a correlated subquery per
    row, and it keeps precedence logic in one readable place.
    """

    def __init__(self, adjudications: list[Adjudication], now: dt.datetime | None = None):
        self.now = now or utcnow()
        self._by_scope: dict[tuple[str, str], Adjudication] = {}
        # Pending decisions are surfaced in the UI but do not change risk.
        self._pending: dict[tuple[str, str], list[Adjudication]] = defaultdict(list)
        for a in adjudications:
            key = (a.scope_type, a.scope_key)
            if a.is_active(self.now):
                prior = self._by_scope.get(key)
                # Most recently decided wins within the same scope.
                if prior is None or (a.decided_at or a.requested_at) > (prior.decided_at or prior.requested_at):
                    self._by_scope[key] = a
            elif a.state == "pending_approval":
                self._pending[key].append(a)

    def resolve(self, finding: Finding) -> Adjudication | None:
        for key in scope_keys_for_finding(finding):
            hit = self._by_scope.get(key)
            if hit is not None:
                return hit
        return None

    def pending_for(self, finding: Finding) -> list[Adjudication]:
        out = []
        for key in scope_keys_for_finding(finding):
            out.extend(self._pending.get(key, []))
        return out

    @classmethod
    def load(cls, db, now: dt.datetime | None = None) -> "AdjudicationIndex":
        rows = db.query(Adjudication).filter(
            Adjudication.state.in_(["approved", "pending_approval"])
        ).all()
        return cls(rows, now=now)


# --- Priority scoring -------------------------------------------------------

@dataclass
class Factor:
    name: str
    applied: bool
    points: float = 0.0
    note: str = ""


@dataclass
class RiskView:
    """Everything the UI needs to render one finding's risk, and why."""
    base_severity: str
    effective_severity: str
    adjusted: bool
    priority: str                      # P1..P4
    score: float                       # 0-100
    factors: list[Factor] = field(default_factory=list)
    unknown_inputs: list[str] = field(default_factory=list)
    disposition: str | None = None
    adjudication_id: int | None = None
    adjudication_state: str | None = None
    expires_at: dt.datetime | None = None
    review_due: dt.datetime | None = None
    sla_due: dt.datetime | None = None
    sla_overdue: bool = False
    has_pending: bool = False


_SEVERITY_BASE = {
    "critical": 70.0, "high": 55.0, "medium": 35.0, "low": 18.0, "info": 5.0,
}


def compute_risk(finding: Finding, adj: Adjudication | None,
                 has_pending: bool = False, now: dt.datetime | None = None) -> RiskView:
    now = now or utcnow()
    base_sev = finding.severity
    eff_sev = base_sev
    adjusted = False

    if adj is not None and adj.disposition == Disposition.ADJUST_RISK.value and adj.adjusted_severity:
        eff_sev = adj.adjusted_severity
        adjusted = True

    factors: list[Factor] = []
    unknown: list[str] = []

    score = _SEVERITY_BASE.get(eff_sev, 5.0)
    factors.append(Factor(
        "Severity baseline", True, score,
        f"Effective severity {eff_sev}" + (f" (adjusted from {base_sev})" if adjusted else ""),
    ))

    v = finding.vuln

    # CISA KEV - known exploited. Strongest single signal we actually hold.
    if v and v.kev:
        score += 20
        factors.append(Factor("CISA KEV listed", True, 20, "Known exploited in the wild"))
    else:
        factors.append(Factor("CISA KEV listed", True, 0, "Not on the KEV catalog"))

    # EPSS - probability of exploitation, scaled by percentile when available.
    if v and v.epss_score is not None:
        epss = min(v.epss_score, 1.0)
        if epss >= 0.7:
            pts = 15.0
        elif epss >= 0.4:
            pts = round(10.0 + (epss - 0.4) / 0.3 * 5.0, 1)
        else:
            pts = round(epss / 0.4 * 10.0, 1)
        score += pts
        pct_note = f", {v.epss_percentile:.0%} percentile" if v.epss_percentile else ""
        factors.append(Factor("EPSS probability", True, pts, f"EPSS {epss:.3f}{pct_note}"))
    else:
        factors.append(Factor("EPSS probability", False, 0, "No EPSS feed connected"))
        unknown.append("EPSS score")

    # KEV + EPSS synergy: actively exploited AND high exploitation probability.
    if v and v.kev and v.epss_score is not None and v.epss_score >= 0.4:
        synergy = 8
        score += synergy
        factors.append(Factor(
            "KEV+EPSS synergy", True, synergy,
            "Both actively exploited and high predicted exploitation probability",
        ))
    elif v and v.kev and v.epss_score is not None:
        factors.append(Factor("KEV+EPSS synergy", True, 0, "KEV listed but EPSS below synergy threshold"))

    # Internet exposure - null unless something reliable populated it.
    exposed = finding.asset.internet_facing if finding.asset else None
    if exposed is True:
        score += 12
        factors.append(Factor("Internet exposure", True, 12, "Asset is internet facing"))
    elif exposed is False:
        factors.append(Factor("Internet exposure", True, 0, "Asset is internal only"))
    else:
        factors.append(Factor("Internet exposure", False, 0, "Exposure not determined for this asset"))
        unknown.append("Internet-facing status")

    # Environment.
    env = (finding.asset.environment if finding.asset else None) or "unknown"
    if env == "production":
        score += 8
        factors.append(Factor("Environment", True, 8, "Production asset"))
    elif env == "non_production":
        factors.append(Factor("Environment", True, 0, "Non-production asset"))
    else:
        factors.append(Factor("Environment", False, 0, "Environment not tagged"))
        unknown.append("Environment tag")

    # Data classification.
    if finding.asset and finding.asset.data_classification:
        cls_ = finding.asset.data_classification.lower()
        pts = 10 if cls_ in ("restricted", "confidential", "fci", "cui") else 0
        score += pts
        factors.append(Factor("Data classification", True, pts, finding.asset.data_classification))
    else:
        factors.append(Factor("Data classification", False, 0, "Asset data classification unavailable"))
        unknown.append("Data classification")

    # A fix being available does not raise risk, but it removes the excuse.
    if finding.fix_available:
        score += 5
        factors.append(Factor("Fix available", True, 5, f"Fixed in {finding.fix_version or 'a released version'}"))
    else:
        factors.append(Factor("Fix available", True, 0, "No vendor fix published"))

    score = round(max(0.0, min(100.0, score)), 1)

    # Accepted risk is still tracked and still scored, but it sorts to the
    # bottom of the work queue rather than disappearing.
    if adj is not None and adj.disposition in (
        Disposition.ACCEPT_RISK.value, Disposition.FALSE_POSITIVE.value
    ):
        priority = "P4"
    elif adj is not None and adj.adjusted_priority:
        priority = adj.adjusted_priority
    elif adj is not None and adj.disposition == Disposition.FIX_IMMEDIATELY.value:
        priority = "P1"
    else:
        priority = ("P1" if score >= 80 else "P2" if score >= 60
                    else "P3" if score >= 35 else "P4")
        # Auto-escalate: KEV + high EPSS forces at least P1 regardless of score.
        if v and v.kev and v.epss_score is not None and v.epss_score >= 0.7:
            priority = "P1"
        elif v and v.kev and v.epss_score is not None and v.epss_score >= 0.4 and priority not in ("P1",):
            priority = "P2"

    sla_due, overdue = _sla(finding, eff_sev, adj, now)

    return RiskView(
        base_severity=base_sev,
        effective_severity=eff_sev,
        adjusted=adjusted,
        priority=priority,
        score=score,
        factors=factors,
        unknown_inputs=unknown,
        disposition=adj.disposition if adj else None,
        adjudication_id=adj.id if adj else None,
        adjudication_state=adj.state if adj else None,
        expires_at=adj.expires_at if adj else None,
        review_due=adj.review_due if adj else None,
        sla_due=sla_due,
        sla_overdue=overdue,
        has_pending=has_pending,
    )


def sla_status(first_detected: dt.datetime | None, eff_sev: str, kev: bool,
               adj: Adjudication | None, now: dt.datetime) -> tuple[dt.datetime | None, bool]:
    """Remediation due date and whether it has passed. The single SLA rule:
    accepted/false-positive have none; an explicit due date on a decision wins;
    otherwise severity SLA from first detection, capped by the KEV SLA."""
    if adj is not None and adj.disposition in (
        Disposition.ACCEPT_RISK.value, Disposition.FALSE_POSITIVE.value
    ):
        return None, False
    if adj is not None and adj.remediation_due:
        due = _aware(adj.remediation_due)
        return due, due < now
    first = _aware(first_detected) or now
    days = settings.policy.remediation_sla_days.get(eff_sev, 90)
    if kev:
        days = min(days, settings.policy.kev_sla_days)
    due = first + dt.timedelta(days=days)
    return due, due < now


def _sla(finding: Finding, eff_sev: str, adj: Adjudication | None,
         now: dt.datetime) -> tuple[dt.datetime | None, bool]:
    due, overdue = sla_status(finding.first_detected, eff_sev,
                              bool(finding.vuln and finding.vuln.kev), adj, now)
    # A closed finding is no longer accruing lateness; whether it closed within
    # SLA is reported by the lifecycle timeline and metrics instead.
    if finding.status in CLOSED_STATUSES:
        overdue = False
    return due, overdue


def _aware(value: dt.datetime | None) -> dt.datetime | None:
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)


# --- Policy helpers ---------------------------------------------------------

def default_expiry(disposition: str, severity: str, start: dt.datetime | None = None) -> dt.datetime | None:
    """Suggested expiry for a decision. Routing decisions do not expire."""
    if disposition not in (Disposition.ACCEPT_RISK.value, Disposition.ADJUST_RISK.value,
                           Disposition.FALSE_POSITIVE.value):
        return None
    start = start or utcnow()
    days = settings.policy.max_acceptance_days.get(severity, 180)
    return start + dt.timedelta(days=days)


def default_review_due(severity: str, start: dt.datetime | None = None) -> dt.datetime:
    start = start or utcnow()
    days = settings.policy.review_interval_days.get(severity, 90)
    return start + dt.timedelta(days=days)


def validate_decision(disposition: str, justification: str, expires_at: dt.datetime | None,
                      requested_by: str, approver: str | None) -> list[str]:
    """Policy gate. Returns a list of human-readable problems; empty means ok."""
    problems: list[str] = []
    p = settings.policy
    is_risk_decision = disposition in (
        Disposition.ACCEPT_RISK.value, Disposition.ADJUST_RISK.value,
        Disposition.FALSE_POSITIVE.value,
    )
    if len((justification or "").strip()) < p.min_justification_chars:
        problems.append(
            f"Justification must be at least {p.min_justification_chars} characters. "
            "Record why the risk is tolerable here, not just what the finding is."
        )
    if is_risk_decision:
        if expires_at is None:
            problems.append("A risk decision needs an expiry date. Open-ended acceptances are not tracked.")
        if not approver:
            problems.append("Name an approver for this risk decision.")
        elif p.require_separate_approver and approver == requested_by:
            problems.append("The approver must be someone other than the requester.")
        elif approver not in settings.approvers:
            problems.append(
                f"{approver} is not on the approver roster ({', '.join(settings.approvers)})."
            )
    return problems
