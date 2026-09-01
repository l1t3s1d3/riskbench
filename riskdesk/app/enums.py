"""Controlled vocabularies. Everything downstream keys off these."""
from enum import Enum


class Source(str, Enum):
    WIZ = "wiz"
    FALCON = "falcon"
    GITHUB = "github"
    MANUAL = "manual"


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class FindingCategory(str, Enum):
    OS_VULN = "os_vuln"                  # Falcon Spotlight, Wiz host vulns
    CLOUD_VULN = "cloud_vuln"            # Wiz VM findings on cloud resources
    CONTAINER = "container"              # image layer vulns
    MISCONFIGURATION = "misconfiguration"  # Wiz cloud config rules
    DEPENDENCY = "dependency"            # Dependabot / SCA
    CODE_SCANNING = "code_scanning"      # CodeQL / SAST
    SECRET = "secret"                    # Wiz secrets, GH secret scanning


class FindingStatus(str, Enum):
    OPEN = "open"
    FIXED = "fixed"
    SUPPRESSED_AT_SOURCE = "suppressed_at_source"
    STALE = "stale"          # not seen in the last N syncs


class Disposition(str, Enum):
    """Mirrors the five-disposition adjudication framework, plus a
    factual-correction disposition that is deliberately NOT a risk decision."""
    FIX_IMMEDIATELY = "fix_immediately"
    COMPLEX_RESOLUTION = "complex_resolution"
    DEVELOPER_REVIEW = "developer_review"
    ACCEPT_RISK = "accept_risk"
    ADJUST_RISK = "adjust_risk"
    FALSE_POSITIVE = "false_positive"


# Dispositions that constitute a formal risk decision and therefore require
# approval, an expiry date, and a justification before they take effect.
RISK_DECISION_DISPOSITIONS = {
    Disposition.ACCEPT_RISK,
    Disposition.ADJUST_RISK,
    Disposition.FALSE_POSITIVE,
}

# Dispositions that route work rather than change the risk posture.
ROUTING_DISPOSITIONS = {
    Disposition.FIX_IMMEDIATELY,
    Disposition.COMPLEX_RESOLUTION,
    Disposition.DEVELOPER_REVIEW,
}

DISPOSITION_LABELS = {
    Disposition.FIX_IMMEDIATELY: "Fix immediately",
    Disposition.COMPLEX_RESOLUTION: "Complex resolution",
    Disposition.DEVELOPER_REVIEW: "Developer review",
    Disposition.ACCEPT_RISK: "Accept risk",
    Disposition.ADJUST_RISK: "Adjust risk",
    Disposition.FALSE_POSITIVE: "False positive / not affected",
}


class AdjudicationState(str, Enum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    REVOKED = "revoked"


class ScopeType(str, Enum):
    """What a decision attaches to. Precedence runs most- to least-specific."""
    FINDING = "finding"            # one instance on one asset
    VULN_ON_ASSET = "vuln_on_asset"  # this CVE, this asset
    VULN = "vuln"                  # this CVE everywhere
    COMPONENT = "component"        # e.g. pkg:npm/lodash, or a CodeQL rule id


SCOPE_PRECEDENCE = [
    ScopeType.FINDING,
    ScopeType.VULN_ON_ASSET,
    ScopeType.VULN,
    ScopeType.COMPONENT,
]


class Environment(str, Enum):
    PRODUCTION = "production"
    NON_PRODUCTION = "non_production"
    UNKNOWN = "unknown"


# --- Severity normalization -------------------------------------------------

_SEVERITY_ALIASES = {
    "critical": Severity.CRITICAL, "crit": Severity.CRITICAL,
    "high": Severity.HIGH, "important": Severity.HIGH,
    "medium": Severity.MEDIUM, "moderate": Severity.MEDIUM, "med": Severity.MEDIUM,
    "low": Severity.LOW, "warning": Severity.LOW,
    "info": Severity.INFO, "informational": Severity.INFO, "note": Severity.INFO,
    "none": Severity.INFO, "unknown": Severity.INFO,
}


def normalize_severity(raw: str | None, cvss: float | None = None) -> Severity:
    """Map a source's severity string onto the shared scale.

    Falls back to CVSS v3 qualitative bands when the string is missing or
    unrecognized. Returns INFO rather than guessing upward when we have nothing.
    """
    if raw:
        hit = _SEVERITY_ALIASES.get(str(raw).strip().lower())
        if hit:
            return hit
    if cvss is not None:
        if cvss >= 9.0:
            return Severity.CRITICAL
        if cvss >= 7.0:
            return Severity.HIGH
        if cvss >= 4.0:
            return Severity.MEDIUM
        if cvss > 0:
            return Severity.LOW
    return Severity.INFO
