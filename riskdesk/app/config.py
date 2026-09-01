"""Runtime configuration, read from environment (.env is loaded at startup).

Nothing here is a secret in code. Credentials come from the environment only.
"""
import os
from dataclasses import dataclass, field


def _list(name: str, default: str = "") -> list[str]:
    raw = os.getenv(name, default)
    return [x.strip() for x in raw.split(",") if x.strip()]


def _int(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, default))
    except (TypeError, ValueError):
        return default


@dataclass
class WizConfig:
    client_id: str = field(default_factory=lambda: os.getenv("WIZ_CLIENT_ID", ""))
    client_secret: str = field(default_factory=lambda: os.getenv("WIZ_CLIENT_SECRET", ""))
    # Your tenant's API endpoint, e.g. https://api.us17.app.wiz.io/graphql
    api_url: str = field(default_factory=lambda: os.getenv("WIZ_API_URL", ""))
    auth_url: str = field(default_factory=lambda: os.getenv("WIZ_AUTH_URL", "https://auth.app.wiz.io/oauth/token"))
    audience: str = field(default_factory=lambda: os.getenv("WIZ_AUDIENCE", "wiz-api"))
    page_size: int = field(default_factory=lambda: _int("WIZ_PAGE_SIZE", 500))

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret and self.api_url)


@dataclass
class FalconConfig:
    client_id: str = field(default_factory=lambda: os.getenv("FALCON_CLIENT_ID", ""))
    client_secret: str = field(default_factory=lambda: os.getenv("FALCON_CLIENT_SECRET", ""))
    # Match your Falcon cloud: api.crowdstrike.com | api.us-2.crowdstrike.com |
    # api.eu-1.crowdstrike.com | api.laggar.gcw.crowdstrike.com
    base_url: str = field(default_factory=lambda: os.getenv("FALCON_BASE_URL", "https://api.crowdstrike.com"))
    member_cid: str = field(default_factory=lambda: os.getenv("FALCON_MEMBER_CID", ""))
    page_size: int = field(default_factory=lambda: _int("FALCON_PAGE_SIZE", 400))
    # FQL applied to the Spotlight query. Default pulls open findings only.
    filter_fql: str = field(default_factory=lambda: os.getenv("FALCON_FILTER_FQL", "status:!'closed'"))

    @property
    def configured(self) -> bool:
        return bool(self.client_id and self.client_secret)


@dataclass
class GitHubConfig:
    token: str = field(default_factory=lambda: os.getenv("GITHUB_TOKEN", ""))
    org: str = field(default_factory=lambda: os.getenv("GITHUB_ORG", ""))
    api_url: str = field(default_factory=lambda: os.getenv("GITHUB_API_URL", "https://api.github.com"))
    page_size: int = field(default_factory=lambda: _int("GITHUB_PAGE_SIZE", 100))
    # Which alert families to pull.
    include_dependabot: bool = field(default_factory=lambda: os.getenv("GITHUB_DEPENDABOT", "1") == "1")
    include_code_scanning: bool = field(default_factory=lambda: os.getenv("GITHUB_CODE_SCANNING", "1") == "1")
    include_secret_scanning: bool = field(default_factory=lambda: os.getenv("GITHUB_SECRET_SCANNING", "1") == "1")

    @property
    def configured(self) -> bool:
        return bool(self.token and self.org)


@dataclass
class Policy:
    """Adjudication policy. Change these to match what Chris signs off on."""
    # Maximum life of a risk acceptance before it must be re-argued, by the
    # severity it was accepted at.
    max_acceptance_days: dict = field(default_factory=lambda: {
        "critical": 90, "high": 180, "medium": 365, "low": 365, "info": 365,
    })
    # How long after approval the first periodic review falls due.
    review_interval_days: dict = field(default_factory=lambda: {
        "critical": 30, "high": 90, "medium": 180, "low": 180, "info": 180,
    })
    min_justification_chars: int = 40
    # Risk decisions (accept / adjust / false positive) need a second person.
    require_separate_approver: bool = field(
        default_factory=lambda: os.getenv("RISKDESK_REQUIRE_SEPARATE_APPROVER", "1") == "1"
    )
    # Remediation SLA in days, by effective severity. Drives "overdue" flags.
    remediation_sla_days: dict = field(default_factory=lambda: {
        "critical": 15, "high": 30, "medium": 90, "low": 180, "info": 365,
    })
    # CISA KEV overrides the severity SLA when shorter.
    kev_sla_days: int = 14


@dataclass
class Settings:
    wiz: WizConfig = field(default_factory=WizConfig)
    falcon: FalconConfig = field(default_factory=FalconConfig)
    github: GitHubConfig = field(default_factory=GitHubConfig)
    policy: Policy = field(default_factory=Policy)

    # Local identity. This build has no SSO; the current user is whoever the
    # browser session says it is, chosen from this roster. See README.
    users: list[str] = field(default_factory=lambda: _list(
        "RISKDESK_USERS", "lucas,liang,ezechias,derron,igor,eric.poon,chris"))
    approvers: list[str] = field(default_factory=lambda: _list(
        "RISKDESK_APPROVERS", "chris,eric.poon,lucas,liang"))
    default_user: str = field(default_factory=lambda: os.getenv("RISKDESK_DEFAULT_USER", "lucas"))
    org_name: str = field(default_factory=lambda: os.getenv("RISKDESK_ORG_NAME", "PLI"))
    # Findings not seen in this many days are marked stale by the sync.
    stale_after_days: int = field(default_factory=lambda: _int("RISKDESK_STALE_DAYS", 14))


settings = Settings()


def reload_settings() -> Settings:
    global settings
    settings = Settings()
    return settings
