"""Centralized external API query definitions.

Every query RiskDesk sends to Wiz, CrowdStrike Falcon, and GitHub Dependabot
is defined here.  Edit the strings and filter dicts in this one file when a
vendor schema drifts or you need to pull extra fields for troubleshooting.

Each constant carries an inline comment block explaining what it does so an
operator can read this file top-to-bottom without jumping into connector code.
"""
from __future__ import annotations


# ---------------------------------------------------------------------------
#  WIZ  —  GraphQL queries against the tenant's API endpoint
# ---------------------------------------------------------------------------

# Vulnerability findings (host, VM, container package CVEs + secret detections).
# Paginated; variables: $filterBy, $first, $after
WIZ_VULN_FINDINGS = """
query VulnerabilityFindings($filterBy: VulnerabilityFindingFilters, $first: Int, $after: String) {
  vulnerabilityFindings(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      name
      CVEDescription
      CVSSSeverity
      score
      hasExploit
      hasCisaKevExploit
      epssProbability
      epssPercentile
      firstDetectedAt
      lastDetectedAt
      resolvedAt
      status
      remediation
      detailedName
      version
      fixedVersion
      detectionMethod
      link
      locationPath
      vendorSeverity
      vulnerableAsset {
        ... on VulnerableAssetBase {
          id
          name
          type
          cloudPlatform
          subscriptionExternalId
          subscriptionName
          region
          tags
        }
        ... on VulnerableAssetVirtualMachine {
          id
          name
          type
          operatingSystem
          ipAddresses
          cloudPlatform
          subscriptionExternalId
          subscriptionName
          region
          hasLimitedInternetExposure
          hasHighInternetExposure
          tags
        }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

# Default filter for vulnerability sync: only open / in-progress findings.
WIZ_VULN_DEFAULT_FILTER = {"status": ["OPEN", "IN_PROGRESS"]}

# Cloud misconfiguration rule failures.
# Paginated; variables: $filterBy, $first, $after
WIZ_CONFIG_FINDINGS = """
query ConfigurationFindings($filterBy: ConfigurationFindingFilters, $first: Int, $after: String) {
  configurationFindings(filterBy: $filterBy, first: $first, after: $after) {
    nodes {
      id
      severity
      result
      analyzedAt
      firstSeenAt
      remediation
      rule { id name description shortName remediationInstructions }
      resource {
        id
        providerId
        name
        type
        region
        subscription { id name externalId cloudProvider }
        tags { key value }
      }
    }
    pageInfo { hasNextPage endCursor }
  }
}
"""

# Default filter for configuration sync: only failures.
WIZ_CONFIG_DEFAULT_FILTER = {"result": ["FAIL"]}

# Lightweight connectivity test — smallest possible query.
WIZ_PROBE = "query { __typename }"

# Diagnostic one-liner probes (used by /api/sync/diagnose/wiz)
WIZ_DIAG_VULN_PROBE = (
    "query { vulnerabilityFindings(first: 1) "
    "{ totalCount nodes { id name status } } }"
)
WIZ_DIAG_CONFIG_PROBE = (
    "query { configurationFindings(first: 1) "
    "{ totalCount nodes { id severity result } } }"
)

# Schema introspection query — lists all fields on a named type.
WIZ_INTROSPECT = (
    "query($n:String!){ __type(name:$n){ name fields { name type "
    "{ name kind ofType { name kind } } } } }"
)

# Types worth inspecting when diagnosing schema drift.
WIZ_INTROSPECT_TYPES = [
    "VulnerabilityFinding",
    "ConfigurationFinding",
    "VulnerableAssetBase",
    "VulnerableAssetVirtualMachine",
]


# ---------------------------------------------------------------------------
#  CROWDSTRIKE FALCON  —  REST Spotlight API
# ---------------------------------------------------------------------------

# Combined Spotlight endpoint — returns vulnerabilities with embedded host,
# CVE, and remediation facets in one call.
FALCON_SPOTLIGHT_PATH = "/spotlight/combined/vulnerabilities/v1"

# Facets requested on every combined call.
FALCON_SPOTLIGHT_FACETS = ["cve", "host_info", "remediation", "evaluation_logic"]

# Default FQL filter — exclude already-closed findings.
FALCON_DEFAULT_FQL = "status:!'closed'"

# OAuth2 token endpoint (appended to base_url).
FALCON_TOKEN_PATH = "/oauth2/token"

# Lightweight check: hit Spotlight with limit=1 to verify the scope is granted.
FALCON_PROBE_PARAMS = {"limit": 1}

# Alerts API v2 — unified EDR detections / alerts (requires "Alerts: Read" scope).
FALCON_ALERTS_LIST_PATH = "/alerts/queries/alerts/v2"
FALCON_ALERTS_HYDRATE_PATH = "/alerts/entities/alerts/v2"
# Alerts hydrate accepts up to 1000 composite_ids per request; keep well under.
FALCON_ALERTS_HYDRATE_BATCH = 100


# ---------------------------------------------------------------------------
#  QUERY REGISTRY  —  machine-readable catalogue for the diagnostics UI
# ---------------------------------------------------------------------------

QUERY_REGISTRY = [
    {
        "source": "wiz",
        "name": "vuln_findings",
        "label": "Vulnerability Findings",
        "type": "graphql",
        "query": WIZ_VULN_FINDINGS,
        "default_filter": WIZ_VULN_DEFAULT_FILTER,
        "description": "Host/VM/container CVEs and secret detections.",
    },
    {
        "source": "wiz",
        "name": "config_findings",
        "label": "Configuration Findings",
        "type": "graphql",
        "query": WIZ_CONFIG_FINDINGS,
        "default_filter": WIZ_CONFIG_DEFAULT_FILTER,
        "description": "Cloud misconfiguration rule failures.",
    },
    {
        "source": "wiz",
        "name": "introspect",
        "label": "Schema Introspection",
        "type": "graphql",
        "query": WIZ_INTROSPECT,
        "description": "List fields exposed by a named GraphQL type.",
    },
    {
        "source": "wiz",
        "name": "diag_vuln_probe",
        "label": "Diagnostic: Vulnerability Probe",
        "type": "graphql",
        "query": WIZ_DIAG_VULN_PROBE,
        "description": "Quick single-record probe for vuln findings.",
    },
    {
        "source": "wiz",
        "name": "diag_config_probe",
        "label": "Diagnostic: Config Probe",
        "type": "graphql",
        "query": WIZ_DIAG_CONFIG_PROBE,
        "description": "Quick single-record probe for config findings.",
    },
    {
        "source": "falcon",
        "name": "spotlight_combined",
        "label": "Spotlight Combined Vulnerabilities",
        "type": "rest",
        "endpoint": FALCON_SPOTLIGHT_PATH,
        "facets": FALCON_SPOTLIGHT_FACETS,
        "default_filter": FALCON_DEFAULT_FQL,
        "description": "Combined endpoint with host, CVE, and remediation facets.",
    },
    # --- GitHub Advanced Security ---
    {
        "source": "github",
        "name": "dependabot_alerts",
        "label": "Dependabot Alerts",
        "type": "rest",
        "endpoint": "/orgs/{org}/dependabot/alerts",
        "default_params": {"state": "open", "per_page": 100},
        "description": "SCA vulnerability alerts from Dependabot.",
    },
    {
        "source": "github",
        "name": "code_scanning_alerts",
        "label": "Code Scanning Alerts",
        "type": "rest",
        "endpoint": "/orgs/{org}/code-scanning/alerts",
        "default_params": {"state": "open", "per_page": 100},
        "description": "SAST alerts from CodeQL and third-party tools.",
    },
    {
        "source": "github",
        "name": "secret_scanning_alerts",
        "label": "Secret Scanning Alerts",
        "type": "rest",
        "endpoint": "/orgs/{org}/secret-scanning/alerts",
        "default_params": {"state": "open", "per_page": 100},
        "description": "Exposed credentials detected by GitHub secret scanning.",
    },
    {
        "source": "github",
        "name": "security_advisories",
        "label": "Repository Advisories",
        "type": "rest",
        "endpoint": "/orgs/{org}/security-advisories",
        "default_params": {"per_page": 100},
        "description": "Private security advisories drafted in the org.",
    },
]


# ---------------------------------------------------------------------------
#  GITHUB  —  REST endpoints and query parameters
# ---------------------------------------------------------------------------

GITHUB_ALERT_FAMILIES = [
    {
        "name": "dependabot",
        "label": "Dependabot",
        "org_path": "/orgs/{org}/dependabot/alerts",
        "repo_path": "/repos/{owner}/{repo}/dependabot/alerts",
        "scopes": "Repository permissions -> Dependabot alerts: read",
    },
    {
        "name": "code_scanning",
        "label": "Code Scanning",
        "org_path": "/orgs/{org}/code-scanning/alerts",
        "repo_path": "/repos/{owner}/{repo}/code-scanning/alerts",
        "scopes": "Repository permissions -> Code scanning alerts: read",
    },
    {
        "name": "secret_scanning",
        "label": "Secret Scanning",
        "org_path": "/orgs/{org}/secret-scanning/alerts",
        "repo_path": "/repos/{owner}/{repo}/secret-scanning/alerts",
        "scopes": "Repository permissions -> Secret scanning alerts: read",
    },
]

GITHUB_SECURITY_STATES = ["open", "fixed", "dismissed", "auto_dismissed"]
