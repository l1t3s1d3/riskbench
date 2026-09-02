"""Wiz connector.

Wiz authenticates with OAuth2 client credentials against auth.app.wiz.io and
serves everything from one GraphQL endpoint that is specific to your tenant's
region (WIZ_API_URL, e.g. https://api.us17.app.wiz.io/graphql).

Three queries are wired up:
  vulnerabilityFindings   host / VM / container package vulnerabilities
  configurationFindings   cloud misconfiguration rule failures
  (secrets arrive as vulnerability findings with a secret detection method)

IMPORTANT -- verify the queries against your own tenant before trusting a sync.
Wiz's GraphQL schema is versioned per tenant and fields do get added and
deprecated. The three query strings below are isolated as module constants for
exactly that reason. Run:

    python -m app.cli wiz-introspect --type VulnerabilityFinding

to print the fields your tenant actually exposes, then edit the constant if a
field name has drifted. A field the connector asks for that does not exist will
fail the whole query, so this is worth doing once up front.
"""
from __future__ import annotations

import logging
import time
from typing import Iterator

import httpx

from ..config import settings
from ..enums import FindingCategory, normalize_severity
from .base import Connector, NormalizedAsset, NormalizedRecord, NormalizedVuln, parse_ts

log = logging.getLogger(__name__)


VULN_FINDINGS_QUERY = """
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

CONFIG_FINDINGS_QUERY = """
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


class WizConnector(Connector):
    source = "wiz"

    def __init__(self, cfg=None):
        self.cfg = cfg or settings.wiz
        self._token: str | None = None
        self._token_expiry: float = 0.0

    def configured(self) -> bool:
        return self.cfg.configured

    # --- auth ---------------------------------------------------------------

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        r = httpx.post(
            self.cfg.auth_url,
            data={
                "grant_type": "client_credentials",
                "client_id": self.cfg.client_id,
                "client_secret": self.cfg.client_secret,
                "audience": self.cfg.audience,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        if r.status_code >= 400:
            raise RuntimeError(
                f"Wiz token request failed ({r.status_code}): {r.text[:200]}. "
                "Check the service account id/secret and WIZ_AUDIENCE."
            )
        payload = r.json()
        self._token = payload["access_token"]
        self._token_expiry = time.time() + payload.get("expires_in", 3600)
        return self._token

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json",
        }

    def check(self) -> tuple[bool, str]:
        if not self.configured():
            return False, "WIZ_CLIENT_ID, WIZ_CLIENT_SECRET and WIZ_API_URL are not all set."
        try:
            self._get_token()
        except Exception as exc:
            return False, str(exc)
        try:
            data = self.graphql("query { __typename }", {})
        except Exception as exc:
            return False, f"Authenticated, but the GraphQL probe failed: {exc}"
        return True, f"Connected to {self.cfg.api_url}."

    # --- transport ----------------------------------------------------------

    def graphql(self, query: str, variables: dict, attempts: int = 5) -> dict:
        for attempt in range(attempts):
            r = httpx.post(
                self.cfg.api_url,
                json={"query": query, "variables": variables},
                headers=self._headers(),
                timeout=120,
            )
            if r.status_code == 429:
                time.sleep(min(2 ** attempt, 60))
                continue
            if r.status_code in (500, 502, 503, 504):
                time.sleep(2 ** attempt)
                continue
            if r.status_code >= 400:
                raise RuntimeError(f"Wiz GraphQL {r.status_code}: {r.text[:400]}")
            body = r.json()
            if body.get("errors"):
                msgs = "; ".join(e.get("message", "") for e in body["errors"])
                raise RuntimeError(
                    f"Wiz GraphQL error: {msgs}. If this names an unknown field, your "
                    "tenant schema differs -- run `python -m app.cli wiz-introspect`."
                )
            return body.get("data") or {}
        raise RuntimeError("Wiz rate limit did not clear after retries.")

    def introspect(self, type_name: str) -> list[str]:
        """List the fields your tenant exposes on a GraphQL type."""
        data = self.graphql(
            "query($n:String!){ __type(name:$n){ name fields { name type { name kind "
            "ofType { name kind } } } } }",
            {"n": type_name},
        )
        t = data.get("__type")
        if not t:
            return []
        out = []
        for f in t.get("fields") or []:
            ty = f.get("type") or {}
            tname = ty.get("name") or (ty.get("ofType") or {}).get("name") or ty.get("kind")
            out.append(f"{f['name']}: {tname}")
        return out

    # --- fetch --------------------------------------------------------------

    def fetch(self, limit: int | None = None) -> Iterator[NormalizedRecord]:
        seen = 0
        for rec in self._fetch_vulns():
            yield rec
            seen += 1
            if limit and seen >= limit:
                return
        try:
            for rec in self._fetch_config():
                yield rec
                seen += 1
                if limit and seen >= limit:
                    return
        except Exception as exc:
            # Cloud config is a separate entitlement; do not fail the whole sync.
            log.warning("Wiz configuration findings skipped: %s", exc)

    def _paginate(self, query: str, root: str, filter_by: dict) -> Iterator[dict]:
        after = None
        while True:
            data = self.graphql(query, {
                "filterBy": filter_by,
                "first": min(self.cfg.page_size, 500),
                "after": after,
            })
            block = data.get(root) or {}
            for node in block.get("nodes") or []:
                yield node
            page = block.get("pageInfo") or {}
            if not page.get("hasNextPage"):
                return
            after = page.get("endCursor")
            if not after:
                return

    def _fetch_vulns(self) -> Iterator[NormalizedRecord]:
        for node in self._paginate(VULN_FINDINGS_QUERY, "vulnerabilityFindings",
                                   {"status": ["OPEN", "IN_PROGRESS"]}):
            rec = self._map_vuln(node)
            if rec is not None:
                yield rec

    def _fetch_config(self) -> Iterator[NormalizedRecord]:
        for node in self._paginate(CONFIG_FINDINGS_QUERY, "configurationFindings",
                                   {"result": ["FAIL"]}):
            rec = self._map_config(node)
            if rec is not None:
                yield rec

    # --- mappers ------------------------------------------------------------

    def _map_vuln(self, node: dict) -> NormalizedRecord | None:
        asset_node = node.get("vulnerableAsset") or {}
        name = node.get("name") or ""
        cve_id = name if name.upper().startswith("CVE-") else None
        canonical = cve_id or name or f"wiz:{node.get('id')}"

        severity = normalize_severity(
            node.get("vendorSeverity") or node.get("CVSSSeverity"), node.get("score")
        )
        detection = (node.get("detectionMethod") or "").lower()
        category = (FindingCategory.SECRET.value if "secret" in detection
                    else FindingCategory.CLOUD_VULN.value)

        asset = NormalizedAsset(
            source_asset_id=asset_node.get("id") or "unknown",
            name=asset_node.get("name") or asset_node.get("id") or "unknown",
            asset_type=(asset_node.get("type") or "cloud_resource").lower(),
            os_name=asset_node.get("operatingSystem"),
            ip_address=(asset_node.get("ipAddresses") or [None])[0],
            cloud_provider=(asset_node.get("cloudPlatform") or "").lower() or None,
            cloud_account=asset_node.get("subscriptionExternalId") or asset_node.get("subscriptionName"),
            region=asset_node.get("region"),
            internet_facing=_exposure(asset_node),
            environment=_env_from_tags(asset_node.get("tags")),
            tags=_tags(asset_node.get("tags")),
        )

        return NormalizedRecord(
            source_finding_id=str(node.get("id")),
            category=category,
            asset=asset,
            vuln=NormalizedVuln(
                canonical_id=canonical,
                cve_id=cve_id,
                title=name or canonical,
                description=node.get("CVEDescription"),
                cvss_score=node.get("score"),
                severity=severity.value,
                epss_score=node.get("epssProbability"),
                epss_percentile=node.get("epssPercentile"),
                kev=bool(node.get("hasCisaKevExploit")),
                remediation=node.get("remediation"),
                references=[node["link"]] if node.get("link") else [],
            ),
            severity=severity.value,
            source_severity=node.get("vendorSeverity") or node.get("CVSSSeverity"),
            status="fixed" if node.get("resolvedAt") else "open",
            component=node.get("detailedName"),
            component_version=node.get("version"),
            component_key=(f"pkg:generic/{node.get('detailedName', '').lower()}"
                           if node.get("detailedName") else None),
            location=node.get("locationPath"),
            fix_available=bool(node.get("fixedVersion")),
            fix_version=node.get("fixedVersion"),
            first_detected=parse_ts(node.get("firstDetectedAt")),
            last_seen=parse_ts(node.get("lastDetectedAt")),
            source_url=node.get("link"),
            raw=node,
        )

    def _map_config(self, node: dict) -> NormalizedRecord | None:
        rule = node.get("rule") or {}
        res = node.get("resource") or {}
        sub = res.get("subscription") or {}
        severity = normalize_severity(node.get("severity"))
        rule_id = rule.get("id") or rule.get("shortName") or "unknown"

        asset = NormalizedAsset(
            source_asset_id=res.get("id") or res.get("providerId") or "unknown",
            name=res.get("name") or res.get("providerId") or "unknown",
            asset_type=(res.get("type") or "cloud_resource").lower(),
            cloud_provider=(sub.get("cloudProvider") or "").lower() or None,
            cloud_account=sub.get("externalId") or sub.get("name"),
            region=res.get("region"),
            environment=_env_from_tags(res.get("tags")),
            tags=_tags(res.get("tags")),
        )

        return NormalizedRecord(
            source_finding_id=str(node.get("id")),
            category=FindingCategory.MISCONFIGURATION.value,
            asset=asset,
            vuln=NormalizedVuln(
                canonical_id=f"wiz-rule:{rule_id}",
                title=rule.get("name") or rule.get("shortName") or rule_id,
                description=rule.get("description"),
                severity=severity.value,
                remediation=rule.get("remediationInstructions") or node.get("remediation"),
            ),
            severity=severity.value,
            source_severity=node.get("severity"),
            status="open",
            component=rule.get("shortName"),
            component_key=f"rule:wiz:{rule_id}",
            first_detected=parse_ts(node.get("firstSeenAt")),
            last_seen=parse_ts(node.get("analyzedAt")),
            raw=node,
        )


def _exposure(asset_node: dict) -> bool | None:
    """Only assert exposure when Wiz says so explicitly."""
    if asset_node.get("hasHighInternetExposure"):
        return True
    if asset_node.get("hasLimitedInternetExposure") is True:
        return True
    if asset_node.get("hasHighInternetExposure") is False and \
       asset_node.get("hasLimitedInternetExposure") is False:
        return False
    return None


def _tags(tags) -> dict:
    if isinstance(tags, dict):
        return tags
    if isinstance(tags, list):
        return {t.get("key"): t.get("value") for t in tags if isinstance(t, dict) and t.get("key")}
    return {}


def _env_from_tags(tags) -> str | None:
    d = {str(k).lower(): str(v).lower() for k, v in _tags(tags).items()}
    val = d.get("environment") or d.get("env") or d.get("stage")
    if not val:
        return None
    if val.startswith("prod"):
        return "production"
    if any(val.startswith(p) for p in ("dev", "test", "stag", "uat", "qa", "nonprod", "non-prod")):
        return "non_production"
    return None
