"""CrowdStrike Falcon Spotlight connector.

Uses the combined Spotlight endpoint, which returns vulnerability records with
host, CVE and remediation facets in one call rather than the query-then-hydrate
two-step. Pagination is cursor based via the `after` token.

Requires a Falcon API client with the **Spotlight vulnerabilities: READ** scope.
Spotlight is licensed separately from Falcon Complete's EDR coverage; if the
scope is missing you will get a 403 from an otherwise valid token.

Set FALCON_BASE_URL to the cloud your CID lives in:
  us-1  https://api.crowdstrike.com
  us-2  https://api.us-2.crowdstrike.com
  eu-1  https://api.eu-1.crowdstrike.com
  gov   https://api.laggar.gcw.crowdstrike.com
"""
from __future__ import annotations

import datetime as dt
import logging
import time
from typing import Iterator

import httpx

from ..config import settings
from ..enums import FindingCategory, Severity, normalize_severity
from .base import Connector, NormalizedAsset, NormalizedRecord, NormalizedVuln, parse_ts

log = logging.getLogger(__name__)

FACETS = ["cve", "host_info", "remediation", "evaluation_logic"]


class FalconConnector(Connector):
    source = "falcon"

    def __init__(self, cfg=None):
        self.cfg = cfg or settings.falcon
        self._token: str | None = None
        self._token_expiry: float = 0.0

    def configured(self) -> bool:
        return self.cfg.configured

    # --- auth ---------------------------------------------------------------

    def _headers(self) -> dict:
        h = {"Authorization": f"Bearer {self._get_token()}", "Accept": "application/json"}
        if self.cfg.member_cid:
            h["X-CS-USERUUID"] = self.cfg.member_cid
        return h

    def _get_token(self) -> str:
        if self._token and time.time() < self._token_expiry - 60:
            return self._token
        data = {"client_id": self.cfg.client_id, "client_secret": self.cfg.client_secret}
        if self.cfg.member_cid:
            data["member_cid"] = self.cfg.member_cid
        r = httpx.post(
            f"{self.cfg.base_url}/oauth2/token",
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=30,
        )
        if r.status_code >= 400:
            raise RuntimeError(
                f"Falcon token request failed ({r.status_code}). "
                "Check the client id/secret and that FALCON_BASE_URL matches your cloud."
            )
        payload = r.json()
        self._token = payload["access_token"]
        self._token_expiry = time.time() + payload.get("expires_in", 1799)
        return self._token

    def check(self) -> tuple[bool, str]:
        if not self.configured():
            return False, "FALCON_CLIENT_ID and FALCON_CLIENT_SECRET are not set."
        try:
            self._get_token()
        except Exception as exc:
            return False, str(exc)
        try:
            r = httpx.get(
                f"{self.cfg.base_url}/spotlight/combined/vulnerabilities/v1",
                params={"filter": self.cfg.filter_fql, "limit": 1},
                headers=self._headers(), timeout=30,
            )
        except Exception as exc:
            return False, f"Could not reach {self.cfg.base_url}: {exc}"
        if r.status_code == 403:
            return False, ("Authenticated, but the API client lacks the Spotlight "
                           "vulnerabilities READ scope.")
        if r.status_code >= 400:
            return False, f"Spotlight returned {r.status_code}: {r.text[:200]}"
        total = r.json().get("meta", {}).get("pagination", {}).get("total")
        return True, f"Connected. {total if total is not None else 'an unknown number of'} findings match the current filter."

    # --- fetch --------------------------------------------------------------

    def fetch(self, limit: int | None = None) -> Iterator[NormalizedRecord]:
        after: str | None = None
        seen = 0
        while True:
            params = {
                "filter": self.cfg.filter_fql,
                "limit": min(self.cfg.page_size, 400),
                "facet": FACETS,
            }
            if after:
                params["after"] = after
            r = self._get_with_retry(
                f"{self.cfg.base_url}/spotlight/combined/vulnerabilities/v1", params
            )
            body = r.json()
            resources = body.get("resources") or []
            if not resources:
                return
            for item in resources:
                rec = self._map(item)
                if rec is not None:
                    yield rec
                    seen += 1
                    if limit and seen >= limit:
                        return
            after = body.get("meta", {}).get("pagination", {}).get("after")
            if not after:
                return

    def _get_with_retry(self, url: str, params: dict, attempts: int = 5) -> httpx.Response:
        for attempt in range(attempts):
            r = httpx.get(url, params=params, headers=self._headers(), timeout=90)
            if r.status_code == 429:
                wait = float(r.headers.get("X-RateLimit-RetryAfter", 0)) - time.time()
                time.sleep(max(2.0, min(wait, 60.0)) if wait > 0 else 2 ** attempt)
                continue
            if r.status_code in (500, 502, 503, 504):
                time.sleep(2 ** attempt)
                continue
            if r.status_code >= 400:
                raise RuntimeError(f"Falcon Spotlight {r.status_code}: {r.text[:300]}")
            return r
        raise RuntimeError("Falcon Spotlight rate limit not cleared after retries.")

    def _map(self, item: dict) -> NormalizedRecord | None:
        cve = item.get("cve") or {}
        host = item.get("host_info") or {}
        remediation = (item.get("remediation") or {}).get("entities") or []
        apps = item.get("apps") or []

        cve_id = cve.get("id")
        canonical = cve_id or f"falcon:{item.get('id')}"

        cvss = cve.get("base_score")
        severity = normalize_severity(cve.get("severity"), cvss)

        aid = host.get("aid") or item.get("aid") or "unknown"
        asset = NormalizedAsset(
            source_asset_id=aid,
            name=host.get("hostname") or aid,
            asset_type=(host.get("product_type_desc") or "endpoint").lower(),
            os_name=host.get("os_version") or host.get("platform"),
            ip_address=host.get("local_ip"),
            # Falcon reports the cloud provider for cloud-hosted sensors.
            cloud_provider=(host.get("service_provider") or "").lower() or None,
            cloud_account=host.get("service_provider_account_id"),
            owner=host.get("machine_domain"),
            tags={
                "groups": host.get("groups") or [],
                "tags": host.get("tags") or [],
                "sensor_version": host.get("agent_version"),
                "last_seen": host.get("last_seen"),
            },
            # Falcon does not assert exposure or environment; leave unset.
            environment=_env_from_tags(host),
        )

        app = apps[0] if apps else {}
        fix_version = None
        remediation_text = None
        if remediation:
            remediation_text = remediation[0].get("action")
            fix_version = remediation[0].get("title")

        vuln = NormalizedVuln(
            canonical_id=canonical,
            cve_id=cve_id,
            title=cve.get("description", "")[:400] or canonical,
            description=cve.get("description"),
            cvss_score=cvss,
            cvss_vector=cve.get("vector"),
            severity=severity.value,
            kev=bool(cve.get("exploit_status", 0) and int(cve.get("exploit_status", 0)) >= 60),
            published_at=parse_ts(cve.get("published_date")),
            remediation=remediation_text,
            references=cve.get("references") or [],
        )

        product = app.get("product_name_version") or app.get("product_name_normalized")
        return NormalizedRecord(
            source_finding_id=str(item.get("id")),
            category=FindingCategory.OS_VULN.value,
            asset=asset,
            vuln=vuln,
            severity=severity.value,
            source_severity=cve.get("severity"),
            status="fixed" if item.get("status") == "closed" else "open",
            component=product,
            component_version=app.get("product_name_version"),
            component_key=_component_key(app),
            fix_available=bool(remediation),
            fix_version=fix_version,
            first_detected=parse_ts(item.get("created_timestamp")),
            last_seen=parse_ts(item.get("updated_timestamp")),
            raw=item,
        )


def _component_key(app: dict) -> str | None:
    name = app.get("product_name_normalized")
    if not name:
        return None
    vendor = (app.get("vendor_normalized") or "generic").lower().replace(" ", "-")
    return f"pkg:app/{vendor}/{name.lower().replace(' ', '-')}"


def _env_from_tags(host: dict) -> str | None:
    """Best-effort environment read from Falcon grouping tags.

    Only returns a value when a tag says so explicitly. Anything else stays
    None so the scoring engine reports it as untagged instead of assuming.
    """
    blobs = [str(x).lower() for x in (host.get("tags") or []) + (host.get("groups") or [])]
    joined = " ".join(blobs)
    if any(k in joined for k in ("prod", "production")) and "non-prod" not in joined and "nonprod" not in joined:
        return "production"
    if any(k in joined for k in ("nonprod", "non-prod", "dev", "test", "staging", "uat")):
        return "non_production"
    return None
