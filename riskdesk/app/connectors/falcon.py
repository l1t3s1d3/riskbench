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

from ..api_queries import (
    FALCON_DEFAULT_FQL,
    FALCON_SPOTLIGHT_FACETS,
    FALCON_SPOTLIGHT_PATH,
    FALCON_TOKEN_PATH,
)
from ..config import settings
from ..enums import FindingCategory, Severity, normalize_severity
from .base import Connector, NormalizedAsset, NormalizedRecord, NormalizedVuln, parse_ts

log = logging.getLogger(__name__)


class FalconConnector(Connector):
    source = "falcon"

    def __init__(self, cfg=None):
        self.cfg = cfg or settings.falcon
        self._token: str | None = None
        self._token_expiry: float = 0.0
        self.skipped_categories: set[str] = set()

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
            f"{self.cfg.base_url}{FALCON_TOKEN_PATH}",
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
                f"{self.cfg.base_url}{FALCON_SPOTLIGHT_PATH}",
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
        seen = 0
        self.skipped_categories = set()
        for rec in self._fetch_with_filter(self.cfg.filter_fql, limit):
            yield rec
            seen += 1
            if limit and seen >= limit:
                return
        # Resolved pass: pull recently-closed vulnerabilities so historical
        # remediation data is captured with the real closed_timestamp.
        window = self.cfg.resolved_window_days
        if window:
            closed_fql = f"status:'closed'+closed_timestamp:>'now-{window}d'"
            try:
                for rec in self._fetch_with_filter(closed_fql, limit):
                    yield rec
                    seen += 1
                    if limit and seen >= limit:
                        return
            except Exception as exc:
                log.warning("Falcon resolved-pull skipped: %s", exc)
        # EDR detections / alerts: a separate feed from Spotlight. Requires the
        # "Alerts: Read" scope.
        if self.cfg.include_detections:
            try:
                for rec in self._fetch_detections(
                        days=self.cfg.detections_window_days, limit=limit):
                    yield rec
                    seen += 1
                    if limit and seen >= limit:
                        return
            except Exception as exc:
                log.warning("Falcon detections pull skipped: %s", exc)
                self.skipped_categories.add(FindingCategory.DETECTION.value)
        else:
            self.skipped_categories.add(FindingCategory.DETECTION.value)

    def _fetch_with_filter(self, fql: str, limit: int | None) -> Iterator[NormalizedRecord]:
        after: str | None = None
        seen = 0
        while True:
            params = {
                "filter": fql,
                "limit": min(self.cfg.page_size, 400),
                "facet": FALCON_SPOTLIGHT_FACETS,
            }
            if after:
                params["after"] = after
            r = self._get_with_retry(
                f"{self.cfg.base_url}{FALCON_SPOTLIGHT_PATH}", params
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

    # --- EDR detections (Alerts API v2) --------------------------------------

    def _fetch_detections(self, days: int, limit: int | None) -> Iterator[NormalizedRecord]:
        """Pull detections/alerts from Falcon's unified alerts API.

        Two-step: list composite ids, then hydrate in batches. Covers both
        currently-open alerts and closed alerts in the last `days` days, so
        historical remediation reporting works for detections too."""
        from ..api_queries import (
            FALCON_ALERTS_LIST_PATH, FALCON_ALERTS_HYDRATE_PATH,
            FALCON_ALERTS_HYDRATE_BATCH,
        )
        fql = f"updated_timestamp:>'now-{days}d'"
        offset = 0
        seen = 0
        page = min(self.cfg.detections_page_size, 1000)
        while True:
            params = {"filter": fql, "limit": page, "offset": offset,
                      "sort": "updated_timestamp.desc"}
            r = self._get_with_retry(f"{self.cfg.base_url}{FALCON_ALERTS_LIST_PATH}", params)
            body = r.json()
            ids = body.get("resources") or []
            if not ids:
                return
            # Hydrate in batches so the POST body stays small.
            for i in range(0, len(ids), FALCON_ALERTS_HYDRATE_BATCH):
                batch = ids[i:i + FALCON_ALERTS_HYDRATE_BATCH]
                hr = httpx.post(
                    f"{self.cfg.base_url}{FALCON_ALERTS_HYDRATE_PATH}",
                    json={"composite_ids": batch},
                    headers=self._headers(), timeout=90,
                )
                if hr.status_code == 403:
                    raise RuntimeError(
                        "403 on alerts hydrate: the API client is missing the "
                        "'Alerts: Read' scope. Grant it in the CrowdStrike console.")
                if hr.status_code >= 400:
                    raise RuntimeError(f"Falcon Alerts hydrate {hr.status_code}: {hr.text[:300]}")
                for alert in (hr.json().get("resources") or []):
                    rec = self._map_detection(alert)
                    if rec is not None:
                        yield rec
                        seen += 1
                        if limit and seen >= limit:
                            return
            # Pagination: the alerts API returns total; walk until we exhaust it.
            total = body.get("meta", {}).get("pagination", {}).get("total", 0)
            offset += len(ids)
            if offset >= total:
                return

    def _map_detection(self, alert: dict) -> NormalizedRecord | None:
        """Map a Falcon alert into a NormalizedRecord with category=detection.

        Detections differ from vulnerabilities: they are threat events, not
        latent weaknesses. The canonical_id is the detection rule name, so
        many detections on different hosts group under one 'vuln' row for
        trending, the way CVEs do."""
        aid = alert.get("device", {}).get("device_id") or alert.get("aid") or "unknown"
        hostname = (alert.get("device") or {}).get("hostname") or aid
        asset = NormalizedAsset(
            source_asset_id=aid,
            name=hostname,
            asset_type=(alert.get("device", {}).get("product_type_desc") or "endpoint").lower(),
            os_name=alert.get("device", {}).get("os_version"),
            ip_address=alert.get("device", {}).get("local_ip"),
            environment=_env_from_tags(alert.get("device") or {}),
            tags={
                "groups": (alert.get("device") or {}).get("groups") or [],
                "tags": (alert.get("device") or {}).get("tags") or [],
                "platform": (alert.get("device") or {}).get("platform_name"),
            },
        )

        sev_num = alert.get("severity") or alert.get("severity_name") or 0
        sev = _falcon_severity(sev_num)
        name = alert.get("name") or alert.get("display_name") or alert.get("type") or "unknown"
        technique = alert.get("technique") or alert.get("tactic")
        description = alert.get("description") or alert.get("objective") or ""

        canonical = f"falcon-detect:{name}"
        vuln = NormalizedVuln(
            canonical_id=canonical,
            title=name[:400],
            description=description,
            severity=sev,
            references=[alert.get("falcon_host_link")] if alert.get("falcon_host_link") else [],
        )

        status_raw = (alert.get("status") or "").lower()
        resolved_statuses = {"closed", "resolved", "true_positive", "false_positive", "ignored"}
        status = ("fixed" if status_raw in resolved_statuses
                  else "suppressed_at_source" if status_raw == "ignored"
                  else "open")
        # updated_timestamp when closed, else assigned_to_date, else now.
        resolved_at = (parse_ts(alert.get("updated_timestamp"))
                       if status != "open" else None)

        return NormalizedRecord(
            source_finding_id=f"detect:{alert.get('composite_id') or alert.get('id')}",
            category=FindingCategory.DETECTION.value,
            asset=asset, vuln=vuln,
            severity=sev,
            source_severity=str(sev_num),
            status=status,
            component=technique,
            component_key=f"detect:{name}",
            location=alert.get("filepath") or alert.get("cmdline"),
            first_detected=parse_ts(alert.get("created_timestamp") or alert.get("timestamp")),
            last_seen=parse_ts(alert.get("updated_timestamp")),
            resolved_at=resolved_at,
            source_url=alert.get("falcon_host_link"),
            raw=alert,
        )

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
            resolved_at=parse_ts(item.get("closed_timestamp")),
            raw=item,
        )


def _component_key(app: dict) -> str | None:
    name = app.get("product_name_normalized")
    if not name:
        return None
    vendor = (app.get("vendor_normalized") or "generic").lower().replace(" ", "-")
    return f"pkg:app/{vendor}/{name.lower().replace(' ', '-')}"


def _falcon_severity(raw) -> str:
    """Map Falcon's 1-100 severity (or named severity) to our 5-level scale."""
    if isinstance(raw, str):
        return normalize_severity(raw).value
    try:
        n = int(raw)
    except (TypeError, ValueError):
        return "info"
    if n >= 70:
        return "critical"
    if n >= 50:
        return "high"
    if n >= 30:
        return "medium"
    if n > 0:
        return "low"
    return "info"


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
