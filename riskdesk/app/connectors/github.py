"""GitHub Advanced Security connector.

Pulls three org-level alert families:

  /orgs/{org}/dependabot/alerts        vulnerable dependencies (SCA)
  /orgs/{org}/code-scanning/alerts     CodeQL and other SAST results
  /orgs/{org}/secret-scanning/alerts   leaked credentials

Note on naming: GitHub Copilot itself does not expose a vulnerability API.
Copilot Autofix produces remediation suggestions that ride along on
*code scanning* alerts, which is what this connector reads. If the intent was
Copilot Autofix coverage, that shows up here as the `autofix_available` flag on
code scanning records rather than as a separate feed.

Token needs, on a fine-grained PAT or GitHub App installation:
  Repository permissions -> Dependabot alerts: read
                            Code scanning alerts: read
                            Secret scanning alerts: read
  Organization access    -> all repositories (or the subset you want covered)
Classic PATs need `security_events` plus `repo`.
"""
from __future__ import annotations

import logging
import time
from typing import Iterator

import httpx

from ..config import settings
from ..enums import FindingCategory, normalize_severity
from .base import Connector, NormalizedAsset, NormalizedRecord, NormalizedVuln, parse_ts, purl

log = logging.getLogger(__name__)


class GitHubConnector(Connector):
    source = "github"

    def __init__(self, cfg=None):
        self.cfg = cfg or settings.github

    def configured(self) -> bool:
        return self.cfg.configured

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.cfg.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def check(self) -> tuple[bool, str]:
        if not self.configured():
            return False, "GITHUB_TOKEN and GITHUB_ORG are not set."
        try:
            r = httpx.get(f"{self.cfg.api_url}/orgs/{self.cfg.org}",
                          headers=self._headers(), timeout=30)
        except Exception as exc:
            return False, f"Could not reach {self.cfg.api_url}: {exc}"
        if r.status_code == 404:
            return False, f"Organization '{self.cfg.org}' not found, or the token cannot see it."
        if r.status_code == 401:
            return False, "GitHub rejected the token."
        if r.status_code >= 400:
            return False, f"GitHub returned {r.status_code}: {r.text[:200]}"

        enabled = []
        for label, path in (
            ("Dependabot", "dependabot/alerts"),
            ("code scanning", "code-scanning/alerts"),
            ("secret scanning", "secret-scanning/alerts"),
        ):
            probe = httpx.get(f"{self.cfg.api_url}/orgs/{self.cfg.org}/{path}",
                              params={"per_page": 1}, headers=self._headers(), timeout=30)
            enabled.append(f"{label}: {'ok' if probe.status_code < 400 else probe.status_code}")
        return True, "Connected. " + "; ".join(enabled)

    # --- fetch --------------------------------------------------------------

    def fetch(self, limit: int | None = None) -> Iterator[NormalizedRecord]:
        seen = 0
        streams = []
        if self.cfg.include_dependabot:
            streams.append(("dependabot/alerts", self._map_dependabot))
        if self.cfg.include_code_scanning:
            streams.append(("code-scanning/alerts", self._map_code_scanning))
        if self.cfg.include_secret_scanning:
            streams.append(("secret-scanning/alerts", self._map_secret_scanning))

        for path, mapper in streams:
            try:
                for item in self._paginate(f"/orgs/{self.cfg.org}/{path}"):
                    rec = mapper(item)
                    if rec is not None:
                        yield rec
                        seen += 1
                        if limit and seen >= limit:
                            return
            except PermissionError as exc:
                # One disabled feature should not fail the whole sync.
                log.warning("Skipping %s: %s", path, exc)

    def _paginate(self, path: str) -> Iterator[dict]:
        url = f"{self.cfg.api_url}{path}"
        params = {"per_page": self.cfg.page_size, "state": "open"}
        while url:
            r = self._get_with_retry(url, params)
            if r.status_code in (403, 404):
                raise PermissionError(f"{r.status_code} on {path}: {r.json().get('message', '')}")
            for item in r.json():
                yield item
            url = _next_link(r.headers.get("Link", ""))
            params = None  # the Link header carries the query string forward

    def _get_with_retry(self, url: str, params: dict | None, attempts: int = 5) -> httpx.Response:
        for attempt in range(attempts):
            r = httpx.get(url, params=params, headers=self._headers(), timeout=60)
            if r.status_code in (403, 429) and r.headers.get("x-ratelimit-remaining") == "0":
                reset = int(r.headers.get("x-ratelimit-reset", 0))
                time.sleep(max(2.0, min(reset - time.time() + 2, 120)))
                continue
            if r.status_code in (500, 502, 503, 504):
                time.sleep(2 ** attempt)
                continue
            return r
        raise RuntimeError("GitHub rate limit did not clear after retries.")

    # --- mappers ------------------------------------------------------------

    def _repo_asset(self, item: dict) -> NormalizedAsset:
        repo = item.get("repository") or {}
        full = repo.get("full_name") or f"{self.cfg.org}/unknown"
        return NormalizedAsset(
            source_asset_id=full,
            name=full,
            asset_type="repository",
            owner=(repo.get("owner") or {}).get("login"),
            tags={
                "private": repo.get("private"),
                "archived": repo.get("archived"),
                "default_branch": repo.get("default_branch"),
                "html_url": repo.get("html_url"),
            },
            # A repo is not "internet facing" in the network sense; leave unset
            # rather than encoding a misleading value.
        )

    def _map_dependabot(self, item: dict) -> NormalizedRecord | None:
        adv = item.get("security_advisory") or {}
        dep = item.get("dependency") or {}
        pkg = dep.get("package") or {}
        vuln_meta = item.get("security_vulnerability") or {}

        cve_id = adv.get("cve_id")
        ghsa = adv.get("ghsa_id")
        canonical = cve_id or ghsa or f"gh-dependabot:{item.get('number')}"

        cvss = (adv.get("cvss") or {}).get("score")
        severity = normalize_severity(adv.get("severity") or vuln_meta.get("severity"), cvss)
        first_patched = (vuln_meta.get("first_patched_version") or {}).get("identifier")

        repo_asset = self._repo_asset(item)
        return NormalizedRecord(
            source_finding_id=f"dependabot:{repo_asset.source_asset_id}:{item.get('number')}",
            category=FindingCategory.DEPENDENCY.value,
            asset=repo_asset,
            vuln=NormalizedVuln(
                canonical_id=canonical,
                cve_id=cve_id,
                title=adv.get("summary") or canonical,
                description=adv.get("description"),
                cvss_score=cvss,
                cvss_vector=(adv.get("cvss") or {}).get("vector_string"),
                severity=severity.value,
                published_at=parse_ts(adv.get("published_at")),
                remediation=(f"Upgrade {pkg.get('name')} to {first_patched}"
                             if first_patched else None),
                references=[r.get("url") for r in (adv.get("references") or []) if r.get("url")],
            ),
            severity=severity.value,
            source_severity=adv.get("severity"),
            status="open" if item.get("state") == "open" else "fixed",
            component=pkg.get("name"),
            component_version=vuln_meta.get("vulnerable_version_range"),
            component_key=purl(pkg.get("ecosystem"), pkg.get("name")),
            location=dep.get("manifest_path"),
            fix_available=bool(first_patched),
            fix_version=first_patched,
            first_detected=parse_ts(item.get("created_at")),
            last_seen=parse_ts(item.get("updated_at")),
            source_url=item.get("html_url"),
            raw=item,
        )

    def _map_code_scanning(self, item: dict) -> NormalizedRecord | None:
        rule = item.get("rule") or {}
        inst = item.get("most_recent_instance") or {}
        loc = (inst.get("location") or {})
        tool = (item.get("tool") or {}).get("name") or "code-scanning"

        rule_id = rule.get("id") or "unknown-rule"
        canonical = f"{tool.lower()}:{rule_id}"
        severity = normalize_severity(
            rule.get("security_severity_level") or rule.get("severity")
        )

        repo_asset = self._repo_asset(item)
        path = loc.get("path")
        location = f"{path}:{loc.get('start_line')}" if path else None

        return NormalizedRecord(
            source_finding_id=f"codescan:{repo_asset.source_asset_id}:{item.get('number')}",
            category=FindingCategory.CODE_SCANNING.value,
            asset=repo_asset,
            vuln=NormalizedVuln(
                canonical_id=canonical,
                title=rule.get("description") or rule_id,
                description=rule.get("full_description") or inst.get("message", {}).get("text"),
                severity=severity.value,
                remediation=rule.get("help"),
                references=[item.get("html_url")] if item.get("html_url") else [],
            ),
            severity=severity.value,
            source_severity=rule.get("security_severity_level") or rule.get("severity"),
            status="open" if item.get("state") == "open" else "fixed",
            component=tool,
            component_key=f"rule:{canonical}",
            location=location,
            # Copilot Autofix availability rides on the alert, when enabled.
            fix_available=bool(item.get("autofix_available")),
            first_detected=parse_ts(item.get("created_at")),
            last_seen=parse_ts(item.get("updated_at") or inst.get("commit_sha")),
            source_url=item.get("html_url"),
            raw=item,
        )

    def _map_secret_scanning(self, item: dict) -> NormalizedRecord | None:
        secret_type = item.get("secret_type") or "unknown"
        display = item.get("secret_type_display_name") or secret_type
        repo_asset = self._repo_asset(item)
        # A live credential in source control is treated as critical by default;
        # downgrade individually via an adjust-risk decision if it is a test key.
        severity = "critical" if item.get("validity") == "active" else "high"

        return NormalizedRecord(
            source_finding_id=f"secret:{repo_asset.source_asset_id}:{item.get('number')}",
            category=FindingCategory.SECRET.value,
            asset=repo_asset,
            vuln=NormalizedVuln(
                canonical_id=f"secret:{secret_type}",
                title=f"Exposed credential: {display}",
                description=("A credential of this type was found in repository content. "
                             "Rotate the credential first, then remove it from history."),
                severity=severity,
                remediation="Revoke and rotate the credential, then purge it from git history.",
            ),
            severity=severity,
            source_severity=item.get("validity"),
            status="open" if item.get("state") == "open" else "fixed",
            component=display,
            component_key=f"secret:{secret_type}",
            location=None,
            fix_available=False,
            first_detected=parse_ts(item.get("created_at")),
            last_seen=parse_ts(item.get("updated_at")),
            source_url=item.get("html_url"),
            raw=item,
        )


def _next_link(link_header: str) -> str | None:
    for part in link_header.split(","):
        section = part.split(";")
        if len(section) < 2:
            continue
        if 'rel="next"' in section[1].strip():
            return section[0].strip().strip("<>")
    return None
