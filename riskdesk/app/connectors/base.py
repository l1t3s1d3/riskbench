"""Connector contract.

Every source produces NormalizedRecord objects. The sync layer owns all
database writes, so a connector is a pure read-and-map component and can be
tested against a saved API payload without a database.
"""
from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Iterator


@dataclass
class NormalizedAsset:
    source_asset_id: str
    name: str
    asset_type: str | None = None
    os_name: str | None = None
    ip_address: str | None = None
    cloud_provider: str | None = None
    cloud_account: str | None = None
    region: str | None = None
    environment: str | None = None          # leave None if the source cannot say
    internet_facing: bool | None = None     # leave None if not verified
    data_classification: str | None = None
    owner: str | None = None
    tags: dict = field(default_factory=dict)


@dataclass
class NormalizedVuln:
    canonical_id: str                       # CVE-… where one exists, else source id
    cve_id: str | None = None
    title: str | None = None
    description: str | None = None
    cvss_score: float | None = None
    cvss_vector: str | None = None
    severity: str = "info"
    epss_score: float | None = None
    epss_percentile: float | None = None
    kev: bool = False
    published_at: dt.datetime | None = None
    remediation: str | None = None
    references: list = field(default_factory=list)


@dataclass
class NormalizedRecord:
    source_finding_id: str
    category: str
    asset: NormalizedAsset
    vuln: NormalizedVuln
    severity: str = "info"
    source_severity: str | None = None
    status: str = "open"
    component: str | None = None
    component_version: str | None = None
    component_key: str | None = None
    location: str | None = None
    fix_available: bool = False
    fix_version: str | None = None
    first_detected: dt.datetime | None = None
    last_seen: dt.datetime | None = None
    source_url: str | None = None
    raw: dict = field(default_factory=dict)


class Connector:
    source: str = "unknown"

    def configured(self) -> bool:
        raise NotImplementedError

    def check(self) -> tuple[bool, str]:
        """Cheap credential/connectivity probe. (ok, message)."""
        raise NotImplementedError

    def fetch(self, limit: int | None = None) -> Iterator[NormalizedRecord]:
        raise NotImplementedError


def parse_ts(value) -> dt.datetime | None:
    """Tolerant ISO-8601 parser. Sources vary on 'Z', offsets and precision."""
    if not value:
        return None
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    s = str(value).strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    # Trim sub-second precision beyond microseconds, which fromisoformat rejects.
    if "." in s:
        head, _, tail = s.partition(".")
        digits = ""
        rest = ""
        for i, ch in enumerate(tail):
            if ch.isdigit():
                digits += ch
            else:
                rest = tail[i:]
                break
        s = f"{head}.{digits[:6]}{rest}"
    try:
        parsed = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def purl(ecosystem: str | None, name: str | None) -> str | None:
    """Stable component key so a decision on a package covers every repo."""
    if not name:
        return None
    eco = (ecosystem or "generic").lower()
    return f"pkg:{eco}/{name.lower()}"
