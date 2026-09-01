"""Synthetic data generator.

Exists so the interface can be evaluated before any credential is issued.
Everything it produces is invented. Records are tagged `demo: true` in `raw`
and the UI shows a banner while any demo data is present, so demo rows can
never be mistaken for a real scan result or quoted in a report.
"""
from __future__ import annotations

import datetime as dt
import random
from typing import Iterator

from ..enums import FindingCategory
from .base import Connector, NormalizedAsset, NormalizedRecord, NormalizedVuln

SEED = 20260826

CVES = [
    ("CVE-2024-3094", 10.0, "critical", "xz-utils backdoor in liblzma", True),
    ("CVE-2021-44228", 10.0, "critical", "Log4Shell remote code execution in Apache Log4j 2", True),
    ("CVE-2023-4863", 8.8, "high", "Heap buffer overflow in libwebp", True),
    ("CVE-2024-21762", 9.8, "critical", "Out-of-bounds write in FortiOS SSL VPN", True),
    ("CVE-2023-38545", 9.8, "critical", "SOCKS5 heap buffer overflow in curl", False),
    ("CVE-2024-6387", 8.1, "high", "regreSSHion signal handler race in OpenSSH", False),
    ("CVE-2023-44487", 7.5, "high", "HTTP/2 Rapid Reset denial of service", True),
    ("CVE-2024-27198", 9.8, "critical", "Authentication bypass in TeamCity", True),
    ("CVE-2022-22965", 9.8, "critical", "Spring4Shell remote code execution", True),
    ("CVE-2023-23397", 9.8, "critical", "Elevation of privilege in Microsoft Outlook", True),
    ("CVE-2024-1086", 7.8, "high", "Use-after-free in Linux netfilter nf_tables", True),
    ("CVE-2023-5678", 5.3, "medium", "Excessive time in OpenSSL DH key checks", False),
    ("CVE-2024-2511", 5.9, "medium", "Unbounded session cache growth in OpenSSL", False),
    ("CVE-2023-45853", 9.8, "critical", "Integer overflow in zlib MiniZip", False),
    ("CVE-2024-28085", 6.7, "medium", "wall command escape sequence injection in util-linux", False),
    ("CVE-2023-29491", 7.8, "high", "Local privilege escalation in ncurses", False),
    ("CVE-2022-40982", 6.5, "medium", "Downfall transient execution side channel", False),
    ("CVE-2024-25062", 7.5, "high", "Use-after-free in libxml2 XML reader", False),
    ("CVE-2023-50387", 7.5, "high", "KeyTrap DNSSEC resource exhaustion", False),
    ("CVE-2024-45490", 7.5, "high", "Negative length handling in libexpat", False),
    ("CVE-2023-48795", 5.9, "medium", "Terrapin prefix truncation in SSH transport", False),
    ("CVE-2024-0727", 5.5, "medium", "NULL pointer dereference in OpenSSL PKCS12", False),
]

WINDOWS_HOSTS = [f"PLI-NYC-WS{i:03d}" for i in range(1, 41)] + \
                [f"PLI-SF-WS{i:03d}" for i in range(1, 16)]
SERVER_HOSTS = [f"pli-app{i:02d}" for i in range(1, 9)] + \
               [f"pli-sql{i:02d}" for i in range(1, 4)] + \
               [f"pli-web{i:02d}" for i in range(1, 5)]
AZURE_RESOURCES = [
    ("pli-prod-aks-node-01", "virtual_machine", "production"),
    ("pli-prod-aks-node-02", "virtual_machine", "production"),
    ("pli-prod-api-plan", "app_service", "production"),
    ("pli-prod-storage", "storage_account", "production"),
    ("pli-uat-api-plan", "app_service", "non_production"),
    ("pli-dev-sandbox-vm", "virtual_machine", "non_production"),
    ("pli-prod-keyvault", "key_vault", "production"),
    ("pli-prod-sqlmi", "sql_managed_instance", "production"),
    ("pli-media-cdn-origin", "storage_account", "production"),
    ("pli-dev-buildagent", "virtual_machine", "non_production"),
]
AWS_RESOURCES = [
    ("pli-legacy-ec2-01", "virtual_machine", "production"),
    ("pli-legacy-s3-archive", "storage_bucket", "production"),
    ("pli-lambda-transcode", "serverless_function", "production"),
]
REPOS = [
    "pli/programs-web", "pli/catalog-api", "pli/checkout-service",
    "pli/member-portal", "pli/content-pipeline", "pli/infra-terraform",
    "pli/legacy-cms", "pli/mobile-app",
]
NPM_PKGS = [("lodash", "4.17.20", "4.17.21"), ("axios", "0.21.1", "1.6.8"),
            ("minimist", "1.2.5", "1.2.8"), ("express", "4.17.1", "4.19.2"),
            ("jsonwebtoken", "8.5.1", "9.0.2"), ("semver", "5.7.1", "7.5.4")]
PY_PKGS = [("django", "3.2.12", "4.2.11"), ("requests", "2.25.1", "2.32.0"),
           ("pillow", "9.0.0", "10.3.0"), ("cryptography", "38.0.1", "42.0.5")]
CODEQL_RULES = [
    ("js/sql-injection", "Database query built from user-controlled sources", "high"),
    ("js/xss", "DOM text reinterpreted as HTML", "high"),
    ("py/path-injection", "Uncontrolled data used in path expression", "high"),
    ("js/hardcoded-credentials", "Hard-coded credentials in source", "critical"),
    ("py/weak-cryptographic-algorithm", "Use of a broken or weak cryptographic algorithm", "medium"),
    ("js/insecure-randomness", "Insecure randomness in a security context", "medium"),
]
WIZ_RULES = [
    ("wiz-az-001", "Storage account allows public blob access", "high"),
    ("wiz-az-014", "Network security group permits 0.0.0.0/0 on management ports", "critical"),
    ("wiz-az-022", "Key Vault soft-delete and purge protection disabled", "medium"),
    ("wiz-aws-007", "S3 bucket server-side encryption not enforced", "high"),
    ("wiz-az-031", "SQL managed instance auditing disabled", "medium"),
    ("wiz-az-045", "VM disk encryption not enabled", "high"),
]


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class DemoConnector(Connector):
    """Produces records for a given source label with a fixed seed."""

    def __init__(self, source: str, volume: int = 1):
        self.source = source
        self.volume = volume
        self.rng = random.Random(f"{SEED}-{source}")

    def configured(self) -> bool:
        return True

    def check(self) -> tuple[bool, str]:
        return True, f"Demo generator ready for {self.source}. Data is synthetic."

    def fetch(self, limit: int | None = None) -> Iterator[NormalizedRecord]:
        gen = {
            "falcon": self._falcon,
            "wiz": self._wiz,
            "github": self._github,
        }[self.source]
        count = 0
        for rec in gen():
            rec.raw["demo"] = True
            yield rec
            count += 1
            if limit and count >= limit:
                return

    def _age(self, max_days: int = 400) -> dt.datetime:
        return _now() - dt.timedelta(days=self.rng.randint(1, max_days),
                                     hours=self.rng.randint(0, 23))

    # --- falcon (endpoints) -------------------------------------------------

    def _falcon(self) -> Iterator[NormalizedRecord]:
        hosts = WINDOWS_HOSTS + SERVER_HOSTS
        n = 0
        for host in hosts:
            is_server = host.startswith("pli-")
            env = "production" if is_server else None
            per_host = self.rng.randint(3, 14) * self.volume
            for _ in range(per_host):
                cve_id, cvss, sev, title, kev = self.rng.choice(CVES)
                first = self._age()
                product = self.rng.choice([
                    ("Google Chrome", "microsoft"), ("Microsoft Office", "microsoft"),
                    ("Adobe Acrobat Reader", "adobe"), ("OpenSSL", "openssl"),
                    ("Zoom", "zoom"), ("7-Zip", "igor-pavlov"), ("Node.js", "nodejs"),
                ])
                has_fix = self.rng.random() < 0.82
                n += 1
                yield NormalizedRecord(
                    source_finding_id=f"demo-falcon-{n:06d}",
                    category=FindingCategory.OS_VULN.value,
                    asset=NormalizedAsset(
                        source_asset_id=f"aid-{abs(hash(host)) % 10**12:012d}",
                        name=host,
                        asset_type="server" if is_server else "workstation",
                        os_name="Windows Server 2022" if is_server else self.rng.choice(
                            ["Windows 11 23H2", "Windows 11 22H2", "macOS 14.5"]),
                        ip_address=f"10.{20 if 'NYC' in host else 30}.{self.rng.randint(1,8)}.{self.rng.randint(2,250)}",
                        environment=env,
                        tags={"site": "NYC" if "NYC" in host or is_server else "SF"},
                    ),
                    vuln=NormalizedVuln(
                        canonical_id=cve_id, cve_id=cve_id, title=title,
                        description=f"{title}. Synthetic record for interface evaluation.",
                        cvss_score=cvss, severity=sev, kev=kev,
                        remediation=f"Update {product[0]} to the current supported release.",
                    ),
                    severity=sev, source_severity=sev.upper(),
                    component=product[0],
                    component_key=f"pkg:app/{product[1]}/{product[0].lower().replace(' ', '-')}",
                    fix_available=has_fix,
                    fix_version="latest" if has_fix else None,
                    first_detected=first, last_seen=_now() - dt.timedelta(hours=self.rng.randint(1, 30)),
                    raw={"source": "demo"},
                )

    # --- wiz (cloud) --------------------------------------------------------

    def _wiz(self) -> Iterator[NormalizedRecord]:
        n = 0
        resources = ([(r, "azure", e, t) for r, t, e in AZURE_RESOURCES] +
                     [(r, "aws", e, t) for r, t, e in AWS_RESOURCES])
        for name, cloud, env, rtype in resources:
            exposed = None
            if "web" in name or "cdn" in name or "api" in name:
                exposed = True
            elif "sql" in name or "keyvault" in name:
                exposed = False
            per = self.rng.randint(8, 30) * self.volume
            for _ in range(per):
                cve_id, cvss, sev, title, kev = self.rng.choice(CVES)
                has_fix = self.rng.random() < 0.7
                n += 1
                yield NormalizedRecord(
                    source_finding_id=f"demo-wiz-{n:06d}",
                    category=FindingCategory.CLOUD_VULN.value,
                    asset=NormalizedAsset(
                        source_asset_id=f"wiz-{abs(hash(name)) % 10**10:010d}",
                        name=name, asset_type=rtype,
                        os_name="Ubuntu 22.04 LTS" if rtype == "virtual_machine" else None,
                        cloud_provider=cloud,
                        cloud_account="e2f1-prod-sub" if env == "production" else "a91c-dev-sub",
                        region="eastus" if cloud == "azure" else "us-east-1",
                        environment=env, internet_facing=exposed,
                        tags={"environment": env, "owner": "platform"},
                    ),
                    vuln=NormalizedVuln(
                        canonical_id=cve_id, cve_id=cve_id, title=title,
                        description=f"{title}. Synthetic record for interface evaluation.",
                        cvss_score=cvss, severity=sev, kev=kev,
                        # Wiz is the one source in this demo that carries EPSS.
                        epss_score=round(self.rng.random() ** 3, 4),
                        remediation="Patch the affected package and redeploy the image.",
                    ),
                    severity=sev, source_severity=sev.upper(),
                    component=self.rng.choice(["openssl", "glibc", "curl", "zlib", "libxml2", "systemd"]),
                    component_key=f"pkg:deb/{self.rng.choice(['openssl','glibc','curl','zlib'])}",
                    fix_available=has_fix,
                    fix_version="1.1.1w" if has_fix else None,
                    first_detected=self._age(), last_seen=_now(),
                    raw={"source": "demo"},
                )
            # A few misconfigurations per resource.
            for _ in range(self.rng.randint(0, 3)):
                rid, rname, sev = self.rng.choice(WIZ_RULES)
                n += 1
                yield NormalizedRecord(
                    source_finding_id=f"demo-wiz-cfg-{n:06d}",
                    category=FindingCategory.MISCONFIGURATION.value,
                    asset=NormalizedAsset(
                        source_asset_id=f"wiz-{abs(hash(name)) % 10**10:010d}",
                        name=name, asset_type=rtype, cloud_provider=cloud,
                        cloud_account="e2f1-prod-sub" if env == "production" else "a91c-dev-sub",
                        environment=env, internet_facing=exposed,
                    ),
                    vuln=NormalizedVuln(
                        canonical_id=f"wiz-rule:{rid}", title=rname, severity=sev,
                        description="Cloud configuration rule failure. Synthetic record.",
                        remediation="Apply the hardened configuration in the resource template.",
                    ),
                    severity=sev, source_severity=sev.upper(),
                    component=rid, component_key=f"rule:wiz:{rid}",
                    first_detected=self._age(180), last_seen=_now(),
                    raw={"source": "demo"},
                )

    # --- github -------------------------------------------------------------

    def _github(self) -> Iterator[NormalizedRecord]:
        n = 0
        for repo in REPOS:
            asset = NormalizedAsset(
                source_asset_id=repo, name=repo, asset_type="repository",
                owner="pli", tags={"private": True, "default_branch": "main"},
            )
            for _ in range(self.rng.randint(4, 18) * self.volume):
                eco, pkgs = self.rng.choice([("npm", NPM_PKGS), ("pip", PY_PKGS)])
                pkg, bad, fixed = self.rng.choice(pkgs)
                cve_id, cvss, sev, title, kev = self.rng.choice(CVES)
                n += 1
                yield NormalizedRecord(
                    source_finding_id=f"demo-gh-dep-{n:06d}",
                    category=FindingCategory.DEPENDENCY.value,
                    asset=asset,
                    vuln=NormalizedVuln(
                        canonical_id=cve_id, cve_id=cve_id, title=title,
                        description=f"{title}. Synthetic record for interface evaluation.",
                        cvss_score=cvss, severity=sev, kev=kev,
                        remediation=f"Upgrade {pkg} to {fixed}",
                    ),
                    severity=sev, source_severity=sev,
                    component=pkg, component_version=f"< {fixed}",
                    component_key=f"pkg:{eco}/{pkg}",
                    location="package.json" if eco == "npm" else "requirements.txt",
                    fix_available=True, fix_version=fixed,
                    first_detected=self._age(300), last_seen=_now(),
                    raw={"source": "demo"},
                )
            for _ in range(self.rng.randint(1, 8)):
                rule, desc, sev = self.rng.choice(CODEQL_RULES)
                n += 1
                yield NormalizedRecord(
                    source_finding_id=f"demo-gh-cs-{n:06d}",
                    category=FindingCategory.CODE_SCANNING.value,
                    asset=asset,
                    vuln=NormalizedVuln(
                        canonical_id=f"codeql:{rule}", title=desc, severity=sev,
                        description=f"{desc}. Synthetic record for interface evaluation.",
                    ),
                    severity=sev, source_severity=sev,
                    component="CodeQL", component_key=f"rule:codeql:{rule}",
                    location=f"src/{self.rng.choice(['api','web','lib'])}/"
                             f"{self.rng.choice(['handler','router','model'])}.{'js' if 'js/' in rule else 'py'}"
                             f":{self.rng.randint(20, 400)}",
                    fix_available=self.rng.random() < 0.4,
                    first_detected=self._age(200), last_seen=_now(),
                    raw={"source": "demo"},
                )
            if self.rng.random() < 0.35:
                n += 1
                stype = self.rng.choice(["azure_storage_account_key", "aws_access_key_id",
                                         "github_personal_access_token", "slack_incoming_webhook_url"])
                yield NormalizedRecord(
                    source_finding_id=f"demo-gh-sec-{n:06d}",
                    category=FindingCategory.SECRET.value,
                    asset=asset,
                    vuln=NormalizedVuln(
                        canonical_id=f"secret:{stype}",
                        title=f"Exposed credential: {stype.replace('_', ' ')}",
                        severity="critical",
                        description="A credential was found in repository content. Synthetic record.",
                        remediation="Revoke and rotate the credential, then purge it from git history.",
                    ),
                    severity="critical", source_severity="active",
                    component=stype, component_key=f"secret:{stype}",
                    first_detected=self._age(120), last_seen=_now(),
                    raw={"source": "demo"},
                )
