"""Pipeline integration for RiskDesk.

Provides:
  1. POST /api/pipeline/import — receives scan results from CI pipeline
     steps (Trivy, ZAP, SonarQube) and converts them to RiskDesk findings
  2. GET/POST /api/pipeline/containers — manage the DevSecOps containers
     from the RiskDesk admin UI

The import endpoint normalizes results from multiple scanner formats into
the same NormalizedRecord structure the connectors use, so pipeline findings
show up alongside Wiz/Falcon/GitHub findings with the same adjudication
and risk scoring behavior.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import subprocess

from .connectors.base import NormalizedAsset, NormalizedRecord, NormalizedVuln
from .enums import FindingCategory, normalize_severity
from .sync import run_sync
from .db import SessionLocal
from .models import AuditEvent, Finding, utcnow

log = logging.getLogger(__name__)


def import_pipeline_scan(db, payload: dict, actor: str = "pipeline") -> dict:
    """Import results from a CI pipeline scan.

    Payload format:
      {
        "source": "trivy" | "zap" | "sonar",
        "scan_type": "container" | "sca" | "dast" | "sast" | "filesystem",
        "target": "repo-name" or "image-name",
        "report": { ... scanner-specific JSON ... },
        "timestamp": "ISO-8601"
      }
    """
    source_tool = payload.get("source", "unknown")
    scan_type = payload.get("scan_type", "unknown")
    target = payload.get("target", "unknown")
    report = payload.get("report", {})

    if source_tool == "trivy":
        records = _parse_trivy(report, target, scan_type)
    elif source_tool == "zap":
        records = _parse_zap(report, target)
    else:
        log.warning("Unknown pipeline source: %s", source_tool)
        return {"imported": 0, "error": f"Unknown source: {source_tool}"}

    # Use the sync engine to upsert findings
    from .connectors.base import Connector

    class PipelineConnector(Connector):
        source = "pipeline"
        def configured(self): return True
        def check(self): return True, "Pipeline import"
        def fetch(self, limit=None):
            for r in records:
                yield r

    from .sync import _upsert_asset, _upsert_vuln, _upsert_finding
    stats = {"assets": 0, "findings": 0, "new": 0, "closed": 0}
    asset_cache = {}
    vuln_cache = {}

    for rec in records:
        asset_id = _upsert_asset(db, "pipeline", rec, asset_cache, stats)
        vuln_id = _upsert_vuln(db, rec, vuln_cache)
        _upsert_finding(db, "pipeline", rec, asset_id, vuln_id, stats)

    db.add(AuditEvent(
        actor=actor, action="pipeline.import",
        entity_type="pipeline", entity_id=f"{source_tool}/{scan_type}",
        summary=f"Pipeline import: {source_tool} {scan_type} on {target} — {stats['findings']} findings ({stats['new']} new)",
        detail={"source": source_tool, "scan_type": scan_type, "target": target, **stats},
    ))
    db.commit()

    return {
        "source": source_tool,
        "scan_type": scan_type,
        "target": target,
        "imported": stats["findings"],
        "new": stats["new"],
    }


def _parse_trivy(report: dict, target: str, scan_type: str) -> list[NormalizedRecord]:
    """Convert Trivy JSON output to NormalizedRecords."""
    records = []
    results = report.get("Results") or []

    asset = NormalizedAsset(
        source_asset_id=f"pipeline:{target}",
        name=target,
        asset_type="container_image" if scan_type == "container" else "repository",
    )

    for result_block in results:
        target_name = result_block.get("Target", target)
        result_type = result_block.get("Type", "")

        for vuln in result_block.get("Vulnerabilities") or []:
            cve = vuln.get("VulnerabilityID", "")
            severity = normalize_severity(vuln.get("Severity"), vuln.get("CVSS", {}).get("nvd", {}).get("V3Score"))
            pkg = vuln.get("PkgName", "")
            installed = vuln.get("InstalledVersion", "")
            fixed = vuln.get("FixedVersion", "")

            records.append(NormalizedRecord(
                source_finding_id=f"trivy:{target}:{cve}:{pkg}:{installed}",
                category=(FindingCategory.CONTAINER.value if scan_type == "container"
                          else FindingCategory.DEPENDENCY.value),
                asset=asset,
                vuln=NormalizedVuln(
                    canonical_id=cve,
                    cve_id=cve if cve.startswith("CVE-") else None,
                    title=vuln.get("Title") or cve,
                    description=vuln.get("Description"),
                    cvss_score=vuln.get("CVSS", {}).get("nvd", {}).get("V3Score"),
                    severity=severity.value,
                    remediation=f"Upgrade {pkg} from {installed} to {fixed}" if fixed else None,
                    references=[vuln.get("PrimaryURL")] if vuln.get("PrimaryURL") else [],
                ),
                severity=severity.value,
                source_severity=vuln.get("Severity"),
                component=pkg,
                component_version=installed,
                component_key=f"pkg:{result_type.lower()}/{pkg}" if pkg else None,
                fix_available=bool(fixed),
                fix_version=fixed or None,
                last_seen=utcnow(),
                raw=vuln,
            ))

        for secret in result_block.get("Secrets") or []:
            records.append(NormalizedRecord(
                source_finding_id=f"trivy:secret:{target}:{secret.get('RuleID', '')}:{secret.get('StartLine', '')}",
                category=FindingCategory.SECRET.value,
                asset=asset,
                vuln=NormalizedVuln(
                    canonical_id=f"secret:{secret.get('RuleID', 'unknown')}",
                    title=f"Secret detected: {secret.get('Title', secret.get('RuleID', ''))}",
                    severity="critical",
                    remediation="Rotate the credential and remove it from the codebase.",
                ),
                severity="critical",
                source_severity="CRITICAL",
                location=f"{target_name}:{secret.get('StartLine', '')}",
                raw=secret,
            ))

    return records


def _parse_zap(report: dict, target: str) -> list[NormalizedRecord]:
    """Convert ZAP JSON report to NormalizedRecords."""
    records = []
    asset = NormalizedAsset(
        source_asset_id=f"pipeline:{target}",
        name=target,
        asset_type="web_application",
    )

    for site in report.get("site") or []:
        for alert in site.get("alerts") or []:
            risk = (alert.get("riskdesc") or "").split(" ")[0].lower()
            severity = normalize_severity(risk)
            plugin_id = alert.get("pluginid", "")
            name = alert.get("name") or alert.get("alert", "")

            instances = alert.get("instances") or [{}]
            for i, inst in enumerate(instances[:50]):
                records.append(NormalizedRecord(
                    source_finding_id=f"zap:{target}:{plugin_id}:{i}",
                    category=FindingCategory.CODE_SCANNING.value,
                    asset=asset,
                    vuln=NormalizedVuln(
                        canonical_id=f"zap:{plugin_id}",
                        title=name,
                        description=alert.get("desc"),
                        severity=severity.value,
                        remediation=alert.get("solution"),
                        references=[r for r in (alert.get("reference") or "").split("\n") if r.strip()],
                    ),
                    severity=severity.value,
                    source_severity=risk,
                    location=inst.get("uri"),
                    raw={"alert": name, "uri": inst.get("uri"), "method": inst.get("method")},
                ))

    return records


# --- Container management ---------------------------------------------------

COMPOSE_FILE = "/opt/devsecops-pipeline/docker-compose.yml"

PIPELINE_SERVICES = {
    "gitea": {"name": "Gitea", "desc": "Self-hosted Git", "port": 3000},
    "woodpecker-server": {"name": "Woodpecker CI", "desc": "CI/CD engine", "port": 8000},
    "woodpecker-agent": {"name": "Woodpecker Agent", "desc": "CI worker", "port": None},
    "sonarqube": {"name": "SonarQube", "desc": "Static analysis (SAST)", "port": 9090},
    "zap": {"name": "OWASP ZAP", "desc": "Dynamic analysis (DAST)", "port": 8090},
    "defectdojo": {"name": "DefectDojo", "desc": "Vulnerability aggregator", "port": 8080},
    "trivy-agent": {"name": "Trivy Agent", "desc": "Container & dependency scanner", "port": None},
    "openscap-agent": {"name": "OpenSCAP Agent", "desc": "CIS/STIG compliance scanner", "port": None},
    "postgres": {"name": "PostgreSQL", "desc": "Shared database", "port": None},
    "redis": {"name": "Redis", "desc": "Cache", "port": None},
}


def get_container_status() -> list[dict]:
    """Get the status of all pipeline containers."""
    try:
        result = subprocess.run(
            ["docker", "ps", "-a", "--format", "{{.Names}}\t{{.Status}}\t{{.State}}"],
            capture_output=True, text=True, timeout=15,
        )
        if result.returncode != 0:
            return [{"error": "Could not query Docker. Is the socket mounted?"}]
    except FileNotFoundError:
        return [{"error": "Docker CLI not available."}]
    except Exception as exc:
        return [{"error": str(exc)}]

    running = {}
    for line in result.stdout.strip().split("\n"):
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 3:
            running[parts[0]] = {"status": parts[1], "state": parts[2]}

    services = []
    for svc_name, info in PIPELINE_SERVICES.items():
        container = f"pli-{svc_name.replace('woodpecker-server', 'woodpecker').replace('woodpecker-agent', 'wp-agent')}"
        container_info = running.get(container, {})
        services.append({
            "service": svc_name,
            "name": info["name"],
            "description": info["desc"],
            "port": info["port"],
            "container": container,
            "state": container_info.get("state", "not found"),
            "status": container_info.get("status", "not deployed"),
        })
    return services


def manage_container(action: str, service: str) -> dict:
    """Start, stop, or restart a pipeline container."""
    if action not in ("start", "stop", "restart", "logs"):
        return {"error": f"Unknown action: {action}"}
    if service not in PIPELINE_SERVICES:
        return {"error": f"Unknown service: {service}"}

    container = f"pli-{service.replace('woodpecker-server', 'woodpecker').replace('woodpecker-agent', 'wp-agent')}"

    if action == "logs":
        try:
            result = subprocess.run(
                ["docker", "logs", "--tail", "100", container],
                capture_output=True, text=True, timeout=15,
            )
            return {"service": service, "logs": result.stdout[-5000:] + result.stderr[-2000:]}
        except Exception as exc:
            return {"error": str(exc)}

    try:
        result = subprocess.run(
            ["docker", action, container],
            capture_output=True, text=True, timeout=60,
        )
        return {
            "service": service, "action": action,
            "success": result.returncode == 0,
            "output": result.stdout[:500] + result.stderr[:500],
        }
    except Exception as exc:
        return {"error": str(exc)}
