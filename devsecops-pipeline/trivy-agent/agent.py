"""Trivy scanning agent.

Runs continuously, scanning:
  - All local Docker images (container vuln scanning)
  - Filesystem paths mounted into the container (dependency/SBOM scanning)
  - Config files for misconfigurations (IaC scanning)

Results are reported to:
  1. RiskDesk via its API (findings and compliance data)
  2. DefectDojo via its import API (for teams that use both)
  3. Local JSON files in /results for archival

The agent runs on a configurable interval and can also be triggered via
an HTTP endpoint for on-demand scans from the CI pipeline.
"""
import json
import logging
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("trivy-agent")

RISKDESK_URL = os.getenv("RISKDESK_URL", "http://localhost:8080")
RISKDESK_TOKEN = os.getenv("RISKDESK_API_TOKEN", "")
DOJO_URL = os.getenv("DOJO_URL", "")
DOJO_TOKEN = os.getenv("DOJO_API_TOKEN", "")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "3600"))
RESULTS_DIR = Path(os.getenv("RESULTS_DIR", "/results"))
RESULTS_DIR.mkdir(parents=True, exist_ok=True)


def scan_image(image: str) -> dict | None:
    """Scan a Docker image with Trivy and return the JSON report."""
    out_file = RESULTS_DIR / f"trivy-image-{_safe(image)}.json"
    cmd = [
        "trivy", "image", "--format", "json", "--output", str(out_file),
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
        "--vuln-type", "os,library",
        "--scanners", "vuln,secret,misconfig",
        image,
    ]
    log.info("Scanning image: %s", image)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        log.error("Trivy failed for %s: %s", image, result.stderr[:500])
        return None
    try:
        return json.loads(out_file.read_text())
    except Exception as exc:
        log.error("Could not parse Trivy output: %s", exc)
        return None


def scan_filesystem(path: str) -> dict | None:
    """Scan a filesystem path for vulnerabilities and misconfigurations."""
    out_file = RESULTS_DIR / f"trivy-fs-{_safe(path)}.json"
    cmd = [
        "trivy", "fs", "--format", "json", "--output", str(out_file),
        "--severity", "CRITICAL,HIGH,MEDIUM,LOW",
        "--scanners", "vuln,secret,misconfig",
        path,
    ]
    log.info("Scanning filesystem: %s", path)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        log.error("Trivy fs failed for %s: %s", path, result.stderr[:500])
        return None
    try:
        return json.loads(out_file.read_text())
    except Exception:
        return None


def get_local_images() -> list[str]:
    """List Docker images on the host (via mounted docker.sock)."""
    try:
        result = subprocess.run(
            ["docker", "images", "--format", "{{.Repository}}:{{.Tag}}"],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return []
        images = [
            line.strip() for line in result.stdout.strip().split("\n")
            if line.strip() and "<none>" not in line
        ]
        return images
    except Exception as exc:
        log.warning("Could not list Docker images: %s", exc)
        return []


def report_to_riskdesk(report: dict, scan_type: str, target: str):
    """Push Trivy results to RiskDesk as pipeline findings."""
    if not RISKDESK_TOKEN:
        log.debug("No RiskDesk token configured, skipping")
        return
    headers = {"Authorization": f"Bearer {RISKDESK_TOKEN}", "Content-Type": "application/json"}
    try:
        # Use the generic import endpoint if available, otherwise post individual findings
        r = httpx.post(
            f"{RISKDESK_URL}/api/pipeline/import",
            json={
                "source": "trivy",
                "scan_type": scan_type,
                "target": target,
                "report": report,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            headers=headers,
            timeout=60,
        )
        log.info("RiskDesk import: %s %s", r.status_code, r.text[:200])
    except Exception as exc:
        log.warning("RiskDesk report failed: %s", exc)


def report_to_defectdojo(report_path: str, scan_type: str, product_name: str):
    """Push Trivy JSON to DefectDojo's reimport API."""
    if not DOJO_TOKEN or not DOJO_URL:
        return
    headers = {"Authorization": f"Token {DOJO_TOKEN}"}
    try:
        with open(report_path, "rb") as f:
            r = httpx.post(
                f"{DOJO_URL}/api/v2/reimport-scan/",
                headers=headers,
                data={
                    "scan_type": "Trivy Scan",
                    "product_name": product_name,
                    "engagement_name": f"Pipeline-{scan_type}",
                    "auto_create_context": "true",
                    "active": "true",
                    "verified": "false",
                    "minimum_severity": "Low",
                },
                files={"file": (Path(report_path).name, f, "application/json")},
                timeout=120,
            )
        log.info("DefectDojo import: %s", r.status_code)
    except Exception as exc:
        log.warning("DefectDojo report failed: %s", exc)


def run_scan_cycle():
    """One full scan cycle."""
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")

    # Scan all local container images
    images = get_local_images()
    log.info("Found %d local images", len(images))
    for image in images:
        report = scan_image(image)
        if report:
            report_to_riskdesk(report, "container", image)
            report_path = RESULTS_DIR / f"trivy-image-{_safe(image)}.json"
            report_to_defectdojo(str(report_path), "container", image.split(":")[0])

    # Scan mounted filesystem paths
    scan_paths = os.getenv("TRIVY_SCAN_PATHS", "").split(",")
    for path in scan_paths:
        path = path.strip()
        if path and Path(path).exists():
            report = scan_filesystem(path)
            if report:
                report_to_riskdesk(report, "filesystem", path)

    log.info("Scan cycle complete. Next in %ds", SCAN_INTERVAL)


def _safe(s: str) -> str:
    return "".join(c if c.isalnum() or c in "-_." else "_" for c in s)[:100]


if __name__ == "__main__":
    log.info("Trivy agent starting (interval=%ds)", SCAN_INTERVAL)
    while True:
        try:
            run_scan_cycle()
        except Exception:
            log.exception("Scan cycle failed")
        time.sleep(SCAN_INTERVAL)
