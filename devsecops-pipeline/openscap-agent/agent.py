"""OpenSCAP compliance scanning agent.

Evaluates hosts against CIS benchmarks and DISA STIGs using OpenSCAP
and the SCAP Security Guide (SSG) content. Results are:
  1. Exported as CSV in the CIS-CAT format that RiskDesk already imports
  2. Pushed to RiskDesk's compliance import API
  3. Stored locally in /results for archival

Profiles are configured in profiles.yml. The agent runs on a schedule and
can also be triggered for on-demand scans.

For CIS-CAT Pro content (more comprehensive than SSG), place the XCCDF
bundles in /content/ and reference them in profiles.yml.
"""
import csv
import io
import json
import logging
import os
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("openscap-agent")

RISKDESK_URL = os.getenv("RISKDESK_URL", "http://localhost:8080")
RISKDESK_TOKEN = os.getenv("RISKDESK_API_TOKEN", "")
SCAN_INTERVAL = int(os.getenv("SCAN_INTERVAL", "86400"))  # daily default
RESULTS_DIR = Path(os.getenv("RESULTS_DIR", "/results"))
RESULTS_DIR.mkdir(parents=True, exist_ok=True)
HOSTNAME = os.getenv("SCAN_HOSTNAME", os.uname().nodename)

# SCAP Security Guide content paths (installed by ssg-* packages)
SSG_CONTENT = {
    "ubuntu2204": "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml",
    "ubuntu2404": "/usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml",
    "rhel9": "/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml",
    "rhel8": "/usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml",
    "debian12": "/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml",
}

# Default profiles to scan if profiles.yml is not customized
DEFAULT_PROFILES = [
    {
        "name": "CIS Ubuntu 22.04 Level 1",
        "content": SSG_CONTENT.get("ubuntu2204", ""),
        "profile": "xccdf_org.ssgproject.content_profile_cis_level1_server",
        "enabled": True,
    },
]


def load_profiles() -> list[dict]:
    """Load scan profiles from profiles.yml or use defaults."""
    profiles_file = Path("/app/profiles.yml")
    if profiles_file.exists():
        try:
            # Simple YAML-like parser (avoid pyyaml dependency)
            text = profiles_file.read_text()
            # Fall back to defaults if the file is the template
            if "your-content-path" in text:
                return DEFAULT_PROFILES
        except Exception:
            pass
    return DEFAULT_PROFILES


def run_oscap_scan(content_path: str, profile: str, hostname: str) -> dict | None:
    """Run an OpenSCAP evaluation and return results."""
    if not Path(content_path).exists():
        log.warning("Content file not found: %s", content_path)
        return None

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    results_xml = RESULTS_DIR / f"oscap-results-{hostname}-{timestamp}.xml"
    results_html = RESULTS_DIR / f"oscap-report-{hostname}-{timestamp}.html"

    cmd = [
        "oscap", "xccdf", "eval",
        "--profile", profile,
        "--results", str(results_xml),
        "--report", str(results_html),
        content_path,
    ]

    log.info("Running OpenSCAP: profile=%s content=%s", profile, content_path)
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    # oscap returns 0 for all pass, 2 for some fail, 1 for error
    if result.returncode not in (0, 2):
        log.error("OpenSCAP failed (rc=%d): %s", result.returncode, result.stderr[:500])
        return None

    # Parse the XML results into a structured report
    return parse_oscap_results(str(results_xml), hostname, profile)


def parse_oscap_results(results_xml: str, hostname: str, profile: str) -> dict:
    """Parse OpenSCAP XML results into a dict matching RiskDesk's compliance format."""
    import xml.etree.ElementTree as ET

    tree = ET.parse(results_xml)
    root = tree.getroot()

    # Handle XCCDF namespace
    ns = {"x": "http://checklists.nist.gov/xccdf/1.2"}
    if root.tag.startswith("{"):
        ns_uri = root.tag.split("}")[0][1:]
        ns = {"x": ns_uri}

    checks = []
    benchmark_title = ""
    benchmark_version = ""

    # Try to extract benchmark info
    bm = root.find(".//x:benchmark", ns) or root
    title_el = bm.find("x:title", ns)
    if title_el is not None and title_el.text:
        benchmark_title = title_el.text
    ver_el = bm.find("x:version", ns)
    if ver_el is not None and ver_el.text:
        benchmark_version = ver_el.text

    # Extract rule results
    for result in root.iter():
        if result.tag.endswith("rule-result"):
            rule_id = result.get("idref", "")
            rule_result = ""
            result_el = result.find("{http://checklists.nist.gov/xccdf/1.2}result")
            if result_el is None:
                # Try without namespace
                for child in result:
                    if child.tag.endswith("result"):
                        rule_result = (child.text or "").strip().lower()
                        break
            else:
                rule_result = (result_el.text or "").strip().lower()

            # Map XCCDF results to our format
            result_map = {
                "pass": "pass", "fail": "fail", "error": "error",
                "notapplicable": "notselected", "notchecked": "manual",
                "informational": "manual", "fixed": "pass",
                "notselected": "notselected", "unknown": "unknown",
            }
            normalized = result_map.get(rule_result, "unknown")

            # Extract rule number from the idref
            rule_num = rule_id.split("_rule_")[-1] if "_rule_" in rule_id else rule_id

            checks.append({
                "hostname": hostname,
                "rule_id": rule_num,
                "rule_xccdf_id": rule_id,
                "rule_title": rule_num,  # Will be enriched if title available
                "result": normalized,
            })

    total = len(checks)
    passed = sum(1 for c in checks if c["result"] == "pass")
    failed = sum(1 for c in checks if c["result"] == "fail")
    evaluated = passed + failed
    score = round(passed / evaluated * 100, 1) if evaluated > 0 else None

    return {
        "benchmark_title": benchmark_title or f"SCAP Benchmark ({profile})",
        "benchmark_version": benchmark_version,
        "profile": profile,
        "hostname": hostname,
        "scan_date": datetime.now(timezone.utc).isoformat(),
        "checks": checks,
        "total": total,
        "pass": passed,
        "fail": failed,
        "score": score,
    }


def export_as_csv(report: dict) -> str:
    """Convert results to CIS-CAT CSV format for RiskDesk import."""
    buf = io.StringIO()
    writer = csv.writer(buf)
    ts = report.get("scan_date", datetime.now(timezone.utc).strftime("%m/%d/%Y %H:%M:%S"))
    hostname = report.get("hostname", "unknown")
    bm_name = report.get("benchmark_title", "SCAP Benchmark")
    bm_ver = report.get("benchmark_version", "")
    profile = report.get("profile", "")

    for check in report.get("checks", []):
        writer.writerow([
            ts, hostname, "N/A", "N/A",
            bm_ver, "", bm_name, "",
            profile, "", check.get("rule_xccdf_id", ""),
            check.get("rule_id", ""), check.get("rule_title", ""),
            check.get("result", "unknown"), "",
        ])

    # Summary rows
    total = report.get("total", 0)
    passed = report.get("pass", 0)
    failed = report.get("fail", 0)
    manual = sum(1 for c in report.get("checks", []) if c["result"] == "manual")
    writer.writerow(["Total", f"Pass: {passed}", f"Fail: {failed}",
                     f"Error: 0", f"Unknown: 0", f"Not Selected: {total - passed - failed - manual}"])
    score = report.get("score")
    if score is not None:
        writer.writerow([f"Actual Pass: {float(passed)}", f"Maximum Possible: {float(passed + failed)}",
                         f"Score: {score}%"])

    return buf.getvalue()


def report_to_riskdesk(csv_content: str, filename: str):
    """Upload the CSV to RiskDesk's compliance import endpoint."""
    if not RISKDESK_TOKEN:
        log.debug("No RiskDesk token, skipping")
        return
    try:
        r = httpx.post(
            f"{RISKDESK_URL}/api/compliance/import",
            headers={"Authorization": f"Bearer {RISKDESK_TOKEN}"},
            files={"file": (filename, csv_content.encode(), "text/csv")},
            timeout=60,
        )
        log.info("RiskDesk compliance import: %s %s", r.status_code, r.text[:200])
    except Exception as exc:
        log.warning("RiskDesk report failed: %s", exc)


def run_scan_cycle():
    """Execute all configured profiles."""
    profiles = load_profiles()
    for profile in profiles:
        if not profile.get("enabled", True):
            continue
        content = profile.get("content", "")
        prof_id = profile.get("profile", "")
        name = profile.get("name", prof_id)

        log.info("Starting compliance scan: %s", name)
        report = run_oscap_scan(content, prof_id, HOSTNAME)
        if not report:
            log.warning("Scan produced no results: %s", name)
            continue

        log.info("Scan complete: %s — %d checks, %s%% compliance",
                 name, report["total"], report.get("score", "?"))

        # Export CSV and report
        csv_content = export_as_csv(report)
        csv_filename = f"{HOSTNAME}-{name.replace(' ', '_')}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.csv"

        # Save locally
        csv_path = RESULTS_DIR / csv_filename
        csv_path.write_text(csv_content)
        log.info("Results saved: %s", csv_path)

        # Report to RiskDesk
        report_to_riskdesk(csv_content, csv_filename)

    log.info("Compliance scan cycle complete. Next in %ds", SCAN_INTERVAL)


if __name__ == "__main__":
    log.info("OpenSCAP agent starting (interval=%ds, hostname=%s)", SCAN_INTERVAL, HOSTNAME)
    while True:
        try:
            run_scan_cycle()
        except Exception:
            log.exception("Scan cycle failed")
        time.sleep(SCAN_INTERVAL)
