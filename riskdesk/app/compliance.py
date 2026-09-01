"""CIS and STIG compliance tracking.

Imports benchmark scan results from CSV exports (CIS-CAT, SCAP tools, STIG
Viewer exports) and tracks compliance percentages over time per host and
per benchmark.

Supported import formats:

  CIS-CAT CSV   the format from CIS-CAT Pro Assessor / CIS-CAT Lite exports.
                 No header row. Fields: timestamp, hostname, ?, ?, version,
                 scap_component_id, benchmark_name, benchmark_xccdf_id,
                 profile, profile_xccdf_id, rule_xccdf_id, rule_number,
                 rule_title, result, references. Summary rows at the bottom
                 with totals and score.

  STIG CSV       tab/comma-delimited exports from STIG Viewer or Evaluate-STIG.
                 Detected by the presence of a header row with known column
                 names (Vuln_Num, Rule_ID, Status, etc.).

Both formats land in the same schema. The parser auto-detects which format
a file is in.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import logging
import re
from dataclasses import dataclass, field

from sqlalchemy import func, select

from .models import (
    ComplianceBenchmark, ComplianceCheck, ComplianceScan, utcnow,
)

log = logging.getLogger(__name__)


@dataclass
class ParsedCheck:
    hostname: str
    rule_id: str
    rule_xccdf_id: str | None
    rule_title: str
    result: str          # pass, fail, manual, error, notselected, unknown
    references: str | None
    profile: str | None
    scan_date: dt.datetime | None


@dataclass
class ParsedScan:
    framework: str       # cis | stig
    benchmark_name: str
    benchmark_version: str | None
    benchmark_xccdf_id: str | None
    profile: str | None
    profile_xccdf_id: str | None
    scan_date: dt.datetime | None
    checks: list[ParsedCheck] = field(default_factory=list)
    # Summary from the file itself (if present)
    summary_pass: int | None = None
    summary_fail: int | None = None
    summary_error: int | None = None
    summary_manual: int | None = None
    summary_not_selected: int | None = None
    summary_score: float | None = None
    source_file: str | None = None


# --- Format detection and parsing ------------------------------------------

def parse_file(content: str | bytes, filename: str | None = None) -> list[ParsedScan]:
    """Auto-detect format and parse. Returns one or more scans (a file may
    cover multiple hosts or benchmarks)."""
    if isinstance(content, bytes):
        for enc in ("utf-8-sig", "utf-8", "latin-1"):
            try:
                content = content.decode(enc)
                break
            except UnicodeDecodeError:
                continue

    content = content.replace("\r\n", "\n").replace("\r", "\n")

    # Detect format
    first_line = content.split("\n", 1)[0].strip()
    if _is_stig_format(first_line):
        scans = _parse_stig(content, filename)
    else:
        scans = _parse_cis(content, filename)

    for s in scans:
        s.source_file = filename
    return scans


def _is_stig_format(first_line: str) -> bool:
    """STIG exports have a header row with recognizable column names."""
    lower = first_line.lower()
    stig_markers = ("vuln_num", "rule_id", "stig_id", "v-", "status", "finding_details")
    return any(m in lower for m in stig_markers)


# --- CIS-CAT parser -------------------------------------------------------

def _parse_cis(content: str, filename: str | None) -> list[ParsedScan]:
    reader = csv.reader(io.StringIO(content))
    rows = list(reader)

    checks: list[ParsedCheck] = []
    benchmark_name = None
    benchmark_version = None
    benchmark_xccdf = None
    profile = None
    profile_xccdf = None
    scan_date = None
    summary = {}

    for row in rows:
        if len(row) >= 14:
            # Check row
            ts_str = row[0].strip()
            hostname = row[1].strip()
            bm_ver = row[4].strip()
            bm_name = row[6].strip()
            bm_xccdf = row[7].strip()
            prof = row[8].strip()
            prof_xccdf = row[9].strip()
            rule_xccdf = row[10].strip()
            rule_num = row[11].strip()
            rule_title = row[12].strip()
            result = row[13].strip().lower()
            refs = row[14].strip() if len(row) > 14 else None

            # Grab metadata from first row
            if benchmark_name is None:
                benchmark_name = bm_name
                benchmark_version = bm_ver
                benchmark_xccdf = bm_xccdf
                profile = prof
                profile_xccdf = prof_xccdf
                scan_date = _parse_cis_date(ts_str)

            # Normalize result
            result = _normalize_result(result)

            checks.append(ParsedCheck(
                hostname=hostname,
                rule_id=rule_num,
                rule_xccdf_id=rule_xccdf,
                rule_title=rule_title,
                result=result,
                references=refs,
                profile=prof,
                scan_date=scan_date or _parse_cis_date(ts_str),
            ))

        elif len(row) >= 2:
            # Summary rows: "Total", "Pass: 48", "Fail: 3", ...
            # or "Actual Pass: 48.0", "Maximum Possible: 51.0", "Score: 94%"
            for cell in row:
                cell = cell.strip()
                m = re.match(r"Pass:\s*(\d+)", cell)
                if m: summary["pass"] = int(m.group(1))
                m = re.match(r"Fail:\s*(\d+)", cell)
                if m: summary["fail"] = int(m.group(1))
                m = re.match(r"Error:\s*(\d+)", cell)
                if m: summary["error"] = int(m.group(1))
                m = re.match(r"Unknown:\s*(\d+)", cell)
                if m: summary.setdefault("manual", 0)  # sometimes unknown = manual
                m = re.match(r"Not Selected:\s*(\d+)", cell)
                if m: summary["not_selected"] = int(m.group(1))
                m = re.match(r"Score:\s*([\d.]+)%", cell)
                if m: summary["score"] = float(m.group(1))

    if not checks:
        return []

    scan = ParsedScan(
        framework="cis",
        benchmark_name=benchmark_name or "Unknown CIS Benchmark",
        benchmark_version=benchmark_version,
        benchmark_xccdf_id=benchmark_xccdf,
        profile=profile,
        profile_xccdf_id=profile_xccdf,
        scan_date=scan_date,
        checks=checks,
        summary_pass=summary.get("pass"),
        summary_fail=summary.get("fail"),
        summary_error=summary.get("error"),
        summary_manual=summary.get("manual"),
        summary_not_selected=summary.get("not_selected"),
        summary_score=summary.get("score"),
    )
    return [scan]


def _parse_cis_date(s: str) -> dt.datetime | None:
    for fmt in ("%m/%d/%Y %H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return dt.datetime.strptime(s, fmt).replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    return None


# --- STIG parser -----------------------------------------------------------

def _parse_stig(content: str, filename: str | None) -> list[ParsedScan]:
    """Parse STIG Viewer / Evaluate-STIG CSV exports."""
    reader = csv.DictReader(io.StringIO(content))
    fieldnames = reader.fieldnames or []
    lower_fields = {f.lower().strip(): f for f in fieldnames}

    # Map common column name variants
    def col(candidates: list[str]) -> str | None:
        for c in candidates:
            if c.lower() in lower_fields:
                return lower_fields[c.lower()]
        return None

    vuln_col = col(["vuln_num", "vuln num", "v-id", "vid", "stig_id", "stig id", "rule_id"])
    title_col = col(["rule_title", "rule title", "title", "check_name", "group_title"])
    status_col = col(["status", "result", "finding", "compliance_status"])
    host_col = col(["hostname", "host_name", "host name", "target", "asset"])
    severity_col = col(["severity", "cat", "category"])
    details_col = col(["finding_details", "finding details", "details", "comments"])

    if not vuln_col or not status_col:
        raise ValueError(
            f"Could not identify STIG columns. Found: {fieldnames[:10]}. "
            f"Need at least a vulnerability ID column and a status column."
        )

    # Derive benchmark name from filename or first row
    bm_name = "STIG Benchmark"
    if filename:
        clean = re.sub(r"[-_]\d{8}T\d+Z?\.csv$", "", filename, flags=re.I)
        clean = clean.replace("_", " ").replace("-", " ").strip()
        if clean:
            bm_name = clean

    checks: list[ParsedCheck] = []
    for row in reader:
        vid = (row.get(vuln_col) or "").strip()
        if not vid:
            continue
        title = (row.get(title_col) or vid).strip() if title_col else vid
        status = (row.get(status_col) or "").strip().lower()
        hostname = (row.get(host_col) or "unknown").strip() if host_col else "unknown"
        result = _normalize_result(status)

        checks.append(ParsedCheck(
            hostname=hostname,
            rule_id=vid,
            rule_xccdf_id=None,
            rule_title=title,
            result=result,
            references=(row.get(details_col) or "").strip()[:500] if details_col else None,
            profile=None,
            scan_date=None,
        ))

    if not checks:
        return []

    return [ParsedScan(
        framework="stig",
        benchmark_name=bm_name,
        benchmark_version=None,
        benchmark_xccdf_id=None,
        profile=None,
        profile_xccdf_id=None,
        scan_date=None,
        checks=checks,
    )]


# --- Result normalization --------------------------------------------------

def _normalize_result(raw: str) -> str:
    r = raw.strip().lower()
    mapping = {
        "pass": "pass", "passed": "pass", "compliant": "pass",
        "notafinding": "pass", "not_a_finding": "pass", "not a finding": "pass",
        "fail": "fail", "failed": "fail", "open": "fail",
        "non-compliant": "fail", "noncompliant": "fail",
        "manual": "manual", "not_reviewed": "manual", "not reviewed": "manual",
        "not_applicable": "notselected", "not applicable": "notselected",
        "na": "notselected", "n/a": "notselected", "notselected": "notselected",
        "not selected": "notselected",
        "error": "error", "unknown": "unknown",
        "informational": "manual",
    }
    return mapping.get(r, "unknown")


# --- Import into database --------------------------------------------------

def import_scan(db, parsed: ParsedScan, actor: str = "system") -> dict:
    """Import a parsed scan into the database. Returns a summary."""
    # Upsert benchmark
    bm = db.execute(
        select(ComplianceBenchmark).where(
            ComplianceBenchmark.framework == parsed.framework,
            ComplianceBenchmark.name == parsed.benchmark_name,
            ComplianceBenchmark.version == (parsed.benchmark_version or ""),
            ComplianceBenchmark.profile == (parsed.profile or ""),
        )
    ).scalar_one_or_none()
    if not bm:
        bm = ComplianceBenchmark(
            framework=parsed.framework,
            name=parsed.benchmark_name,
            version=parsed.benchmark_version or "",
            xccdf_id=parsed.benchmark_xccdf_id,
            profile=parsed.profile or "",
            profile_xccdf_id=parsed.profile_xccdf_id,
        )
        db.add(bm)
        db.flush()

    # Compute stats
    results = {"pass": 0, "fail": 0, "manual": 0, "error": 0,
               "notselected": 0, "unknown": 0}
    hosts = set()
    for c in parsed.checks:
        results[c.result] = results.get(c.result, 0) + 1
        hosts.add(c.hostname)

    evaluated = results["pass"] + results["fail"]
    score = round(results["pass"] / evaluated * 100, 1) if evaluated > 0 else None
    # Prefer the file's own score if present
    if parsed.summary_score is not None:
        score = parsed.summary_score

    scan = ComplianceScan(
        benchmark_id=bm.id,
        scan_date=parsed.scan_date or utcnow(),
        source_file=parsed.source_file,
        imported_by=actor,
        total_checks=len(parsed.checks),
        total_pass=parsed.summary_pass if parsed.summary_pass is not None else results["pass"],
        total_fail=parsed.summary_fail if parsed.summary_fail is not None else results["fail"],
        total_manual=parsed.summary_manual if parsed.summary_manual is not None else results["manual"],
        total_error=parsed.summary_error if parsed.summary_error is not None else results["error"],
        total_not_selected=parsed.summary_not_selected if parsed.summary_not_selected is not None else results["notselected"],
        score_percent=score,
        host_count=len(hosts),
    )
    db.add(scan)
    db.flush()

    # Insert check rows
    for c in parsed.checks:
        db.add(ComplianceCheck(
            scan_id=scan.id,
            benchmark_id=bm.id,
            hostname=c.hostname,
            rule_id=c.rule_id,
            rule_xccdf_id=c.rule_xccdf_id,
            rule_title=c.rule_title,
            result=c.result,
            references=c.references,
            profile=c.profile,
            scan_date=c.scan_date or parsed.scan_date,
        ))
    db.commit()

    return {
        "scan_id": scan.id,
        "benchmark": bm.name,
        "version": bm.version,
        "profile": bm.profile,
        "framework": bm.framework,
        "hosts": list(hosts),
        "host_count": len(hosts),
        "total_checks": len(parsed.checks),
        "pass": results["pass"],
        "fail": results["fail"],
        "manual": results["manual"],
        "score_percent": score,
    }


# --- Query helpers ---------------------------------------------------------

def get_compliance_summary(db) -> dict:
    """Dashboard summary: per-benchmark latest score and trend."""
    benchmarks = db.execute(
        select(ComplianceBenchmark).order_by(ComplianceBenchmark.name)
    ).scalars().all()

    summaries = []
    for bm in benchmarks:
        scans = db.execute(
            select(ComplianceScan)
            .where(ComplianceScan.benchmark_id == bm.id)
            .order_by(ComplianceScan.scan_date.desc())
            .limit(20)
        ).scalars().all()
        if not scans:
            continue
        latest = scans[0]
        trend = [{"scan_id": s.id, "date": s.scan_date.isoformat() if s.scan_date else None,
                  "score": s.score_percent, "pass": s.total_pass, "fail": s.total_fail,
                  "hosts": s.host_count} for s in reversed(scans)]
        summaries.append({
            "benchmark_id": bm.id,
            "framework": bm.framework,
            "name": bm.name,
            "version": bm.version,
            "profile": bm.profile,
            "latest_score": latest.score_percent,
            "latest_pass": latest.total_pass,
            "latest_fail": latest.total_fail,
            "latest_manual": latest.total_manual,
            "latest_date": latest.scan_date.isoformat() if latest.scan_date else None,
            "latest_hosts": latest.host_count,
            "scan_count": len(scans),
            "trend": trend,
        })
    return {"benchmarks": summaries}


def get_scan_detail(db, scan_id: int) -> dict | None:
    scan = db.get(ComplianceScan, scan_id)
    if not scan:
        return None
    bm = db.get(ComplianceBenchmark, scan.benchmark_id)
    checks = db.execute(
        select(ComplianceCheck)
        .where(ComplianceCheck.scan_id == scan_id)
        .order_by(ComplianceCheck.hostname, ComplianceCheck.rule_id)
    ).scalars().all()

    # Per-host breakdown
    hosts: dict[str, dict] = {}
    for c in checks:
        h = hosts.setdefault(c.hostname, {"pass": 0, "fail": 0, "manual": 0, "other": 0, "checks": []})
        if c.result == "pass":
            h["pass"] += 1
        elif c.result == "fail":
            h["fail"] += 1
        elif c.result == "manual":
            h["manual"] += 1
        else:
            h["other"] += 1
        h["checks"].append({
            "rule_id": c.rule_id, "rule_title": c.rule_title,
            "result": c.result, "references": c.references,
        })

    for hname, h in hosts.items():
        evaluated = h["pass"] + h["fail"]
        h["score"] = round(h["pass"] / evaluated * 100, 1) if evaluated > 0 else None
        h["total"] = h["pass"] + h["fail"] + h["manual"] + h["other"]

    return {
        "scan_id": scan.id,
        "benchmark": bm.name if bm else None,
        "version": bm.version if bm else None,
        "profile": bm.profile if bm else None,
        "framework": bm.framework if bm else None,
        "scan_date": scan.scan_date.isoformat() if scan.scan_date else None,
        "source_file": scan.source_file,
        "imported_by": scan.imported_by,
        "score_percent": scan.score_percent,
        "total_pass": scan.total_pass,
        "total_fail": scan.total_fail,
        "total_manual": scan.total_manual,
        "host_count": scan.host_count,
        "hosts": {hname: {k: v for k, v in h.items() if k != "checks"}
                  for hname, h in hosts.items()},
        "fail_details": [
            {"hostname": c.hostname, "rule_id": c.rule_id,
             "rule_title": c.rule_title, "references": c.references}
            for c in checks if c.result == "fail"
        ],
        "manual_details": [
            {"hostname": c.hostname, "rule_id": c.rule_id,
             "rule_title": c.rule_title}
            for c in checks if c.result == "manual"
        ],
    }


def get_host_compliance(db, hostname: str) -> dict:
    """All benchmark results for a single host across time."""
    checks = db.execute(
        select(ComplianceCheck)
        .where(ComplianceCheck.hostname == hostname)
        .order_by(ComplianceCheck.scan_id.desc())
    ).scalars().all()
    if not checks:
        return {"hostname": hostname, "scans": []}

    by_scan: dict[int, list] = {}
    for c in checks:
        by_scan.setdefault(c.scan_id, []).append(c)

    scans_out = []
    for scan_id, scan_checks in by_scan.items():
        scan = db.get(ComplianceScan, scan_id)
        bm = db.get(ComplianceBenchmark, scan.benchmark_id) if scan else None
        p = sum(1 for c in scan_checks if c.result == "pass")
        f = sum(1 for c in scan_checks if c.result == "fail")
        evaluated = p + f
        scans_out.append({
            "scan_id": scan_id,
            "benchmark": bm.name if bm else None,
            "profile": bm.profile if bm else None,
            "date": scan.scan_date.isoformat() if scan and scan.scan_date else None,
            "pass": p, "fail": f,
            "score": round(p / evaluated * 100, 1) if evaluated > 0 else None,
            "fails": [{"rule_id": c.rule_id, "rule_title": c.rule_title}
                      for c in scan_checks if c.result == "fail"],
        })

    return {"hostname": hostname, "scans": scans_out}
