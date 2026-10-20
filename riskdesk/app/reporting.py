"""Executive report generation.

Produces a single-page executive summary as JSON (for the UI or API consumers)
and optionally as a PPTX slide deck. The report pulls from the dashboard,
compliance, and register to give the CIO a complete picture without manual
assembly.
"""
from __future__ import annotations

import datetime as dt
import io
import json

from sqlalchemy import func, select

from .config import settings
from .models import (
    Adjudication, AuditEvent, ComplianceScan, ComplianceBenchmark,
    ComplianceTarget, Finding, Vuln, Asset, utcnow,
)
from .queries import build_resolution_map
from .enums import Disposition
from .risk import sla_status


def generate_executive_summary(db) -> dict:
    """The data that goes into an executive report."""
    now = utcnow()
    resolution = build_resolution_map(db)

    # --- Vulnerability posture ---
    rows = db.execute(
        select(Finding.id, Finding.severity, Finding.source, Finding.first_detected, Vuln.kev)
        .join(Vuln, Finding.vuln_id == Vuln.id)
        .where(Finding.status == "open")
    ).all()

    by_severity = {}
    by_source = {}
    by_disposition = {}
    overdue = 0
    kev_open = 0
    for fid, sev, source, first_detected, kev in rows:
        adj = resolution.get(fid)
        eff = sev
        disp = adj.disposition if adj else "none"
        if adj and adj.disposition == Disposition.ADJUST_RISK.value and adj.adjusted_severity:
            eff = adj.adjusted_severity
        by_severity[eff] = by_severity.get(eff, 0) + 1
        by_source[source] = by_source.get(source, 0) + 1
        by_disposition[disp] = by_disposition.get(disp, 0) + 1
        if kev:
            kev_open += 1
        if sla_status(first_detected, eff, bool(kev), adj, now)[1]:
            overdue += 1

    # --- Decisions ---
    pending = db.execute(
        select(func.count()).select_from(Adjudication)
        .where(Adjudication.state == "pending_approval")
    ).scalar() or 0
    horizon = now + dt.timedelta(days=30)
    expiring = db.execute(
        select(func.count()).select_from(Adjudication)
        .where(Adjudication.state == "approved",
               Adjudication.expires_at.isnot(None),
               Adjudication.expires_at > now,
               Adjudication.expires_at <= horizon)
    ).scalar() or 0
    from .lifecycle import lifecycle_metrics
    lc = lifecycle_metrics(db, days=90, now=now)

    # --- Compliance ---
    compliance = []
    benchmarks = db.execute(select(ComplianceBenchmark)).scalars().all()
    for bm in benchmarks:
        latest = db.execute(
            select(ComplianceScan)
            .where(ComplianceScan.benchmark_id == bm.id)
            .order_by(ComplianceScan.scan_date.desc())
            .limit(1)
        ).scalar_one_or_none()
        if not latest:
            continue
        target = db.execute(
            select(ComplianceTarget).where(ComplianceTarget.benchmark_id == bm.id)
        ).scalar_one_or_none()
        compliance.append({
            "benchmark": bm.name,
            "profile": bm.profile,
            "current_score": latest.score_percent,
            "target_score": target.target_percent if target else None,
            "target_date": target.target_date.isoformat() if target and target.target_date else None,
            "on_track": (latest.score_percent >= _glide_path_score(target, now)
                         if target else None),
            "pass": latest.total_pass,
            "fail": latest.total_fail,
            "scan_date": latest.scan_date.isoformat() if latest.scan_date else None,
        })

    # --- Assets ---
    total_assets = db.execute(select(func.count()).select_from(Asset)).scalar() or 0
    unique_vulns = db.execute(select(func.count()).select_from(Vuln)).scalar() or 0

    return {
        "generated_at": now.isoformat(),
        "org": settings.org_name,
        "vulnerability_posture": {
            "open_findings": len(rows),
            "unique_vulns": unique_vulns,
            "total_assets": total_assets,
            "by_severity": by_severity,
            "by_source": by_source,
            "kev_open": kev_open,
            "overdue": overdue,
            "adjudicated": len(rows) - by_disposition.get("none", 0),
            "not_adjudicated": by_disposition.get("none", 0),
            "accepted": by_disposition.get("accept_risk", 0),
        },
        "decisions": {
            "pending_approval": pending,
            "expiring_30d": expiring,
        },
        "remediation_90d": {
            "opened": lc["opened_in_window"],
            "closed": lc["closed_in_window"],
            "mttr_days": lc["mttr_days"],
            "closed_within_sla_pct": lc["closed_within_sla_pct"],
            "reopened": lc["reopened_in_window"],
            "awaiting_verification": lc["awaiting_verification"],
        },
        "compliance": compliance,
    }


def _glide_path_score(target, now: dt.datetime) -> float:
    """Where the score should be right now to hit the target on time."""
    if not target or not target.baseline_percent or not target.baseline_date:
        return target.target_percent if target else 0
    start = target.baseline_date
    if start.tzinfo is None:
        start = start.replace(tzinfo=dt.timezone.utc)
    end = target.target_date
    if end.tzinfo is None:
        end = end.replace(tzinfo=dt.timezone.utc)
    total_span = (end - start).total_seconds()
    if total_span <= 0:
        return target.target_percent
    elapsed = (now - start).total_seconds()
    progress = min(1.0, max(0.0, elapsed / total_span))
    return target.baseline_percent + progress * (target.target_percent - target.baseline_percent)


def generate_report_pptx(db) -> bytes:
    """Generate a one-page executive summary as PPTX bytes."""
    try:
        from pptx import Presentation
        from pptx.util import Inches, Pt, Emu
        from pptx.dml.color import RGBColor
        from pptx.enum.text import PP_ALIGN
    except ImportError:
        raise RuntimeError(
            "python-pptx is not installed. Run: pip install python-pptx\n"
            "Or use the JSON report at /api/report instead."
        )

    data = generate_executive_summary(db)
    vp = data["vulnerability_posture"]
    dec = data["decisions"]

    prs = Presentation()
    prs.slide_width = Inches(13.333)
    prs.slide_height = Inches(7.5)
    slide = prs.slides.add_slide(prs.slide_layouts[6])  # blank

    SEAL = RGBColor(0xA5, 0x1C, 0x30)
    INK = RGBColor(0x16, 0x17, 0x1B)
    SLATE = RGBColor(0x5A, 0x5E, 0x68)
    WHITE = RGBColor(0xFF, 0xFF, 0xFF)

    # Title bar
    bar = slide.shapes.add_shape(1, Inches(0), Inches(0), prs.slide_width, Inches(0.05))
    bar.fill.solid()
    bar.fill.fore_color.rgb = SEAL
    bar.line.fill.background()

    title = slide.shapes.add_textbox(Inches(0.5), Inches(0.15), Inches(8), Inches(0.5))
    tf = title.text_frame
    p = tf.paragraphs[0]
    p.text = f"{data['org']} Security Posture"
    p.font.size = Pt(28)
    p.font.bold = True
    p.font.color.rgb = INK

    date_box = slide.shapes.add_textbox(Inches(9), Inches(0.2), Inches(4), Inches(0.3))
    dp = date_box.text_frame.paragraphs[0]
    dp.text = dt.date.today().strftime("%B %d, %Y")
    dp.font.size = Pt(12)
    dp.font.color.rgb = SLATE
    dp.alignment = PP_ALIGN.RIGHT

    # Stat cards
    stats = [
        ("Open Findings", str(vp["open_findings"]), ""),
        ("Not Adjudicated", str(vp["not_adjudicated"]), ""),
        ("Past SLA", str(vp["overdue"]), "is-notice"),
        ("KEV Open", str(vp["kev_open"]), "is-seal"),
        ("Pending Approval", str(dec["pending_approval"]), ""),
        ("Lapsing in 30d", str(dec["expiring_30d"]), ""),
    ]
    for i, (label, value, cls) in enumerate(stats):
        x = Inches(0.5 + (i % 6) * 2.1)
        y = Inches(0.9)
        box = slide.shapes.add_shape(1, x, y, Inches(1.9), Inches(0.8))
        box.fill.solid()
        box.fill.fore_color.rgb = RGBColor(0xF2, 0xF2, 0xF2)
        box.line.color.rgb = RGBColor(0xD8, 0xD8, 0xD8)
        tf = box.text_frame
        tf.word_wrap = True
        p1 = tf.paragraphs[0]
        p1.text = value
        p1.font.size = Pt(22)
        p1.font.bold = True
        p1.font.color.rgb = SEAL if "seal" in cls else INK
        p1.alignment = PP_ALIGN.CENTER
        p2 = tf.add_paragraph()
        p2.text = label.upper()
        p2.font.size = Pt(8)
        p2.font.color.rgb = SLATE
        p2.alignment = PP_ALIGN.CENTER

    # Severity breakdown
    y_sev = Inches(2.0)
    sev_title = slide.shapes.add_textbox(Inches(0.5), y_sev, Inches(4), Inches(0.3))
    sev_title.text_frame.paragraphs[0].text = "BY SEVERITY"
    sev_title.text_frame.paragraphs[0].font.size = Pt(9)
    sev_title.text_frame.paragraphs[0].font.color.rgb = SLATE
    sev_title.text_frame.paragraphs[0].font.bold = True

    for i, sev in enumerate(["critical", "high", "medium", "low"]):
        count = vp["by_severity"].get(sev, 0)
        y = y_sev + Inches(0.35 + i * 0.35)
        label = slide.shapes.add_textbox(Inches(0.5), y, Inches(1.2), Inches(0.3))
        label.text_frame.paragraphs[0].text = sev.capitalize()
        label.text_frame.paragraphs[0].font.size = Pt(11)
        val = slide.shapes.add_textbox(Inches(1.8), y, Inches(1), Inches(0.3))
        val.text_frame.paragraphs[0].text = str(count)
        val.text_frame.paragraphs[0].font.size = Pt(11)
        val.text_frame.paragraphs[0].font.bold = True

    # Compliance section
    if data["compliance"]:
        y_comp = Inches(2.0)
        comp_title = slide.shapes.add_textbox(Inches(5), y_comp, Inches(8), Inches(0.3))
        comp_title.text_frame.paragraphs[0].text = "COMPLIANCE"
        comp_title.text_frame.paragraphs[0].font.size = Pt(9)
        comp_title.text_frame.paragraphs[0].font.color.rgb = SLATE
        comp_title.text_frame.paragraphs[0].font.bold = True

        for i, c in enumerate(data["compliance"][:4]):
            y = y_comp + Inches(0.35 + i * 0.5)
            name = slide.shapes.add_textbox(Inches(5), y, Inches(5), Inches(0.25))
            name.text_frame.paragraphs[0].text = f"{c['benchmark']}"
            name.text_frame.paragraphs[0].font.size = Pt(11)
            score = slide.shapes.add_textbox(Inches(10.5), y, Inches(2), Inches(0.25))
            score_text = f"{c['current_score']}%"
            if c.get("target_score"):
                score_text += f" / {c['target_score']}% target"
            score.text_frame.paragraphs[0].text = score_text
            score.text_frame.paragraphs[0].font.size = Pt(11)
            score.text_frame.paragraphs[0].font.bold = True
            score.text_frame.paragraphs[0].alignment = PP_ALIGN.RIGHT

    buf = io.BytesIO()
    prs.save(buf)
    return buf.getvalue()
