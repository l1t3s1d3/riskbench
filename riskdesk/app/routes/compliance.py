"""Compliance and targets routes."""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from sqlalchemy import select

from .. import compliance as compliance_svc
from ..db import get_session
from ..models import AuditEvent, ComplianceBenchmark, ComplianceScan, ComplianceTarget
from .deps import current_user, parse_date

router = APIRouter(prefix="/api", tags=["compliance"])


@router.get("/compliance")
def compliance_summary(db=Depends(get_session)):
    return compliance_svc.get_compliance_summary(db)


@router.post("/compliance/import")
async def import_compliance(request: Request, db=Depends(get_session)):
    form = await request.form()
    file = form.get("file")
    if not file or not hasattr(file, "read"):
        raise HTTPException(400, "Upload a CSV file as 'file' in a multipart form.")
    content = await file.read()
    filename = getattr(file, "filename", "upload.csv")
    actor = current_user(request)

    try:
        scans = compliance_svc.parse_file(content, filename)
    except Exception as exc:
        raise HTTPException(422, f"Could not parse the file: {exc}")

    if not scans:
        raise HTTPException(422, "No benchmark results found in the file.")

    results = []
    for parsed in scans:
        r = compliance_svc.import_scan(db, parsed, actor=actor)
        results.append(r)
        db.add(AuditEvent(
            actor=actor, action="compliance.import",
            entity_type="scan", entity_id=str(r["scan_id"]),
            summary=(f"Imported {r['framework'].upper()} scan: {r['benchmark']} "
                     f"({r['host_count']} hosts, {r['score_percent']}% compliance)"),
            detail=r,
        ))
    db.commit()
    return {"imported": len(results), "scans": results}


@router.get("/compliance/scans/{scan_id}")
def compliance_scan_detail(scan_id: int, db=Depends(get_session)):
    detail = compliance_svc.get_scan_detail(db, scan_id)
    if not detail:
        raise HTTPException(404, "Scan not found.")
    return detail


@router.get("/compliance/hosts/{hostname}")
def compliance_host(hostname: str, db=Depends(get_session)):
    return compliance_svc.get_host_compliance(db, hostname)


@router.get("/compliance/scans")
def list_compliance_scans(db=Depends(get_session)):
    scans = db.execute(
        select(ComplianceScan).order_by(ComplianceScan.scan_date.desc()).limit(100)
    ).scalars().all()
    return [{
        "id": s.id, "benchmark_id": s.benchmark_id,
        "scan_date": s.scan_date.isoformat() if s.scan_date else None,
        "source_file": s.source_file, "imported_by": s.imported_by,
        "total_pass": s.total_pass, "total_fail": s.total_fail,
        "total_manual": s.total_manual, "score_percent": s.score_percent,
        "host_count": s.host_count,
    } for s in scans]


@router.get("/compliance/targets")
def list_targets(db=Depends(get_session)):
    rows = db.execute(
        select(ComplianceTarget).order_by(ComplianceTarget.target_date)
    ).scalars().all()
    return [{
        "id": t.id, "benchmark_id": t.benchmark_id,
        "target_percent": t.target_percent,
        "target_date": t.target_date.isoformat() if t.target_date else None,
        "baseline_percent": t.baseline_percent,
        "baseline_date": t.baseline_date.isoformat() if t.baseline_date else None,
        "description": t.description,
    } for t in rows]


@router.post("/compliance/targets")
def set_target(request: Request, body: dict = Body(...), db=Depends(get_session)):
    bm_id = body.get("benchmark_id")
    if not bm_id:
        raise HTTPException(422, "benchmark_id is required.")
    bm = db.get(ComplianceBenchmark, bm_id)
    if not bm:
        raise HTTPException(404, "Benchmark not found.")

    existing = db.execute(
        select(ComplianceTarget).where(ComplianceTarget.benchmark_id == bm_id)
    ).scalar_one_or_none()
    if existing:
        existing.target_percent = body.get("target_percent", existing.target_percent)
        if body.get("target_date"):
            existing.target_date = parse_date(body["target_date"])
        if body.get("baseline_percent") is not None:
            existing.baseline_percent = body["baseline_percent"]
        if body.get("baseline_date"):
            existing.baseline_date = parse_date(body["baseline_date"])
        existing.description = body.get("description", existing.description)
        db.commit()
        return {"id": existing.id}

    target = ComplianceTarget(
        benchmark_id=bm_id,
        target_percent=body.get("target_percent", 100),
        target_date=parse_date(body.get("target_date")),
        baseline_percent=body.get("baseline_percent"),
        baseline_date=parse_date(body.get("baseline_date")),
        description=body.get("description"),
        created_by=current_user(request),
    )
    db.add(target)
    db.commit()
    return {"id": target.id}
