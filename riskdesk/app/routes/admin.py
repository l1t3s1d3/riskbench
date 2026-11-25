"""Admin routes: views, correlations, enrichment, tokens, config, reporting, pipeline."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from sqlalchemy import select

from .. import connector_config as cc_service
from .. import correlation as corr_service
from .. import enrichment as enrich_service
from .. import pipeline as pipeline_service
from .. import reporting as report_service
from .. import tokens as token_service
from ..db import get_session
from ..models import Asset, AssetCorrelation, AssetGroup, AuditEvent, SavedView
from ..schemas import AssetGroupListOut, AssetGroupOut
from .deps import current_user, current_user_obj

router = APIRouter(prefix="/api", tags=["admin"])


# --- saved views ------------------------------------------------------------

@router.get("/views")
def list_views(request: Request, db=Depends(get_session)):
    actor = current_user(request)
    rows = db.execute(
        select(SavedView).where(
            (SavedView.owner == actor) | (SavedView.shared.is_(True))
        ).order_by(SavedView.pinned.desc(), SavedView.name)
    ).scalars().all()
    return [{
        "id": v.id, "name": v.name, "description": v.description,
        "filters": v.filters, "owner": v.owner, "shared": v.shared,
        "pinned": v.pinned, "is_mine": v.owner == actor,
    } for v in rows]


@router.post("/views")
def create_view(request: Request, body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    v = SavedView(
        name=body.get("name", "Untitled"),
        description=body.get("description"),
        filters=body.get("filters", {}),
        owner=actor,
        shared=body.get("shared", False),
        pinned=body.get("pinned", False),
    )
    db.add(v)
    db.commit()
    return {"id": v.id, "name": v.name}


@router.put("/views/{view_id}")
def update_view(view_id: int, request: Request, body: dict = Body(...),
                db=Depends(get_session)):
    v = db.get(SavedView, view_id)
    if not v:
        raise HTTPException(404)
    if v.owner != current_user(request):
        raise HTTPException(403, "You can only edit your own views.")
    for field in ("name", "description", "filters", "shared", "pinned"):
        if field in body:
            setattr(v, field, body[field])
    db.commit()
    return {"ok": True}


@router.delete("/views/{view_id}")
def delete_view(view_id: int, request: Request, db=Depends(get_session)):
    v = db.get(SavedView, view_id)
    if not v:
        raise HTTPException(404)
    if v.owner != current_user(request):
        raise HTTPException(403)
    db.delete(v)
    db.commit()
    return {"deleted": view_id}


# --- asset groups -----------------------------------------------------------

def _serialize_group(g: AssetGroup, asset_count: int = 0) -> dict:
    return {
        "id": g.id, "name": g.name, "description": g.description,
        "business_unit": g.business_unit, "owner": g.owner,
        "criticality": g.criticality, "tags": g.tags or {},
        "asset_count": asset_count,
        "created_by": g.created_by,
        "created_at": g.created_at.isoformat() if g.created_at else None,
        "updated_at": g.updated_at.isoformat() if g.updated_at else None,
    }


@router.get("/asset-groups", response_model=AssetGroupListOut)
def list_asset_groups(q: str = "", business_unit: str = "", db=Depends(get_session)):
    from sqlalchemy import func
    stmt = select(AssetGroup, func.count(Asset.id).label("cnt")).outerjoin(
        Asset, Asset.asset_group_id == AssetGroup.id
    ).group_by(AssetGroup.id)
    if q:
        stmt = stmt.where(AssetGroup.name.ilike(f"%{q}%"))
    if business_unit:
        stmt = stmt.where(AssetGroup.business_unit == business_unit)
    rows = db.execute(stmt.order_by(AssetGroup.name)).all()
    return {
        "groups": [_serialize_group(g, cnt) for g, cnt in rows],
        "total": len(rows),
    }


@router.post("/asset-groups", response_model=AssetGroupOut)
def create_asset_group(request: Request, body: dict = Body(...), db=Depends(get_session)):
    name = (body.get("name") or "").strip()
    if not name:
        raise HTTPException(422, "Name is required.")
    existing = db.execute(select(AssetGroup).where(AssetGroup.name == name)).scalar_one_or_none()
    if existing:
        raise HTTPException(409, f"Asset group '{name}' already exists.")
    g = AssetGroup(
        name=name,
        description=body.get("description"),
        business_unit=body.get("business_unit"),
        owner=body.get("owner"),
        criticality=body.get("criticality", "medium"),
        tags=body.get("tags", {}),
        created_by=current_user(request),
    )
    db.add(g)
    db.commit()
    db.add(AuditEvent(
        actor=current_user(request), action="asset_group.create",
        entity_type="asset_group", entity_id=str(g.id),
        summary=f"Asset group created: {g.name}",
    ))
    db.commit()
    return _serialize_group(g)


@router.put("/asset-groups/{group_id}", response_model=AssetGroupOut)
def update_asset_group(group_id: int, request: Request, body: dict = Body(...),
                       db=Depends(get_session)):
    g = db.get(AssetGroup, group_id)
    if not g:
        raise HTTPException(404)
    for field in ("name", "description", "business_unit", "owner", "criticality", "tags"):
        if field in body:
            setattr(g, field, body[field])
    db.commit()
    db.add(AuditEvent(
        actor=current_user(request), action="asset_group.update",
        entity_type="asset_group", entity_id=str(g.id),
        summary=f"Asset group updated: {g.name}",
    ))
    db.commit()
    from sqlalchemy import func
    cnt = db.execute(
        select(func.count()).select_from(Asset).where(Asset.asset_group_id == g.id)
    ).scalar() or 0
    return _serialize_group(g, cnt)


@router.delete("/asset-groups/{group_id}")
def delete_asset_group(group_id: int, request: Request, db=Depends(get_session)):
    g = db.get(AssetGroup, group_id)
    if not g:
        raise HTTPException(404)
    db.execute(
        select(Asset).where(Asset.asset_group_id == group_id)
    )
    from sqlalchemy import update
    db.execute(update(Asset).where(Asset.asset_group_id == group_id).values(asset_group_id=None))
    db.delete(g)
    db.add(AuditEvent(
        actor=current_user(request), action="asset_group.delete",
        entity_type="asset_group", entity_id=str(group_id),
        summary=f"Asset group deleted: {g.name}",
    ))
    db.commit()
    return {"deleted": group_id}


@router.post("/asset-groups/{group_id}/assets")
def assign_assets_to_group(group_id: int, request: Request, body: dict = Body(...),
                           db=Depends(get_session)):
    """Assign assets to a group by asset IDs or by pattern match on asset name."""
    g = db.get(AssetGroup, group_id)
    if not g:
        raise HTTPException(404)
    asset_ids = body.get("asset_ids", [])
    pattern = (body.get("name_pattern") or "").strip()
    assigned = 0

    if asset_ids:
        from sqlalchemy import update
        result = db.execute(
            update(Asset).where(Asset.id.in_(asset_ids)).values(
                asset_group_id=group_id, business_unit=g.business_unit
            )
        )
        assigned = result.rowcount or 0

    if pattern:
        from sqlalchemy import update
        result = db.execute(
            update(Asset).where(Asset.name.ilike(pattern)).values(
                asset_group_id=group_id, business_unit=g.business_unit
            )
        )
        assigned += result.rowcount or 0

    db.commit()
    db.add(AuditEvent(
        actor=current_user(request), action="asset_group.assign",
        entity_type="asset_group", entity_id=str(group_id),
        summary=f"Assigned {assigned} assets to group '{g.name}'",
    ))
    db.commit()
    return {"group_id": group_id, "assigned": assigned}


# --- asset correlation ------------------------------------------------------

@router.get("/correlations")
def list_correlations(q: str = "", db=Depends(get_session)):
    return corr_service.get_correlations(db, q=q or None)


@router.post("/correlations/auto")
def auto_correlate(request: Request, body: dict = Body(default={}),
                   db=Depends(get_session)):
    method = body.get("method", "hostname")
    dry_run = body.get("dry_run", False)
    return corr_service.auto_correlate(db, method=method, dry_run=dry_run)


@router.post("/correlations")
def create_correlation(request: Request, body: dict = Body(...),
                       db=Depends(get_session)):
    actor = current_user(request)
    corr = corr_service.create_manual_correlation(
        db,
        canonical_name=body.get("canonical_name", ""),
        asset_ids=body.get("asset_ids", []),
        actor=actor,
        environment=body.get("environment"),
        data_classification=body.get("data_classification"),
        owner=body.get("owner"),
        notes=body.get("notes"),
    )
    return {"id": corr.id, "canonical_name": corr.canonical_name}


@router.get("/correlations/stats")
def correlation_stats(db=Depends(get_session)):
    return corr_service.get_deduplicated_counts(db)


@router.delete("/correlations/{corr_id}")
def delete_correlation(corr_id: int, request: Request, db=Depends(get_session)):
    corr = db.get(AssetCorrelation, corr_id)
    if not corr:
        raise HTTPException(404)
    db.delete(corr)
    db.commit()
    return {"deleted": corr_id}


# --- enrichment (EPSS + KEV) -----------------------------------------------

@router.post("/enrich")
def run_enrichment(request: Request, db=Depends(get_session)):
    return enrich_service.enrich_all(db)


@router.post("/enrich/epss")
def run_epss(request: Request, db=Depends(get_session)):
    return enrich_service.enrich_epss(db)


@router.post("/enrich/kev")
def run_kev(request: Request, db=Depends(get_session)):
    return enrich_service.enrich_kev(db)


# --- API tokens -------------------------------------------------------------

@router.get("/tokens")
def list_tokens(request: Request, db=Depends(get_session)):
    user = current_user_obj(request, db)
    if not user:
        raise HTTPException(401)
    return token_service.list_tokens(db, user.id)


@router.post("/tokens")
def create_token(request: Request, body: dict = Body(...), db=Depends(get_session)):
    user = current_user_obj(request, db)
    if not user:
        raise HTTPException(401)
    name = body.get("name", "API Token")
    scopes = body.get("scopes")
    expires_days = body.get("expires_days")
    token, plaintext = token_service.create_token(
        db, user, name, scopes=scopes, expires_days=expires_days
    )
    return {
        "id": token.id, "name": token.name, "prefix": token.token_prefix,
        "token": plaintext,
        "message": "Copy this token now. It cannot be retrieved again.",
    }


@router.delete("/tokens/{token_id}")
def revoke_token(token_id: int, request: Request, db=Depends(get_session)):
    user = current_user_obj(request, db)
    if not user:
        raise HTTPException(401)
    ok = token_service.revoke_token(db, token_id, user.id)
    if not ok:
        raise HTTPException(404)
    return {"revoked": token_id}


# --- connector configuration (admin) ---------------------------------------

@router.get("/config/sources")
def list_source_configs(request: Request, db=Depends(get_session)):
    result = {}
    for source in ("wiz", "falcon", "github", "jira"):
        result[source] = {
            "config": cc_service.get_config_display(db, source),
            "fields": cc_service.get_field_definitions(source),
        }
    return result


@router.get("/config/sources/{source}")
def get_source_config(source: str, request: Request, db=Depends(get_session)):
    if source not in ("wiz", "falcon", "github", "jira"):
        raise HTTPException(400)
    return {
        "config": cc_service.get_config_display(db, source),
        "fields": cc_service.get_field_definitions(source),
    }


@router.post("/config/sources/{source}")
def save_source_config(source: str, request: Request, body: dict = Body(...),
                       db=Depends(get_session)):
    if source not in ("wiz", "falcon", "github", "jira"):
        raise HTTPException(400)
    actor = current_user(request)
    config = body.get("config", {})
    result = cc_service.save_config(db, source, config, actor)
    db.add(AuditEvent(
        actor=actor, action="config.update",
        entity_type="connector", entity_id=source,
        summary=f"Connector config updated for {source}",
    ))
    db.commit()
    return {"config": result}


# --- reporting --------------------------------------------------------------

@router.get("/report")
def executive_report(db=Depends(get_session)):
    return report_service.generate_executive_summary(db)


@router.get("/report/pptx")
def executive_report_pptx(db=Depends(get_session)):
    try:
        pptx_bytes = report_service.generate_report_pptx(db)
    except RuntimeError as e:
        raise HTTPException(422, str(e))
    stamp = dt.date.today().isoformat()
    return StreamingResponse(
        iter([pptx_bytes]),
        media_type="application/vnd.openxmlformats-officedocument.presentationml.presentation",
        headers={"Content-Disposition": f'attachment; filename="security-report-{stamp}.pptx"'},
    )


# --- pipeline integration ---------------------------------------------------

@router.post("/pipeline/import")
def pipeline_import(request: Request, body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    return pipeline_service.import_pipeline_scan(db, body, actor=actor)


@router.get("/pipeline/containers")
def list_pipeline_containers(request: Request):
    return pipeline_service.get_container_status()


@router.post("/pipeline/containers/{service}/{action}")
def manage_pipeline_container(service: str, action: str, request: Request):
    return pipeline_service.manage_container(action, service)


# --- storage ----------------------------------------------------------------

@router.get("/storage/stats")
def storage_stats_endpoint(db=Depends(get_session)):
    """Per-column compression stats and SQLite file size."""
    from .. import storage as storage_service
    return storage_service.storage_stats(db)


@router.post("/storage/compress")
def storage_compress_endpoint(
    request: Request,
    body: dict = Body(default_factory=dict),
    db=Depends(get_session),
):
    """Backfill compression on existing rows, then optionally VACUUM.
    Pass `{"vacuum": true}` to also reclaim free pages (SQLite)."""
    from .. import storage as storage_service
    actor = current_user(request)
    report = storage_service.compress_backfill(db)
    did_vacuum = None
    if body.get("vacuum"):
        did_vacuum = storage_service.vacuum(db)
    db.add(AuditEvent(
        actor=actor, action="storage.compress",
        entity_type="system", entity_id="storage",
        summary="Storage compression backfill" + (" + VACUUM" if did_vacuum else ""),
        detail={"backfill": report, "vacuum": did_vacuum},
    ))
    db.commit()
    return {"backfill": report, "vacuum": did_vacuum}
