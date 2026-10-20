"""Exception request routes."""
from __future__ import annotations

from fastapi import APIRouter, Body, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from .. import exceptions as exc_service
from ..db import get_session
from ..models import ExceptionComment, ExceptionRequest
from .deps import current_user, current_user_obj, parse_date

router = APIRouter(prefix="/api", tags=["exceptions"])


@router.get("/exceptions")
def list_exceptions(
    status: list[str] = Query(default=[]),
    submitted_by: str = "",
    reviewer: str = "",
    q: str = "",
    page: int = 1, page_size: int = 50,
    db=Depends(get_session), request: Request = None,
):
    stmt = select(ExceptionRequest)
    if status:
        stmt = stmt.where(ExceptionRequest.status.in_(status))
    if submitted_by:
        stmt = stmt.where(ExceptionRequest.submitted_by == submitted_by)
    if reviewer:
        stmt = stmt.where(ExceptionRequest.assigned_reviewer == reviewer)
    if q:
        term = f"%{q}%"
        stmt = stmt.where(
            ExceptionRequest.title.ilike(term) |
            ExceptionRequest.justification.ilike(term) |
            ExceptionRequest.scope_label.ilike(term)
        )
    rows = db.execute(stmt.order_by(ExceptionRequest.created_at.desc())).scalars().all()
    total = len(rows)
    start = max(0, (page - 1) * page_size)
    return {
        "total": total, "page": page,
        "exceptions": [exc_service.serialize_exception(e) for e in rows[start:start + page_size]],
    }


@router.post("/exceptions")
def submit_exception(request: Request, body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    user_obj = current_user_obj(request, db)
    exc = exc_service.create_exception(
        db,
        title=body.get("title", ""),
        finding_ids=body.get("finding_ids", []),
        requested_disposition=body.get("requested_disposition", ""),
        justification=body.get("justification", ""),
        actor=actor,
        scope=body.get("scope", "finding"),
        business_impact=body.get("business_impact"),
        compensating_controls=body.get("compensating_controls"),
        adjusted_severity=body.get("adjusted_severity"),
        requested_duration_days=body.get("requested_duration_days"),
        submitter_team=user_obj.team if user_obj else body.get("submitter_team"),
        submitter_email=user_obj.email if user_obj else body.get("submitter_email"),
    )
    return exc_service.serialize_exception(exc)


@router.get("/exceptions/{exc_id}")
def get_exception(exc_id: int, request: Request, db=Depends(get_session)):
    exc = db.get(ExceptionRequest, exc_id)
    if not exc:
        raise HTTPException(404, "Exception not found.")
    comments = db.execute(
        select(ExceptionComment)
        .where(ExceptionComment.exception_id == exc_id)
        .order_by(ExceptionComment.created_at.asc())
    ).scalars().all()
    user_obj = current_user_obj(request, db)
    is_security = user_obj and user_obj.role in ("security", "admin")
    return exc_service.serialize_exception(exc, comments, include_internal=is_security)


@router.post("/exceptions/{exc_id}/assign")
def assign_exception_reviewer(exc_id: int, request: Request,
                              body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    exc = exc_service.assign_reviewer(db, exc_id, body.get("reviewer", ""), actor)
    return exc_service.serialize_exception(exc)


@router.post("/exceptions/{exc_id}/review")
def review_exception(exc_id: int, request: Request,
                     body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    exc = exc_service.review_exception(
        db, exc_id,
        decision=body.get("decision", ""),
        actor=actor,
        note=body.get("note"),
        expires_at=parse_date(body.get("expires_at")),
        approver=body.get("approver"),
    )
    return exc_service.serialize_exception(exc)


@router.post("/exceptions/{exc_id}/request-info")
def request_exception_info(exc_id: int, request: Request,
                           body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    exc = exc_service.request_info(db, exc_id, body.get("message", ""), actor)
    return exc_service.serialize_exception(exc)


@router.post("/exceptions/{exc_id}/respond")
def respond_to_exception_info(exc_id: int, request: Request,
                              body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    exc = exc_service.respond_to_info(db, exc_id, body.get("message", ""), actor)
    return exc_service.serialize_exception(exc)


@router.post("/exceptions/{exc_id}/comment")
def comment_on_exception(exc_id: int, request: Request,
                         body: dict = Body(...), db=Depends(get_session)):
    actor = current_user(request)
    exc_service.add_comment(
        db, exc_id, body.get("body", ""), actor,
        is_internal=bool(body.get("is_internal")),
    )
    return {"ok": True}


@router.post("/exceptions/{exc_id}/withdraw")
def withdraw_exception(exc_id: int, request: Request, db=Depends(get_session)):
    actor = current_user(request)
    exc = exc_service.withdraw_exception(db, exc_id, actor)
    return exc_service.serialize_exception(exc)
