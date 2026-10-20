"""Authentication and user management routes."""
from __future__ import annotations

import datetime as dt

from fastapi import APIRouter, Body, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from ..auth import (
    AUTH_MODE, COOKIE_NAME, authenticate, check_permission, create_session,
    create_user, get_session_user, has_permission, _hash_password,
)
from ..db import get_session
from ..models import User
from .deps import current_user, current_user_obj

router = APIRouter(prefix="/api", tags=["auth"])


@router.post("/auth/login")
def login(request: Request, body: dict = Body(...), db=Depends(get_session)):
    if AUTH_MODE == "none":
        return {"ok": True, "user": body.get("username"), "role": "admin",
                "auth_mode": "none", "message": "Auth is disabled. Everyone is admin."}
    username = (body.get("username") or "").strip().lower()
    password = body.get("password") or ""
    user = authenticate(db, username, password)
    if not user:
        raise HTTPException(401, "Invalid username or password.")
    token = create_session(db, user, request)
    response = JSONResponse({
        "ok": True, "user": user.username, "display_name": user.display_name,
        "role": user.role, "team": user.team, "auth_mode": AUTH_MODE,
    })
    response.set_cookie(
        COOKIE_NAME, token, httponly=True, samesite="lax",
        max_age=int(dt.timedelta(hours=12).total_seconds()),
        secure=request.url.scheme == "https",
    )
    return response


@router.post("/auth/logout")
def logout(request: Request, db=Depends(get_session)):
    from ..models import Session as SessModel
    token = request.cookies.get(COOKIE_NAME)
    if token:
        sess = db.execute(select(SessModel).where(SessModel.token == token)).scalar_one_or_none()
        if sess:
            db.delete(sess)
            db.commit()
    response = JSONResponse({"ok": True})
    response.delete_cookie(COOKIE_NAME)
    return response


@router.get("/auth/me")
def auth_me(request: Request, db=Depends(get_session)):
    user = get_session_user(db, request)
    if not user:
        return {"authenticated": False, "auth_mode": AUTH_MODE}
    return {
        "authenticated": True, "auth_mode": AUTH_MODE,
        "username": user.username, "display_name": user.display_name,
        "role": user.role, "team": user.team, "email": user.email,
        "permissions": {p: has_permission(user, p) for p in [
            "submit_exception", "review_exception", "create_adjudication",
            "manage_rules", "manage_users", "run_sync",
        ]},
    }


@router.post("/auth/change-password")
def change_password(request: Request, body: dict = Body(...), db=Depends(get_session)):
    user = get_session_user(db, request)
    if not user:
        raise HTTPException(401, "Not authenticated.")
    new_pw = body.get("new_password", "")
    if len(new_pw) < 8:
        raise HTTPException(422, "Password must be at least 8 characters.")
    user.password_hash = _hash_password(new_pw)
    db.commit()
    return {"ok": True}


# --- user management --------------------------------------------------------

@router.get("/users")
def list_users(request: Request, db=Depends(get_session)):
    rows = db.execute(select(User).order_by(User.username)).scalars().all()
    return [{
        "id": u.id, "username": u.username, "display_name": u.display_name,
        "email": u.email, "role": u.role, "team": u.team, "active": u.active,
        "auth_method": u.auth_method,
        "last_login": u.last_login.isoformat() if u.last_login else None,
    } for u in rows]


@router.post("/users")
def create_user_api(request: Request, body: dict = Body(...), db=Depends(get_session)):
    if AUTH_MODE != "none":
        user_obj = get_session_user(db, request)
        if not user_obj:
            raise HTTPException(401)
        check_permission(user_obj, "manage_users")
    try:
        user = create_user(
            db,
            username=(body.get("username") or "").strip().lower(),
            password=body.get("password"),
            display_name=body.get("display_name"),
            email=body.get("email"),
            role=body.get("role", "team"),
            team=body.get("team"),
            auth_method=body.get("auth_method", "local"),
        )
    except ValueError as e:
        raise HTTPException(422, str(e))
    return {"id": user.id, "username": user.username, "role": user.role}


@router.put("/users/{user_id}")
def update_user_api(user_id: int, request: Request, body: dict = Body(...),
                    db=Depends(get_session)):
    if AUTH_MODE != "none":
        actor_obj = get_session_user(db, request)
        if not actor_obj:
            raise HTTPException(401)
        check_permission(actor_obj, "manage_users")
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(404, "User not found.")
    for field in ("display_name", "email", "role", "team", "active", "auth_method"):
        if field in body:
            setattr(user, field, body[field])
    if "password" in body and body["password"]:
        user.password_hash = _hash_password(body["password"])
    db.commit()
    return {"ok": True, "username": user.username, "role": user.role}
