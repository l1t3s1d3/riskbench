"""Shared dependencies for API routes."""
from __future__ import annotations

import datetime as dt

from fastapi import HTTPException, Request

from ..auth import AUTH_MODE, get_session_user
from ..config import settings
from ..db import get_session
from .. import tokens as token_service


def current_user(request: Request) -> str:
    """Resolve the current user. Works in all auth modes + bearer tokens."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        raw_token = auth_header[7:].strip()
        db = next(get_session())
        try:
            user, _ = token_service.validate_token(db, raw_token)
            if user:
                return user.username
        finally:
            db.close()
    if AUTH_MODE == "none":
        user = request.headers.get("X-RiskDesk-User") or settings.default_user
        return user if user in settings.users else settings.default_user
    db = next(get_session())
    try:
        u = get_session_user(db, request)
        return u.username if u else settings.default_user
    finally:
        db.close()


def current_user_obj(request: Request, db):
    """Get the full User object for the current request."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        user, _ = token_service.validate_token(db, auth_header[7:].strip())
        return user
    return get_session_user(db, request)


def parse_date(value) -> dt.datetime | None:
    if not value:
        return None
    if isinstance(value, dt.datetime):
        return value
    s = str(value)
    try:
        if len(s) == 10:
            return dt.datetime.fromisoformat(s).replace(tzinfo=dt.timezone.utc)
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        parsed = dt.datetime.fromisoformat(s)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
    except ValueError:
        raise HTTPException(422, f"Could not read the date '{value}'. Use YYYY-MM-DD.")
