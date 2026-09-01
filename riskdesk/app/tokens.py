"""API token management for automation.

Tokens are long-lived bearer credentials for CI pipelines, scheduled scripts,
and external integrations. They carry the same role as the user who created
them, optionally restricted to a subset of permissions.

Usage:
  Authorization: Bearer riskdesk_xxxxxxxxxxxxxxxxxxxx

Tokens are stored hashed (same as passwords). The plaintext is shown exactly
once at creation and cannot be recovered.
"""
from __future__ import annotations

import hashlib
import secrets

from sqlalchemy import select

from .models import ApiToken, User, utcnow


TOKEN_PREFIX = "riskdesk_"


def create_token(db, user: User, name: str, scopes: list[str] | None = None,
                 expires_days: int | None = None) -> tuple[ApiToken, str]:
    """Create a new API token. Returns (token_record, plaintext).
    The plaintext is shown once and cannot be recovered."""
    import datetime as dt

    raw = TOKEN_PREFIX + secrets.token_urlsafe(40)
    token_hash = hashlib.sha256(raw.encode()).hexdigest()

    token = ApiToken(
        name=name,
        token_hash=token_hash,
        token_prefix=raw[:len(TOKEN_PREFIX) + 8],
        user_id=user.id,
        scopes=scopes or [],
        expires_at=(utcnow() + dt.timedelta(days=expires_days)) if expires_days else None,
    )
    db.add(token)
    db.commit()
    return token, raw


def validate_token(db, raw_token: str) -> tuple[User | None, ApiToken | None]:
    """Check a bearer token and return the associated user."""
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    token = db.execute(
        select(ApiToken).where(ApiToken.token_hash == token_hash)
    ).scalar_one_or_none()

    if not token or not token.active:
        return None, None
    if token.expires_at:
        exp = token.expires_at
        if exp.tzinfo is None:
            import datetime as dt
            exp = exp.replace(tzinfo=dt.timezone.utc)
        if exp < utcnow():
            return None, None

    user = db.get(User, token.user_id)
    if not user or not user.active:
        return None, None

    token.last_used = utcnow()
    db.commit()
    return user, token


def list_tokens(db, user_id: int) -> list[dict]:
    tokens = db.execute(
        select(ApiToken).where(ApiToken.user_id == user_id)
        .order_by(ApiToken.created_at.desc())
    ).scalars().all()
    return [{
        "id": t.id, "name": t.name, "prefix": t.token_prefix,
        "scopes": t.scopes, "active": t.active,
        "last_used": t.last_used.isoformat() if t.last_used else None,
        "expires_at": t.expires_at.isoformat() if t.expires_at else None,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    } for t in tokens]


def revoke_token(db, token_id: int, user_id: int) -> bool:
    token = db.get(ApiToken, token_id)
    if not token or token.user_id != user_id:
        return False
    token.active = False
    db.commit()
    return True
