"""Authentication and authorization.

Two modes, controlled by RISKDESK_AUTH_MODE in .env:

  local    Username/password stored in the database. Passwords are hashed with
           SHA-256 + salt (bcrypt is better but adds a C dependency; swap in
           `pip install bcrypt` and change _hash/_verify if you want it).

  proxy    Trusts headers set by a reverse proxy that handles SSO upstream.
           The proxy MUST strip these headers from client requests or anyone
           can impersonate anyone. Header names are configurable.

  none     The original no-auth mode. Everyone acts as RISKDESK_DEFAULT_USER.
           Only appropriate on localhost during initial setup.

Roles:
  admin      manage users, rules, schedules, all security operations
  security   review/approve exceptions, create adjudications, run syncs
  team       submit exception requests, view findings, view own requests
  viewer     read-only access to findings and the register

Session tokens are stored in httpOnly cookies and expire after
RISKDESK_SESSION_HOURS (default 12).
"""
from __future__ import annotations

import datetime as dt
import hashlib
import os
import secrets
from functools import wraps

from fastapi import HTTPException, Request, Response
from sqlalchemy import select

from .db import SessionLocal
from .models import Session, User, utcnow

AUTH_MODE = os.getenv("RISKDESK_AUTH_MODE", "none")  # none | local | proxy
SESSION_HOURS = int(os.getenv("RISKDESK_SESSION_HOURS", "12"))
COOKIE_NAME = "riskdesk_session"

# Proxy-mode header names (must match your IdP/reverse proxy config)
PROXY_USER_HEADER = os.getenv("RISKDESK_PROXY_USER_HEADER", "X-Forwarded-User")
PROXY_EMAIL_HEADER = os.getenv("RISKDESK_PROXY_EMAIL_HEADER", "X-Forwarded-Email")
PROXY_NAME_HEADER = os.getenv("RISKDESK_PROXY_NAME_HEADER", "X-Forwarded-Name")
PROXY_GROUPS_HEADER = os.getenv("RISKDESK_PROXY_GROUPS_HEADER", "X-Forwarded-Groups")

# Role hierarchy
ROLE_LEVELS = {"admin": 5, "executive": 4, "security": 3, "team": 2, "viewer": 1}

# Which roles can do what
PERMISSIONS = {
    "view_findings":       {"viewer", "team", "security", "executive", "admin"},
    "export":              {"team", "security", "executive", "admin"},
    "submit_exception":    {"team", "security", "executive", "admin"},
    "review_exception":    {"security", "executive", "admin"},
    "approve_exception":   {"security", "executive", "admin"},
    "create_adjudication": {"security", "executive", "admin"},
    "approve_adjudication":{"executive", "admin"},           # executives and admins can approve
    "manage_rules":        {"security", "admin"},
    "manage_schedules":    {"security", "admin"},
    "run_sync":            {"security", "admin"},
    "manage_users":        {"admin"},
    "view_audit":          {"security", "executive", "admin"},
}


def _hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    h = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return f"sha256:{salt}:{h}"


def _verify_password(password: str, stored: str) -> bool:
    if not stored or not stored.startswith("sha256:"):
        return False
    parts = stored.split(":", 2)
    if len(parts) != 3:
        return False
    _, salt, expected = parts
    h = hashlib.sha256(f"{salt}:{password}".encode()).hexdigest()
    return secrets.compare_digest(h, expected)


def create_user(db, username: str, password: str | None = None,
                display_name: str | None = None, email: str | None = None,
                role: str = "team", team: str | None = None,
                auth_method: str = "local") -> User:
    existing = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if existing:
        raise ValueError(f"User {username} already exists")
    user = User(
        username=username,
        display_name=display_name or username,
        email=email,
        password_hash=_hash_password(password) if password else None,
        role=role,
        team=team,
        auth_method=auth_method,
    )
    db.add(user)
    db.commit()
    return user


def authenticate(db, username: str, password: str) -> User | None:
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if not user or not user.active:
        return None
    if user.auth_method == "sso":
        return None  # SSO users can't log in with a password
    if not _verify_password(password, user.password_hash):
        return None
    user.last_login = utcnow()
    db.commit()
    return user


def create_session(db, user: User, request: Request) -> str:
    token = secrets.token_urlsafe(48)
    sess = Session(
        token=token,
        user_id=user.id,
        expires_at=utcnow() + dt.timedelta(hours=SESSION_HOURS),
        ip_address=request.client.host if request.client else None,
        user_agent=request.headers.get("user-agent", "")[:500],
    )
    db.add(sess)
    db.commit()
    return token


def get_session_user(db, request: Request) -> User | None:
    """Resolve the current user from the request. Returns None if not authenticated."""
    if AUTH_MODE == "none":
        return _legacy_user(db, request)
    if AUTH_MODE == "proxy":
        return _proxy_user(db, request)
    # local mode: check cookie
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        return None
    sess = db.execute(
        select(Session).where(Session.token == token)
    ).scalar_one_or_none()
    if not sess:
        return None
    if sess.expires_at.replace(tzinfo=dt.timezone.utc) < utcnow():
        db.delete(sess)
        db.commit()
        return None
    user = db.get(User, sess.user_id)
    if not user or not user.active:
        return None
    return user


def _legacy_user(db, request: Request) -> User:
    """No-auth mode: auto-provision from the header or default user."""
    from .config import settings
    username = request.headers.get("X-RiskDesk-User") or settings.default_user
    if username not in settings.users:
        username = settings.default_user
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if not user:
        role_map = {
            "lucas": "admin", "liang": "admin",
            "eric.poon": "executive", "chris": "executive",
            "ezechias": "security",
        }
        user = User(
            username=username, display_name=username,
            role=role_map.get(username, "team"),
            auth_method="none", active=True,
        )
        db.add(user)
        db.commit()
    return user


def _proxy_user(db, request: Request) -> User | None:
    """SSO proxy mode: trust headers from the reverse proxy."""
    username = request.headers.get(PROXY_USER_HEADER)
    if not username:
        return None
    username = username.strip().lower()
    user = db.execute(select(User).where(User.username == username)).scalar_one_or_none()
    if user:
        # Update from headers on each request
        email = request.headers.get(PROXY_EMAIL_HEADER)
        name = request.headers.get(PROXY_NAME_HEADER)
        if email:
            user.email = email
        if name:
            user.display_name = name
        user.last_login = utcnow()
        db.commit()
        return user if user.active else None

    # Auto-provision new SSO user
    groups = request.headers.get(PROXY_GROUPS_HEADER, "")
    role = _role_from_groups(groups)
    user = User(
        username=username,
        display_name=request.headers.get(PROXY_NAME_HEADER) or username,
        email=request.headers.get(PROXY_EMAIL_HEADER),
        role=role,
        auth_method="sso",
        active=True,
        last_login=utcnow(),
    )
    db.add(user)
    db.commit()
    return user


def _role_from_groups(groups_header: str) -> str:
    """Map SSO group memberships to a role. Customize for your IdP."""
    groups = {g.strip().lower() for g in groups_header.split(",") if g.strip()}
    # These group names are examples; edit to match your AD/Okta/Entra groups
    if "riskdesk-admins" in groups or "security-admins" in groups:
        return "admin"
    if "riskdesk-executive" in groups or "executive-team" in groups or "cio-office" in groups:
        return "executive"
    if "security-team" in groups or "riskdesk-security" in groups:
        return "security"
    if "riskdesk-viewers" in groups:
        return "viewer"
    return "team"


def require_auth(request: Request) -> User:
    """FastAPI dependency: returns the authenticated user or raises 401."""
    if AUTH_MODE == "none":
        db = SessionLocal()
        try:
            return _legacy_user(db, request)
        finally:
            db.close()
    db = SessionLocal()
    try:
        user = get_session_user(db, request)
    finally:
        db.close()
    if not user:
        raise HTTPException(status_code=401, detail="Not authenticated")
    return user


def require_role(*roles: str):
    """FastAPI dependency factory: checks role membership."""
    def checker(request: Request) -> User:
        user = require_auth(request)
        if user.role not in roles:
            raise HTTPException(
                status_code=403,
                detail=f"This action requires one of: {', '.join(roles)}. Your role is {user.role}."
            )
        return user
    return checker


def has_permission(user: User, permission: str) -> bool:
    allowed = PERMISSIONS.get(permission, set())
    return user.role in allowed


def check_permission(user: User, permission: str):
    if not has_permission(user, permission):
        raise HTTPException(
            status_code=403,
            detail=f"Permission '{permission}' requires role: {', '.join(PERMISSIONS.get(permission, set()))}. Your role is {user.role}."
        )


def cleanup_expired_sessions(db):
    """Remove expired sessions. Called periodically."""
    db.execute(
        Session.__table__.delete().where(Session.expires_at < utcnow())
    )
    db.commit()


def seed_default_users(db):
    """Create initial users from the config roster if none exist."""
    from .config import settings
    count = db.execute(select(User)).scalars().all()
    if count:
        return

    # Role assignments -- edit this to match your org.
    # admin:      full control, manages users and platform config
    # executive:  approves risk decisions, views everything, no infra management
    # security:   reviews exceptions, creates adjudications, manages rules
    # team:       submits exceptions, views findings assigned to them
    role_map = {
        "lucas": "admin",
        "liang": "admin",
        "eric.poon": "executive",
        "chris": "executive",
        "ezechias": "security",
        "derron": "team",
        "igor": "team",
    }
    for username in settings.users:
        role = role_map.get(username, "team")
        user = User(
            username=username,
            display_name=username,
            role=role,
            auth_method="local" if AUTH_MODE == "local" else "none",
            active=True,
        )
        if AUTH_MODE == "local":
            user.password_hash = _hash_password(f"changeme-{username}")
        db.add(user)
    db.commit()
