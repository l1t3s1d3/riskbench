"""Shared test fixtures — in-memory SQLite + FastAPI TestClient."""
from __future__ import annotations

import os

os.environ["RISKDESK_DB_URL"] = "sqlite:///:memory:"
os.environ["RISKDESK_AUTH_MODE"] = "none"
os.environ["RISKDESK_SCHEDULER_ENABLED"] = "0"

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.db as db_mod
from app.db import Base
from app import models  # noqa: F401 — register all tables

# ---------------------------------------------------------------------------
# Single shared in-memory engine with StaticPool.  StaticPool ensures every
# checkout returns the *same* underlying SQLite connection, so all sessions
# (including those created by startup helpers) see the same in-memory DB.
# We also monkey-patch app.db so init_db(), SessionLocal(), and the
# dependency override all route through this engine.
# ---------------------------------------------------------------------------

_engine = create_engine(
    "sqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)


@event.listens_for(_engine, "connect")
def _pragmas(dbapi_conn, _rec):
    cur = dbapi_conn.cursor()
    cur.execute("PRAGMA foreign_keys=ON")
    cur.close()


_TestSession = sessionmaker(bind=_engine, autoflush=False)

db_mod.engine = _engine
db_mod.SessionLocal = _TestSession

from app.main import app  # noqa: E402
from app.db import get_session  # noqa: E402
from app.models import Asset, Finding, Ticket, TicketFinding, User, Vuln  # noqa: E402


@pytest.fixture(autouse=True)
def _create_tables():
    """Create all tables before each test and drop them after."""
    Base.metadata.create_all(_engine)
    yield
    Base.metadata.drop_all(_engine)


@pytest.fixture()
def db():
    session = _TestSession()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture()
def client(db):
    from fastapi.testclient import TestClient

    def _override():
        try:
            yield db
        finally:
            pass

    app.dependency_overrides[get_session] = _override
    with TestClient(app, raise_server_exceptions=True) as c:
        yield c
    app.dependency_overrides.clear()


@pytest.fixture()
def seed_data(db):
    asset = Asset(
        source="wiz", source_asset_id="test-asset-1",
        name="test-host-01", asset_type="server",
    )
    vuln = Vuln(
        canonical_id="CVE-2024-0001", cve_id="CVE-2024-0001",
        title="Test Vulnerability", severity="high", cvss_score=8.5,
    )
    db.add_all([asset, vuln])
    db.flush()

    finding = Finding(
        source="wiz", source_finding_id="wiz-f-1",
        asset_id=asset.id, vuln_id=vuln.id,
        category="os_vuln", status="open", severity="high",
    )
    db.add(finding)
    db.commit()
    return {"asset": asset, "vuln": vuln, "finding": finding}


@pytest.fixture()
def seed_user(db):
    from app.auth import _hash_password
    user = User(
        username="testuser", display_name="Test User",
        email="test@example.com", role="admin", team="security",
        password_hash=_hash_password("password123"),
        auth_method="local", active=True,
    )
    db.add(user)
    db.commit()
    return user
