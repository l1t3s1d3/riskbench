"""RiskDesk application entry point.

Mounts all API routers and serves the static SPA. The route logic lives
in the ``routes/`` package; this file is just wiring.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")

from fastapi import FastAPI  # noqa: E402
from fastapi.responses import FileResponse, JSONResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402

from . import adjudication as adj_service  # noqa: E402
from . import connector_config as cc_service  # noqa: E402
from .auth import cleanup_expired_sessions, seed_default_users  # noqa: E402
from .db import get_session, init_db  # noqa: E402
from .routes import (  # noqa: E402
    adjudications, admin, auth, compliance, exceptions, falcon, findings, github, sync, tickets,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

STATIC = Path(__file__).resolve().parent / "static"


@asynccontextmanager
async def lifespan(app: FastAPI):
    # --- startup ---
    init_db()
    from .db import SessionLocal
    db = SessionLocal()
    try:
        seed_default_users(db)
        cc_service.apply_all_from_db(db)
        n = adj_service.expire_lapsed(db)
        if n:
            logging.info("Expired %d lapsed decisions on startup", n)
        cleanup_expired_sessions(db)
    finally:
        db.close()
    from . import scheduler
    scheduler.start()
    yield
    # --- shutdown ---
    scheduler.stop()


app = FastAPI(title="RiskDesk", version="1.0.0", docs_url="/api/docs", lifespan=lifespan)


# --- exception handlers -----------------------------------------------------

@app.exception_handler(adj_service.PolicyError)
def _policy_error(_request, exc: adj_service.PolicyError):
    return JSONResponse(status_code=422, content={"problems": exc.problems})


# --- routers ----------------------------------------------------------------

app.include_router(findings.router)
app.include_router(adjudications.router)
app.include_router(sync.router)
app.include_router(auth.router)
app.include_router(exceptions.router)
app.include_router(compliance.router)
app.include_router(tickets.router)
app.include_router(admin.router)
app.include_router(falcon.router)
app.include_router(github.router)


# --- static UI --------------------------------------------------------------

app.mount("/static", StaticFiles(directory=STATIC), name="static")


@app.get("/")
def index():
    return FileResponse(STATIC / "index.html")
