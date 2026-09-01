import os
from pathlib import Path

from sqlalchemy import create_engine, event
from sqlalchemy.orm import DeclarativeBase, sessionmaker

DATA_DIR = Path(os.getenv("RISKDESK_DATA_DIR", Path(__file__).resolve().parent.parent / "data"))
DATA_DIR.mkdir(parents=True, exist_ok=True)

# as_posix() keeps the URL free of backslashes on Windows. SQLAlchemy does parse
# sqlite:///C:\Users\... correctly, so this is belt-and-braces rather than a fix,
# but forward slashes are the documented form and survive being passed through
# shells, config files and env vars without anything eating the escapes.
DB_URL = os.getenv("RISKDESK_DB_URL", f"sqlite:///{(DATA_DIR / 'riskdesk.db').as_posix()}")

engine = create_engine(
    DB_URL,
    future=True,
    connect_args={"check_same_thread": False} if DB_URL.startswith("sqlite") else {},
)


@event.listens_for(engine, "connect")
def _sqlite_pragmas(dbapi_conn, _rec):
    if DB_URL.startswith("sqlite"):
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")      # concurrent reads during sync
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()


SessionLocal = sessionmaker(bind=engine, autoflush=False, future=True)


class Base(DeclarativeBase):
    pass


def get_session():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    from . import models  # noqa: F401  (registers tables)
    Base.metadata.create_all(engine)
