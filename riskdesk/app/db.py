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
    add_missing_columns(engine)
    add_missing_indexes(engine)


def add_missing_columns(bind) -> list[str]:
    """Additive-only migration: ALTER TABLE ADD COLUMN for model columns the
    database lacks. create_all creates new tables but never alters existing ones."""
    import logging

    from sqlalchemy import inspect, text

    insp = inspect(bind)
    existing_tables = set(insp.get_table_names())
    added: list[str] = []
    with bind.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue
            have = {c["name"] for c in insp.get_columns(table.name)}
            new_cols = set()
            for col in table.columns:
                if col.name in have:
                    continue
                ddl = f"ALTER TABLE {table.name} ADD COLUMN {col.name} {col.type.compile(dialect=bind.dialect)}"
                default = col.default.arg if col.default is not None and col.default.is_scalar else None
                if default is not None:
                    literal = int(default) if isinstance(default, bool) else default
                    ddl += f" NOT NULL DEFAULT {literal!r}" if not col.nullable else f" DEFAULT {literal!r}"
                elif not col.nullable:
                    logging.warning("Cannot add NOT NULL column %s.%s without a default", table.name, col.name)
                    continue
                conn.execute(text(ddl))
                added.append(f"{table.name}.{col.name}")
                new_cols.add(col.name)
            present = have | new_cols
            for idx in table.indexes:
                cols = {c.name for c in idx.columns}
                if cols & new_cols and cols <= present:
                    idx.create(conn, checkfirst=True)
    if added:
        logging.info("Schema migration added columns: %s", ", ".join(added))
    return added


def add_missing_indexes(bind) -> list[str]:
    """Create any index declared on the model that is missing from the live
    DB. create_all does this for new tables, but when a new Index() is added
    to an existing table's __table_args__ nothing picks it up. This closes
    that gap so performance-critical indexes land automatically on upgrade."""
    import logging

    from sqlalchemy import inspect

    insp = inspect(bind)
    existing_tables = set(insp.get_table_names())
    added: list[str] = []
    with bind.begin() as conn:
        for table in Base.metadata.sorted_tables:
            if table.name not in existing_tables:
                continue
            existing = {idx["name"] for idx in insp.get_indexes(table.name)}
            # Both explicit Index() entries and the single-column index=True
            # indexes live under table.indexes.
            for idx in table.indexes:
                if idx.name in existing:
                    continue
                try:
                    idx.create(conn, checkfirst=True)
                    added.append(idx.name)
                except Exception as exc:
                    logging.warning("Could not create index %s: %s", idx.name, exc)
    if added:
        logging.info("Created missing indexes: %s", ", ".join(added))
    return added
