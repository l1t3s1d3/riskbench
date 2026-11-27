"""Storage stats + one-shot compression backfill + VACUUM.

New rows auto-compress through :class:`app.compression.CompressedJSON`.
Rows that were written before the column switched (pre-existing
Finding.raw, AuditEvent.detail, etc.) are still uncompressed plain JSON.
This module provides:

  * :func:`storage_stats` — page counts, table bytes, compression hits.
  * :func:`compress_backfill` — walks target tables, re-persists each row
    so the TypeDecorator packs the payload on bind.
  * :func:`vacuum` — reclaims deleted space (SQLite only).

All three are safe to call repeatedly: compression is idempotent and
VACUUM is a no-op when there is nothing to reclaim.
"""
from __future__ import annotations

import json

from sqlalchemy import select, text

from .compression import is_packed, ratio
from .models import Adjudication, AuditEvent, Finding, SyncRun


_TARGETS = {
    "finding.raw": (Finding, Finding.raw, "findings", "raw"),
    "audit_event.detail": (AuditEvent, AuditEvent.detail, "audit_events", "detail"),
    "adjudication.scope_filter": (Adjudication, Adjudication.scope_filter,
                                   "adjudications", "scope_filter"),
    "sync_run.delta": (SyncRun, SyncRun.delta, "sync_runs", "delta"),
}


def storage_stats(db) -> dict:
    """Summary of row counts, compressed-row counts, and savings per
    compressible column. For SQLite also returns page/file sizes.

    Reads the on-disk JSON text with raw SQL so the TypeDecorator does
    not decompress it before we can measure compression."""
    out: dict = {"columns": {}}
    for name, (model, col, table, colname) in _TARGETS.items():
        rows_raw = db.execute(
            text(f"SELECT {colname} FROM {table} WHERE {colname} IS NOT NULL")
        ).scalars().all()
        n_packed = 0
        compressed_bytes = 0
        uncompressed_bytes = 0
        total = 0
        for v in rows_raw:
            if v is None:
                continue
            total += 1
            value = json.loads(v) if isinstance(v, str) else v
            if is_packed(value):
                c, u = ratio(value)
                n_packed += 1
                compressed_bytes += c
                uncompressed_bytes += u
        out["columns"][name] = {
            "rows": total,
            "compressed_rows": n_packed,
            "uncompressed_rows": total - n_packed,
            "compressed_bytes": compressed_bytes,
            "uncompressed_equivalent_bytes": uncompressed_bytes,
            "savings_bytes": max(0, uncompressed_bytes - compressed_bytes),
            "ratio": (uncompressed_bytes / compressed_bytes) if compressed_bytes else 0.0,
        }

    bind = db.get_bind()
    out["backend"] = bind.dialect.name
    if bind.dialect.name == "sqlite":
        try:
            page_count = db.execute(text("PRAGMA page_count")).scalar() or 0
            page_size = db.execute(text("PRAGMA page_size")).scalar() or 0
            freelist = db.execute(text("PRAGMA freelist_count")).scalar() or 0
            out["sqlite"] = {
                "file_bytes": page_count * page_size,
                "page_count": page_count,
                "page_size": page_size,
                "free_pages": freelist,
                "reclaimable_bytes": freelist * page_size,
            }
        except Exception:
            pass
    return out


def compress_backfill(db, batch_size: int = 500) -> dict:
    """Walk each target column and re-persist any row whose payload is
    not yet in the packed wrapper form. Returns per-column counts.
    """
    report: dict = {}
    for name, (model, col, _table, _colname) in _TARGETS.items():
        touched = 0
        skipped_small = 0
        processed = 0
        # Stream rows rather than loading the full set, so a six-figure
        # finding table does not blow up memory.
        rows = db.execute(select(model).where(col.isnot(None))).scalars()
        pending = 0
        for row in rows:
            value = getattr(row, col.key)
            processed += 1
            if value in (None, {}, []) or is_packed(value):
                skipped_small += 1
                continue
            # Reassigning triggers the TypeDecorator's pack() on flush.
            setattr(row, col.key, value)
            touched += 1
            pending += 1
            if pending >= batch_size:
                db.commit()
                pending = 0
        if pending:
            db.commit()
        report[name] = {
            "rows_processed": processed,
            "rows_touched": touched,
            "rows_already_packed_or_small": skipped_small,
        }
    return report


def vacuum(db) -> dict:
    """Reclaim deleted/fragmented space. SQLite-only; a no-op elsewhere."""
    bind = db.get_bind()
    if bind.dialect.name != "sqlite":
        return {"ran": False, "reason": f"vacuum not supported for {bind.dialect.name}"}

    before = db.execute(text("PRAGMA page_count")).scalar() or 0
    page_size = db.execute(text("PRAGMA page_size")).scalar() or 0
    # VACUUM cannot run inside a transaction. Commit, then step out.
    db.commit()
    db.execute(text("COMMIT"))
    try:
        db.execute(text("VACUUM"))
    finally:
        db.execute(text("BEGIN"))
    after = db.execute(text("PRAGMA page_count")).scalar() or 0
    return {
        "ran": True,
        "pages_before": before,
        "pages_after": after,
        "bytes_reclaimed": max(0, (before - after) * page_size),
    }
