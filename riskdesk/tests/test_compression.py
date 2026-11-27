"""Transparent compression of JSON payload columns."""
from __future__ import annotations

from app.compression import (
    COMPRESSION_THRESHOLD_BYTES, is_packed, pack, unpack,
)
from app.models import AuditEvent, Finding, Vuln, Asset


def test_small_payload_stays_inline():
    small = {"a": 1, "b": "x"}
    packed = pack(small)
    assert packed == small
    assert not is_packed(packed)


def test_large_payload_gets_packed_and_roundtrips():
    big = {"items": [{"id": i, "payload": "x" * 100} for i in range(10)]}
    packed = pack(big)
    assert is_packed(packed)
    # The wrapper should be a tiny marker dict, not the original.
    assert set(packed.keys()) == {"__gz__"}
    assert unpack(packed) == big


def test_already_packed_passthrough():
    big = {"items": [{"id": i} for i in range(200)]}
    packed = pack(big)
    repacked = pack(packed)
    assert repacked is packed


def test_finding_raw_column_autopacks_and_unpacks(db):
    asset = Asset(source="falcon", source_asset_id="h1", name="h1", asset_type="server")
    vuln = Vuln(canonical_id="CVE-X", severity="high")
    db.add_all([asset, vuln])
    db.flush()
    big_raw = {"note": "x" * (COMPRESSION_THRESHOLD_BYTES * 3), "nested": {"a": list(range(50))}}
    f = Finding(source="falcon", source_finding_id="f1", asset_id=asset.id,
                vuln_id=vuln.id, category="os_vuln", status="open", severity="high",
                raw=big_raw)
    db.add(f)
    db.commit()

    # Raw payload roundtrips through the TypeDecorator as plain dict.
    db.expire_all()
    f2 = db.execute(db.query(Finding).filter_by(id=f.id).statement).first()[0]
    assert f2.raw == big_raw

    # And underlying JSON on disk is the packed wrapper, not the original.
    from sqlalchemy import text
    raw_literal = db.execute(text("SELECT raw FROM findings WHERE id=:i"),
                             {"i": f.id}).scalar()
    import json
    stored = json.loads(raw_literal) if isinstance(raw_literal, str) else raw_literal
    assert is_packed(stored)


def test_audit_event_detail_autopacks(db):
    detail = {"items": [{"finding_id": i, "note": "hello"} for i in range(200)]}
    ev = AuditEvent(actor="tester", action="test", entity_type="x", entity_id="1",
                    summary="s", detail=detail)
    db.add(ev)
    db.commit()
    db.expire_all()
    got = db.get(AuditEvent, ev.id)
    assert got.detail == detail

    from sqlalchemy import text
    import json
    raw = db.execute(text("SELECT detail FROM audit_events WHERE id=:i"),
                     {"i": ev.id}).scalar()
    stored = json.loads(raw) if isinstance(raw, str) else raw
    assert is_packed(stored)


def test_storage_stats_and_backfill(db):
    from app import storage
    # Seed one small and one big detail payload.
    db.add(AuditEvent(actor="t", action="a", entity_type="x", entity_id="1",
                      summary="s", detail={"ok": True}))
    db.add(AuditEvent(actor="t", action="a", entity_type="x", entity_id="2",
                      summary="s", detail={"x" * 10: "y" * 1000}))
    db.commit()

    stats = storage.storage_stats(db)
    audit = stats["columns"]["audit_event.detail"]
    assert audit["rows"] == 2
    assert audit["compressed_rows"] == 1
    assert audit["savings_bytes"] >= 0

    # Backfill is idempotent.
    report = storage.compress_backfill(db)
    assert "audit_event.detail" in report
