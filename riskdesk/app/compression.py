"""JSON payload compression.

Source payloads (Finding.raw, AuditEvent.detail, Adjudication.scope_filter,
SyncRun.delta) hold the full connector response or a bulk decision's
finding list. They compress 5-10x with plain zlib on typical data.

A compressed payload is stored as a small dict
`{"__gz__": "<base64 zlib bytes>"}`. Compression is transparent when the
column is declared with :class:`CompressedJSON`: SQLAlchemy packs on bind
and unpacks on result, so call sites keep working with dicts.

We only compress payloads above a threshold. Short dicts stay inline so
small-payload reads skip the base64 decode.
"""
from __future__ import annotations

import base64
import json
import zlib
from typing import Any

from sqlalchemy import JSON
from sqlalchemy.types import TypeDecorator

# Payloads smaller than this (serialized) are left as plain JSON. Below the
# threshold, gzip framing is larger than what it saves.
COMPRESSION_THRESHOLD_BYTES = 512

# zlib level 6 is the usual sweet spot for size-vs-CPU on API payloads.
COMPRESSION_LEVEL = 6

_MARKER = "__gz__"


def is_packed(value: Any) -> bool:
    """True when `value` is a compressed-payload wrapper."""
    return isinstance(value, dict) and _MARKER in value and len(value) == 1


def pack(value: Any) -> Any:
    """Return `value` compressed, or unchanged if it is small enough that
    compression would not pay off, or already a wrapper."""
    if value is None or value == {} or value == []:
        return value
    if is_packed(value):
        return value
    encoded = json.dumps(value, separators=(",", ":"), default=str).encode("utf-8")
    if len(encoded) < COMPRESSION_THRESHOLD_BYTES:
        return value
    blob = zlib.compress(encoded, COMPRESSION_LEVEL)
    return {_MARKER: base64.b64encode(blob).decode("ascii")}


def unpack(value: Any) -> Any:
    """Return `value` decompressed if it is a wrapper, else unchanged."""
    if not is_packed(value):
        return value
    try:
        blob = base64.b64decode(value[_MARKER])
        text = zlib.decompress(blob).decode("utf-8")
        return json.loads(text)
    except (ValueError, zlib.error):
        # If anything is corrupt, preserve the wrapper so a caller can
        # inspect it rather than silently returning None.
        return value


def ratio(value: Any) -> tuple[int, int]:
    """Returns (compressed_size, original_size) in bytes for diagnostics.

    `value` is a packed wrapper; original size is the uncompressed JSON
    length. Returns (0, 0) if the value is not packed.
    """
    if not is_packed(value):
        return 0, 0
    try:
        blob = base64.b64decode(value[_MARKER])
        return len(blob), len(zlib.decompress(blob))
    except (ValueError, zlib.error):
        return 0, 0


class CompressedJSON(TypeDecorator):
    """A JSON column that transparently compresses large payloads.

    Writes go through :func:`pack` (small dicts stay inline), reads
    through :func:`unpack`. The underlying storage is still the JSON
    type, so existing queries that look at other columns are unaffected.
    SQL expressions over the JSON body of a compressed row will see the
    wrapper rather than the real content; use a dedicated boolean column
    instead of searching a `raw` payload when you need a SQL predicate.
    """
    impl = JSON
    cache_ok = True

    def process_bind_param(self, value, dialect):
        return pack(value) if value is not None else None

    def process_result_value(self, value, dialect):
        return unpack(value) if value is not None else None
