"""Tiny TTL cache for the expensive read paths.

What's cached and why:
  build_resolution_map   loads every active adjudication and resolves it to
                         finding ids via 4 queries. Rebuilt on every request.
                         Only changes on adjudication create/decide/revoke.
  grouped_search / facets
                         Scan every matching finding and group in Python.
                         Only change on sync write, adjudication write, or
                         finding verify.
  lifecycle_trends       One-pass scan of all findings, bucketed in Python.

Design notes:
  - In-process only. Single-instance app; a process restart cleanly empties
    the cache, so there is no cold-cache migration to worry about.
  - 60s TTL for the resolution map, 15s for query results. Short enough that
    a scheduled sync's effects show up on the next page refresh even without
    an explicit invalidate.
  - Explicit invalidation hooks fire on the four mutation surfaces that
    matter (sync complete, adjudication write, finding verify, historical
    import). Everything else relies on the TTL.
  - Keys are the function arguments stringified. For object-ish arguments
    (FindingFilter dataclass) we use .as_dict() which already drops defaults.
"""
from __future__ import annotations

import json
import threading
import time
from functools import wraps

DEFAULT_TTL = 15.0           # seconds, for most entries
RESOLUTION_MAP_TTL = 60.0    # seconds, rarely changes


class TTLCache:
    """Thread-safe TTL cache. Values are kept until explicitly invalidated
    or until TTL expires on next read."""

    def __init__(self):
        self._store: dict[str, tuple[float, object]] = {}
        self._lock = threading.Lock()

    def get(self, key: str):
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                return None
            expiry, value = entry
            if expiry <= time.time():
                del self._store[key]
                return None
            return value

    def set(self, key: str, value, ttl: float = DEFAULT_TTL):
        with self._lock:
            self._store[key] = (time.time() + ttl, value)

    def invalidate(self, prefix: str | None = None):
        with self._lock:
            if prefix is None:
                self._store.clear()
                return
            for k in [k for k in self._store if k.startswith(prefix)]:
                del self._store[k]

    def size(self) -> int:
        return len(self._store)


# One shared cache for the process.
_cache = TTLCache()


def invalidate_all() -> None:
    """Call after any change that could affect finding counts, severity
    rollups, or adjudication coverage. Called from sync completion,
    adjudication create/decide/revoke/renew/expire, and finding verify."""
    _cache.invalidate()


def invalidate(prefix: str) -> None:
    _cache.invalidate(prefix)


def cache_size() -> int:
    return _cache.size()


def _key(prefix: str, *parts) -> str:
    """Stable hashable key from a prefix and arbitrary parts. Dataclasses
    with an as_dict() method are serialised via that; everything else via
    repr so lists and dicts order stably enough."""
    frags = [prefix]
    for p in parts:
        if hasattr(p, "as_dict"):
            frags.append(json.dumps(p.as_dict(), sort_keys=True, default=str))
        elif isinstance(p, (dict, list)):
            frags.append(json.dumps(p, sort_keys=True, default=str))
        else:
            frags.append(repr(p))
    return "|".join(frags)


def cached(prefix: str, ttl: float = DEFAULT_TTL, *, skip_first_arg: bool = True):
    """Decorator: cache a function's return value by its args. By default the
    first positional arg (the DB session) is skipped because it is not part
    of the identity -- any db from the same engine yields the same answer."""
    def wrap(fn):
        @wraps(fn)
        def inner(*args, **kwargs):
            start = 1 if skip_first_arg and args else 0
            key = _key(prefix, *args[start:], kwargs)
            hit = _cache.get(key)
            if hit is not None:
                return hit
            value = fn(*args, **kwargs)
            _cache.set(key, value, ttl=ttl)
            return value
        return inner
    return wrap
