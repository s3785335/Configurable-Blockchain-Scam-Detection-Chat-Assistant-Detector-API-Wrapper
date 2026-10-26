"""
Lightweight in-session cache.

Key = (resource_id, options, provider). Avoids repeat calls for the same
request within a session. Intentionally simple -- no persistence, no
distributed cache -- swap for Redis/etc. later if needed without changing
callers.
"""

import time
from typing import Any


class SimpleCache:
    def __init__(self, ttl_seconds: int = 300):
        self._ttl = ttl_seconds
        self._store: dict[tuple, tuple[float, Any]] = {}

    @staticmethod
    def make_key(resource_id: str, options: dict, provider: str) -> tuple:
        return (resource_id, tuple(sorted(options.items())), provider)

    def get(self, key: tuple):
        entry = self._store.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if time.monotonic() > expires_at:
            self._store.pop(key, None)
            return None
        return value

    def set(self, key: tuple, value: Any) -> None:
        self._store[key] = (time.monotonic() + self._ttl, value)
