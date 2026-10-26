"""
Per-provider rate limiting.

Spaces outgoing calls to each provider so they never exceed
config.rate_limit_per_second. Limits are per process: with several
container replicas, each replica enforces its own limit.
"""

import asyncio
import threading
import time


class RateLimiter:
    def __init__(self):
        self._next_allowed: dict[str, float] = {}
        self._lock = threading.Lock()

    def _reserve(self, provider: str, rate_per_second: float) -> float:
        """Reserve the next slot and return how long to wait for it."""
        if rate_per_second <= 0:
            return 0.0
        interval = 1.0 / rate_per_second
        with self._lock:
            now = time.monotonic()
            slot = max(now, self._next_allowed.get(provider, now))
            self._next_allowed[provider] = slot + interval
            return slot - now

    def wait(self, provider: str, rate_per_second: float) -> None:
        delay = self._reserve(provider, rate_per_second)
        if delay > 0:
            time.sleep(delay)

    async def await_slot(self, provider: str, rate_per_second: float) -> None:
        delay = self._reserve(provider, rate_per_second)
        if delay > 0:
            await asyncio.sleep(delay)
