"""
app/utils/rate_limiter.py
─────────────────────────
In-memory sliding-window rate limiter.

Uses ``collections.deque`` to track request timestamps per identifier
(e.g. ``device_id`` or ``session_id``).  Thread-safe via ``asyncio.Lock``.

Old entries are lazily evicted on each ``check()`` call, keeping memory
usage bounded.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque


class RateLimiter:
    """Async-safe sliding-window rate limiter.

    Each ``identifier`` (e.g. a device_id or session_id) maintains its
    own deque of request timestamps.  A request is allowed only when the
    number of timestamps within the window is below the limit.

    Example
    -------
    >>> limiter = RateLimiter()
    >>> allowed = await limiter.check("device_001", limit=30, window_seconds=60)
    """

    def __init__(self) -> None:
        """Initialise the limiter with an empty request log."""
        self._requests: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def check(
        self,
        identifier: str,
        limit: int,
        window_seconds: int = 60,
    ) -> bool:
        """Check whether a request from ``identifier`` should be allowed.

        If allowed, the current timestamp is recorded.  If denied, no
        side-effect occurs (the caller should return HTTP 429).

        Parameters
        ----------
        identifier : str
            Unique key for the rate-limit bucket (e.g. device_id).
        limit : int
            Maximum allowed requests within the window.
        window_seconds : int
            Sliding window size in seconds.

        Returns
        -------
        bool
            ``True`` if the request is within limits, ``False`` if it
            should be rate-limited.
        """
        now = time.monotonic()
        cutoff = now - window_seconds

        async with self._lock:
            dq = self._requests[identifier]

            # Evict expired entries
            while dq and dq[0] < cutoff:
                dq.popleft()

            if len(dq) >= limit:
                return False

            dq.append(now)
            return True

    async def reset(self, identifier: str) -> None:
        """Clear all recorded requests for an identifier.

        Parameters
        ----------
        identifier : str
            The bucket key to reset.
        """
        async with self._lock:
            self._requests.pop(identifier, None)

    async def remaining(
        self,
        identifier: str,
        limit: int,
        window_seconds: int = 60,
    ) -> int:
        """Return how many requests remain in the current window.

        Parameters
        ----------
        identifier : str
            Unique key for the rate-limit bucket.
        limit : int
            Maximum allowed requests within the window.
        window_seconds : int
            Sliding window size in seconds.

        Returns
        -------
        int
            Number of requests still available (≥ 0).
        """
        now = time.monotonic()
        cutoff = now - window_seconds

        async with self._lock:
            dq = self._requests[identifier]
            while dq and dq[0] < cutoff:
                dq.popleft()
            return max(0, limit - len(dq))
