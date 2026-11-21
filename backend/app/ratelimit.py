"""In-memory limiter for failed logins.

Two limits apply:
  - per account and IP address: 5 failures in 60 seconds
  - per IP address overall: 20 failures in 60 seconds (catches credential stuffing)

Once a limit is hit, further login attempts are refused (HTTP 429) until the oldest
failure falls out of the 60-second window. This is held in memory, so it resets when
the server restarts. A production system would keep it in a shared store such as Redis.
"""
import os
import time
from collections import defaultdict, deque


def enabled() -> bool:
    return os.getenv("RATE_LIMIT", "on").strip().lower() != "off"


class FailureLimiter:
    def __init__(self, max_failures: int, window_seconds: int):
        self.max = max_failures
        self.window = window_seconds
        self._events = defaultdict(deque)

    def _prune(self, key, now):
        q = self._events[key]
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def retry_after(self, key) -> int:
        """Seconds until another attempt is allowed (0 = allowed now)."""
        now = time.monotonic()
        q = self._prune(key, now)
        if len(q) >= self.max:
            return int(self.window - (now - q[0])) + 1
        return 0

    def record_failure(self, key):
        self._events[key].append(time.monotonic())

    def clear(self, key):
        self._events.pop(key, None)


account_limiter = FailureLimiter(max_failures=5, window_seconds=60)
ip_limiter = FailureLimiter(max_failures=20, window_seconds=60)