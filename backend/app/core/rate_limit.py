from __future__ import annotations

from collections import deque
from threading import Lock
from time import monotonic


class AuthRateLimiter:
    def __init__(self, limit: int, window_seconds: int = 60, max_clients: int = 10_000) -> None:
        if limit < 1 or window_seconds < 1 or max_clients < 1:
            raise ValueError("Rate-limit settings must be positive")
        self.limit = limit
        self.window_seconds = window_seconds
        self.max_clients = max_clients
        self._requests: dict[str, deque[float]] = {}
        self._lock = Lock()

    def allow(self, client_key: str, now: float | None = None) -> bool:
        current_time = monotonic() if now is None else now
        cutoff = current_time - self.window_seconds
        with self._lock:
            requests = self._requests.get(client_key)
            if requests is None:
                self._remove_expired(cutoff)
                if len(self._requests) >= self.max_clients:
                    return False
                requests = self._requests[client_key] = deque()
            while requests and requests[0] <= cutoff:
                requests.popleft()
            if len(requests) >= self.limit:
                return False
            requests.append(current_time)
            return True

    def _remove_expired(self, cutoff: float) -> None:
        expired = []
        for client_key, requests in self._requests.items():
            while requests and requests[0] <= cutoff:
                requests.popleft()
            if not requests:
                expired.append(client_key)
        for client_key in expired:
            del self._requests[client_key]
