"""In-process request rate limiting.

A dependency-free sliding-window limiter used to throttle abuse-prone endpoints
(login, registration, password recovery). State is per-process and in-memory:
it needs no external service, but it does NOT share counts across multiple
worker processes. For a horizontally scaled deployment, back this with a shared
store such as Redis instead.
"""
import os
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request, status

# When more than this many distinct client keys are tracked, sweep out entries
# that have been idle for longer than _IDLE_TTL_SECONDS so a burst of unique
# source IPs cannot slowly leak memory.
_MAX_TRACKED_KEYS = 10_000
_IDLE_TTL_SECONDS = 3600


class SlidingWindowRateLimiter:
    def __init__(self) -> None:
        self._hits: dict[tuple[str, str], deque] = defaultdict(deque)
        self._lock = threading.Lock()

    def hit(self, bucket: str, client: str, limit: int, window_seconds: int) -> None:
        """Record one request and raise HTTP 429 if the client has exceeded
        `limit` requests within the trailing `window_seconds` for this bucket."""
        now = time.monotonic()
        cutoff = now - window_seconds
        key = (bucket, client)
        with self._lock:
            dq = self._hits[key]
            while dq and dq[0] <= cutoff:
                dq.popleft()
            if len(dq) >= limit:
                retry_after = int(dq[0] + window_seconds - now) + 1
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many attempts. Please slow down and try again shortly.",
                    headers={"Retry-After": str(max(retry_after, 1))},
                )
            dq.append(now)
            if len(self._hits) > _MAX_TRACKED_KEYS:
                self._prune(now - _IDLE_TTL_SECONDS)

    def _prune(self, older_than: float) -> None:
        # Caller must hold the lock. Windows in use are far shorter than
        # _IDLE_TTL_SECONDS, so this never drops a still-active client.
        stale = [k for k, dq in self._hits.items() if not dq or dq[-1] <= older_than]
        for k in stale:
            del self._hits[k]


_limiter = SlidingWindowRateLimiter()


def _trust_proxy_headers() -> bool:
    # X-Forwarded-For is only meaningful when a trusted reverse proxy strips or
    # sets it. Accepting it by default would let a direct client rotate the
    # header and evade per-IP throttling.
    return os.getenv("TRUST_PROXY_HEADERS", "false").strip().lower() in {"1", "true", "yes", "on"}


def _client_key(request: Request) -> str:
    # Honour the first X-Forwarded-For hop only when running behind a trusted
    # proxy; otherwise fall back to the direct socket peer.
    if _trust_proxy_headers():
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            first = forwarded.split(",")[0].strip()
            if first:
                return first
    return request.client.host if request.client else "unknown"


def rate_limit(bucket: str, limit: int, window_seconds: int):
    """Build a FastAPI dependency that throttles a route by client IP.

    Usage:
        @router.post("/login", dependencies=[Depends(rate_limit("login", 5, 60))])
    """
    def _dependency(request: Request) -> None:
        _limiter.hit(bucket, _client_key(request), limit, window_seconds)

    return _dependency
