"""Thread-safe rate limiting utilities."""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass
from threading import Lock
from time import monotonic
from typing import Deque, Dict, Mapping, Protocol, runtime_checkable


@runtime_checkable
class RequestLike(Protocol):
    headers: Mapping[str, str]
    remote_addr: str | None


@dataclass
class RateLimiterConfig:
    max_calls: int = 10
    per_seconds: int = 60


class RateLimiter:
    """Simple in-memory rate limiter safe for threaded environments."""

    def __init__(self, config: RateLimiterConfig | None = None) -> None:
        self.config = config or RateLimiterConfig()
        self._buckets: Dict[str, Deque[float]] = {}
        self._lock = Lock()

    def _bucket_for(self, key: str, config: RateLimiterConfig) -> Deque[float]:
        with self._lock:
            bucket = self._buckets.get(key)
            if bucket is None:
                bucket = deque(maxlen=config.max_calls)
                self._buckets[key] = bucket
            return bucket

    def allow(
        self,
        request: RequestLike,
        *,
        max_calls: int | None = None,
        per_seconds: int | None = None,
    ) -> bool:
        config = RateLimiterConfig(
            max_calls=max_calls or self.config.max_calls,
            per_seconds=per_seconds or self.config.per_seconds,
        )
        key_base = (
            request.headers.get("Authorization", "")[7:]
            or request.remote_addr
            or "anonymous"
        )
        bucket_key = f"{key_base}:{config.max_calls}:{config.per_seconds}"
        bucket = self._bucket_for(bucket_key, config)
        now = monotonic()

        with self._lock:
            while bucket and now - bucket[0] > config.per_seconds:
                bucket.popleft()
            if len(bucket) >= config.max_calls:
                return False
            bucket.append(now)
            return True
