"""Container object passed to route modules."""

from __future__ import annotations

from dataclasses import dataclass
from time import time

from .auth import AuthManager
from .buffers import BufferStore
from .config import Settings
from .metrics import Metrics
from .rate_limit import RateLimiter


@dataclass(slots=True)
class Services:
    settings: Settings
    auth: AuthManager
    rate_limiter: RateLimiter
    buffers: BufferStore
    metrics: Metrics
    start_time: float = time()
