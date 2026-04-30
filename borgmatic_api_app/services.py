"""Container object passed to route modules."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from time import time
from typing import TYPE_CHECKING

from .auth import AuthManager
from .buffers import BufferStore
from .config import Settings
from .metrics import Metrics
from .rate_limit import RateLimiter

if TYPE_CHECKING:
    from .actions import ActionStore
    from .audit import AuditLogger


@dataclass(slots=True)
class Services:
    settings: Settings
    auth: AuthManager
    rate_limiter: RateLimiter
    buffers: BufferStore
    metrics: Metrics
    start_time: float = field(default_factory=time)

    # Action policy store
    actions_store: "ActionStore" = None  # noqa: FA100

    # Audit logger
    audit_logger: "AuditLogger" = None  # noqa: FA100

    # Thread pool for async action execution
    executor: "ThreadPoolExecutor" = None  # noqa: FA100
