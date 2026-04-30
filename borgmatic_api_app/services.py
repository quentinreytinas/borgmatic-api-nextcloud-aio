"""Container object passed to route modules."""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from time import time
from typing import TYPE_CHECKING, Any, Dict, Optional

from .auth import AuthManager
from .buffers import BufferStore
from .config import Settings
from .metrics import Metrics
from .rate_limit import RateLimiter

if TYPE_CHECKING:
    from .actions import ActionStore
    from .audit import AuditLogger

logger = logging.getLogger(__name__)


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


def run_nextcloud_daily_backup(
    services: "Services",
    job_id: str,
    remote_repo: Optional[str] = None,
    host_location: Optional[str] = None,
    restore_after: bool = False,
    daily_backup: bool = True,
    check_backup: bool = False,
    stop_containers: bool = True,
    start_containers: bool = True,
    automatic_updates: bool = False,
    stop_timeout: int = 60,
    timeout_sec: int = 21600,
) -> Dict[str, Any]:
    """Run a Nextcloud AIO daily backup using policy-based parameters.

    This is the bridge between the action system and the legacy backup runner.
    All parameters are pre-validated by the ActionPolicy system.
    """
    # Import here to avoid circular imports at module level
    from .routes.legacy import (
        _aio_daily_backup_run_for_target_job,
        _buf_get,
    )

    # Build the body that the legacy runner expects
    body: Dict[str, Any] = {
        "restore_after": restore_after,
        "daily_backup": daily_backup,
        "check_backup": check_backup,
        "stop_containers": stop_containers,
        "start_containers": start_containers,
        "automatic_updates": automatic_updates,
        "stop_timeout": stop_timeout,
        "timeout": timeout_sec,
    }
    if remote_repo:
        body["remote_repo"] = remote_repo
    if host_location:
        body["host_location"] = host_location

    # Run the legacy backup job synchronously in the background thread
    _aio_daily_backup_run_for_target_job(job_id, body)

    # Collect the final status from the buffer
    buf = _buf_get(job_id)
    final_status = buf.get_final_status() if buf else {}
    return final_status
