"""Action-based automation routes.

Provides a secure, policy-driven endpoint for triggering predefined backup
actions without exposing sensitive configuration to the caller.
"""

from __future__ import annotations

import logging
import time
import uuid
from typing import TYPE_CHECKING

from flask import Blueprint, current_app, jsonify, request

from ..auth import require_action

if TYPE_CHECKING:
    from ..services import Services

logger = logging.getLogger(__name__)

bp = Blueprint("actions", __name__, url_prefix="/actions")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _json_ok(data: dict, status: int = 200):
    return jsonify(data), status


def _json_error(status: int, code: str, message: str):
    return jsonify({"error": code, "message": message}), status


def _services() -> "Services":
    return current_app.config["SERVICES"]


# ---------------------------------------------------------------------------
# GET /actions — list available actions (safe fields only)
# ---------------------------------------------------------------------------
@bp.route("/", methods=["GET"])
@require_action()
def list_actions():
    """List available actions without exposing secrets.

    Returns only name, type, description, and target_display.
    """
    try:
        services = _services()
        store = services.actions_store
        return _json_ok({"actions": store.list_public()})
    except Exception as e:
        return _json_error(500, "internal_error", str(e))


# ---------------------------------------------------------------------------
# POST /actions/<name>/run — trigger a predefined action
# ---------------------------------------------------------------------------
@bp.route("/<name>/run", methods=["POST"])
@require_action()
def run_action(name: str):
    """Trigger a predefined action by name.

    The request body is intentionally ignored to prevent payload-based attacks.
    The action is executed asynchronously and a job_id is returned immediately.
    """
    try:
        services = _services()
        store = services.actions_store
        policy = store.get(name)

        if policy is None:
            return _json_error(
                404, "action_not_found", f"Action '{name}' is not defined"
            )

        # Validate action type is supported
        if policy.type != "nextcloud_aio_backup":
            return _json_error(
                501,
                "action_type_not_supported",
                f"Action type '{policy.type}' is not yet supported for automated execution",
            )

        # Generate job ID
        job_id = str(uuid.uuid4())

        # Record audit entry
        audit = services.audit_logger
        audit.log_action_start(
            action_name=name,
            source_ip=request.remote_addr,
            token_role="action",
            job_id=job_id,
            target_repo=policy.target_display,
        )

        # Schedule async execution
        services.executor.submit(
            _execute_nextcloud_backup,
            services=services,
            policy=policy,
            job_id=job_id,
            audit_logger=audit,
        )

        return _json_ok(
            {
                "job_id": job_id,
                "action": name,
                "status": "queued",
                "message": f"Action '{name}' triggered successfully",
            },
            status=202,
        )

    except Exception as e:
        return _json_error(500, "internal_error", str(e))


# ---------------------------------------------------------------------------
# Action execution (runs in background thread)
# ---------------------------------------------------------------------------
def _execute_nextcloud_backup(
    services: "Services",
    policy: "ActionPolicy",  # noqa: F821
    job_id: str,
    audit_logger,
) -> None:
    """Execute a Nextcloud AIO backup action based on the policy."""
    start_time = time.time()
    try:
        from .legacy import _aio_daily_backup_run_for_target_job, _buf_get

        # Build the body expected by the existing legacy backup runner
        body = {
            "restore_after": policy.restore_after,
            "daily_backup": policy.daily_backup,
            "check_backup": policy.check_backup,
            "stop_containers": policy.stop_containers,
            "start_containers": policy.start_containers,
            "automatic_updates": policy.automatic_updates,
            "stop_timeout": policy.stop_timeout,
            "timeout": policy.timeout,
        }
        if policy.remote_repo:
            body["remote_repo"] = policy.remote_repo
        if policy.host_location:
            body["host_location"] = policy.host_location

        _aio_daily_backup_run_for_target_job(job_id, body)

        buf = _buf_get(job_id)
        result = buf.get_final_status() if buf else {}

        duration = time.time() - start_time
        audit_logger.log_action_complete(
            job_id=job_id,
            result="success",
            exit_code=result.get("returncode", 0) if isinstance(result, dict) else 0,
            duration_sec=round(duration, 2),
        )

    except Exception as e:
        duration = time.time() - start_time
        logger.exception("Action execution failed for job %s", job_id)
        audit_logger.log_action_complete(
            job_id=job_id,
            result="fail",
            exit_code=-1,
            duration_sec=round(duration, 2),
            error=str(e),
        )
