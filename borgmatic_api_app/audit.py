"""Structured audit logging for the Borgmatic API.

Records action execution events to both stdout (for Docker log collection)
and optionally to a JSON-lines file. Secrets (passphrases, tokens, SSH keys)
are never logged.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass(slots=True)
class AuditEntry:
    """A single audit log entry."""

    timestamp: float
    event: str  # "action_start" | "action_complete"
    action_name: str = ""
    source_ip: str = ""
    token_role: str = ""
    job_id: str = ""
    target_repo: str = ""  # sanitized (no credentials)
    result: str = ""  # "success" | "fail" | "timeout"
    exit_code: int = 0
    duration_sec: float = 0.0
    error: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class AuditLogger:
    """Writes structured audit entries to stdout and optionally to a file."""

    def __init__(
        self,
        log_path: Optional[Path] = None,
        stdout: bool = True,
    ) -> None:
        self._log_path = log_path
        self._stdout = stdout
        self._file_handle = None

        # Open file handle if path is provided
        if log_path:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                self._file_handle = open(log_path, "a", encoding="utf-8")
            except OSError as e:
                logger.warning("Cannot open audit log file %s: %s", log_path, e)
                self._file_handle = None

    def _write(self, entry: AuditEntry) -> None:
        line = json.dumps(entry.to_dict(), default=str)

        if self._stdout:
            # Use a dedicated logger for audit entries so they can be filtered
            logger.info("[AUDIT] %s", line)

        if self._file_handle:
            try:
                self._file_handle.write(line + "\n")
                self._file_handle.flush()
            except OSError as e:
                logger.warning("Failed to write audit log: %s", e)

    def log_action_start(
        self,
        action_name: str,
        source_ip: str,
        token_role: str,
        job_id: str,
        target_repo: str,
    ) -> None:
        """Log the start of an action execution."""
        entry = AuditEntry(
            timestamp=time.time(),
            event="action_start",
            action_name=action_name,
            source_ip=source_ip,
            token_role=token_role,
            job_id=job_id,
            target_repo=target_repo,
        )
        self._write(entry)

    def log_action_complete(
        self,
        job_id: str,
        result: str,
        exit_code: int,
        duration_sec: float,
        error: str = "",
    ) -> None:
        """Log the completion of an action execution."""
        entry = AuditEntry(
            timestamp=time.time(),
            event="action_complete",
            job_id=job_id,
            result=result,
            exit_code=exit_code,
            duration_sec=duration_sec,
            error=error,
        )
        self._write(entry)

    def close(self) -> None:
        """Close the file handle if open."""
        if self._file_handle:
            self._file_handle.close()
            self._file_handle = None

    def __del__(self) -> None:
        self.close()