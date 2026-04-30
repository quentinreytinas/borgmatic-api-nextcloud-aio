"""Policy-based actions system for the Borgmatic API.

This module provides a secure, policy-driven automation layer where predefined
actions can be triggered without exposing sensitive configuration details.

Each action is defined in a YAML policy file and validated at load time.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Allowed action types
ALLOWED_ACTION_TYPES = {"nextcloud_aio_backup"}

# Name pattern: simple alphanumeric with hyphens/underscores
NAME_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]*$")

# SSH URL pattern (must contain @ and :)
SSH_URL_PATTERN = re.compile(r"^ssh://[^@]+@[^:]+:\d+/")

# Host location pattern (must start with / and not end with /)
HOST_LOCATION_PATTERN = re.compile(r"^/[^/].*/$|^/[^/]+$")


@dataclass(frozen=True, slots=True)
class ActionPolicy:
    """A validated, pre-defined action policy."""

    name: str
    type: str
    description: str = ""

    # Target (exactly one of these)
    remote_repo: str = ""
    host_location: str = ""

    # Backup behaviour
    restore_after: bool = False
    daily_backup: bool = True
    check_backup: bool = False

    # Container lifecycle
    stop_containers: bool = True
    start_containers: bool = True
    automatic_updates: bool = False

    # Timeouts
    stop_timeout: int = 60
    timeout: int = 21600

    @property
    def target_display(self) -> str:
        """Return a sanitized target identifier for audit logs (no credentials)."""
        if self.remote_repo:
            # Mask credentials from SSH URL
            url = self.remote_repo
            if "@" in url:
                parts = url.split("@", 1)
                url = f"{parts[0]}@***:{parts[1].split(':', 1)[1] if ':' in parts[1] else parts[1]}"
            return url
        return self.host_location


class ActionPolicyError(ValueError):
    """Raised when a policy fails validation."""


class ActionStore:
    """Loads and provides access to predefined action policies."""

    def __init__(self, policy_path: Optional[Path] = None) -> None:
        self._policies: Dict[str, ActionPolicy] = {}
        self._policy_path = policy_path

    @property
    def policies(self) -> Dict[str, ActionPolicy]:
        return dict(self._policies)

    @property
    def policy_names(self) -> List[str]:
        return list(self._policies.keys())

    def load_from_file(self, path: Optional[Path] = None) -> None:
        """Load policies from a YAML file."""
        p = path or self._policy_path
        if p is None or not p.exists():
            logger.info("No actions policy file found at %s", p)
            return

        try:
            import yaml
        except ImportError:
            logger.warning("PyYAML not available; cannot load actions policy from %s", p)
            return

        try:
            raw = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        except Exception as e:
            raise ActionPolicyError(f"Failed to parse policy file {p}: {e}")

        actions = raw.get("allowed_actions", raw) if isinstance(raw, dict) else {}
        for name, cfg in actions.items():
            policy = self._validate_and_create(name, cfg)
            self._policies[policy.name] = policy
            logger.info("Loaded action policy: %s", policy.name)

    def add_policy(self, policy: ActionPolicy) -> None:
        """Add a single policy programmatically."""
        self._policies[policy.name] = policy

    def get(self, name: str) -> Optional[ActionPolicy]:
        """Get a policy by name."""
        return self._policies.get(name)

    def list_public(self) -> List[Dict[str, str]]:
        """Return a list of actions with only safe fields (no secrets)."""
        result = []
        for policy in self._policies.values():
            result.append(
                {
                    "name": policy.name,
                    "type": policy.type,
                    "description": policy.description,
                    "target_display": policy.target_display,
                }
            )
        return result

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------
    def _validate_and_create(self, name: str, cfg: Dict[str, Any]) -> ActionPolicy:
        """Validate a raw config dict and return an ActionPolicy."""
        errors: List[str] = []

        # --- name ---
        if not NAME_PATTERN.match(name):
            errors.append(
                f"Action name '{name}' is invalid; "
                f"must match {NAME_PATTERN.pattern}"
            )

        # --- type ---
        action_type = str(cfg.get("type", "")).lower()
        if action_type not in ALLOWED_ACTION_TYPES:
            errors.append(
                f"Action type '{action_type}' is not allowed; "
                f"must be one of {ALLOWED_ACTION_TYPES}"
            )

        # --- target (exactly one of remote_repo or host_location) ---
        remote_repo = str(cfg.get("remote_repo", ""))
        host_location = str(cfg.get("host_location", ""))

        if remote_repo and host_location:
            errors.append(
                "Action must specify exactly one of remote_repo or host_location, not both"
            )
        elif not remote_repo and not host_location:
            errors.append(
                "Action must specify exactly one of remote_repo or host_location"
            )
        else:
            if remote_repo and not SSH_URL_PATTERN.match(remote_repo):
                errors.append(
                    f"remote_repo must be an SSH URL (ssh://user@host:port/path), "
                    f"got: {remote_repo[:50]}..."
                )
            if host_location and not host_location.startswith("/"):
                errors.append(
                    f"host_location must be an absolute path starting with /, "
                    f"got: {host_location[:50]}..."
                )

        # --- timeouts ---
        timeout = cfg.get("timeout", 21600)
        stop_timeout = cfg.get("stop_timeout", 60)
        try:
            timeout = int(timeout)
            if not (60 <= timeout <= 86400):
                errors.append(f"timeout must be between 60 and 86400, got {timeout}")
        except (TypeError, ValueError):
            errors.append(f"timeout must be an integer, got {timeout!r}")

        try:
            stop_timeout = int(stop_timeout)
            if not (10 <= stop_timeout <= 300):
                errors.append(f"stop_timeout must be between 10 and 300, got {stop_timeout}")
        except (TypeError, ValueError):
            errors.append(f"stop_timeout must be an integer, got {stop_timeout!r}")

        if errors:
            raise ActionPolicyError(
                f"Invalid action policy '{name}':\n" + "\n".join(f" - {e}" for e in errors)
            )

        return ActionPolicy(
            name=name,
            type=action_type,
            description=str(cfg.get("description", "")),
            remote_repo=remote_repo,
            host_location=host_location,
            restore_after=bool(cfg.get("restore_after", False)),
            daily_backup=bool(cfg.get("daily_backup", True)),
            check_backup=bool(cfg.get("check_backup", False)),
            stop_containers=bool(cfg.get("stop_containers", True)),
            start_containers=bool(cfg.get("start_containers", True)),
            automatic_updates=bool(cfg.get("automatic_updates", False)),
            stop_timeout=stop_timeout,
            timeout=timeout,
        )