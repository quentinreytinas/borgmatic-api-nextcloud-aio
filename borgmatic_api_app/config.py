"""Application configuration handling for the Borgmatic API."""

from __future__ import annotations

from dataclasses import dataclass, field
import os
from pathlib import Path
from typing import Dict, List


@dataclass(slots=True)
class ExecWhitelistEntry:
    """Entry describing which commands are allowed for docker exec."""

    commands: List[str]
    no_shell: bool
    description: str


@dataclass(slots=True)
class Settings:
    """Runtime settings loaded from the environment."""

    borg_config_dir: Path
    borg_base_dir: Path
    borg_ssh_dir: Path
    aio_master: str
    aio_daily: str
    aio_health: str
    aio_config_file: Path
    required_aio_archive_format: str
    docker_host: str
    exec_whitelist: Dict[str, ExecWhitelistEntry]
    dangerous_commands: List[str]

    # --- Authentication tokens ---
    admin_token: str
    action_token: str
    read_token: str

    # --- Legacy token (kept for backwards compatibility when SECURE_MODE=false) ---
    legacy_token: str = field(default="")

    # --- Security flags ---
    secure_mode: bool = field(default=False)
    enable_admin_endpoints: bool = field(default=True)
    enable_config_write: bool = field(default=True)
    enable_break_lock: bool = field(default=True)
    enable_passphrase_change: bool = field(default=True)
    enable_arbitrary_targets: bool = field(default=True)

    # --- Actions policy file ---
    actions_policy_path: Path = field(default=Path("/etc/borgmatic-api/allowed_actions.yaml"))

    # --- Audit ---
    audit_log_path: Path = field(default=Path("/var/log/borgmatic-api/audit.log"))
    audit_stdout: bool = field(default=True)

    from_header: str = field(default="BorgmaticAPI")
    sse_heartbeat: int = field(default=15)
    sse_base_url: str = field(default="")
    ready_webhook_url: str = field(default="")
    daily_stop_timeout: int = field(default=30)

    @property
    def use_socket_proxy(self) -> bool:
        return self.docker_host.startswith("tcp://")

    def validate(self) -> None:
        """Validate token configuration based on SECURE_MODE."""
        if self.secure_mode:
            errors = []
            if not self.admin_token:
                errors.append("SECURE_MODE=true requires API_ADMIN_TOKEN")
            if not self.action_token:
                errors.append("SECURE_MODE=true requires API_ACTION_TOKEN")
            if not self.read_token:
                errors.append("SECURE_MODE=true requires API_READ_TOKEN")
            if errors:
                raise RuntimeError("\n".join(errors))
        else:
            # Legacy mode: API_TOKEN acts as admin
            if not self.legacy_token:
                raise RuntimeError(
                    "API_TOKEN must be set and non empty to start the Borgmatic API"
                )
            # In legacy mode, propagate legacy token to admin for backwards compat
            if not self.admin_token:
                self.admin_token = self.legacy_token
            if not self.read_token:
                self.read_token = self.legacy_token


DEFAULT_WHITELIST = {
    "nextcloud-aio-mastercontainer": ExecWhitelistEntry(
        commands=["/daily-backup.sh", "/healthcheck.sh"],
        no_shell=True,
        description="Nextcloud AIO Master - backup and health scripts only",
    )
}

DANGEROUS_COMMANDS = [
    "bash",
    "sh",
    "zsh",
    "fish",
    "ash",
    "rm",
    "rmdir",
    "dd",
    "nc",
    "netcat",
    "curl",
    "wget",
    "chmod",
    "chown",
    "useradd",
    "passwd",
    "iptables",
    "ip",
    "mount",
    "umount",
    "kill",
    "killall",
    "pkill",
]


def _load_exec_whitelist() -> Dict[str, ExecWhitelistEntry]:
    # For now only the default entry is supported; we keep the hook to allow
    # future extension or configuration through the environment.
    return DEFAULT_WHITELIST.copy()


def load_settings() -> Settings:
    """Load settings from the environment."""

    # --- Tokens ---
    admin_token = os.environ.get("API_ADMIN_TOKEN", "").strip()
    action_token = os.environ.get("API_ACTION_TOKEN", "").strip()
    read_token = os.environ.get("API_READ_TOKEN", "").strip()
    legacy_token = os.environ.get("API_TOKEN", "").strip()

    settings = Settings(
        borg_config_dir=Path(
            os.environ.get("BORGMATIC_CONFIG_DIR", "/etc/borgmatic.d")
        ).resolve(),
        borg_base_dir=Path(os.environ.get("BORG_BASE_DIR", "/var/lib/borg")).resolve(),
        borg_ssh_dir=Path(os.environ.get("BORG_SSH_DIR", "/root/.ssh")).resolve(),
        aio_master=os.environ.get("AIO_MASTER", "nextcloud-aio-mastercontainer"),
        aio_daily=os.environ.get("AIO_DAILY", "/daily-backup.sh"),
        aio_health=os.environ.get("AIO_HEALTH", "/healthcheck.sh"),
        aio_config_file=Path(
            os.environ.get(
                "AIO_CONFIG_FILE",
                "/nextcloud_aio_mastercontainer/data/configuration.json",
            )
        ).resolve(),
        required_aio_archive_format="{now:%Y%m%d_%H%M%S}-nextcloud-aio",
        docker_host=os.environ.get("DOCKER_HOST", ""),
        exec_whitelist=_load_exec_whitelist(),
        dangerous_commands=DANGEROUS_COMMANDS,
        admin_token=admin_token,
        action_token=action_token,
        read_token=read_token,
        legacy_token=legacy_token,
        secure_mode=os.environ.get("SECURE_MODE", "false").lower() in ("1", "true", "yes"),
        enable_admin_endpoints=os.environ.get("ENABLE_ADMIN_ENDPOINTS", "true").lower() in ("1", "true", "yes"),
        enable_config_write=os.environ.get("ENABLE_CONFIG_WRITE", "true").lower() in ("1", "true", "yes"),
        enable_break_lock=os.environ.get("ENABLE_BREAK_LOCK", "true").lower() in ("1", "true", "yes"),
        enable_passphrase_change=os.environ.get("ENABLE_PASSPHRASE_CHANGE", "true").lower() in ("1", "true", "yes"),
        enable_arbitrary_targets=os.environ.get("ENABLE_ARBITRARY_TARGETS", "true").lower() in ("1", "true", "yes"),
        actions_policy_path=Path(
            os.environ.get(
                "ACTIONS_POLICY_PATH",
                "/etc/borgmatic-api/allowed_actions.yaml",
            )
        ).resolve(),
        audit_log_path=Path(
            os.environ.get(
                "AUDIT_LOG_PATH",
                "/var/log/borgmatic-api/audit.log",
            )
        ).resolve(),
        audit_stdout=os.environ.get("AUDIT_STDOUT", "true").lower() in ("1", "true", "yes"),
        from_header=os.environ.get("APP_FROM_HEADER", "BorgmaticAPI"),
        sse_heartbeat=int(os.environ.get("APP_SSE_HEARTBEAT_SEC", "15")),
        sse_base_url=os.environ.get("APP_SSE_BASE_URL", "").rstrip("/"),
        ready_webhook_url=os.environ.get("APP_READY_WEBHOOK_URL", "").strip(),
        daily_stop_timeout=int(os.environ.get("AIO_STOP_TIMEOUT", "30")),
    )

    settings.validate()
    return settings
