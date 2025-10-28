"""Application configuration handling for the Borgmatic API."""

from __future__ import annotations

from dataclasses import dataclass
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
    required_aio_archive_format: str
    docker_host: str
    exec_whitelist: Dict[str, ExecWhitelistEntry]
    dangerous_commands: List[str]
    write_token: str
    read_token: str
    from_header: str
    sse_heartbeat: int
    sse_base_url: str
    ready_webhook_url: str

    @property
    def use_socket_proxy(self) -> bool:
        return self.docker_host.startswith("tcp://")

    def validate(self) -> None:
        if not self.write_token:
            raise RuntimeError(
                "API_TOKEN must be set and non empty to start the Borgmatic API"
            )
        if not self.read_token:
            raise RuntimeError(
                "API_READ_TOKEN must be set and non empty to start the Borgmatic API"
            )


DEFAULT_WHITELIST = {
    "nextcloud-aio-mastercontainer": ExecWhitelistEntry(
        commands=["/daily-backup.sh", "/healthcheck.sh"],
        no_shell=True,
        description="Nextcloud AIO Master - backup and health scripts only",
    )
}

DANGEROUS_COMMANDS = [
    "bash",
    # "sh",  # removed to avoid blocking daily-backup.sh
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

    settings = Settings(
        borg_config_dir=Path(
            os.environ.get("BORGMATIC_CONFIG_DIR", "/etc/borgmatic.d")
        ).resolve(),
        borg_base_dir=Path(os.environ.get("BORG_BASE_DIR", "/var/lib/borg")).resolve(),
        borg_ssh_dir=Path(os.environ.get("BORG_SSH_DIR", "/root/.ssh")).resolve(),
        aio_master=os.environ.get("AIO_MASTER", "nextcloud-aio-mastercontainer"),
        aio_daily=os.environ.get("AIO_DAILY", "/daily-backup.sh"),
        aio_health=os.environ.get("AIO_HEALTH", "/healthcheck.sh"),
        required_aio_archive_format="{now:%Y%m%d_%H%M%S}-nextcloud-aio",
        docker_host=os.environ.get("DOCKER_HOST", ""),
        exec_whitelist=_load_exec_whitelist(),
        dangerous_commands=DANGEROUS_COMMANDS,
        write_token=os.environ.get("API_TOKEN", "").strip(),
        read_token=os.environ.get(
            "API_READ_TOKEN", os.environ.get("API_TOKEN", "")
        ).strip(),
        from_header=os.environ.get("APP_FROM_HEADER", "BorgmaticAPI"),
        sse_heartbeat=int(os.environ.get("APP_SSE_HEARTBEAT_SEC", "15")),
        sse_base_url=os.environ.get("APP_SSE_BASE_URL", "").rstrip("/"),
        ready_webhook_url=os.environ.get("APP_READY_WEBHOOK_URL", "").strip(),
    )

    settings.validate()
    return settings
