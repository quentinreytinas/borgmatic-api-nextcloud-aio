"""Docker helper routines."""

from __future__ import annotations

import json
import os
import subprocess
from typing import Any, Dict, Iterable, List

from .config import ExecWhitelistEntry, Settings


def _build_docker_env(settings: Settings) -> Dict[str, str]:
    """Construct the environment for Docker CLI calls."""

    env = os.environ.copy()
    if settings.use_socket_proxy and settings.docker_host:
        env["DOCKER_HOST"] = settings.docker_host
    return env


def check_docker_available(settings: Settings) -> tuple[bool, str]:
    """Return Docker availability and a diagnostic message.

    The helper honours ``DOCKER_HOST`` when the socket proxy is enabled so the
    health check behaves exactly like the rest of the application.
    """

    env = _build_docker_env(settings)

    try:
        result = subprocess.run(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            capture_output=True,
            text=True,
            timeout=5,
            env=env,
        )
        if result.returncode == 0:
            version = result.stdout.strip()
            mode = "Socket Proxy" if settings.use_socket_proxy else "Direct Socket"
            return True, f"Docker {version} ({mode})"
        return False, f"Docker CLI error: {result.stderr}"
    except subprocess.TimeoutExpired:
        return False, "Docker CLI timeout"
    except FileNotFoundError:
        return False, "Docker CLI not found"
    except Exception as exc:  # pragma: no cover - safety net
        return False, f"Docker check failed: {exc}"


def _command_to_str(command: Iterable[str]) -> str:
    return " ".join(command)


def validate_docker_exec(
    settings: Settings, container: str, command: List[str]
) -> None:
    whitelist: Dict[str, ExecWhitelistEntry] = settings.exec_whitelist
    if container not in whitelist:
        allowed = ", ".join(sorted(whitelist.keys())) or "aucun"
        raise PermissionError(
            f"Container '{container}' interdit. Autorisés : {allowed}"
        )

    config = whitelist[container]
    command_str = _command_to_str(command)

    if config.no_shell:
        for shell in ("bash", "sh", "zsh", "fish", "ash"):
            if shell in command:
                raise PermissionError(
                    f"Shell interdit pour '{container}'. Commande refusée : {shell}"
                )

    blocked = [
        dangerous
        for dangerous in settings.dangerous_commands
        if any(dangerous == part.lower() for part in command)
    ]
    if blocked:
        forbidden = ", ".join(sorted(set(blocked)))
        raise PermissionError(f"La commande contient {forbidden}, ce qui est interdit")

    allowed = config.commands
    if allowed:
        if not any(
            command_str == candidate or command_str.startswith(candidate)
            for candidate in allowed
        ):
            allowed_commands = ", ".join(allowed)
            raise PermissionError(
                f"Commande '{command_str}' refusée pour '{container}'. Autorisées : {allowed_commands}"
            )

    print(
        f"[SECURITY] docker exec validated: container={container}, command={command_str}"
    )


def handle_docker_error(
    settings: Settings, operation: str, error: Exception
) -> Dict[str, Any]:
    message = str(error)
    lowered = message.lower()
    if "permission denied" in lowered:
        return {
            "error": "docker_permission_denied",
            "message": f"Docker Socket Proxy denied {operation}",
            "hint": "Check socket-proxy permissions in docker-compose.yml",
            "proxy_mode": settings.use_socket_proxy,
        }
    if "connection refused" in lowered:
        return {
            "error": "docker_connection_refused",
            "message": "Cannot connect to Docker Socket Proxy",
            "hint": "Ensure docker-socket-proxy service is running",
            "proxy_mode": settings.use_socket_proxy,
        }
    if "no such container" in lowered:
        return {
            "error": "container_not_found",
            "message": f"Container not found for {operation}",
            "hint": "Verify container name and ensure it's running",
        }
    return {
        "error": "docker_error",
        "message": f"{operation} failed: {message}",
        "proxy_mode": settings.use_socket_proxy,
    }


def docker_ps(settings: Settings, all_containers: bool = False) -> List[Dict[str, Any]]:
    try:
        fmt = "{{.ID}}|{{.Names}}|{{.Image}}|{{.Status}}|{{.State}}"
        args = ["docker", "ps"] + (["-a"] if all_containers else []) + ["--format", fmt]
        process = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=10,
            env=_build_docker_env(settings),
        )
        if process.returncode != 0:
            raise RuntimeError(f"Docker ps failed: {process.stderr}")

        containers: List[Dict[str, Any]] = []
        for line in (process.stdout or "").splitlines():
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) >= 5:
                cid, name, image, status, state = parts[:5]
                containers.append(
                    {
                        "id": cid,
                        "name": name,
                        "image": image,
                        "status": status,
                        "running": state.lower() == "running",
                    }
                )
        return containers
    except Exception as exc:  # pragma: no cover - safety net
        raise RuntimeError(json.dumps(handle_docker_error(settings, "docker ps", exc)))


def docker_volumes(
    settings: Settings, compute_size: bool = False
) -> List[Dict[str, Any]]:
    try:
        args = ["docker", "volume", "ls", "--format", "{{.Name}}|{{.Mountpoint}}"]
        process = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=10,
            env=_build_docker_env(settings),
        )
        if process.returncode != 0:
            raise RuntimeError(f"Docker volume ls failed: {process.stderr}")

        volumes: List[Dict[str, Any]] = []
        for line in (process.stdout or "").splitlines():
            if not line.strip():
                continue
            parts = line.split("|")
            if len(parts) >= 2:
                name, mountpoint = parts[:2]
                info: Dict[str, Any] = {"name": name, "mountpoint": mountpoint}
                if compute_size and mountpoint:
                    size_process = subprocess.run(
                        ["du", "-sb", mountpoint], capture_output=True, text=True
                    )
                    try:
                        info["size_bytes"] = int(
                            (size_process.stdout or "0").split()[0]
                        )
                    except Exception:
                        info["size_bytes"] = None
                volumes.append(info)
        return volumes
    except Exception as exc:  # pragma: no cover - safety net
        raise RuntimeError(
            json.dumps(handle_docker_error(settings, "docker volume ls", exc))
        )
