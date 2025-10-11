#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Legacy route implementation for the Borgmatic API."""

import base64
import json
import os
import re
import socket
import subprocess
import threading
import time
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml
from flask import Blueprint, Response, request, stream_with_context

from ..auth import AuthError
from ..buffers import StreamBuffer
from ..docker import (
    check_docker_available,
    handle_docker_error,
    validate_docker_exec,
    docker_ps,
    docker_volumes,
)
from ..services import Services

bp = Blueprint("borgmatic", __name__)

SERVICES: Optional[Services] = None
BORG_CONFIG_DIR = ""
BORG_BASE_DIR = ""
BORG_SSH_DIR = ""
AIO_MASTER = ""
AIO_DAILY = ""
AIO_HEALTH = ""
REQUIRED_AIO_ARCHIVE_FORMAT = "{now:%Y%m%d_%H%M%S}-nextcloud-aio"
USE_SOCKET_PROXY = False
ALLOWED_EXEC_CONTAINERS: Dict[str, Dict[str, Any]] = {}
DANGEROUS_COMMANDS: List[str] = []
APP_SSE_HEARTBEAT_SEC = 15
SSE_BASE_URL = ""
READY_WEBHOOK_URL = ""
READY_HOOKS: set[str] = set()
START_TIME = time.time()


def _services() -> Services:
    if SERVICES is None:  # pragma: no cover - defensive
        raise RuntimeError("Services not initialised")
    return SERVICES


def _settings():
    return _services().settings


def _auth():
    return _services().auth


def _buffers():
    return _services().buffers


def _rate_limiter():
    return _services().rate_limiter


def _metrics():
    return _services().metrics


@bp.before_app_request
def _track_requests():
    if request.blueprint == bp.name and SERVICES is not None:
        _metrics().inc("requests_total")


# =============================================================================
# DOCKER SOCKET PROXY - Helpers & Security
# =============================================================================
def _check_docker_available() -> tuple[bool, str]:
    return check_docker_available(_settings())


def _validate_docker_exec(container: str, command: List[str]) -> None:
    """
    Valide qu'une commande docker exec est autorisée selon la whitelist.
    Lève PermissionError si la commande n'est pas autorisée.

    Args:
        container: Nom du conteneur
        command: Liste des arguments de la commande (ex: ["/daily-backup.sh"])

    Raises:
        PermissionError: Si le conteneur ou la commande n'est pas autorisé
    """
    validate_docker_exec(_settings(), container, command)


def _handle_docker_error(operation: str, error: Exception) -> Dict[str, Any]:
    return handle_docker_error(_settings(), operation, error)


# =============================================================================
# HELPERS: JSON / AUTH / CONFIG RESOLUTION
# =============================================================================
def _json_ok(data: Dict[str, Any]):
    data = {"ok": True, **data}
    if SERVICES is not None:
        _metrics().inc("responses_ok")
    return (
        json.dumps(data, ensure_ascii=False),
        200,
        {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
        },
    )


def _json_error(status: int, error: str, message: str, **extra):
    payload = {"ok": False, "error": error, "message": message}
    payload.update(extra)
    if SERVICES is not None:
        _metrics().inc(f"responses_error_{status}")
    return (
        json.dumps(payload, ensure_ascii=False),
        status,
        {
            "Content-Type": "application/json; charset=utf-8",
            "Cache-Control": "no-store",
        },
    )


def _require_auth(read_only=False):
    try:
        _auth().verify(request, read_only=read_only)
    except AuthError as exc:
        raise PermissionError(str(exc))


def _enforce_distinct_pass(borg_pass: Optional[str], ssh_pass: Optional[str]):
    if borg_pass and ssh_pass and borg_pass == ssh_pass:
        raise ValueError(
            "borg_passphrase and ssh_passphrase must be distinct when both are provided"
        )


# --- Résolution unifiée des configs (.yaml/.yml) + garde-fou label ---
SAFE_LABEL_RE = re.compile(r"^[a-zA-Z0-9._-]+$")


def _resolve_config(label: str) -> Path:
    """
    Trouve le fichier de config borgmatic pour `label` dans BORGMATIC_CONFIG_DIR,
    en testant .yaml puis .yml. Valide le label. Lève FileNotFoundError sinon.
    """
    if not SAFE_LABEL_RE.match(label):
        raise ValueError("Invalid label format")
    base = Path(BORG_CONFIG_DIR)
    for ext in (".yaml", ".yml"):
        p = base / f"{label}{ext}"
        if p.exists():
            return p
    raise FileNotFoundError(f"Config {label} not found")


# =============================================================================
# RATE LIMIT (simple)
# =============================================================================
def rate_limited(max_calls=10, per_seconds=60):
    def deco(f):
        @wraps(f)
        def wrapper(*a, **kw):
            limiter = _rate_limiter()
            if not limiter.allow(
                request,
                max_calls=max_calls,
                per_seconds=per_seconds,
            ):
                _metrics().inc("rate_limit_blocked")
                return _json_error(429, "rate_limited", "too many requests")
            return f(*a, **kw)

        return wrapper

    return deco


# =============================================================================
# LOG BUFFERS (thread-safe) + GC
# =============================================================================
def _buf_get(job_id: str) -> StreamBuffer:
    return _buffers().buffer_for(job_id)


# =============================================================================
# VALIDATION ARGUMENTS BORGMATIC
# =============================================================================
ALLOWED_SUB = {
    "create",
    "check",
    "info",
    "repo-list",
    "extract",
    "mount",
    "umount",
    "prune",
    "compact",
    "break-lock",
    "key",
    "config",
}
ALLOWED_FLAGS = {
    "--config",
    "-c",
    "--verbosity",
    "--stats",
    "--progress",
    "--dry-run",
    "--last",
    "--json",
    "--json-lines",
    "--archive",
    "--match-archives",
    "--options",
    "--repair",
    "--successful",
}


def _validate_borgmatic_args(args: List[str]):
    assert args and args[0] == "borgmatic", "bad executable"
    # Déterminer subcommand (après --config si présent)
    if len(args) < 2:
        raise AssertionError("missing subcommand")
    if args[1] in ("--config", "-c"):
        if len(args) < 4:
            raise AssertionError("missing subcommand")
        sub = args[3]  # borgmatic --config <file> SUB ...
    else:
        sub = args[1]
    if sub not in ALLOWED_SUB:
        raise PermissionError(f"subcommand not allowed: {sub}")

    # --config doit résider dans BORGMATIC_CONFIG_DIR
    for i, a in enumerate(args):
        if a in ("--config", "-c") and i + 1 < len(args):
            p = Path(args[i + 1]).resolve()
            root = Path(BORG_CONFIG_DIR).resolve()
            if root not in p.parents and p.parent != root and p != root:
                raise PermissionError("config path outside BORGMATIC_CONFIG_DIR")

    # Flags autorisés
    for a in args:
        if a.startswith("--") or a.startswith("-"):
            if a not in ALLOWED_FLAGS and a not in ("--config", "-c"):
                raise PermissionError(f"flag not allowed: {a}")


# =============================================================================
# EXECUTION BORGMATIC (async)
# =============================================================================
def _run_borgmatic(args: List[str], env: Dict[str, str], job_id: str):
    _validate_borgmatic_args(args)
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, **env},
        text=True,
        bufsize=1,
        universal_newlines=True,
    )
    buf = _buf_get(job_id)

    def reader(stream, kind: str):
        for line in iter(stream.readline, ""):
            buf.push(kind, line.rstrip("\n"))
        buf.push("done", f"{kind}.done")

    threading.Thread(target=reader, args=(proc.stdout, "stdout"), daemon=True).start()
    threading.Thread(target=reader, args=(proc.stderr, "stderr"), daemon=True).start()
    return proc


# =============================================================================
# 1) SYSTEM & EVENTS
# =============================================================================
@bp.route("/")
def index():
    return _json_ok(
        {
            "message": "Borgmatic API is alive",
            "since": START_TIME,
            "uptime": time.time() - START_TIME,
            "docker_mode": "Socket Proxy" if USE_SOCKET_PROXY else "Direct Socket",
            "security": {
                "exec_whitelist_enabled": True,
                "allowed_containers": list(ALLOWED_EXEC_CONTAINERS.keys()),
            },
        }
    )


@bp.route("/health")
def health():
    try:
        _require_auth(read_only=True)
        checks = {
            "api": "ok",
            "docker": "unknown",
            "borgmatic": "unknown",
            "ssh": "unknown",
        }

        # Docker (via Socket Proxy ou direct)
        docker_ok, docker_msg = _check_docker_available()
        checks["docker"] = "ok" if docker_ok else "error"
        checks["docker_details"] = docker_msg

        # borgmatic
        try:
            p = subprocess.run(
                ["borgmatic", "--version"], capture_output=True, text=True, timeout=3
            )
            checks["borgmatic"] = "ok" if p.returncode == 0 else "error"
        except Exception:
            checks["borgmatic"] = "error"

        # ssh dir
        checks["ssh"] = "ok" if Path(BORG_SSH_DIR).exists() else "error"

        overall = (
            "healthy"
            if all(v == "ok" for k, v in checks.items() if not k.endswith("_details"))
            else "degraded"
        )
        return _json_ok({"status": overall, "checks": checks})
    except Exception as e:
        return _json_error(500, "health_check_failed", str(e))


@bp.route("/status")
def status():
    try:
        _require_auth(read_only=True)
        docker_ok, docker_msg = _check_docker_available()
        return _json_ok(
            {
                "sse_base": SSE_BASE_URL or request.host_url.rstrip("/"),
                "configs_dir": BORG_CONFIG_DIR,
                "ssh_dir": BORG_SSH_DIR,
                "jobs_count": len(_buffers().active_jobs()),
                "now": time.time(),
                "docker_mode": "Socket Proxy" if USE_SOCKET_PROXY else "Direct Socket",
                "docker_status": docker_msg,
            }
        )
    except Exception as e:
        return _json_error(401, "unauthorized", str(e))


@bp.route("/metrics")
def metrics():
    try:
        _require_auth(read_only=True)
        snapshot = _metrics().snapshot()
        data = {
            "uptime_seconds": time.time() - START_TIME,
            "requests_total": snapshot.get("requests_total", 0),
            "rate_limit_blocked": snapshot.get("rate_limit_blocked", 0),
            "responses_ok": snapshot.get("responses_ok", 0),
        }
        for key, value in snapshot.items():
            if key.startswith("responses_error_"):
                data[key] = value
        return _json_ok({"metrics": data})
    except Exception as e:
        return _json_error(401, "unauthorized", str(e))


@bp.route("/ready")
def ready():
    try:
        _require_auth(read_only=True)
        return _json_ok({"ready": True, "sse_heartbeat": APP_SSE_HEARTBEAT_SEC})
    except Exception as e:
        return _json_error(401, "unauthorized", str(e))


@bp.route("/ready/webhook/register", methods=["POST"])
def ready_register():
    try:
        _require_auth(read_only=True)
        body = request.get_json(force=True, silent=True) or {}
        url = (body.get("url") or READY_WEBHOOK_URL or "").strip()
        if not url:
            return _json_error(400, "bad_request", "Missing url")
        READY_HOOKS.add(url)
        return _json_ok({"registered": True, "hooks": list(READY_HOOKS)})
    except Exception as e:
        return _json_error(401, "unauthorized", str(e))


@bp.route("/ready/webhook/trigger", methods=["POST"])
def ready_trigger():
    try:
        _require_auth(read_only=True)
        return _json_ok({"triggered": list(READY_HOOKS)})
    except Exception as e:
        return _json_error(401, "unauthorized", str(e))


@bp.route("/events/stream")
def events_stream():
    """SSE: kinds=stdout,stderr,status ; job_id=... ; heartbeat=APP_SSE_HEARTBEAT_SEC ; idle close=900s"""
    try:
        _require_auth(read_only=True)
        kinds = [
            k.strip()
            for k in request.args.get("kinds", "stdout,stderr,status").split(",")
        ]
        job_id = request.args.get("job_id")
        IDLE_CLOSE_SEC = 900

        def stream():
            last_beat = last_any = time.time()
            cursor = 0
            while True:
                had_item = False
                if job_id:
                    buf = _buffers().get(job_id)
                    if buf:
                        items = buf.drain(cursor=cursor, max_items=200)
                        if items:
                            cursor = items[-1]["id"] + 1
                            had_item = True
                            for it in items:
                                if it["kind"] in kinds:
                                    yield f"event: {it['kind']}\ndata: {json.dumps(it, ensure_ascii=False)}\n\n"
                now = time.time()
                if now - last_beat >= APP_SSE_HEARTBEAT_SEC:
                    yield f"event: heartbeat\ndata: {json.dumps({'t': now})}\n\n"
                    last_beat = now
                if had_item:
                    last_any = now
                if now - last_any > IDLE_CLOSE_SEC:
                    break
                time.sleep(0.2)

        return Response(stream_with_context(stream()), mimetype="text/event-stream")
    except Exception as e:
        return _json_error(401, "unauthorized", str(e))


@bp.route("/events/poll/<job_id>")
def events_poll(job_id: str):
    try:
        _require_auth(read_only=True)
        cursor = int(request.args.get("cursor", 0))
        buf = _buffers().get(job_id)
        if not buf:
            return _json_ok({"items": [], "cursor": cursor})
        items = buf.drain(cursor=cursor, max_items=200)
        new_cursor = cursor
        if items:
            new_cursor = items[-1]["id"] + 1
        return _json_ok({"items": items, "cursor": new_cursor})
    except Exception as e:
        return _json_error(401, "unauthorized", str(e))


# =============================================================================
# 2) DOCKER: CONTAINERS & VOLUMES (Compatible Socket Proxy)
# =============================================================================
def _docker_ps(all_containers=False) -> List[Dict[str, Any]]:
    try:
        return docker_ps(_settings(), all_containers=all_containers)
    except Exception as e:
        error_details = _handle_docker_error("docker ps", e)
        raise RuntimeError(json.dumps(error_details))


def _docker_volumes(compute_size=False) -> List[Dict[str, Any]]:
    try:
        return docker_volumes(_settings(), compute_size=compute_size)
    except Exception as e:
        error_details = _handle_docker_error("docker volume ls", e)
        raise RuntimeError(json.dumps(error_details))


@bp.route("/containers")
def containers_state():
    try:
        _require_auth(read_only=True)
        scope = request.args.get("scope", "aio")
        all_flag = request.args.get("all", "false").lower() == "true"

        try:
            containers = _docker_ps(all_containers=all_flag)
        except RuntimeError as e:
            # Tenter de parser les détails d'erreur
            try:
                error_details = json.loads(str(e))
                return _json_error(503, **error_details)
            except Exception:
                return _json_error(503, "docker_error", str(e))

        if scope == "aio":
            containers = [
                c for c in containers if c["name"].startswith("nextcloud-aio-")
            ]

        return _json_ok({"containers": containers})
    except Exception as e:
        return _json_error(400, "docker_error", str(e))


@bp.route("/volumes/status")
def volumes_status():
    try:
        _require_auth(read_only=True)
        scope = request.args.get("scope", "aio")
        compute_size = request.args.get("compute_size", "false").lower() == "true"

        try:
            vols = _docker_volumes(compute_size=compute_size)
        except RuntimeError as e:
            try:
                error_details = json.loads(str(e))
                return _json_error(503, **error_details)
            except Exception:
                return _json_error(503, "docker_error", str(e))

        if scope == "aio":
            vols = [v for v in vols if v["name"].startswith("nextcloud_aio_")]

        return _json_ok({"volumes": vols})
    except Exception as e:
        return _json_error(400, "docker_error", str(e))


# =============================================================================
# 3) NEXTCLOUD AIO (docker exec sans shell - Compatible Socket Proxy)
# =============================================================================
@bp.route("/nextcloud/containers/state")
def aio_containers_state():
    try:
        _require_auth(read_only=True)
        try:
            containers = _docker_ps(all_containers=True)
        except RuntimeError as e:
            try:
                error_details = json.loads(str(e))
                return _json_error(503, **error_details)
            except Exception:
                return _json_error(503, "docker_error", str(e))

        containers = [c for c in containers if c["name"].startswith("nextcloud-aio-")]
        return _json_ok({"containers": containers})
    except Exception as e:
        return _json_error(400, "docker_error", str(e))


@bp.route("/nextcloud/running")
def aio_running():
    try:
        _require_auth(read_only=True)
        try:
            containers = _docker_ps(all_containers=False)
        except RuntimeError as e:
            try:
                error_details = json.loads(str(e))
                return _json_error(503, **error_details)
            except Exception:
                return _json_error(503, "docker_error", str(e))

        running = any(
            c["name"].startswith("nextcloud-aio-") and c["running"] for c in containers
        )
        return _json_ok({"running": running})
    except Exception as e:
        return _json_error(400, "docker_error", str(e))


@bp.route("/nextcloud/official-daily-backup", methods=["POST"])
@rate_limited(5, 60)
def aio_official_daily_backup():
    """Exécute le script officiel daily-backup.sh via docker exec."""
    try:
        _require_auth(read_only=False)
        body = request.get_json(force=True, silent=True) or {}
        env_args = []
        for k in (
            "STOP_CONTAINERS",
            "BACKUP_RESTORE_PASSWORD",
            "AUTOMATIC_UPDATES",
            "START_CONTAINERS",
        ):
            v = body.get(k)
            if v is not None:
                env_args += ["--env", f"{k}={v}"]

        # VALIDATION SÉCURITÉ : Vérifier que la commande est autorisée
        try:
            _validate_docker_exec(AIO_MASTER, [AIO_DAILY])
        except PermissionError as pe:
            return _json_error(403, "exec_forbidden", str(pe))

        args = ["docker", "exec"] + env_args + [AIO_MASTER, AIO_DAILY]

        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=3600)
            return _json_ok(
                {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
            )
        except subprocess.TimeoutExpired:
            return _json_error(408, "timeout", "daily-backup.sh timeout after 1h")
        except Exception as e:
            error_details = _handle_docker_error("docker exec daily-backup", e)
            return _json_error(503, **error_details)
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


@bp.route("/nextcloud/check-backup", methods=["POST"])
@rate_limited(10, 60)
def aio_check_backup():
    try:
        _require_auth(read_only=False)

        # VALIDATION SÉCURITÉ
        try:
            _validate_docker_exec(AIO_MASTER, [AIO_HEALTH])
        except PermissionError as pe:
            return _json_error(403, "exec_forbidden", str(pe))

        args = ["docker", "exec", AIO_MASTER, AIO_HEALTH]

        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=600)
            return _json_ok(
                {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
            )
        except Exception as e:
            error_details = _handle_docker_error("docker exec healthcheck", e)
            return _json_error(503, **error_details)
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


@bp.route("/nextcloud/start-and-update", methods=["POST"])
@rate_limited(5, 60)
def aio_start_and_update():
    try:
        _require_auth(read_only=False)
        body = request.get_json(force=True, silent=True) or {}
        env_args = ["--env", f"AUTOMATIC_UPDATES={body.get('AUTOMATIC_UPDATES','1')}"]

        # VALIDATION SÉCURITÉ
        try:
            _validate_docker_exec(AIO_MASTER, [AIO_DAILY])
        except PermissionError as pe:
            return _json_error(403, "exec_forbidden", str(pe))

        args = ["docker", "exec"] + env_args + [AIO_MASTER, AIO_DAILY]

        try:
            p = subprocess.run(args, capture_output=True, text=True, timeout=3600)
            return _json_ok(
                {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
            )
        except Exception as e:
            error_details = _handle_docker_error("docker exec start-and-update", e)
            return _json_error(503, **error_details)
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


@bp.route("/nextcloud/serverinfo", methods=["POST"])
@rate_limited(30, 60)
def aio_serverinfo():
    try:
        _require_auth(read_only=False)
        body = request.get_json(force=True, silent=True) or {}
        user = body.get("user")
        app_password = body.get("app_password")
        base_url = (body.get("base_url") or "http://nextcloud-aio-apache:11000").rstrip(
            "/"
        )
        if not (user and app_password):
            return _json_error(400, "bad_request", "user & app_password required")
        import urllib.request

        req = urllib.request.Request(
            f"{base_url}/ocs/v2.php/apps/serverinfo/api/v1/info?format=json"
        )
        auth_header = base64.b64encode(f"{user}:{app_password}".encode("utf-8")).decode(
            "ascii"
        )
        req.add_header("Authorization", "Basic " + auth_header)
        req.add_header("OCS-APIREQUEST", "true")
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = resp.read().decode("utf-8")
        return _json_ok({"response": json.loads(data)})
    except Exception as e:
        return _json_error(400, "proxy_error", str(e))


# =============================================================================
# 4) CONFIG BORG
# =============================================================================
@bp.route("/configs")
def configs_list():
    try:
        _require_auth(read_only=True)
        files = sorted([p.name for p in Path(BORG_CONFIG_DIR).glob("*.y*ml")])
        return _json_ok({"configs": files})
    except Exception as e:
        return _json_error(401, "unauthorized", str(e))


@bp.route("/configs/<label>")
def config_get(label: str):
    try:
        _require_auth(read_only=True)
        fmt = request.args.get("format", "json")
        try:
            path = _resolve_config(label)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))
        content = path.read_text(encoding="utf-8")
        if fmt == "yaml":
            return (content, 200, {"Content-Type": "text/yaml; charset=utf-8"})
        return _json_ok({"config": yaml.safe_load(content)})
    except ValueError as ve:
        return _json_error(400, "bad_request", str(ve))
    except Exception as e:
        return _json_error(400, "read_error", str(e))


@bp.route("/config/validate-all")
def config_validate_all():
    try:
        _require_auth(read_only=True)
        files = [str(p) for p in Path(BORG_CONFIG_DIR).glob("*.y*ml")]
        out = []
        for f in files:
            args = ["borgmatic", "--config", f, "config", "validate"]
            _validate_borgmatic_args(["borgmatic", "--config", f, "config", "validate"])
            p = subprocess.run(args, capture_output=True, text=True, timeout=60)
            out.append(
                {
                    "file": f,
                    "returncode": p.returncode,
                    "stdout": p.stdout,
                    "stderr": p.stderr,
                }
            )
        return _json_ok({"results": out})
    except Exception as e:
        return _json_error(400, "validate_error", str(e))


@bp.route("/config/validate/<label>", methods=["POST"])
def config_validate_one(label: str):
    try:
        _require_auth(read_only=True)
        body = request.get_json(force=True, silent=True) or {}
        process_timeout = int(body.get("process_timeout", 60))
        try:
            path = _resolve_config(label)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))
        args = ["borgmatic", "--config", str(path), "config", "validate"]
        _validate_borgmatic_args(args)
        p = subprocess.run(
            args, capture_output=True, text=True, timeout=process_timeout
        )
        return _json_ok(
            {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
        )
    except subprocess.TimeoutExpired as te:
        return _json_error(
            408, "timeout", f"config validate timed out after {te.timeout}s"
        )
    except ValueError as ve:
        return _json_error(400, "bad_request", str(ve))
    except Exception as e:
        return _json_error(400, "validate_error", str(e))


@bp.route("/config/<label>/redacted")
def config_redacted(label: str):
    try:
        _require_auth(read_only=True)
        try:
            path = _resolve_config(label)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))
        data = yaml.safe_load(path.read_text(encoding="utf-8"))

        def _rec(o):
            if isinstance(o, dict):
                return {
                    k: (
                        "***"
                        if re.search(r"passphrase|password|token|key", k, re.I)
                        else _rec(v)
                    )
                    for k, v in o.items()
                }
            if isinstance(o, list):
                return [_rec(x) for x in o]
            return o

        return _json_ok({"config": _rec(data)})
    except ValueError as ve:
        return _json_error(400, "bad_request", str(ve))
    except Exception as e:
        return _json_error(400, "read_error", str(e))


@bp.route("/configs/<label>/sources")
def config_sources(label: str):
    try:
        _require_auth(read_only=True)
        try:
            path = _resolve_config(label)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return _json_ok({"sources": data.get("sources") or []})
    except ValueError as ve:
        return _json_error(400, "bad_request", str(ve))
    except Exception as e:
        return _json_error(400, "read_error", str(e))


@bp.route("/config/aio-structure/<label>")
def config_check_aio_structure(label: str):
    try:
        _require_auth(read_only=True)
        try:
            path = _resolve_config(label)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        fmt = data.get("archive_name_format")
        ok = fmt == REQUIRED_AIO_ARCHIVE_FORMAT
        return _json_ok(
            {
                "archive_name_format": fmt,
                "required": REQUIRED_AIO_ARCHIVE_FORMAT,
                "ok": ok,
            }
        )
    except ValueError as ve:
        return _json_error(400, "bad_request", str(ve))
    except Exception as e:
        return _json_error(400, "check_error", str(e))


@bp.route("/config/aio-structure-all")
def config_check_aio_structure_all():
    try:
        _require_auth(read_only=True)
        out = []
        for pth in Path(BORG_CONFIG_DIR).glob("*.y*ml"):
            data = yaml.safe_load(pth.read_text(encoding="utf-8"))
            fmt = data.get("archive_name_format")
            ok = fmt == REQUIRED_AIO_ARCHIVE_FORMAT
            out.append({"file": pth.name, "ok": ok, "archive_name_format": fmt})
        return _json_ok({"results": out})
    except Exception as e:
        return _json_error(400, "check_error", str(e))


# =============================================================================
# 5) REPOSITORIES
# =============================================================================
@bp.route("/repositories/<label>/info")
def repo_info(label: str):
    try:
        _require_auth(read_only=True)
        try:
            cfg = _resolve_config(label)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))
        args = ["borgmatic", "--config", str(cfg), "info"]
        _validate_borgmatic_args(args)
        p = subprocess.run(args, capture_output=True, text=True, timeout=90)
        return _json_ok(
            {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
        )
    except ValueError as ve:
        return _json_error(400, "bad_request", str(ve))
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


@bp.route("/repositories/<label>/latest-stats")
def repo_latest_stats(label: str):
    try:
        _require_auth(read_only=True)
        try:
            cfg = _resolve_config(label)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))
        args = ["borgmatic", "--config", str(cfg), "info", "--json", "--last", "1"]
        _validate_borgmatic_args(args)
        p = subprocess.run(args, capture_output=True, text=True, timeout=90)
        try:
            data = json.loads(p.stdout or "{}")
        except Exception:
            data = {"raw": p.stdout}
        return _json_ok({"returncode": p.returncode, "data": data, "stderr": p.stderr})
    except ValueError as ve:
        return _json_error(400, "bad_request", str(ve))
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


@bp.route("/repositories/<label>/check", methods=["POST"])
@rate_limited(10, 60)
def repo_check(label: str):
    try:
        _require_auth(read_only=False)
        body = request.get_json(force=True, silent=True) or {}
        verbosity = str(body.get("verbosity", 1))
        repair = bool(body.get("repair", False))
        borg_pass = body.get("borg_passphrase")
        ssh_pass = body.get("ssh_passphrase")

        _enforce_distinct_pass(borg_pass, ssh_pass)

        try:
            cfg = _resolve_config(label)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))

        env = {}
        if borg_pass:
            env["BORG_PASSPHRASE"] = borg_pass
        if ssh_pass:
            env["SSH_ASKPASS"] = "echo"
            env["SSH_PASSPHRASE"] = ssh_pass

        args = ["borgmatic", "--config", str(cfg), "check", "--verbosity", verbosity]
        if repair:
            args += ["--repair"]
        _validate_borgmatic_args(args)

        job_id = f"check:{label}:{int(time.time())}"
        proc = _run_borgmatic(args, env, job_id)

        sse_base = SSE_BASE_URL or request.host_url.rstrip("/")
        sse_url = f"{sse_base}/events/stream?kinds=stdout,stderr,status&job_id={job_id}"

        return _json_ok({"job_id": job_id, "pid": proc.pid, "sse": sse_url})
    except ValueError as ve:
        return _json_error(400, "invalid_secrets", str(ve))
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


@bp.route("/repositories/<label>/archives/list", methods=["POST"])
def repo_archives_list(label: str):
    try:
        _require_auth(read_only=True)
        body = request.get_json(force=True, silent=True) or {}
        try:
            cfg = _resolve_config(label)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))
        borg_passphrase = body.get("borg_passphrase")
        ssh_passphrase = body.get("ssh_passphrase")
        _enforce_distinct_pass(borg_passphrase, ssh_passphrase)
        env = {}
        if borg_passphrase:
            env["BORG_PASSPHRASE"] = borg_passphrase
        if ssh_passphrase:
            env["SSH_ASKPASS"] = "echo"
            env["SSH_PASSPHRASE"] = ssh_passphrase
        args = ["borgmatic", "--config", str(cfg), "info", "--json"]
        _validate_borgmatic_args(args)
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            env=env,
            timeout=int(body.get("process_timeout", 60)),
        )
        try:
            data = json.loads(p.stdout or "{}")
        except Exception:
            data = {"raw": p.stdout}
        return _json_ok({"returncode": p.returncode, "data": data, "stderr": p.stderr})
    except ValueError as ve:
        return _json_error(400, "invalid_secrets", str(ve))
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


@bp.route("/repositories/<label>/archives/tree", methods=["POST"])
def repo_archives_tree(label: str):
    try:
        _require_auth(read_only=True)
        body = request.get_json(force=True, silent=True) or {}
        try:
            cfg = _resolve_config(label)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))
        archive = body.get("archive", "latest")
        borg_passphrase = body.get("borg_passphrase")
        ssh_passphrase = body.get("ssh_passphrase")
        _enforce_distinct_pass(borg_passphrase, ssh_passphrase)
        env = {}
        if borg_passphrase:
            env["BORG_PASSPHRASE"] = borg_passphrase
        if ssh_passphrase:
            env["SSH_ASKPASS"] = "echo"
            env["SSH_PASSPHRASE"] = ssh_passphrase
        args = [
            "borgmatic",
            "--config",
            str(cfg),
            "info",
            "--json",
            "--archive",
            str(archive),
        ]
        _validate_borgmatic_args(args)
        p = subprocess.run(args, capture_output=True, text=True, env=env, timeout=90)
        try:
            data = json.loads(p.stdout or "{}")
        except Exception:
            data = {"raw": p.stdout}
        return _json_ok({"returncode": p.returncode, "data": data, "stderr": p.stderr})
    except ValueError as ve:
        return _json_error(400, "invalid_secrets", str(ve))
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


@bp.route("/repositories/<label>/passphrase/change", methods=["POST"])
@rate_limited(3, 300)
def repo_passphrase_change(label: str):
    """borgmatic key change-passphrase"""
    try:
        _require_auth(read_only=False)
        body = request.get_json(force=True, silent=True) or {}
        borg_passphrase = body.get("borg_passphrase")
        new_borg_passphrase = body.get("new_borg_passphrase")
        ssh_passphrase = body.get("ssh_passphrase")
        if not borg_passphrase or not new_borg_passphrase:
            return _json_error(
                400, "bad_request", "borg_passphrase & new_borg_passphrase required"
            )
        _enforce_distinct_pass(new_borg_passphrase, ssh_passphrase)
        try:
            cfg = _resolve_config(label)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))

        env = {
            "BORG_PASSPHRASE": borg_passphrase,
            "BORG_NEW_PASSPHRASE": new_borg_passphrase,
        }
        if ssh_passphrase:
            env["SSH_ASKPASS"] = "echo"
            env["SSH_PASSPHRASE"] = ssh_passphrase

        args = ["borgmatic", "--config", str(cfg), "key", "change-passphrase"]
        _validate_borgmatic_args(args)
        p = subprocess.run(args, capture_output=True, text=True, env=env, timeout=180)
        return _json_ok(
            {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
        )
    except ValueError as ve:
        return _json_error(400, "invalid_secrets", str(ve))
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


# =============================================================================
# 6) ARCHIVES (create / dry-run / extract / mount / umount)
# =============================================================================
@bp.route("/create-backup", methods=["POST"])
@rate_limited(5, 60)
def archive_create():
    """Crée une archive via `borgmatic create`. Async; `process_timeout` ignoré (documenté)."""
    try:
        _require_auth(read_only=False)
        body = request.get_json(force=True, silent=True) or {}
        repository = body.get("repository")
        borg_passphrase = body.get("borg_passphrase")
        ssh_passphrase = body.get("ssh_passphrase")
        stats = bool(body.get("stats", True))
        progress = bool(body.get("progress", True))
        verbosity = str(body.get("verbosity", 1))

        _enforce_distinct_pass(borg_passphrase, ssh_passphrase)
        if not repository:
            return _json_error(400, "bad_request", "repository required")

        try:
            cfg_path = _resolve_config(repository)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))

        env = {}
        if borg_passphrase:
            env["BORG_PASSPHRASE"] = borg_passphrase
        if ssh_passphrase:
            env["SSH_ASKPASS"] = "echo"
            env["SSH_ASKPASS_REQUIRE"] = "force"
            env["SSH_PASSPHRASE"] = ssh_passphrase

        args = [
            "borgmatic",
            "--config",
            str(cfg_path),
            "create",
            "--verbosity",
            verbosity,
        ]
        if stats:
            args += ["--stats"]
        if progress:
            args += ["--progress"]
        _validate_borgmatic_args(args)

        job_id = f"create:{int(time.time())}"
        proc = _run_borgmatic(args, env, job_id)

        sse_base = SSE_BASE_URL or request.host_url.rstrip("/")
        sse_url = f"{sse_base}/events/stream?kinds=stdout,stderr,status&job_id={job_id}"
        return _json_ok({"job_id": job_id, "pid": proc.pid, "sse": sse_url})

    except ValueError as ve:
        return _json_error(400, "invalid_secrets", str(ve))
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


@bp.route("/create-backup/dry-run", methods=["POST"])
@rate_limited(10, 60)
def archive_create_dry_run():
    """Dry-run synchrone (avec timeout)."""
    try:
        _require_auth(read_only=False)
        body = request.get_json(force=True, silent=True) or {}
        repository = body.get("repository")
        borg_passphrase = body.get("borg_passphrase")
        ssh_passphrase = body.get("ssh_passphrase")
        verbosity = str(body.get("verbosity", 1))
        stats = bool(body.get("stats", False))
        progress = bool(body.get("progress", False))
        timeout_sec = int(body.get("process_timeout", 60))

        _enforce_distinct_pass(borg_passphrase, ssh_passphrase)
        if not repository:
            return _json_error(400, "bad_request", "repository required")

        try:
            cfg_path = _resolve_config(repository)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))

        env = {}
        if borg_passphrase:
            env["BORG_PASSPHRASE"] = borg_passphrase
        if ssh_passphrase:
            env["SSH_ASKPASS"] = "echo"
            env["SSH_PASSPHRASE"] = ssh_passphrase

        args = [
            "borgmatic",
            "--config",
            str(cfg_path),
            "create",
            "--verbosity",
            verbosity,
            "--dry-run",
        ]
        if stats:
            args += ["--stats"]
        if progress:
            args += ["--progress"]
        _validate_borgmatic_args(args)

        p = subprocess.run(
            args, capture_output=True, text=True, env=env, timeout=timeout_sec
        )
        return _json_ok(
            {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
        )
    except subprocess.TimeoutExpired as te:
        return _json_error(408, "timeout", f"dry-run timed out after {te.timeout}s")
    except ValueError as ve:
        return _json_error(400, "invalid_secrets", str(ve))
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


@bp.route("/archives/extract", methods=["POST"])
@rate_limited(20, 60)
def archive_extract():
    try:
        _require_auth(read_only=False)
        body = request.get_json(force=True, silent=True) or {}
        repo = body.get("repository")
        archive = body.get("archive")
        dest = body.get("destination", "/tmp/borg-extract")
        paths = body.get("paths") or []
        borg_pass = body.get("borg_passphrase")
        ssh_pass = body.get("ssh_passphrase")
        timeout_sec = int(body.get("process_timeout", 600))

        _enforce_distinct_pass(borg_pass, ssh_pass)
        if not (repo and archive):
            return _json_error(400, "bad_request", "repository & archive required")

        try:
            cfg_path = _resolve_config(repo)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))

        env = {}
        if borg_pass:
            env["BORG_PASSPHRASE"] = borg_pass
        if ssh_pass:
            env["SSH_ASKPASS"] = "echo"
            env["SSH_PASSPHRASE"] = ssh_pass

        Path(dest).mkdir(parents=True, exist_ok=True)

        args = [
            "borgmatic",
            "--config",
            str(cfg_path),
            "extract",
            "--archive",
            str(archive),
        ]
        for pth in paths:
            args.append(str(pth))
        _validate_borgmatic_args(args)

        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            env=env,
            timeout=timeout_sec,
            cwd=str(dest),
        )
        return _json_ok(
            {
                "returncode": p.returncode,
                "stdout": p.stdout,
                "stderr": p.stderr,
                "destination": dest,
            }
        )
    except subprocess.TimeoutExpired as te:
        return _json_error(408, "timeout", f"extract timed out after {te.timeout}s")
    except ValueError as ve:
        return _json_error(400, "invalid_secrets", str(ve))
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


@bp.route("/archives/mount", methods=["POST"])
@rate_limited(20, 60)
def archive_mount():
    try:
        _require_auth(read_only=False)
        body = request.get_json(force=True, silent=True) or {}
        repo, archive, mount_point = (
            body.get("repository"),
            body.get("archive"),
            body.get("mount_point"),
        )
        borg_pass, ssh_pass = body.get("borg_passphrase"), body.get("ssh_passphrase")
        timeout_sec = int(body.get("process_timeout", 600))

        _enforce_distinct_pass(borg_pass, ssh_pass)
        if not (repo and archive and mount_point):
            return _json_error(
                400, "bad_request", "repository, archive, mount_point required"
            )

        try:
            cfg_path = _resolve_config(repo)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))

        env = {}
        if borg_pass:
            env["BORG_PASSPHRASE"] = borg_pass
        if ssh_pass:
            env["SSH_ASKPASS"] = "echo"
            env["SSH_PASSPHRASE"] = ssh_pass

        Path(mount_point).mkdir(parents=True, exist_ok=True)

        args = [
            "borgmatic",
            "--config",
            str(cfg_path),
            "mount",
            "--archive",
            str(archive),
            "--mount-point",
            str(mount_point),
        ]
        if body.get("options"):
            args += ["--options", str(body["options"])]
        _validate_borgmatic_args(args)

        p = subprocess.run(
            args, capture_output=True, text=True, env=env, timeout=timeout_sec
        )
        return _json_ok(
            {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
        )
    except subprocess.TimeoutExpired as te:
        return _json_error(408, "timeout", f"mount timed out after {te.timeout}s")
    except ValueError as ve:
        return _json_error(400, "invalid_secrets", str(ve))
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


@bp.route("/archives/umount", methods=["POST"])
@rate_limited(20, 60)
def archive_umount():
    try:
        _require_auth(read_only=False)
        body = request.get_json(force=True, silent=True) or {}
        mount_point = body.get("mount_point")
        borg_pass = body.get("borg_passphrase")
        ssh_pass = body.get("ssh_passphrase")
        timeout_sec = int(body.get("process_timeout", 120))

        _enforce_distinct_pass(borg_pass, ssh_pass)
        if not mount_point:
            return _json_error(400, "bad_request", "mount_point required")

        env = {}
        if borg_pass:
            env["BORG_PASSPHRASE"] = borg_pass
        if ssh_pass:
            env["SSH_ASKPASS"] = "echo"
            env["SSH_PASSPHRASE"] = ssh_pass

        args = ["borgmatic", "umount", "--mount-point", str(mount_point)]
        _validate_borgmatic_args(args)

        p = subprocess.run(
            args, capture_output=True, text=True, env=env, timeout=timeout_sec
        )
        return _json_ok(
            {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
        )
    except subprocess.TimeoutExpired as te:
        return _json_error(408, "timeout", f"umount timed out after {te.timeout}s")
    except ValueError as ve:
        return _json_error(400, "invalid_secrets", str(ve))
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


# =============================================================================
# 7) LOCKS
# =============================================================================
@bp.route("/borgmatic-locks/quick-check/<label>")
def lock_quick_check(label: str):
    try:
        _require_auth(read_only=True)
        try:
            cfg = _resolve_config(label)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))
        args = ["borgmatic", "--config", str(cfg), "repo-list"]
        _validate_borgmatic_args(args)
        p = subprocess.run(args, capture_output=True, text=True, timeout=30)
        out = (p.stdout or "") + "\n" + (p.stderr or "")
        has_lock = ("lock.exclusive" in out.lower()) or ("lock.roster" in out.lower())
        lock_info = {"detection_method": "repo-list"} if has_lock else {}
        return _json_ok(
            {"locked": has_lock, "lock_info": lock_info, "returncode": p.returncode}
        )
    except Exception as e:
        return _json_error(400, "check_error", str(e))


@bp.route("/borgmatic-locks/status")
def locks_status():
    try:
        _require_auth(read_only=True)
        results = []
        for pth in Path(BORG_CONFIG_DIR).glob("*.y*ml"):
            args = ["borgmatic", "--config", str(pth), "repo-list"]
            _validate_borgmatic_args(args)
            p = subprocess.run(args, capture_output=True, text=True, timeout=30)
            out = (p.stdout or "") + "\n" + (p.stderr or "")
            results.append(
                {"file": pth.name, "locked": ("lock.exclusive" in out.lower())}
            )
        return _json_ok({"results": results})
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


@bp.route("/borgmatic-locks/active")
def locks_active():
    try:
        _require_auth(read_only=True)
        active = []
        for pth in Path(BORG_CONFIG_DIR).glob("*.y*ml"):
            args = ["borgmatic", "--config", str(pth), "repo-list"]
            _validate_borgmatic_args(args)
            p = subprocess.run(args, capture_output=True, text=True, timeout=30)
            out = (p.stdout or "") + "\n" + (p.stderr or "")
            if "lock.exclusive" in out.lower():
                active.append(pth.stem)
        return _json_ok({"active": active})
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


@bp.route("/borgmatic-locks/break/<label>", methods=["POST"])
@rate_limited(5, 300)
def locks_break(label: str):
    try:
        _require_auth(read_only=False)
        try:
            cfg = _resolve_config(label)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))
        args = ["borgmatic", "--config", str(cfg), "break-lock"]
        _validate_borgmatic_args(args)
        p = subprocess.run(args, capture_output=True, text=True, timeout=60)
        return _json_ok(
            {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
        )
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


@bp.route("/borgmatic-locks/emergency-break-all", methods=["POST"])
@rate_limited(3, 600)
def locks_emergency_break_all():
    try:
        _require_auth(read_only=False)
        out = []
        for pth in Path(BORG_CONFIG_DIR).glob("*.y*ml"):
            args = ["borgmatic", "--config", str(pth), "break-lock"]
            _validate_borgmatic_args(args)
            p = subprocess.run(args, capture_output=True, text=True, timeout=60)
            out.append({"file": pth.name, "rc": p.returncode, "stderr": p.stderr})

        # Redémarrer Nextcloud AIO (via docker exec)
        try:
            # VALIDATION SÉCURITÉ
            _validate_docker_exec(AIO_MASTER, [AIO_DAILY])

            restart_args = [
                "docker",
                "exec",
                "--env",
                "START_CONTAINERS=1",
                AIO_MASTER,
                AIO_DAILY,
            ]
            p = subprocess.run(
                restart_args, capture_output=True, text=True, timeout=600
            )
            restart_result = {
                "rc": p.returncode,
                "stdout": p.stdout,
                "stderr": p.stderr,
            }
        except PermissionError as pe:
            restart_result = {"error": f"exec_forbidden: {str(pe)}"}
        except Exception as e:
            error_details = _handle_docker_error("docker exec restart", e)
            restart_result = {"error": error_details}

        return _json_ok(
            {
                "locks_broken": out,
                "nextcloud_restart": restart_result,
                "timestamp": time.time(),
            }
        )
    except Exception as e:
        return _json_error(400, "exec_error", str(e))


# =============================================================================
# 8) EMERGENCY
# =============================================================================
@bp.route("/emergency/status")
def emergency_status():
    try:
        _require_auth(read_only=True)
        # process borgmatic ?
        p = subprocess.run(["pgrep", "-a", "borgmatic"], capture_output=True, text=True)
        active_processes = [line for line in (p.stdout or "").splitlines()]

        # mounts « borg »
        p = subprocess.run(["mount"], capture_output=True, text=True)
        active_mounts = [
            ln for ln in (p.stdout or "").splitlines() if "borg" in ln.lower()
        ]

        # containers AIO (avec gestion d'erreur Socket Proxy)
        try:
            containers = _docker_ps(all_containers=True)
            aio = [c for c in containers if c["name"].startswith("nextcloud-aio-")]
            running_count = sum(1 for c in aio if c["running"])
        except RuntimeError as e:
            try:
                error_details = json.loads(str(e))
                return _json_error(503, **error_details)
            except Exception:
                aio = []
                running_count = 0

        # locks actifs (heuristique)
        locks = []
        for pth in Path(BORG_CONFIG_DIR).glob("*.y*ml"):
            args = ["borgmatic", "--config", str(pth), "repo-list"]
            _validate_borgmatic_args(args)
            p = subprocess.run(args, capture_output=True, text=True, timeout=10)
            if "lock.exclusive" in ((p.stdout or "") + (p.stderr or "")).lower():
                locks.append(pth.stem)

        status = "normal"
        if len(active_processes) > 2 or len(active_mounts) > 3 or len(locks) > 0:
            status = "warning"
        if len(active_processes) > 5 or len(locks) > 2:
            status = "critical"

        return _json_ok(
            {
                "status": status,
                "active_borgmatic_processes": len(active_processes),
                "active_borg_mounts": len(active_mounts),
                "aio_containers_running": running_count,
                "aio_containers_total": len(aio),
                "active_locks": locks,
                "timestamp": time.time(),
            }
        )
    except Exception as e:
        return _json_error(500, "status_error", str(e))


@bp.route("/emergency/shutdown", methods=["POST"])
@rate_limited(2, 600)
def emergency_shutdown():
    """Arrêt d'urgence : umount borg, SIGTERM borgmatic, stop containers AIO, cleanup cache."""
    try:
        _require_auth(read_only=False)
        results = {}

        # 1) umount (fusermount -u sur tous les points 'borg')
        try:
            mounts = subprocess.run(
                ["mount"], capture_output=True, text=True, timeout=10
            ).stdout.splitlines()
            targets = [
                ln.split()[2]
                for ln in mounts
                if "borg" in ln.lower() and len(ln.split()) >= 3
            ]
            rc = 0
            out = ""
            err = ""
            for m in targets:
                p = subprocess.run(
                    ["fusermount", "-u", m], capture_output=True, text=True, timeout=10
                )
                rc = max(rc, p.returncode)
                out += p.stdout
                err += p.stderr
            results["umount"] = {"rc": rc, "stdout": out, "stderr": err}
        except Exception as e:
            results["umount"] = {"error": str(e)}

        # 2) SIGTERM borgmatic (puis SIGKILL si nécessaire)
        try:
            subprocess.run(["pkill", "-TERM", "borgmatic"], timeout=5)
            time.sleep(2)
            subprocess.run(["pkill", "-KILL", "-f", "borgmatic"], timeout=5)
            results["kill_borgmatic"] = {"ok": True}
        except Exception as e:
            results["kill_borgmatic"] = {"error": str(e)}

        # 3) Stop containers AIO (sauf master/watchtower/socket-proxy)
        try:
            containers = _docker_ps(all_containers=False)
            names = [
                c["name"] for c in containers if c["name"].startswith("nextcloud-aio-")
            ]
            to_stop = [
                n
                for n in names
                if not any(
                    x in n
                    for x in ("mastercontainer", "watchtower", "docker-socket-proxy")
                )
            ]
            out = ""
            err = ""
            rc = 0
            for n in to_stop:
                try:
                    p = subprocess.run(
                        ["docker", "stop", n],
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    rc = max(rc, p.returncode)
                    out += p.stdout
                    err += p.stderr
                except Exception as stop_err:
                    err += f"Failed to stop {n}: {str(stop_err)}\n"
            results["stop_containers"] = {"rc": rc, "stdout": out, "stderr": err}
        except RuntimeError as e:
            try:
                error_details = json.loads(str(e))
                results["stop_containers"] = {"error": error_details}
            except Exception:
                results["stop_containers"] = {"error": str(e)}

        # 4) Cleanup cache
        cache_dir = Path("/root/.cache/borg")
        if cache_dir.exists():
            import shutil

            shutil.rmtree(cache_dir, ignore_errors=True)
            results["cache_cleanup"] = {"cleared": True}
        else:
            results["cache_cleanup"] = {"cleared": False}

        return _json_ok(
            {"emergency_shutdown": True, "results": results, "timestamp": time.time()}
        )
    except Exception as e:
        return _json_error(500, "emergency_error", str(e))


# --- Alias routes pour compatibilité avec anciennes URLs ---
@bp.route("/emergency-status")
def emergency_status_alias():
    return emergency_status()


@bp.route("/emergency-shutdown", methods=["POST"])
def emergency_shutdown_alias():
    return emergency_shutdown()


# =============================================================================
# 9) SSH KEYS
# =============================================================================
@bp.route("/ssh-keys")
def ssh_list():
    try:
        _require_auth(read_only=True)
        keys = sorted([p.stem for p in Path(BORG_SSH_DIR).glob("id_*.pub")])
        return _json_ok({"keys": keys})
    except Exception as e:
        return _json_error(401, "unauthorized", str(e))


@bp.route("/ssh-keys/<label>/status")
def ssh_status(label: str):
    try:
        _require_auth(read_only=True)
        prv = Path(BORG_SSH_DIR) / f"id_{label}"
        pub = Path(BORG_SSH_DIR) / f"id_{label}.pub"
        return _json_ok(
            {
                "exists": prv.exists() and pub.exists(),
                "private": str(prv),
                "public": str(pub),
            }
        )
    except Exception as e:
        return _json_error(401, "unauthorized", str(e))


@bp.route("/ssh-keys/<label>/pub")
def ssh_pub(label: str):
    try:
        _require_auth(read_only=True)
        pub = Path(BORG_SSH_DIR) / f"id_{label}.pub"
        if not pub.exists():
            return _json_error(404, "not_found", f"SSH key {label} not found")
        content = pub.read_text(encoding="utf-8").strip()
        restrict = request.args.get("restrict_to_path")
        comment = request.args.get("comment") or f"borgmatic@{label}"
        auth_line = content
        if restrict:
            auth_line = f'command="borg serve --restrict-to-path {restrict}",restrict {content} {comment}'
        return _json_ok({"public": content, "authorized_keys": auth_line})
    except Exception as e:
        return _json_error(400, "read_error", str(e))


@bp.route("/ssh-keys/<label>", methods=["POST"])
@rate_limited(10, 300)
def ssh_create(label: str):
    try:
        _require_auth(read_only=False)
        body = request.get_json(force=True, silent=True) or {}
        ssh_passphrase = body.get("ssh_passphrase") or ""
        _enforce_distinct_pass("dummy", ssh_passphrase)
        prv = Path(BORG_SSH_DIR) / f"id_{label}"
        pub = Path(BORG_SSH_DIR) / f"id_{label}.pub"
        prv.parent.mkdir(parents=True, exist_ok=True)
        if prv.exists() or pub.exists():
            return _json_error(409, "exists", f"SSH key {label} already exists")
        p = subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-N",
                ssh_passphrase,
                "-f",
                str(prv),
                "-C",
                f"borgmatic-{label}",
            ],
            capture_output=True,
            text=True,
        )
        if p.returncode != 0:
            return _json_error(400, "ssh_error", p.stderr)
        return _json_ok({"created": True, "private": str(prv), "public": str(pub)})
    except ValueError as ve:
        return _json_error(400, "invalid_secrets", str(ve))
    except Exception as e:
        return _json_error(400, "ssh_error", str(e))


@bp.route("/ssh-keys/<label>", methods=["DELETE"])
@rate_limited(10, 300)
def ssh_delete(label: str):
    try:
        _require_auth(read_only=False)
        prv = Path(BORG_SSH_DIR) / f"id_{label}"
        pub = Path(BORG_SSH_DIR) / f"id_{label}.pub"
        ok = False
        for pth in (prv, pub):
            if pth.exists():
                pth.unlink()
                ok = True
        return _json_ok({"deleted": ok})
    except Exception as e:
        return _json_error(400, "ssh_error", str(e))


@bp.route("/ssh-keys/<label>/replace", methods=["POST"])
@rate_limited(10, 300)
def ssh_replace(label: str):
    try:
        _require_auth(read_only=False)
        body = request.get_json(force=True, silent=True) or {}
        ssh_passphrase = body.get("ssh_passphrase") or ""
        _enforce_distinct_pass("dummy", ssh_passphrase)
        prv = Path(BORG_SSH_DIR) / f"id_{label}"
        pub = Path(BORG_SSH_DIR) / f"id_{label}.pub"
        if prv.exists():
            prv.unlink()
        if pub.exists():
            pub.unlink()
        p = subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-N",
                ssh_passphrase,
                "-f",
                str(prv),
                "-C",
                f"borgmatic-{label}",
            ],
            capture_output=True,
            text=True,
        )
        if p.returncode != 0:
            return _json_error(400, "ssh_error", p.stderr)
        return _json_ok({"replaced": True, "private": str(prv), "public": str(pub)})
    except ValueError as ve:
        return _json_error(400, "invalid_secrets", str(ve))
    except Exception as e:
        return _json_error(400, "ssh_error", str(e))


@bp.route("/ssh-keys/<label>/renew", methods=["POST"])
def ssh_renew(label: str):
    return ssh_replace(label)


@bp.route("/ssh-keys/<label>/test", methods=["POST"])
@rate_limited(20, 60)
def ssh_test(label: str):
    try:
        _require_auth(read_only=False)
        body = request.get_json(force=True, silent=True) or {}
        borg_passphrase = body.get("borg_passphrase")
        ssh_passphrase = body.get("ssh_passphrase")
        _enforce_distinct_pass(borg_passphrase, ssh_passphrase)
        try:
            cfg = _resolve_config(label)
        except FileNotFoundError as e:
            return _json_error(404, "not_found", str(e))
        env = {}
        if borg_passphrase:
            env["BORG_PASSPHRASE"] = borg_passphrase
        if ssh_passphrase:
            env["SSH_ASKPASS"] = "echo"
            env["SSH_PASSPHRASE"] = ssh_passphrase
        args = ["borgmatic", "--config", str(cfg), "info"]
        _validate_borgmatic_args(args)
        p = subprocess.run(args, capture_output=True, text=True, env=env, timeout=30)
        return _json_ok(
            {"returncode": p.returncode, "stdout": p.stdout, "stderr": p.stderr}
        )
    except ValueError as ve:
        return _json_error(400, "invalid_secrets", str(ve))
    except Exception as e:
        return _json_error(400, "ssh_error", str(e))


# =============================================================================
# 10) NETWORK & JOBS
# =============================================================================
@bp.route("/net/tcp-check")
def net_tcp_check():
    try:
        _require_auth(read_only=True)
        host = request.args.get("host")
        port = int(request.args.get("port"))
        timeout = float(request.args.get("timeout", 3))
        with socket.create_connection((host, port), timeout=timeout):
            pass
        return _json_ok({"ok": True})
    except Exception as e:
        return _json_error(400, "tcp_error", str(e))


@bp.route("/jobs/<job_id>")
def job_get(job_id: str):
    try:
        _require_auth(read_only=True)
        buf = _buffers().get(job_id)
        if not buf:
            return _json_error(404, "not_found", f"job {job_id} not found")
        return _json_ok({"job_id": job_id})
    except Exception as e:
        return _json_error(401, "unauthorized", str(e))


# =============================================================================
# 11) SECURITY - EXEC WHITELIST MANAGEMENT
# =============================================================================
@bp.route("/security/exec-whitelist")
def security_exec_whitelist():
    """Affiche la whitelist actuelle des commandes docker exec autorisées"""
    try:
        _require_auth(read_only=True)
        return _json_ok(
            {
                "whitelist": ALLOWED_EXEC_CONTAINERS,
                "dangerous_commands_blocked": DANGEROUS_COMMANDS,
                "total_containers": len(ALLOWED_EXEC_CONTAINERS),
            }
        )
    except Exception as e:
        return _json_error(401, "unauthorized", str(e))


@bp.route("/security/exec-whitelist/validate", methods=["POST"])
def security_validate_exec():
    """
    Teste si une commande docker exec serait autorisée (dry-run).
    Utile pour tester la whitelist sans exécuter réellement la commande.
    """
    try:
        _require_auth(read_only=True)
        body = request.get_json(force=True, silent=True) or {}
        container = body.get("container")
        command = body.get("command", [])

        if not container or not command:
            return _json_error(400, "bad_request", "container and command required")

        if isinstance(command, str):
            command = [command]

        try:
            _validate_docker_exec(container, command)
            return _json_ok(
                {
                    "allowed": True,
                    "container": container,
                    "command": command,
                    "message": "Command would be allowed",
                }
            )
        except PermissionError as pe:
            return _json_ok(
                {
                    "allowed": False,
                    "container": container,
                    "command": command,
                    "reason": str(pe),
                }
            )
    except Exception as e:
        return _json_error(400, "validation_error", str(e))


@bp.route("/security/audit-log")
def security_audit_log():
    """
    Retourne les dernières commandes docker exec validées (pour audit).
    Note: Implémentation basique - en production, utiliser un vrai système de logs.
    """
    try:
        _require_auth(read_only=True)
        # En production, lire depuis un fichier de log ou une DB
        return _json_ok(
            {
                "message": "Audit logs available in container stdout",
                "hint": "docker logs borgmatic-api | grep '[SECURITY]'",
            }
        )
    except Exception as e:
        return _json_error(401, "unauthorized", str(e))


def _configure_blueprint(services: Services) -> None:
    global SERVICES, BORG_CONFIG_DIR, BORG_BASE_DIR, BORG_SSH_DIR
    global AIO_MASTER, AIO_DAILY, AIO_HEALTH, USE_SOCKET_PROXY
    global ALLOWED_EXEC_CONTAINERS, DANGEROUS_COMMANDS
    global APP_SSE_HEARTBEAT_SEC, SSE_BASE_URL, READY_WEBHOOK_URL, START_TIME

    SERVICES = services
    settings = services.settings

    BORG_CONFIG_DIR = str(settings.borg_config_dir)
    BORG_BASE_DIR = str(settings.borg_base_dir)
    BORG_SSH_DIR = str(settings.borg_ssh_dir)
    AIO_MASTER = settings.aio_master
    AIO_DAILY = settings.aio_daily
    AIO_HEALTH = settings.aio_health
    USE_SOCKET_PROXY = settings.use_socket_proxy

    ALLOWED_EXEC_CONTAINERS = {
        name: {
            "commands": entry.commands,
            "no_shell": entry.no_shell,
            "description": entry.description,
        }
        for name, entry in settings.exec_whitelist.items()
    }
    DANGEROUS_COMMANDS = list(settings.dangerous_commands)

    APP_SSE_HEARTBEAT_SEC = settings.sse_heartbeat
    SSE_BASE_URL = settings.sse_base_url
    READY_WEBHOOK_URL = settings.ready_webhook_url
    START_TIME = services.start_time
    READY_HOOKS.clear()


def create_blueprint(services: Services) -> Blueprint:
    """Return a configured blueprint instance.

    Using a factory keeps dependency injection explicit while still allowing the
    legacy module to expose a single blueprint object.
    """

    _configure_blueprint(services)
    return bp


def register_routes(app, services: Services) -> None:
    """Backwards compatible wrapper registering the blueprint on ``app``."""

    app.register_blueprint(create_blueprint(services))
