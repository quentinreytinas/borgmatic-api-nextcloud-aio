import pytest
import json
import time

try:
    from borgmatic_api_app import create_app
except ModuleNotFoundError:  # pragma: no cover - handled in CI without Flask
    create_app = None

if create_app is None:  # pragma: no cover - skip tests when Flask missing
    pytest.skip("Flask is required to run API tests", allow_module_level=True)


@pytest.fixture()
def app(monkeypatch, tmp_path):
    monkeypatch.setenv("API_TOKEN", "test-write")
    monkeypatch.setenv("API_READ_TOKEN", "test-read")
    monkeypatch.setenv("APP_FROM_HEADER", "NodeRED-Internal")
    monkeypatch.delenv("APP_READY_WEBHOOK_URL", raising=False)
    # Redirect audit log to temp dir (avoids /var/log PermissionError in CI)
    log_dir = tmp_path / "logs"
    log_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("AUDIT_LOG_PATH", str(log_dir / "audit.log"))
    # Redirect action policy path to avoid missing file errors
    monkeypatch.setenv("ACTIONS_POLICY_PATH", str(tmp_path / "actions.yaml"))
    aio_config = tmp_path / "configuration.json"
    aio_config.write_text(
        json.dumps(
            {
                "borg_backup_host_location": "/mnt/backup/borgmatic_local",
                "borg_remote_repo": "",
                "wasStartButtonClicked": True,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("AIO_CONFIG_FILE", str(aio_config))
    return create_app()


def auth_headers(write: bool = False) -> dict[str, str]:
    token = "test-write" if write else "test-read"
    return {
        "Authorization": f"Bearer {token}",
        "X-From-NodeRed": "NodeRED-Internal",
    }


def test_create_app_requires_tokens(monkeypatch):
    monkeypatch.delenv("API_TOKEN", raising=False)
    monkeypatch.delenv("API_READ_TOKEN", raising=False)
    with pytest.raises(RuntimeError):
        create_app()


def test_metrics_endpoint_reports_counters(app):
    client = app.test_client()

    status_response = client.get("/status", headers=auth_headers())
    assert status_response.status_code == 200

    metrics_response = client.get("/metrics", headers=auth_headers())
    assert metrics_response.status_code == 200
    payload = metrics_response.get_json()
    metrics = payload["metrics"]
    assert metrics["requests_total"] >= 2
    assert metrics["responses_ok"] >= 1


def test_metrics_requires_authentication(app):
    client = app.test_client()
    response = client.get("/metrics")
    assert response.status_code == 401


def test_health_requires_authentication(app):
    client = app.test_client()

    response = client.get("/health")

    assert response.status_code == 401
    payload = response.get_json()
    assert payload["error"] == "unauthorized"


def test_health_endpoint_returns_checks(monkeypatch, app):
    client = app.test_client()

    monkeypatch.setattr(
        "borgmatic_api_app.routes.legacy._gather_health_checks",
        lambda: ("healthy", {"api": "ok", "docker": "ok"}),
    )

    response = client.get("/health", headers=auth_headers())

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "healthy"
    assert payload["checks"]["api"] == "ok"


def test_public_health_endpoint_available_without_auth(monkeypatch, app):
    client = app.test_client()

    monkeypatch.setattr(
        "borgmatic_api_app.routes.legacy._gather_health_checks",
        lambda: (
            "degraded",
            {
                "api": "ok",
                "docker": "error",
                "docker_details": "no daemon",
            },
        ),
    )

    response = client.get("/health/public")

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["status"] == "degraded"
    assert payload["checks"]["docker_details"] == "no daemon"


def test_daily_backup_stop_endpoint_executes_docker(monkeypatch, app):
    client = app.test_client()
    recorded = {}

    class DummyProcess:
        returncode = 0
        stdout = "Stopped"
        stderr = ""

    def fake_run(args, capture_output, text, timeout, env):
        recorded["args"] = args
        recorded["timeout"] = timeout
        recorded["env"] = env
        return DummyProcess()

    monkeypatch.setattr("borgmatic_api_app.routes.legacy.subprocess.run", fake_run)

    response = client.post(
        "/nextcloud/daily-backup/stop",
        json={"timeout": 42},
        headers=auth_headers(write=True),
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["result"]["returncode"] == 0
    assert recorded["args"][0:2] == ["docker", "exec"]
    assert recorded["args"][-3:] == [
        "nextcloud-aio-mastercontainer",
        "/daily-backup.sh",
        "stop",
    ]
    assert recorded["timeout"] == 42


def test_daily_backup_run_translates_booleans(monkeypatch, app):
    client = app.test_client()

    class DummyProcess:
        returncode = 0
        stdout = "OK"
        stderr = ""

    captured = {}

    def fake_run(args, capture_output, text, timeout, env):
        captured["args"] = args
        captured["timeout"] = timeout
        captured["env"] = env
        return DummyProcess()

    monkeypatch.setattr("borgmatic_api_app.routes.legacy.subprocess.run", fake_run)

    response = client.post(
        "/nextcloud/daily-backup/run",
        json={
            "daily_backup": False,
            "automatic_updates": True,
            "extra_env": {"CUSTOM": "value"},
        },
        headers=auth_headers(write=True),
    )

    assert response.status_code == 200
    payload = response.get_json()
    env_payload = payload["env"]
    assert env_payload["DAILY_BACKUP"] == "0"
    assert env_payload["AUTOMATIC_UPDATES"] == "1"
    assert env_payload["CUSTOM"] == "value"

    args = captured["args"]
    assert "--env" in args
    assert any(entry.endswith("DAILY_BACKUP=0") for entry in args)
    assert any(entry.endswith("AUTOMATIC_UPDATES=1") for entry in args)
    assert any(entry.endswith("CUSTOM=value") for entry in args)
    assert captured["timeout"] == 3600
    assert "DOCKER_HOST" not in captured["env"]


def test_daily_backup_run_returns_error_when_borgbackup_failed(monkeypatch, app):
    client = app.test_client()

    monkeypatch.setattr(
        "borgmatic_api_app.routes.legacy._docker_exec_daily",
        lambda **kwargs: {
            "returncode": 0,
            "stdout": "OK",
            "stderr": "",
            "command": "/daily-backup.sh",
            "env": kwargs.get("env_vars", {}),
        },
    )
    inspect_states = iter(
        [
            {
                "StartedAt": "before",
                "FinishedAt": "before",
                "ExitCode": 0,
                "Status": "exited",
            },
            {
                "StartedAt": "after",
                "FinishedAt": "after",
                "ExitCode": 1,
                "Status": "exited",
            },
        ]
    )
    monkeypatch.setattr(
        "borgmatic_api_app.routes.legacy._docker_inspect_state",
        lambda container: next(inspect_states),
    )
    monkeypatch.setattr(
        "borgmatic_api_app.routes.legacy._docker_logs_tail",
        lambda container, tail=40: "Permission denied (publickey)",
    )

    response = client.post(
        "/nextcloud/daily-backup/run",
        json={"daily_backup": True},
        headers=auth_headers(write=True),
    )

    assert response.status_code == 502
    payload = response.get_json()
    assert payload["error"] == "backup_failed"
    assert payload["borgbackup"]["failed"] is True
    assert "Permission denied" in payload["borgbackup"]["log_tail"]


def test_backup_target_routes_round_trip(monkeypatch, app):
    client = app.test_client()

    response = client.post(
        "/nextcloud/backup-target",
        json={
            "remote_repo": "ssh://sauvegarde_reytinas@192.168.1.10:22//volume1/homes/sauvegarde_reytinas/borgmatic_reytinas_nextcloud/borg"
        },
        headers=auth_headers(write=True),
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["target"]["mode"] == "remote"
    assert payload["previous"]["host_location"] == "/mnt/backup/borgmatic_local"

    get_response = client.get("/nextcloud/backup-target", headers=auth_headers())
    assert get_response.status_code == 200
    get_payload = get_response.get_json()
    assert get_payload["target"]["remote_repo"].startswith(
        "ssh://sauvegarde_reytinas@192.168.1.10:22/"
    )


def test_run_for_target_restores_previous_target(monkeypatch, app):
    client = app.test_client()

    monkeypatch.setattr(
        "borgmatic_api_app.routes.legacy._docker_exec_daily",
        lambda **kwargs: {
            "returncode": 0,
            "stdout": "OK",
            "stderr": "",
            "command": "/daily-backup.sh",
            "env": kwargs.get("env_vars", {}),
        },
    )
    monkeypatch.setattr(
        "borgmatic_api_app.routes.legacy._docker_inspect_state",
        lambda container: None,
    )

    response = client.post(
        "/nextcloud/daily-backup/run-for-target",
        json={
            "remote_repo": "ssh://sauvegarde_reytinas@192.168.1.10:22//volume1/homes/sauvegarde_reytinas/borgmatic_reytinas_nextcloud/borg",
            "restore_after": True,
        },
        headers=auth_headers(write=True),
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["target"]["mode"] == "remote"
    assert payload["restored"]["mode"] == "local"
    assert payload["previous"]["host_location"] == "/mnt/backup/borgmatic_local"


def test_run_for_target_async_returns_job_and_events(monkeypatch, app):
    client = app.test_client()

    monkeypatch.setattr(
        "borgmatic_api_app.routes.legacy._docker_exec_daily_stream",
        lambda **kwargs: {
            "returncode": 0,
            "stdout": "Performing backup...",
            "stderr": "",
            "command": "/daily-backup.sh",
            "env": kwargs.get("env_vars", {}),
        },
    )
    monkeypatch.setattr(
        "borgmatic_api_app.routes.legacy._docker_inspect_state",
        lambda container: None,
    )

    response = client.post(
        "/nextcloud/daily-backup/run-for-target/async",
        json={
            "remote_repo": "ssh://sauvegarde_reytinas@192.168.1.10:22//volume1/homes/sauvegarde_reytinas/borgmatic_reytinas_nextcloud/borg",
            "restore_after": True,
        },
        headers=auth_headers(write=True),
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["job_id"].startswith("aio-run-for-target:")
    assert payload["poll"].endswith(payload["job_id"])
    assert "events/stream" in payload["sse"]

    deadline = time.time() + 2
    items = []
    while time.time() < deadline:
        poll_response = client.get(
            f"/events/poll/{payload['job_id']}",
            headers=auth_headers(),
        )
        assert poll_response.status_code == 200
        items = poll_response.get_json()["items"]
        if any('"event": "success"' in item.get("line", "") for item in items):
            break
        time.sleep(0.05)

    status_lines = [item["line"] for item in items if item.get("kind") == "status"]
    assert any('"event": "queued"' in line for line in status_lines)
    assert any('"event": "start"' in line for line in status_lines)
    assert any('"event": "success"' in line for line in status_lines)


def test_daily_backup_uses_socket_proxy_when_configured(monkeypatch, tmp_path):
    monkeypatch.setenv("API_TOKEN", "test-write")
    monkeypatch.setenv("API_READ_TOKEN", "test-read")
    monkeypatch.setenv("APP_FROM_HEADER", "NodeRED-Internal")
    monkeypatch.setenv("DOCKER_HOST", "tcp://socket-proxy:2375")
    log_dir = tmp_path / "logs"
    log_dir.mkdir(exist_ok=True)
    monkeypatch.setenv("AUDIT_LOG_PATH", str(log_dir / "audit.log"))
    monkeypatch.setenv("ACTIONS_POLICY_PATH", str(tmp_path / "actions.yaml"))

    app = create_app()
    client = app.test_client()

    class DummyProcess:
        returncode = 0
        stdout = "OK"
        stderr = ""

    recorded = {}

    def fake_run(args, capture_output, text, timeout, env):
        recorded["env"] = env
        return DummyProcess()

    monkeypatch.setattr("borgmatic_api_app.routes.legacy.subprocess.run", fake_run)

    response = client.post(
        "/nextcloud/daily-backup/stop",
        headers=auth_headers(write=True),
    )

    assert response.status_code == 200
    assert recorded["env"].get("DOCKER_HOST") == "tcp://socket-proxy:2375"


def test_ports_probe_reports_results(monkeypatch, app):
    client = app.test_client()

    class DummySocket:
        def close(self):
            pass

    def fake_create_connection(address, timeout=None):
        host, port = address
        if port == 8443:
            raise ConnectionRefusedError("refused")
        return DummySocket()

    monkeypatch.setattr(
        "borgmatic_api_app.routes.legacy.socket.create_connection",
        fake_create_connection,
    )

    response = client.post(
        "/nextcloud/ports/probe",
        json={"ports": [80, 8443]},
        headers=auth_headers(),
    )

    assert response.status_code == 200
    payload = response.get_json()
    assert payload["all_online"] is False
    online_result = next(r for r in payload["results"] if r["port"] == 80)
    offline_result = next(r for r in payload["results"] if r["port"] == 8443)
    assert online_result["online"] is True
    assert offline_result["online"] is False
    assert "refused" in offline_result["error"]


# =============================================================================
# Security tests
# =============================================================================


def test_security_headers_present(app):
    """Each response must include basic security headers."""
    client = app.test_client()
    response = client.get("/health/public")
    assert response.headers.get("X-Content-Type-Options") == "nosniff"
    assert response.headers.get("X-Frame-Options") == "DENY"
    assert response.headers.get("X-XSS-Protection") == "1; mode=block"


def test_auth_rejects_empty_bearer_token(app):
    """An empty Bearer token must be rejected with 401."""
    client = app.test_client()
    response = client.get(
        "/health",
        headers={"Authorization": "Bearer ", "X-From-NodeRed": "NodeRED-Internal"},
    )
    assert response.status_code == 401


def test_ssh_create_rejects_invalid_label(app):
    """SSH key creation must reject labels containing path traversal characters."""
    client = app.test_client()
    for bad_label in ("../evil", "../../etc/passwd", "label/sub", "label\x00null"):
        response = client.post(
            f"/ssh-keys/{bad_label}",
            json={},
            headers=auth_headers(write=True),
        )
        assert response.status_code in (
            400,
            404,
        ), f"Expected 400/404 for label {bad_label!r}"


def test_ssh_pub_rejects_invalid_label(app):
    """SSH pub endpoint must reject labels containing path traversal characters."""
    client = app.test_client()
    response = client.get(
        "/ssh-keys/../evil/pub",
        headers=auth_headers(),
    )
    assert response.status_code in (400, 404)


def test_archive_extract_rejects_path_traversal(monkeypatch, app):
    """archive_extract must refuse destinations outside /tmp or /mnt."""
    client = app.test_client()

    monkeypatch.setattr(
        "borgmatic_api_app.routes.legacy._resolve_config",
        lambda label: __import__("pathlib").Path("/etc/borgmatic.d/test.yaml"),
    )

    response = client.post(
        "/archives/extract",
        json={
            "repository": "test",
            "archive": "latest",
            "destination": "/root/.ssh",
        },
        headers=auth_headers(write=True),
    )
    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "bad_request"


def test_archive_extract_rejects_etc_traversal(monkeypatch, app):
    """archive_extract must refuse /etc as destination."""
    client = app.test_client()

    response = client.post(
        "/archives/extract",
        json={
            "repository": "test",
            "archive": "latest",
            "destination": "/etc/cron.d",
        },
        headers=auth_headers(write=True),
    )
    assert response.status_code == 400
    payload = response.get_json()
    assert payload["error"] == "bad_request"


def test_process_timeout_out_of_range_rejected(app):
    """process_timeout above 3600 must be rejected with 400."""
    client = app.test_client()
    response = client.post(
        "/config/validate/test",
        json={"process_timeout": 99999},
        headers=auth_headers(),
    )
    # Will 404 (config not found) or 400 depending on validation order;
    # the timeout error must not cause an unhandled 500.
    assert response.status_code in (400, 404)
    if response.status_code == 400:
        payload = response.get_json()
        assert payload["error"] == "bad_request"


def test_docker_exec_blocks_shell_via_absolute_path():
    """validate_docker_exec must block /bin/sh even when 'sh' is checked by basename."""
    from borgmatic_api_app.docker import validate_docker_exec
    from borgmatic_api_app.config import load_settings
    import os

    os.environ.setdefault("API_TOKEN", "t")
    os.environ.setdefault("API_READ_TOKEN", "t")
    settings = load_settings()

    # /bin/sh is a shell — must be blocked for no_shell containers
    try:
        validate_docker_exec(
            settings, "nextcloud-aio-mastercontainer", ["/bin/sh", "-c", "id"]
        )
        assert False, "Expected PermissionError for /bin/sh"
    except PermissionError:
        pass


def test_docker_exec_allows_daily_backup_script():
    """validate_docker_exec must allow /daily-backup.sh (not a shell by basename)."""
    from borgmatic_api_app.docker import validate_docker_exec
    from borgmatic_api_app.config import load_settings
    import os

    os.environ.setdefault("API_TOKEN", "t")
    os.environ.setdefault("API_READ_TOKEN", "t")
    settings = load_settings()

    # /daily-backup.sh must pass (it's in the whitelist and is not a shell)
    try:
        validate_docker_exec(
            settings, "nextcloud-aio-mastercontainer", ["/daily-backup.sh"]
        )
    except PermissionError as e:
        assert False, f"Expected /daily-backup.sh to be allowed, got: {e}"
