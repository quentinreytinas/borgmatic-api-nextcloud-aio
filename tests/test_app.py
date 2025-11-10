import pytest

try:
    from borgmatic_api_app import create_app
except ModuleNotFoundError:  # pragma: no cover - handled in CI without Flask
    create_app = None

if create_app is None:  # pragma: no cover - skip tests when Flask missing
    pytest.skip("Flask is required to run API tests", allow_module_level=True)


@pytest.fixture()
def app(monkeypatch):
    monkeypatch.setenv("API_TOKEN", "test-write")
    monkeypatch.setenv("API_READ_TOKEN", "test-read")
    monkeypatch.setenv("APP_FROM_HEADER", "NodeRED-Internal")
    monkeypatch.delenv("APP_READY_WEBHOOK_URL", raising=False)
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


def test_daily_backup_uses_socket_proxy_when_configured(monkeypatch):
    monkeypatch.setenv("API_TOKEN", "test-write")
    monkeypatch.setenv("API_READ_TOKEN", "test-read")
    monkeypatch.setenv("APP_FROM_HEADER", "NodeRED-Internal")
    monkeypatch.setenv("DOCKER_HOST", "tcp://socket-proxy:2375")

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
