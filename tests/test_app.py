import pytest

pytest.importorskip("flask")

from borgmatic_api_app import create_app


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
    assert metrics["responses_ok"] >= 2


def test_metrics_requires_authentication(app):
    client = app.test_client()
    response = client.get("/metrics")
    assert response.status_code == 401
