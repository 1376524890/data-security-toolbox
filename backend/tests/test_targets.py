"""The wizard's target helpers: bounded, read-only, and secret-preserving."""
from fastapi.testclient import TestClient

from app.main import app

#: Port 1 refuses immediately, so the test proves the failure path without a wait.
SPEC = {"protocol": "ssh", "host": "127.0.0.1", "port": 1, "username": "root",
        "auth_type": "password", "password": "s3cret-value"}


def test_unreachable_target_reports_a_category_not_the_secret() -> None:
    with TestClient(app) as client:
        response = client.post("/api/v1/targets/test", json=SPEC)
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is False and body["protocol"] == "ssh"
    # The credential is used for this one call and must never come back.
    assert "s3cret-value" not in response.text


def test_browse_rejects_a_protocol_it_cannot_enumerate() -> None:
    with TestClient(app) as client:
        response = client.post("/api/v1/targets/browse", json={**SPEC, "protocol": "ftp"})
    assert response.status_code == 400


def test_test_rejects_an_unknown_auth_type() -> None:
    with TestClient(app) as client:
        response = client.post("/api/v1/targets/test", json={**SPEC, "auth_type": "kerberos"})
    assert response.status_code == 400
