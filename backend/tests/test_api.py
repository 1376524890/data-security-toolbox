from fastapi.testclient import TestClient

from app.main import app


def test_health() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.json()["status"] == "ok"


def test_register_probe() -> None:
    with TestClient(app) as client:
        response = client.post("/api/v1/probes/register", json={"name": "test-probe", "hostname": "host", "ip_address": "10.0.0.1", "metadata": {"services": [{"port": 5432, "service": "postgres"}]}})
        assert response.status_code == 200
        probe_id = response.json()["id"]
        analyze = client.post(f"/api/v1/probes/{probe_id}/analyze")
        assert analyze.status_code == 200



