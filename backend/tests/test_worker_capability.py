from __future__ import annotations

from fastapi.testclient import TestClient

from app.main import app
from app.workers.tasks import worker_capability_heartbeat


def test_worker_capability_heartbeat_and_health() -> None:
    capability = worker_capability_heartbeat()
    assert capability["worker_id"]
    assert "tshark" in capability
    assert "suricata" in capability
    with TestClient(app) as client:
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        body = response.json()
        # Health must expose granular capability fields, not just a status.
        assert "api" in body
        assert "database" in body
        assert "redis" in body
        assert "celery" in body
        assert "analysis_worker" in body
        assert "tshark" in body
        assert "zeek" in body
        assert "suricata" in body
        assert "probe" in body
        assert body["analysis_worker"] in {"online", "ready", "offline"}
