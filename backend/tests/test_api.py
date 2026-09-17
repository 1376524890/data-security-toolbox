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


def test_engine_registry_reports_rules_and_detection_counts() -> None:
    """The console builds its engine filter from this endpoint.

    It must expose the name findings are stored under, plus the rule inventory,
    so no view has to hard-code an engine list that silently matches nothing.
    """
    with TestClient(app) as client:
        registry = client.get("/api/v1/engine/registry").json()
    assert registry
    for entry in registry:
        assert entry["detection_engine"] == entry["name"]
        assert isinstance(entry["rule_count"], int)
        assert isinstance(entry["detection_count"], int)
        assert entry["slug"]
        assert entry["label"]
    sigma = next(entry for entry in registry if entry["name"] == "sigma_log_engine")
    assert sigma["slug"] == "sigma"


def test_rule_library_tags_every_file_with_its_engine() -> None:
    """``/rules`` and the per-engine rule counter must agree.

    The rule library is the only source for both, so a rule list can never show
    a different total than the engine page that renders it.
    """
    with TestClient(app) as client:
        items = client.get("/api/v1/rules").json()["items"]
        registry = client.get("/api/v1/engine/registry").json()
    assert items
    assert all(entry["engine"] for entry in items)
    for entry in registry:
        expected = len([item for item in items if item["engine"] == entry["name"]])
        assert entry["rule_count"] == expected
    sigma = next(entry for entry in registry if entry["name"] == "sigma_log_engine")
    assert sigma["rule_count"] >= 1


def test_rules_endpoint_filters_by_engine() -> None:
    with TestClient(app) as client:
        filtered = client.get("/api/v1/rules", params={"engine": "traffic_engine"}).json()
    assert filtered["total"] >= 1
    assert all(item["engine"] == "traffic_engine" for item in filtered["items"])



