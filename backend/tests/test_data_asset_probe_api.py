"""Probe-side data asset inventory ingestion and job queueing."""
from __future__ import annotations

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import SessionLocal
from app.main import app
from app.models import DataAsset, Task


def _register_probe(client: TestClient, name: str) -> tuple[int, str]:
    response = client.post("/api/v1/probes/register", json={"name": name, "hostname": name, "ip_address": "10.9.9.9", "metadata": {}})
    assert response.status_code == 200
    body = response.json()
    return body["id"], body["token"]


def _headers(probe_id: int, token: str) -> dict[str, str]:
    return {"X-Probe-ID": str(probe_id), "X-Probe-Token": token}


def _report(report_id: str) -> dict:
    return {
        "report_id": report_id,
        "assets": [
            {
                "name": "customers.csv",
                "asset_type": "table",
                "sensitivity": "High",
                "path": "/srv/data/customers.csv",
                "size": 2048,
                "sha256": "a" * 64,
                "modified_at": "2026-09-15T00:00:00+00:00",
                "categories": ["phone", "id_card"],
                "counts": {"phone": 2, "id_card": 2},
                "columns": [
                    {"name": "phone", "detected_type": "phone", "sensitivity": "Medium", "confidence": 0.9, "categories": ["phone"], "count": 2}
                ],
                "evidence": {"extension": ".csv"},
            }
        ],
        "databases": [
            {"name": "mysql@127.0.0.1:3306", "asset_type": "database", "sensitivity": "Medium", "path": "127.0.0.1:3306",
             "categories": ["database"], "counts": {}, "columns": [], "evidence": {"engine": "mysql"}}
        ],
        "scanned_paths": ["/srv/data"],
        "complete": True,
        "observed_at": "2026-09-15T00:00:00+00:00",
        "scanner": "probe-file-inventory",
    }


def test_queued_data_asset_job_is_delivered_to_probe() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "data-asset-probe")
        queued = client.post(f"/api/v1/probes/{probe_id}/data-assets/jobs", json={"paths": ["/srv/data"], "max_files": 10})
        assert queued.status_code == 200
        assert queued.json()["location"] == "probe"

        commands = client.get(f"/api/v1/probes/{probe_id}/commands", headers=_headers(probe_id, token)).json()["commands"]
        assert commands and commands[0]["kind"] == "data_asset_scan"
        assert commands[0]["config"]["paths"] == ["/srv/data"]

        # Only one active collection per probe.
        assert client.post(f"/api/v1/probes/{probe_id}/data-assets/jobs", json={"paths": ["/srv/data"]}).status_code == 409


def test_queued_job_carries_scope_filters_to_the_probe() -> None:
    """Excludes and the type allow-list must reach the probe, not stop at the form."""
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "data-asset-scope-probe")
        queued = client.post(f"/api/v1/probes/{probe_id}/data-assets/jobs", json={
            "paths": ["/srv/data"],
            "exclude_paths": ["/srv/data/tmp", "node_modules"],
            "file_types": ["csv", ".xlsx"],
        })
        assert queued.status_code == 200
        config = client.get(f"/api/v1/probes/{probe_id}/commands",
                            headers=_headers(probe_id, token)).json()["commands"][0]["config"]
        assert config["exclude_paths"] == ["/srv/data/tmp", "node_modules"]
        assert config["file_types"] == [".csv", ".xlsx"]


def test_queued_job_rejects_parent_traversal_in_excludes() -> None:
    with TestClient(app) as client:
        probe_id, _ = _register_probe(client, "data-asset-exclude-probe")
        response = client.post(f"/api/v1/probes/{probe_id}/data-assets/jobs",
                               json={"paths": ["/srv/data"], "exclude_paths": ["/srv/../etc"]})
        assert response.status_code == 422

def test_queued_job_rejects_relative_or_parent_paths() -> None:
    with TestClient(app) as client:
        probe_id, _ = _register_probe(client, "data-asset-path-probe")
        assert client.post(f"/api/v1/probes/{probe_id}/data-assets/jobs", json={"paths": ["relative/dir"]}).status_code == 422
        assert client.post(f"/api/v1/probes/{probe_id}/data-assets/jobs", json={"paths": ["/srv/../etc"]}).status_code == 422


def test_inventory_report_populates_data_assets_and_is_idempotent() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "data-asset-ingest-probe")
        response = client.post(f"/api/v1/probes/{probe_id}/data-assets", json=_report("report-one"), headers=_headers(probe_id, token))
        assert response.status_code == 200
        assert response.json()["assets"] == 2

        replay = client.post(f"/api/v1/probes/{probe_id}/data-assets", json=_report("report-one"), headers=_headers(probe_id, token))
        assert replay.json()["duplicate"] is True

        listed = client.get(f"/api/v1/data/assets?probe_id={probe_id}").json()
        names = {item["name"] for item in listed["items"]}
        assert names == {"customers.csv", "mysql@127.0.0.1:3306"}
        csv_asset = next(item for item in listed["items"] if item["name"] == "customers.csv")
        assert csv_asset["sensitivity"] == "High"
        assert csv_asset["probe"] == "data-asset-ingest-probe"
        assert csv_asset["host"] == "10.9.9.9"
        assert csv_asset["path"] == "/srv/data/customers.csv"
        assert csv_asset["categories"] == ["phone", "id_card"]
        assert csv_asset["columns"][0]["name"] == "phone"

    with SessionLocal() as db:
        row = db.scalar(select(DataAsset).where(DataAsset.name == "customers.csv"))
        assert row is not None and row.source == "probe:data-asset-ingest-probe"
        task = db.scalar(select(Task).where(Task.kind == "data_asset_scan").order_by(Task.id.desc()))
        assert task is not None and task.status == "Success"


def test_inventory_report_requires_matching_probe_credentials() -> None:
    with TestClient(app) as client:
        probe_id, token = _register_probe(client, "data-asset-auth-probe")
        other_id, other_token = _register_probe(client, "data-asset-auth-probe-2")
        denied = client.post(f"/api/v1/probes/{probe_id}/data-assets", json=_report("report-auth"), headers=_headers(other_id, other_token))
        assert denied.status_code == 403
        bad_token = client.post(f"/api/v1/probes/{probe_id}/data-assets", json=_report("report-auth"), headers=_headers(probe_id, "wrong-token"))
        assert bad_token.status_code == 401
