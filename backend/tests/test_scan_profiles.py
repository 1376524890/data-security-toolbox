"""ScanProfile: defaults, validation, versioning, and the per-task snapshot.

The property that matters is that a queued job keeps the configuration it was
created with, so editing a profile cannot retroactively widen or narrow work a
probe is already doing.
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models import ScanProfile, Task
from app.services import scan_profile_service
from shared.scanning.budget import DEFAULT_LIMITS


def _register_probe(client: TestClient, name: str) -> int:
    response = client.post("/api/v1/probes/register",
                           json={"name": name, "hostname": name, "ip_address": "10.7.7.7",
                                 "metadata": {"agent_version": "3.4.0"}})
    assert response.status_code == 200
    return response.json()["id"]


def _payload(**overrides) -> dict:
    body = {"name": "prod-scan", "include_paths": ["/srv/data"], "max_files": 50}
    body.update(overrides)
    return body


# --- defaults --------------------------------------------------------------

def test_service_defaults_match_the_shipped_scanner() -> None:
    values = scan_profile_service.default_values()
    assert values["max_files"] == DEFAULT_LIMITS["max_files"] == 10000
    assert values["max_dirs"] == 500
    assert values["max_depth"] == 3
    assert values["max_runtime_seconds"] == 120
    assert values["max_single_file_size"] == 2 * 1024 * 1024
    assert values["max_full_hash_size"] == 8 * 1024 * 1024
    assert values["max_sample_rows"] == 25
    assert values["large_file_sampling"] is True


def test_the_snapshot_covers_every_profile_field() -> None:
    session = SessionLocal()
    try:
        profile = ScanProfile(name="snapshot-shape", **scan_profile_service.validate(
            {"include_paths": ["/srv/data"], "max_files": 5}))
        session.add(profile)
        session.flush()
        snapshot = scan_profile_service.snapshot(profile)
        for field in scan_profile_service.PROFILE_FIELDS:
            assert field in snapshot, field
        assert snapshot["profile_id"] == profile.id
        assert snapshot["profile_version"] == profile.version
    finally:
        session.rollback()
        session.close()


def test_probe_config_translates_every_probe_knob() -> None:
    values = scan_profile_service.default_values()
    config = scan_profile_service.probe_config(values)
    for key in ("paths", "max_files", "max_depth", "max_dirs", "timeout_seconds", "max_bytes_read",
                "max_single_file_size", "max_full_hash_size", "sample_block_size",
                "max_sample_rows", "xlsx_max_rows", "xlsx_max_entries"):
        assert key in config, key
    assert config["timeout_seconds"] == 120
    assert config["paths"] == []


# --- validation ------------------------------------------------------------

@pytest.mark.parametrize(
    "values, message",
    [
        ({"max_files": 0}, "max_files"),
        ({"max_files": 500000}, "max_files"),
        ({"max_depth": 99}, "max_depth"),
        ({"max_runtime_seconds": 1}, "max_runtime_seconds"),
        ({"max_full_hash_size": 1024 * 1024 * 1024}, "max_full_hash_size"),
        ({"include_paths": ["relative/path"]}, "include_paths"),
        ({"include_paths": ["/srv/../etc"]}, "include_paths"),
        ({"include_paths": "not-a-list"}, "必须是数组"),
        ({"unknown_knob": 1}, "未知字段"),
    ],
)
def test_invalid_values_are_rejected_with_a_reason(values: dict, message: str) -> None:
    with pytest.raises(scan_profile_service.ScanProfileError, match=message):
        scan_profile_service.validate(values)


def test_full_hash_ceiling_cannot_be_raised_to_something_ruinous() -> None:
    """Full hashing is I/O heavy; the ceiling is enforced, not advisory."""
    with pytest.raises(scan_profile_service.ScanProfileError):
        scan_profile_service.validate({"max_full_hash_size": 8 * 1024 * 1024 * 1024})


def test_paths_are_deduplicated() -> None:
    clean = scan_profile_service.validate({"include_paths": ["/srv/data", "/srv/data", "/srv/b"]})
    assert clean["include_paths"] == ["/srv/data", "/srv/b"]


# --- API -------------------------------------------------------------------

def test_create_read_update_and_delete_a_profile() -> None:
    with TestClient(app) as client:
        created = client.post("/api/v1/scan-profiles", json=_payload())
        assert created.status_code == 200, created.text
        body = created.json()
        assert body["name"] == "prod-scan" and body["version"] == 1
        profile_id = body["id"]

        fetched = client.get(f"/api/v1/scan-profiles/{profile_id}").json()
        assert fetched["include_paths"] == ["/srv/data"]
        assert fetched["max_files"] == 50
        assert fetched["max_full_hash_size"] == DEFAULT_LIMITS["max_full_hash_size"]

        updated = client.patch(f"/api/v1/scan-profiles/{profile_id}", json={"max_files": 80})
        assert updated.status_code == 200, updated.text
        assert updated.json()["max_files"] == 80
        assert updated.json()["version"] == 2, "an edit moves the revision counter"

        assert client.delete(f"/api/v1/scan-profiles/{profile_id}").status_code == 200
        assert client.get(f"/api/v1/scan-profiles/{profile_id}").status_code == 404


def test_an_invalid_profile_is_rejected_over_http() -> None:
    with TestClient(app) as client:
        response = client.post("/api/v1/scan-profiles", json=_payload(max_runtime_seconds=1))
        assert response.status_code == 400
        assert "max_runtime_seconds" in response.json()["detail"]


def test_listing_is_bounded_and_sortable_by_whitelist_only() -> None:
    with TestClient(app) as client:
        client.post("/api/v1/scan-profiles", json=_payload(name="listable"))
        listed = client.get("/api/v1/scan-profiles", params={"page": 1, "page_size": 5}).json()
        assert listed["page_size"] == 5
        assert listed["total"] >= 1
        assert client.get("/api/v1/scan-profiles", params={"sort": "drop table"}).status_code == 400


def test_profile_names_are_versioned_not_overwritten() -> None:
    with TestClient(app) as client:
        first = client.post("/api/v1/scan-profiles", json=_payload(name="versioned")).json()
        second = client.post("/api/v1/scan-profiles", json=_payload(name="versioned")).json()
        assert first["version"] == 1 and second["version"] == 2
        assert first["id"] != second["id"]


def test_running_a_profile_queues_a_job_with_the_resolved_config() -> None:
    with TestClient(app) as client:
        probe_id = _register_probe(client, "profile-run-probe")
        profile = client.post("/api/v1/scan-profiles",
                              json=_payload(name="run-me", include_paths=["/srv/data"],
                                            max_files=42, max_depth=2)).json()
        queued = client.post(f"/api/v1/scan-profiles/{profile['id']}/run",
                             json={"probe_id": probe_id})
        assert queued.status_code == 200, queued.text
        assert queued.json()["profile_version"] == profile["version"]

        session = SessionLocal()
        try:
            task = session.get(Task, queued.json()["id"])
            config = task.payload["config"]
            assert config["paths"] == ["/srv/data"]
            assert config["max_files"] == 42
            assert config["max_depth"] == 2
            assert task.payload["profile_id"] == profile["id"]
        finally:
            session.close()


def test_editing_a_profile_does_not_change_an_already_queued_job() -> None:
    """The snapshot is the contract; a later edit must not rewrite history."""
    with TestClient(app) as client:
        probe_id = _register_probe(client, "profile-snapshot-probe")
        profile = client.post("/api/v1/scan-profiles",
                              json=_payload(name="pinned", include_paths=["/srv/data"],
                                            max_files=10)).json()
        queued = client.post(f"/api/v1/scan-profiles/{profile['id']}/run",
                             json={"probe_id": probe_id}).json()

        client.patch(f"/api/v1/scan-profiles/{profile['id']}",
                     json={"include_paths": ["/etc"], "max_files": 1000})

        session = SessionLocal()
        try:
            task = session.get(Task, queued["id"])
            assert task.payload["config"]["paths"] == ["/srv/data"]
            assert task.payload["config"]["max_files"] == 10
            assert task.payload["profile_snapshot"]["profile_version"] == 1
        finally:
            session.close()


def test_a_profile_without_paths_cannot_be_run() -> None:
    with TestClient(app) as client:
        probe_id = _register_probe(client, "profile-nopath-probe")
        profile = client.post("/api/v1/scan-profiles",
                              json={"name": "no-paths", "include_paths": []}).json()
        response = client.post(f"/api/v1/scan-profiles/{profile['id']}/run",
                               json={"probe_id": probe_id})
        assert response.status_code == 400
        assert "include_paths" in response.json()["detail"]


def test_a_disabled_profile_cannot_be_run() -> None:
    with TestClient(app) as client:
        probe_id = _register_probe(client, "profile-disabled-probe")
        profile = client.post("/api/v1/scan-profiles",
                              json=_payload(name="disabled-one", enabled=False)).json()
        response = client.post(f"/api/v1/scan-profiles/{profile['id']}/run",
                               json={"probe_id": probe_id})
        assert response.status_code == 409


def test_a_profile_referenced_by_an_open_task_cannot_be_deleted() -> None:
    with TestClient(app) as client:
        probe_id = _register_probe(client, "profile-guard-probe")
        profile = client.post("/api/v1/scan-profiles", json=_payload(name="guarded")).json()
        client.post(f"/api/v1/scan-profiles/{profile['id']}/run", json={"probe_id": probe_id})
        response = client.delete(f"/api/v1/scan-profiles/{profile['id']}")
        assert response.status_code == 409
        assert "未完成的任务" in response.json()["detail"]


def test_the_legacy_job_endpoint_still_accepts_plain_paths() -> None:
    with TestClient(app) as client:
        probe_id, token = _open_probe(client, "profile-legacy-probe")
        queued = client.post(f"/api/v1/probes/{probe_id}/data-assets/jobs",
                            json={"paths": ["/srv/legacy"], "max_files": 7})
        assert queued.status_code == 200, queued.text
        commands = client.get(f"/api/v1/probes/{probe_id}/commands",
                              headers={"X-Probe-ID": str(probe_id), "X-Probe-Token": token}).json()["commands"]
        assert commands[0]["config"]["paths"] == ["/srv/legacy"]
        assert commands[0]["config"]["max_files"] == 7


def test_the_legacy_endpoint_accepts_a_profile_reference() -> None:
    with TestClient(app) as client:
        probe_id, token = _open_probe(client, "profile-ref-probe")
        profile = client.post("/api/v1/scan-profiles",
                              json=_payload(name="by-ref", include_paths=["/srv/ref"],
                                            max_depth=4)).json()
        queued = client.post(f"/api/v1/probes/{probe_id}/data-assets/jobs",
                             json={"profile_id": profile["id"]})
        assert queued.status_code == 200, queued.text
        commands = client.get(f"/api/v1/probes/{probe_id}/commands",
                              headers={"X-Probe-ID": str(probe_id), "X-Probe-Token": token}).json()["commands"]
        assert commands[0]["config"]["paths"] == ["/srv/ref"]
        assert commands[0]["config"]["max_depth"] == 4


def test_a_profile_reference_that_does_not_exist_is_a_404() -> None:
    with TestClient(app) as client:
        probe_id, _ = _open_probe(client, "profile-missing-probe")
        response = client.post(f"/api/v1/probes/{probe_id}/data-assets/jobs",
                              json={"profile_id": 999999})
        assert response.status_code == 404


def test_an_unsupported_probe_version_is_refused_rather_than_downgraded() -> None:
    with TestClient(app) as client:
        legacy = client.post("/api/v1/probes/register",
                             json={"name": "legacy-probe", "hostname": "legacy-probe",
                                   "ip_address": "10.6.6.6",
                                   "metadata": {"agent_version": "3.2.1"}}).json()
        profile = client.post("/api/v1/scan-profiles", json=_payload(name="for-legacy")).json()
        response = client.post(f"/api/v1/scan-profiles/{profile['id']}/run",
                               json={"probe_id": legacy["id"]})
        assert response.status_code == 409
        assert "不支持数据资产采集" in response.json()["detail"]


def _open_probe(client: TestClient, name: str) -> tuple[int, str]:
    response = client.post("/api/v1/probes/register",
                           json={"name": name, "hostname": name, "ip_address": "10.5.5.5",
                                 "metadata": {"agent_version": "3.4.0"}})
    assert response.status_code == 200
    body = response.json()
    return body["id"], body["token"]
