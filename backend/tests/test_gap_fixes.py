from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models import FileRecord, Probe


def _register(client: TestClient, name: str, metadata: dict | None = None) -> int:
    response = client.post(
        "/api/v1/probes/register",
        json={
            "name": name,
            "hostname": "host",
            "ip_address": "10.0.0.1",
            "metadata": metadata or {},
        },
    )
    assert response.status_code == 200
    return int(response.json()["id"])


def test_heartbeat_merges_metadata_instead_of_replacing() -> None:
    with TestClient(app) as client:
        probe_id = _register(
            client, "merge-probe", {"services": [{"port": 5432}], "system": {"cpu_percent": 1}}
        )
        # File loop overwrites with file_inventory; must not drop system/services.
        hb = client.post(
            f"/api/v1/probes/{probe_id}/heartbeat",
            json={
                "status": "online",
                "metadata": {"file_inventory": [{"sha256": "a" * 64}], "capture_status": "online"},
            },
        )
        assert hb.status_code == 200
        with SessionLocal() as db:
            probe = db.get(Probe, probe_id)
            assert probe is not None
            extra = probe.extra or {}
            assert extra.get("services") == [{"port": 5432}]
            assert extra.get("system", {}).get("cpu_percent") == 1
            assert extra.get("file_inventory") == [{"sha256": "a" * 64}]
            assert extra.get("capture_status") == "online"


def test_file_upload_persists_md5_from_probe_metadata() -> None:
    import hashlib

    with TestClient(app) as client:
        probe_id = _register(client, "md5-probe")
        content = b"hello md5"
        md5 = hashlib.md5(content).hexdigest()
        # Probe supplies an md5 hint; the metadata task recomputes from the
        # stored bytes so the persisted hash always matches the real content.
        files = {"file": ("sample.txt", content, "text/plain")}
        data = {
            "probe_id": str(probe_id),
            "metadata_json": '{"name":"sample.txt","md5":"' + md5
            + '","sha256":"' + "0" * 64 + '"}',
        }
        response = client.post("/api/v1/files/upload", files=files, data=data)
        assert response.status_code == 200
        file_id = int(response.json()["id"])
        with SessionLocal() as db:
            record = db.get(FileRecord, file_id)
            assert record is not None
            assert record.md5 == md5
        detail = client.get(f"/api/v1/files/{file_id}").json()
        assert detail["file"]["md5"] == md5


def test_file_upload_computes_md5_when_absent() -> None:
    import hashlib

    with TestClient(app) as client:
        probe_id = _register(client, "md5-compute-probe")
        content = b"compute me"
        files = {"file": ("compute.bin", content, "application/octet-stream")}
        response = client.post(
            "/api/v1/files/upload",
            files=files,
            data={"probe_id": str(probe_id), "metadata_json": "{}"},
        )
        assert response.status_code == 200
        file_id = int(response.json()["id"])
        expected = hashlib.md5(content).hexdigest()
        with SessionLocal() as db:
            record = db.get(FileRecord, file_id)
            assert record is not None
            assert record.md5 == expected
        detail = client.get(f"/api/v1/files/{file_id}").json()
        assert detail["file"]["md5"] == expected


def test_integrations_reports_worker_zeek_suricata_capability(monkeypatch) -> None:
    fake_capabilities = [
        {
            "worker_id": "worker-1",
            "tshark": {"available": True, "version": "4.0.0"},
            "zeek": {"available": True, "version": "6.0.0"},
            "suricata": {"available": True, "version": "7.0.0", "rule_count": 12},
        }
    ]
    import app.api.v1 as v1

    monkeypatch.setattr(v1, "_read_worker_capabilities", lambda: fake_capabilities)
    with TestClient(app) as client:
        body = client.get("/api/v1/integrations").json()
        by_name = {item["name"]: item for item in body}
        assert by_name["zeek"]["healthy"] is True
        assert by_name["zeek"]["status"] == "ready"
        assert by_name["zeek"]["worker_available"] is True
        assert by_name["suricata"]["healthy"] is True
        assert by_name["suricata"]["rule_count"] == 12
        assert by_name["zeek"]["runtime_version"] == "6.0.0"
        # sigma entry must expose the same metadata contract as adapters.
        assert "adapter_version" in by_name["sigma"]
        assert "last_check" in by_name["sigma"]


def test_integration_engine_persists_extracted_file(monkeypatch, tmp_path) -> None:
    import shutil

    from app.core.config import settings
    from app.integrations.base import AdapterResult
    from app.integrations.engine import IntegrationAdapterEngine

    class FakeAdapter:
        name = "zeek"
        version = "1.0.0"

        def metadata(self):
            return {"name": "zeek", "version": "1.0.0"}

    storage_dir = tmp_path / "storage"
    monkeypatch.setattr(settings, "storage_dir", storage_dir)

    run_dir = tmp_path / "runs" / "run-1" / "zeek"
    run_dir.mkdir(parents=True)
    extracted = run_dir / "F1234567"
    extracted.write_bytes(b"extracted file bytes")

    records = [{"fuid": "F1234567", "filename": "malware.exe", "event_type": "files"}]
    engine = IntegrationAdapterEngine(FakeAdapter())
    engine._persist_extracted_files(AdapterResult("zeek", records, []), run_dir.parent)

    assert records[0]["persisted"] is True
    dest = Path(records[0]["storage_path"])
    assert dest.exists()
    assert dest.read_bytes() == b"extracted file bytes"
    assert dest.parent == storage_dir / "network_files"
    # Original transient workspace must not be required for the download path.
    shutil.rmtree(run_dir.parent)
    assert dest.exists()
