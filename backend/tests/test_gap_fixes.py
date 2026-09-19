from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from sqlalchemy import select

from app.models import DataAsset, DetectionFinding, FileRecord, Probe


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


def test_sensitive_findings_totals_come_from_aggregates_not_the_page() -> None:
    """Cards and chart must not report the size of a page as the total."""
    with TestClient(app) as client:
        with SessionLocal() as db:
            db.add(DataAsset(name="legacy-in-place.csv", asset_type="table", sensitivity="Medium",
                             source="file", columns=[], extra={"status": "observed"}))
            db.add(DataAsset(name="legacy-not-observed.csv", asset_type="table", sensitivity="High",
                             source="file", columns=[], extra={"status": "not_observed"}))
            db.add(DetectionFinding(target_type="file", target_id="legacy-in-place.csv",
                                    engine="data_engine", rule_id="DATA_PII_001",
                                    severity="High", confidence=0.9,
                                    evidence={"file": "legacy-in-place.csv",
                                              "regex": {"counts": {"phone": 3}},
                                              "secret_count": 0},
                                    risk_score=80.0, risk_level="High"))
            db.commit()
        body = client.get("/api/v1/sensitive/findings?page=1&page_size=5").json()
        assert {"findings", "objects", "instances", "detections",
                "data_assets"} <= set(body["totals"])
        assert body["pagination"]["page"] == 1 and body["pagination"]["page_size"] == 5
        # The list total and the headline total are the same aggregation.
        assert body["pagination"]["total"] == body["totals"]["findings"]
        assert len(body["details"]) <= 5
        assert body["details"] and "evidence" in body["details"][0]
        assert body["data_assets"]["observed"]["total"] >= 1
        assert body["data_assets"]["not_observed"]["total"] >= 1
        assert body["data_assets"]["not_observed"]["by_sensitivity"].get("High", 0) >= 1
        assert "data_engine" in {item["source"] for item in body["sources"]}
        assert body["categories"] == sorted(body["categories"],
                                            key=lambda item: -item["risk_score"])


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
    import app.api.integrations as integrations

    monkeypatch.setattr(integrations, "read_worker_capabilities", lambda: fake_capabilities)
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


def test_file_list_accepts_extension_or_mime_for_one_format() -> None:
    with TestClient(app) as client:
        probe_id = _register(client, "file-type-probe")
        png = (
            b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00"
            b"\x1f\x15\xc4\x89\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4"
            b"\x00\x00\x00\x00IEND\xaeB`\x82"
        )
        files = {"file": ("alias-check.png", png, "image/png")}
        response = client.post(
            "/api/v1/files/upload",
            files=files,
            data={"probe_id": str(probe_id), "metadata_json": '{"name":"alias-check.png"}'},
        )
        assert response.status_code == 200
        file_id = int(response.json()["id"])
        # Pin the stored MIME so the assertion does not depend on the async
        # metadata task having run.
        with SessionLocal() as db:
            record = db.get(FileRecord, file_id)
            assert record is not None
            record.file_type = "image/png"
            db.commit()
        for value in ("png", "image/png"):
            listed = client.get("/api/v1/files", params={"file_type": value}).json()
            assert file_id in [item["id"] for item in listed["items"]], value


def test_test_data_import_is_refused_and_not_advertised_by_default(monkeypatch) -> None:
    """The delivery build must not expose the manual test-pack entry."""
    from app.core.config import settings as app_settings

    monkeypatch.setattr(app_settings, "test_data_import_enabled", False)
    with TestClient(app) as client:
        assert client.post("/api/v1/test/import").status_code == 403
        assert client.post("/api/v1/test/clear").status_code == 403
        assert client.get("/api/v1/health").json()["features"]["test_data_import"] is False


def test_production_refuses_to_enable_test_data_import() -> None:
    from app.core.config import Settings

    with pytest.raises(RuntimeError):
        Settings(app_env="production", test_data_import_enabled=True).validate_production()


def test_repeated_file_analysis_keeps_one_current_result() -> None:
    """Three analyses of one file are one current result plus history."""
    content = b"email,phone\nalice@example.com,13800138000\nbob@example.com,13900139000\n"
    with TestClient(app) as client:
        probe_id = _register(client, "reanalyze-probe")
        response = client.post(
            "/api/v1/files/upload",
            files={"file": ("reanalyze.csv", content, "text/csv")},
            data={"probe_id": str(probe_id), "metadata_json": '{"name":"reanalyze.csv"}'},
        )
        assert response.status_code == 200
        file_id = int(response.json()["id"])
        first = client.get(f"/api/v1/files/{file_id}").json()
        assert first["findings"], "the fixture must produce at least one finding"
        assert first["data_assets"]
        for _ in range(2):
            assert client.post(f"/api/v1/files/{file_id}/analyze").status_code == 200
        latest = client.get(f"/api/v1/files/{file_id}").json()
        assert len(latest["findings"]) == len(first["findings"])
        assert len(latest["data_assets"]) == 1
        with SessionLocal() as db:
            record = db.get(FileRecord, file_id)
            rows = db.scalars(select(DetectionFinding).where(
                DetectionFinding.target_type == "file",
                DetectionFinding.target_id == str(file_id))).all()
            # History is kept, but exactly one run is current.
            assert len(rows) == 3 * len(first["findings"])
            assert sum(1 for row in rows if not (row.evidence or {}).get("superseded")) == len(first["findings"])
            assets = db.scalars(select(DataAsset).where(
                DataAsset.source == record.name)).all()
            assert len(assets) == 1
