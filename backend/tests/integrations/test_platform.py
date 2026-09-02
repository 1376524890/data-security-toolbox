from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient
from sqlalchemy import delete, select

from app.core.database import SessionLocal
from app.engine.core.result import DetectionResult
from app.incident_engine.engine import IncidentEngine
from app.integrations.offline_manager import import_offline_path
from app.main import app
from app.models import Asset, IOC, OfflineResource


def test_incident_window_links_ten_minutes() -> None:
    findings = [
        DetectionResult(engine="zeek", rule_id="A", severity="High", confidence=0.8, evidence={"src_ip": "10.0.0.9"}, timestamp="2026-01-01T00:00:00Z"),
        DetectionResult(engine="suricata", rule_id="B", severity="High", confidence=0.8, evidence={"src_ip": "10.0.0.9"}, timestamp="2026-01-01T00:10:00Z"),
    ]
    assert len(IncidentEngine().correlate(findings, 3600)) == 1


def test_incident_window_rejects_two_hours() -> None:
    findings = [
        DetectionResult(engine="zeek", rule_id="A", severity="High", confidence=0.8, evidence={"src_ip": "10.0.0.9"}, timestamp="2026-01-01T00:00:00Z"),
        DetectionResult(engine="suricata", rule_id="B", severity="High", confidence=0.8, evidence={"src_ip": "10.0.0.9"}, timestamp="2026-01-01T02:00:00Z"),
    ]
    assert IncidentEngine().correlate(findings, 3600) == []


def test_incident_window_multiple_clusters() -> None:
    findings = [
        DetectionResult(engine="zeek", rule_id="A", severity="High", confidence=0.8, evidence={"src_ip": "10.0.0.9"}, timestamp="2026-01-01T00:00:00Z"),
        DetectionResult(engine="suricata", rule_id="B", severity="High", confidence=0.8, evidence={"src_ip": "10.0.0.9"}, timestamp="2026-01-01T00:10:00Z"),
        DetectionResult(engine="zeek", rule_id="C", severity="High", confidence=0.8, evidence={"src_ip": "10.0.0.9"}, timestamp="2026-01-01T02:00:00Z"),
        DetectionResult(engine="suricata", rule_id="D", severity="High", confidence=0.8, evidence={"src_ip": "10.0.0.9"}, timestamp="2026-01-01T02:10:00Z"),
    ]
    assert len(IncidentEngine().correlate(findings, 3600)) == 2


def test_offline_import_persists_ioc_and_deduplicates() -> None:
    with TestClient(app):
        with SessionLocal() as db:
            value = "203.0.113.99"
            db.execute(delete(IOC).where(IOC.value == value))
            db.execute(delete(OfflineResource).where(OfflineResource.name == "platform-ioc-test"))
            db.commit()
            source = Path("data/offline_platform_ioc.json")
            source.parent.mkdir(parents=True, exist_ok=True)
            source.write_text(json.dumps({"iocs": [{"value": value, "type": "ip", "source": "platform-test"}]}), encoding="utf-8")
            result = import_offline_path(db, source, "ioc", "platform-ioc-test", "1.0")
            assert result.imported == 1
            assert db.scalar(select(IOC).where(IOC.value == value))
            second = import_offline_path(db, source, "ioc", "platform-ioc-test", "1.0")
            assert second.duplicates == 1
            db.execute(delete(IOC).where(IOC.value == value))
            db.execute(delete(OfflineResource).where(OfflineResource.name == "platform-ioc-test"))
            db.commit()


def test_integration_health_metadata() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/integrations")
        assert response.status_code == 200
        for item in response.json():
            assert {"name", "adapter_version", "installed", "enabled", "healthy", "runtime_version", "supported_types", "last_check", "status", "message", "capabilities"}.issubset(item.keys())


def test_pagination_and_filtering() -> None:
    with TestClient(app):
        with SessionLocal() as db:
            value = "10.99.99.9"
            db.execute(delete(Asset).where(Asset.ip == value))
            for index in range(3):
                db.add(Asset(ip=value, hostname=f"pagination-{index}", service="test", port=1, risk_level="High", asset_type="service"))
            db.commit()
            response = TestClient(app).get("/api/v1/assets", params={"risk": "High", "ip": value, "page": 1, "page_size": 2})
            assert response.status_code == 200
            body = response.json()
            assert body["page"] == 1
            assert body["page_size"] == 2
            assert body["total"] >= 3
            assert len(body["items"]) == 2
            db.execute(delete(Asset).where(Asset.ip == value))
            db.commit()
