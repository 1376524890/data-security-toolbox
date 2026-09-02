from pathlib import Path

from app.core.database import SessionLocal
from app.integrations.offline import export_offline_bundle, load_any
from app.integrations.offline_manager import import_offline_path
from app.models import IOC, LocalCve, OfflineResource
from sqlalchemy import delete


def test_import_offline_json_bundle(tmp_path: Path) -> None:
    target = tmp_path / "iocs" / "items.json"
    target.parent.mkdir()
    target.write_text('{"iocs":[{"value":"1.2.3.4","type":"ip"}]}', encoding="utf-8")
    with SessionLocal() as db:
        db.execute(delete(IOC).where(IOC.value == "1.2.3.4"))
        db.execute(delete(OfflineResource).where(OfflineResource.name == "test-json-bundle"))
        db.commit()
        result = import_offline_path(db, target, "ioc", "test-json-bundle", "1.0")
    assert result.imported == 1
    assert result.categories["ioc"] == 1


def test_import_offline_csv_bundle(tmp_path: Path) -> None:
    target = tmp_path / "cves" / "items.csv"
    target.parent.mkdir()
    target.write_text("cve_id,severity\nCVE-2026-0001,High\n", encoding="utf-8")
    with SessionLocal() as db:
        db.execute(delete(LocalCve).where(LocalCve.cve_id == "CVE-2026-0001"))
        db.execute(delete(OfflineResource).where(OfflineResource.name == "test-cve-bundle"))
        db.commit()
        result = import_offline_path(db, target, "cve", "test-cve-bundle", "1.0")
    assert result.imported == 1
    assert result.categories["cve"] == 1


def test_export_and_import_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "rules" / "custom.json"
    export_offline_bundle(path, {"items": [{"rule_id": "CUSTOM_001"}]})
    assert load_any(path) == {"items": [{"rule_id": "CUSTOM_001"}]}


def test_import_missing_path(tmp_path: Path) -> None:
    with SessionLocal() as db:
        result = import_offline_path(db, tmp_path / "missing")
    assert result.imported == 0
    assert result.errors
