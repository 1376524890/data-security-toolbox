from pathlib import Path

from app.integrations.offline import export_offline_bundle, import_offline_bundle, load_any


def test_import_offline_json_bundle(tmp_path: Path) -> None:
    target = tmp_path / "iocs" / "items.json"
    target.parent.mkdir()
    target.write_text('{"iocs":[{"value":"1.2.3.4","type":"ip"}]}', encoding="utf-8")
    result = import_offline_bundle(tmp_path, ["iocs"])
    assert result.imported == 1
    assert result.categories["iocs"] == 1


def test_import_offline_csv_bundle(tmp_path: Path) -> None:
    target = tmp_path / "cves" / "items.csv"
    target.parent.mkdir()
    target.write_text("cve_id,severity\nCVE-2026-0001,High\n", encoding="utf-8")
    result = import_offline_bundle(tmp_path)
    assert result.imported == 1
    assert result.categories["cves"] == 1


def test_export_and_import_roundtrip(tmp_path: Path) -> None:
    path = tmp_path / "rules" / "custom.json"
    export_offline_bundle(path, {"items": [{"rule_id": "CUSTOM_001"}]})
    assert load_any(path) == {"items": [{"rule_id": "CUSTOM_001"}]}


def test_import_missing_path(tmp_path: Path) -> None:
    result = import_offline_bundle(tmp_path / "missing")
    assert result.imported == 0
    assert result.errors
