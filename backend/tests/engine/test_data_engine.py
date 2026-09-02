from pathlib import Path

from app.engine.core.context import DetectionContext
from app.engine.data_engine.engine import DataEngine, infer_columns, scan_text


def test_scan_text_pii_and_secret() -> None:
    result = scan_text("phone 13800138000 email test@example.com api_key sk-abcdefghijklmnopqrst")
    assert result["pii_count"] >= 2
    assert result["secret_count"] >= 1


def test_infer_columns() -> None:
    columns = infer_columns("user_id,phone,id_card\n1,138,110", "sample.csv")
    assert columns[0]["sensitivity"] == "High"
    assert columns[1]["categories"] == ["phone"]


def test_file_scan(tmp_path: Path) -> None:
    path = tmp_path / "sample.csv"
    path.write_text("phone,email\n13800138000,test@example.com\n", encoding="utf-8")
    context = DetectionContext(target_type="file", files=[path])
    findings = DataEngine().analyze(context)
    assert any(item.rule_id == "DATA_PII_001" for item in findings)

