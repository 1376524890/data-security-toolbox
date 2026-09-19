from pathlib import Path

from app.engine.core.context import DetectionContext
from app.engine.data_engine.engine import DataEngine, infer_columns, scan_text


def test_scan_text_pii_and_secret() -> None:
    result = scan_text("phone 13800138000 email test@example.com api_key sk-abcdefghijklmnopqrst")
    assert result["pii_count"] >= 2
    assert result["secret_count"] >= 1


def test_infer_columns() -> None:
    columns = infer_columns("user_id,phone,id_card\n1,138,110", "sample.csv")
    # Header names alone are candidates, not discovered personal data.
    assert columns[0]["sensitivity"] == "Unknown"
    assert columns[1]["candidate_categories"] == ["phone"]
    assert columns[1]["confirmed_categories"] == []

    with_values = infer_columns("phone,email\n13800138000,test@example.com\n", "sample.csv")
    assert with_values[0]["sensitivity"] == "High"
    assert with_values[0]["confirmed_categories"] == ["phone"]
    assert with_values[0]["sample_hit_count"] >= 1


def test_file_scan(tmp_path: Path) -> None:
    path = tmp_path / "sample.csv"
    path.write_text("phone,email\n13800138000,test@example.com\n", encoding="utf-8")
    context = DetectionContext(target_type="file", files=[path])
    findings = DataEngine().analyze(context)
    assert any(item.rule_id == "DATA_PII_001" for item in findings)


def test_low_confidence_shapes_never_raise_findings(tmp_path: Path) -> None:
    """A hash, a Luhn-failing number and a bare term are clues, not findings."""
    for name, content in (("token.txt", "a" * 64),
                          ("card.txt", "6222020000000008"),
                          ("medical.txt", "medical record 12345")):
        path = tmp_path / name
        path.write_text(content, encoding="utf-8")
        findings = DataEngine().analyze(DetectionContext(target_type="file", files=[path]))
        assert not any(item.rule_id in {"DATA_PII_001", "DATA_SECRET_001"} for item in findings), content


def test_confirmed_values_carry_their_own_confidence(tmp_path: Path) -> None:
    path = tmp_path / "phone.txt"
    path.write_text("13800138000", encoding="utf-8")
    findings = DataEngine().analyze(DetectionContext(target_type="file", files=[path]))
    pii = [item for item in findings if item.rule_id == "DATA_PII_001"]
    assert pii and pii[0].confidence == 0.7


def test_unreadable_document_is_reported_not_silently_clean(tmp_path: Path) -> None:
    path = tmp_path / "broken.pdf"
    path.write_bytes(b"not really a pdf")
    context = DetectionContext(target_type="file", files=[path])
    DataEngine().analyze(context)
    assets = context.data.get("data_assets", [])
    assert assets and assets[0]["scan_status"] == "failed"
    assert assets[0]["sensitivity"] == "Unknown"

