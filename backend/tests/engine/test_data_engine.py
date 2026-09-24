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



def test_capture_container_is_not_a_document_asset(tmp_path, monkeypatch):
    from app.engine.data_engine import engine as module

    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"capture bytes")
    extracted = tmp_path / "unsupported.bin"
    extracted.write_bytes(b"business file")
    inspected = []
    monkeypatch.setattr(module, "yara_scan", lambda path, rules: inspected.append(path) or [])
    context = DetectionContext(target_type="pcap", path=capture, files=[extracted])
    DataEngine().analyze(context)
    assert capture in inspected  # Binary security checks still run.
    assert [a["name"] for a in context.data["data_assets"]] == [extracted.name]
    assert context.data["data_assets"][0]["scan_status"] == "unsupported"


def test_explicitly_uploaded_capture_file_is_still_inventoried(tmp_path):
    capture = tmp_path / "user.pcap"
    capture.write_bytes(b"capture bytes")
    context = DetectionContext(target_type="file", path=capture)
    DataEngine().analyze(context)
    assert context.data["data_assets"][0]["name"] == capture.name


def _stub_ocr(monkeypatch, *, text: str, coverage: str, layout: dict | None = None):
    """Replace the shared OCR call so the engine path is tested, not tesseract."""
    from shared.scanning import ocr

    monkeypatch.setattr(ocr, "extract", lambda path, **kwargs: ocr.OcrResult(
        text=text, pages=1, coverage=coverage,
        reason="complete" if coverage == ocr.COVERAGE_COMPLETE else "no_text_recognized",
        layout=layout or {},
    ))


def test_a_scanned_document_is_read_through_ocr_and_classified(tmp_path, monkeypatch):
    """A document with no text layer is inspected, not merely inventoried."""
    scan = tmp_path / "scan.png"
    scan.write_bytes(b"png" + b"0" * 64)
    _stub_ocr(monkeypatch, coverage="complete",
              text="机密★10年\nXX市人民政府文件\n〔2023〕12号\n关于数据安全的通知\n",
              layout={"red_title_band": True, "red_seal": False})

    context = DetectionContext(target_type="file", files=[scan])
    findings = DataEngine().analyze(context)
    rules = {item.rule_id: item.severity for item in findings}
    assert rules["DATA_CLASSIFIED_001"] == "Critical"
    assert rules["DATA_REDHEAD_001"] == "Medium"

    asset = context.data["data_assets"][0]
    assert asset["ocr_coverage"] == "complete"
    assert asset["document_type"]
    assert asset["scan_status"] == "complete"


def test_ocr_text_reaches_the_sensitive_rules(tmp_path, monkeypatch):
    """The point of OCR is that a photographed number is a finding like any other."""
    scan = tmp_path / "photo.jpg"
    scan.write_bytes(b"jpg" + b"0" * 64)
    _stub_ocr(monkeypatch, coverage="partial", text="联系人 13800138000")

    findings = DataEngine().analyze(DetectionContext(target_type="file", files=[scan]))
    assert any(item.rule_id == "DATA_PII_001" for item in findings)


def test_without_ocr_tools_the_image_is_reported_uninspected(tmp_path, monkeypatch):
    from shared.scanning import ocr

    scan = tmp_path / "scan.png"
    scan.write_bytes(b"png" + b"0" * 64)
    monkeypatch.setattr(ocr, "extract", lambda path, **kwargs: ocr.OcrResult(
        coverage=ocr.COVERAGE_UNAVAILABLE, reason="ocr_unavailable"))
    context = DetectionContext(target_type="file", files=[scan])
    DataEngine().analyze(context)
    asset = context.data["data_assets"][0]
    assert asset["scan_status"] == "unsupported"
    assert asset["sensitivity"] == "Unknown"


def test_a_clean_ocr_read_raises_no_document_finding(tmp_path, monkeypatch):
    scan = tmp_path / "receipt.png"
    scan.write_bytes(b"png" + b"0" * 64)
    _stub_ocr(monkeypatch, coverage="complete", text="购物小票 合计 12.00 元")
    findings = DataEngine().analyze(DetectionContext(target_type="file", files=[scan]))
    assert not any(item.rule_id in {"DATA_CLASSIFIED_001", "DATA_REDHEAD_001"} for item in findings)
