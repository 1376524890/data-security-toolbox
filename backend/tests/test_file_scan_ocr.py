"""A scanned document on a share is inspected, not filed as "binary metadata only".

The file-source scan reaches an image or a scanned PDF as opaque bytes, so
before this it was listed and never read. These tests pin what OCR changed - and
that a missing toolchain still reports the file as uninspected rather than clean.
"""
from __future__ import annotations

from pathlib import Path

from shared.scanning import ocr

from app.services.file_scan import ingest

PDF_BYTES = b"%PDF-1.4\n" + b"%\xe2\xe3\xcf\xd3\n" + b"0" * 2048


def test_a_scanned_pdf_is_read_through_ocr(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "scan.pdf"
    path.write_bytes(PDF_BYTES)
    monkeypatch.setattr(ocr, "extract", lambda target, **kwargs: ocr.OcrResult(
        text="涉密载体管理：保密期限 10 年 联系人 13800138000",
        pages=1, coverage=ocr.COVERAGE_COMPLETE, reason="complete", layout={},
    ))

    scan = ingest.analyze(path, {})
    # Read in part: OCR covers bounded pages/characters, never the whole container.
    assert scan["coverage"] == "partial"
    assert scan["reason"] == "ocr_read"
    assert scan["ocr"]["coverage"] == "complete"
    assert scan["counts"].get("phone") == 1
    assert [item["kind"] for item in scan["document_signals"]] == ["classified_document"]


def test_without_the_toolchain_the_file_stays_uninspected(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "scan.pdf"
    path.write_bytes(PDF_BYTES)
    monkeypatch.setattr(ocr, "extract", lambda target, **kwargs: ocr.OcrResult(
        coverage=ocr.COVERAGE_UNAVAILABLE, reason="ocr_unavailable",
    ))

    scan = ingest.analyze(path, {})
    assert scan["coverage"] == "unsupported"
    assert scan["reason"] == "binary_metadata_only"
    assert scan["document_signals"] == []
    assert scan["counts"] == {}


def test_a_text_file_is_not_sent_through_ocr(tmp_path: Path, monkeypatch) -> None:
    """OCR is a fallback for opaque documents, not a second pass over text."""
    path = tmp_path / "notes.txt"
    path.write_text("hello 13800138000", encoding="utf-8")
    called = []
    monkeypatch.setattr(ocr, "extract", lambda target, **kwargs: called.append(target))

    scan = ingest.analyze(path, {})
    assert called == []
    assert scan["coverage"] == "complete"
    assert scan["counts"].get("phone") == 1
