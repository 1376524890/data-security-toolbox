"""OCR bounds and honesty, proved without a tesseract install.

The binary is not on the test host, and that must not decide whether the
degradation paths are covered: availability and the three external calls are
stubbed, so what is tested is the module's own contract - the coverage
vocabulary, the page/character caps, the budget accounting, and that a budget
stop propagates instead of being reported as an empty read.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from shared.scanning import ocr
from shared.scanning.budget import BudgetExceeded, ScanBudget

TEXT = "机密★10年 某某单位涉密文件"


@pytest.fixture()
def image(tmp_path: Path) -> Path:
    path = tmp_path / "scan.png"
    path.write_bytes(b"png" + b"0" * 512)
    return path


def _stub(monkeypatch, *, text: str = TEXT) -> None:
    monkeypatch.setattr(ocr, "available", lambda: True)
    monkeypatch.setattr(ocr, "recognize_image", lambda path: (True, text, ""))
    monkeypatch.setattr(ocr, "analyze_layout", lambda path: {"red_ratio_top": 0.0,
                                                             "red_ratio_lower": 0.0})


def test_without_the_binary_the_read_is_unavailable_not_empty(image: Path, monkeypatch) -> None:
    monkeypatch.setattr(ocr, "available", lambda: False)
    result = ocr.extract(image)
    assert result.coverage == ocr.COVERAGE_UNAVAILABLE
    assert result.reason == "ocr_unavailable"
    assert not result.ok


def test_an_unsupported_suffix_is_named_as_such(tmp_path: Path) -> None:
    result = ocr.extract(tmp_path / "report.docx")
    assert result.coverage == ocr.COVERAGE_UNSUPPORTED
    assert result.reason == "unsupported_format"


def test_an_image_is_read_and_charged_to_the_budget(image: Path, monkeypatch) -> None:
    _stub(monkeypatch)
    budget = ScanBudget({})
    result = ocr.extract(image, budget=budget)
    assert result.ok and result.coverage == ocr.COVERAGE_COMPLETE
    assert result.text == TEXT
    assert result.pages == 1
    assert budget.bytes_read > 0


def test_an_oversized_raster_is_skipped_rather_than_read(image: Path, monkeypatch) -> None:
    _stub(monkeypatch)
    monkeypatch.setattr(ocr, "MAX_IMAGE_BYTES", image.stat().st_size - 1)
    result = ocr.extract(image)
    assert result.coverage == ocr.COVERAGE_UNSUPPORTED
    assert result.reason == "file_too_large"


def test_a_character_cap_makes_the_read_partial(image: Path, monkeypatch) -> None:
    _stub(monkeypatch)
    result = ocr.extract(image, max_chars=4)
    assert result.coverage == ocr.COVERAGE_PARTIAL
    assert result.reason == "text_truncated"
    assert result.text == TEXT[:4]


def test_a_page_that_fails_to_recognise_keeps_the_pages_that_did(
        tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "scan.pdf"
    source.write_bytes(b"%PDF-1.4" + b"0" * 1024)
    monkeypatch.setattr(ocr, "available", lambda: True)

    def render(path, target, pages):
        written = []
        for index in range(2):
            page = target / f"page-{index + 1}.png"
            page.write_bytes(b"png")
            written.append(page)
        return True, sorted(written), ""

    monkeypatch.setattr(ocr, "render_pdf_pages", render)
    monkeypatch.setattr(ocr, "analyze_layout", lambda path: {})
    calls = {"n": 0}

    def recognize(path):
        calls["n"] += 1
        return (False, "", "ocr_failed") if calls["n"] == 2 else (True, "第一页正文", "")

    monkeypatch.setattr(ocr, "recognize_image", recognize)
    result = ocr.extract(source)
    assert result.pages == 2
    assert "第一页正文" in result.text
    assert result.coverage == ocr.COVERAGE_PARTIAL
    assert "ocr_failed" in result.reason


def test_pages_carry_their_number_so_evidence_can_be_located(tmp_path: Path, monkeypatch) -> None:
    source = tmp_path / "scan.pdf"
    source.write_bytes(b"%PDF-1.4" + b"0" * 1024)
    monkeypatch.setattr(ocr, "available", lambda: True)

    def render(path, target, pages):
        written = []
        for index in range(2):
            page = target / f"page-{index + 1}.png"
            page.write_bytes(b"png")
            written.append(page)
        return True, sorted(written), ""

    monkeypatch.setattr(ocr, "render_pdf_pages", render)
    monkeypatch.setattr(ocr, "recognize_image", lambda path: (True, "正文", ""))
    monkeypatch.setattr(ocr, "analyze_layout", lambda path: {})
    result = ocr.extract(source)
    assert result.ok
    assert "[第 1 页]" in result.text and "[第 2 页]" in result.text


def test_a_budget_stop_propagates_instead_of_reading_as_empty(image: Path, monkeypatch) -> None:
    _stub(monkeypatch)
    budget = ScanBudget({"max_bytes_read": 4})
    with pytest.raises(BudgetExceeded):
        ocr.extract(image, budget=budget)


def test_layout_ratios_become_named_signals() -> None:
    signals = ocr._layout_signals({"red_ratio_top": 0.03, "red_ratio_lower": 0.005})
    assert signals["red_title_band"] is True
    assert signals["red_seal"] is False
    empty = ocr._layout_signals({})
    assert empty["red_title_band"] is False and empty["red_seal"] is False
