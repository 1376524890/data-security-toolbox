"""Bounded OCR for images and scanned PDFs, and the layout signals it yields.

The platform's text detection only ever saw text that had a text layer, so a
scanned page or a photographed 公文 was inventoried and reported as
"binary_metadata_only" - present in the asset list, never examined. This module
closes that gap with the OCR tools a Debian host already packages
(``tesseract-ocr`` + ``poppler-utils`` for PDF rasterising), and it is careful
about three things the rest of the scanner is careful about too:

* **Bounded.** Only the first ``MAX_PAGES`` pages are rendered, the recognised
  text is capped, each external call has a timeout, and every produced byte is
  charged to the scan budget. OCR cannot turn a five-page scan into an hour.
* **Honest.** A missing binary, a failed render or a page with no recognised
  text is reported as such (``unavailable`` / ``failed`` / ``partial``) and never
  as an empty, apparently clean result.
* **Off by default when absent.** ``available()`` is checked first; without the
  tools the module degrades to the previous behaviour instead of raising.

Layout analysis runs on the first page only and is deliberately coarse: a red
ban across the top and/or a red seal low on the page. It is a *signal*, reported
next to the recognised text, not a verdict on its own.
"""
from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

#: Overridable so a test can point at a stub without a real tesseract install.
TESSERACT_BIN = "tesseract"
PDFTOPPM_BIN = "pdftoppm"

#: Chinese first: the documents this feature exists for are Chinese.
OCR_LANGUAGES = "chi_sim+eng"
#: A page whose recognition hangs is abandoned instead of holding the worker.
PAGE_TIMEOUT_SECONDS = 60
#: Rendering DPI for PDF pages: enough for 小四 body text, cheap enough to page.
PDF_RENDER_DPI = 150

MAX_PAGES = 20
MAX_CHARS = 200_000
#: A raster larger than this is left uninspected rather than fed to tesseract:
#: a 200 MP scan costs minutes of CPU and its text is unreadable anyway. Reported
#: as ``unsupported``/``file_too_large``, never as a clean read.
MAX_IMAGE_BYTES = 30 * 1024 * 1024
#: Layout ratios are scale-invariant, so the page is measured on a thumbnail and
#: the per-pixel loop never runs over a full-resolution image.
LAYOUT_SAMPLE_EDGE = 256

COVERAGE_COMPLETE = "complete"
COVERAGE_PARTIAL = "partial"
COVERAGE_FAILED = "failed"
COVERAGE_UNAVAILABLE = "unavailable"
COVERAGE_UNSUPPORTED = "unsupported"

IMAGE_SUFFIXES = frozenset({".png", ".jpg", ".jpeg", ".bmp", ".tif", ".tiff", ".gif", ".webp"})
PDF_SUFFIXES = frozenset({".pdf"})

#: A red pixel is one whose red channel dominates both others by this margin.
_RED_MARGIN = 40
_RED_MIN_VALUE = 120

_AVAILABILITY: bool | None = None


@dataclass(slots=True)
class OcrResult:
    """Recognised text plus how much of the document was actually read."""

    text: str = ""
    pages: int = 0
    coverage: str = COVERAGE_UNAVAILABLE
    reason: str = "not_attempted"
    layout: dict = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.coverage in {COVERAGE_COMPLETE, COVERAGE_PARTIAL}


def is_image(suffix: str) -> bool:
    return str(suffix).lower() in IMAGE_SUFFIXES


def is_pdf(suffix: str) -> bool:
    return str(suffix).lower() in PDF_SUFFIXES


def supported(suffix: str) -> bool:
    return is_image(suffix) or is_pdf(suffix)


def available() -> bool:
    """Whether the OCR toolchain is installed; cached, since it cannot change."""
    global _AVAILABILITY
    if _AVAILABILITY is None:
        _AVAILABILITY = bool(shutil.which(TESSERACT_BIN))
    return _AVAILABILITY


def reset_availability_cache() -> None:
    """Forget the cached probe (tests, and a host that just installed tesseract)."""
    global _AVAILABILITY
    _AVAILABILITY = None


def _run(command: list[str], *, timeout: int = PAGE_TIMEOUT_SECONDS) -> tuple[bool, str, str]:
    """Run one external tool; never raise for a missing binary or a timeout."""
    try:
        completed = subprocess.run(
            command, capture_output=True, timeout=timeout, check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, "", type(exc).__name__
    stdout = completed.stdout.decode("utf-8", "replace") if completed.stdout else ""
    stderr = completed.stderr.decode("utf-8", "replace") if completed.stderr else ""
    return completed.returncode == 0, stdout, stderr


def recognize_image(path: Path) -> tuple[bool, str, str]:
    """OCR one image file through tesseract.

    Default page segmentation (``--psm 3``): a 公文 page is a title band over
    body text, not the single uniform block that ``--psm 6`` assumes.
    """
    return _run([TESSERACT_BIN, str(path), "stdout", "-l", OCR_LANGUAGES, "--psm", "3"])


def render_pdf_pages(path: Path, target: Path, pages: int) -> tuple[bool, list[Path], str]:
    """Rasterise at most ``pages`` pages of ``path`` into ``target`` as PNGs."""
    ok, _stdout, error = _run([
        PDFTOPPM_BIN, "-png", "-r", str(PDF_RENDER_DPI),
        "-f", "1", "-l", str(max(1, pages)), str(path), str(target / "page"),
    ], timeout=PAGE_TIMEOUT_SECONDS * 2)
    rendered = sorted((target).glob("page*.png"))
    if not ok and not rendered:
        return False, [], error or "render_failed"
    return True, rendered, ""


def analyze_layout(image_path: Path) -> dict:
    """Coarse page-level signals: a red title band and a red seal.

    Deliberately coarse and reported as evidence, never as a classification on
    its own - colour cannot tell a 红头文件 from a red poster, so the text rules
    are what name the document type.
    """
    try:
        from PIL import Image
    except ImportError:  # pragma: no cover - Pillow ships with the platform
        return {}
    try:
        with Image.open(image_path) as image:
            rgb = image.convert("RGB")
            width, height = rgb.size
            if width < 8 or height < 8:
                return {}
            if max(width, height) > LAYOUT_SAMPLE_EDGE:
                rgb = rgb.copy()
                rgb.thumbnail((LAYOUT_SAMPLE_EDGE, LAYOUT_SAMPLE_EDGE))
                width, height = rgb.size
            top = rgb.crop((0, 0, width, max(1, int(height * 0.20))))
            lower = rgb.crop((0, int(height * 0.45), width, height))
            return {
                "red_ratio_top": round(_red_ratio(top), 4),
                "red_ratio_lower": round(_red_ratio(lower), 4),
            }
    except Exception:
        return {}


def _red_ratio(image) -> float:
    pixels = image.getdata()
    total = 0
    red = 0
    for r, g, b in pixels:
        total += 1
        if r >= _RED_MIN_VALUE and r - g >= _RED_MARGIN and r - b >= _RED_MARGIN:
            red += 1
    return (red / total) if total else 0.0


def _layout_signals(layout: dict) -> dict:
    """Turn raw colour ratios into named, thresholded signals."""
    top = float(layout.get("red_ratio_top") or 0)
    lower = float(layout.get("red_ratio_lower") or 0)
    return {
        **layout,
        # A 红头文件's title band is a solid red rule: a couple of percent of the
        # top fifth is already far above the noise of a coloured letterhead.
        "red_title_band": top >= 0.02,
        # A seal is a red blob covering a noticeable part of the lower page.
        "red_seal": lower >= 0.01,
    }


def _spend(budget, count: int) -> None:
    if budget is not None and count:
        budget.spend_bytes(int(count))


def _check(budget) -> None:
    if budget is not None:
        budget.check()


def extract(path: Path, *, budget=None, max_pages: int = MAX_PAGES,
            max_chars: int = MAX_CHARS) -> OcrResult:
    """OCR an image or a scanned PDF, bounded by pages, characters and budget.

    ``budget`` is the shared :class:`~shared.scanning.budget.ScanBudget` when the
    caller has one; without it the module still bounds itself.
    """
    suffix = path.suffix.lower()
    if not supported(suffix):
        return OcrResult(coverage=COVERAGE_UNSUPPORTED, reason="unsupported_format")
    if not available():
        return OcrResult(coverage=COVERAGE_UNAVAILABLE, reason="ocr_unavailable")
    pages_limit = max(1, int(max_pages))
    try:
        if is_image(suffix):
            return _extract_image(path, budget, max_chars)
        return _extract_pdf(path, budget, pages_limit, max_chars)
    except Exception as exc:  # noqa: BLE001 - one file must not end a scan
        from .budget import BudgetExceeded

        if isinstance(exc, BudgetExceeded):
            raise
        # ``ocr_error``, not ``type(exc).__name__``: the class name of a
        # third-party failure says which library broke, and this value is shown
        # to the operator and copied into the report.
        return OcrResult(coverage=COVERAGE_FAILED, reason="ocr_error")


def _extract_image(path: Path, budget, max_chars: int) -> OcrResult:
    _check(budget)
    try:
        size = path.stat().st_size
    except OSError:
        return OcrResult(coverage=COVERAGE_FAILED, reason="unreadable")
    if size > MAX_IMAGE_BYTES:
        return OcrResult(coverage=COVERAGE_UNSUPPORTED, reason="file_too_large")
    _spend(budget, size)
    # Spending the file's bytes is where a byte budget runs out; the caller has
    # to hear about it, not receive an apparently empty read.
    _check(budget)
    layout = _layout_signals(analyze_layout(path))
    ok, text, error = recognize_image(path)
    if not ok:
        return OcrResult(coverage=COVERAGE_FAILED, reason=error or "ocr_failed", layout=layout)
    truncated = len(text) > max_chars
    text = text[:max_chars]
    _spend(budget, len(text))
    # A read cut by the character cap was read in part; calling it complete is
    # how a truncated 公文 would come back looking like a clean one.
    coverage = COVERAGE_PARTIAL if (truncated or not text.strip()) else COVERAGE_COMPLETE
    if truncated:
        reason = "text_truncated"
    else:
        reason = "complete" if text.strip() else "no_text_recognized"
    return OcrResult(text=text, pages=1, coverage=coverage, reason=reason, layout=layout)


def _extract_pdf(path: Path, budget, max_pages: int, max_chars: int) -> OcrResult:
    _check(budget)
    try:
        _spend(budget, path.stat().st_size)
    except OSError:
        return OcrResult(coverage=COVERAGE_FAILED, reason="unreadable")
    _check(budget)
    with tempfile.TemporaryDirectory(prefix="dst-ocr-") as temp:
        target = Path(temp)
        ok, pages, error = render_pdf_pages(path, target, max_pages)
        if not ok:
            return OcrResult(coverage=COVERAGE_FAILED, reason=error or "pdf_render_failed")
        if not pages:
            return OcrResult(coverage=COVERAGE_UNSUPPORTED, reason="no_pages_rendered")
        layout = _layout_signals(analyze_layout(pages[0]))
        chunks: list[str] = []
        used = 0
        failed = ""
        stopped_early = False
        for index, page in enumerate(pages):
            _check(budget)
            try:
                _spend(budget, page.stat().st_size)
            except OSError:
                failed = failed or "unreadable_page"
                continue
            page_ok, text, page_error = recognize_image(page)
            if not page_ok:
                failed = failed or (page_error or "ocr_failed")
                continue
            if text:
                chunks.append(f"[第 {index + 1} 页]\n{text}")
                used += len(text)
                _spend(budget, len(text))
            if used >= max_chars:
                stopped_early = True
                break
        text = "\n".join(chunks)[:max_chars]
        # A page cap, a character cap and a failed page all mean the same thing:
        # the document was read in part.
        truncated = stopped_early or len(pages) >= max_pages
        if not text.strip():
            coverage = COVERAGE_FAILED if failed and not chunks else COVERAGE_PARTIAL
            return OcrResult(coverage=coverage, pages=len(pages),
                             reason=failed or "no_text_recognized", layout=layout)
        coverage = COVERAGE_PARTIAL if (truncated or failed) else COVERAGE_COMPLETE
        return OcrResult(text=text, pages=len(pages), coverage=coverage,
                         reason="text_truncated" if truncated else (failed or "complete"),
                         layout=layout)
