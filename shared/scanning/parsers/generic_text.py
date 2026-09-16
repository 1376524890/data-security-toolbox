"""Generic text: the fallback parser and the one used for unknown extensions.

Content is read from bounded windows spread over the file (head/middle/tail), so
a sensitive value in the middle of a large log is found even though the file is
far larger than the sample budget. Encoding is handled for UTF-8 and GB18030,
and a truncated or non-newline-terminated first/last line is reported rather than
silently presented as a full record.
"""
from __future__ import annotations

from pathlib import Path

from ..budget import BudgetExceeded
from ..sampler import sample_text
from .base import COVERAGE_COMPLETE, COVERAGE_FAILED, COVERAGE_PARTIAL, ParseResult, SheetSample


def parse(path: Path, size: int, *, budget, block_size: int | None = None) -> ParseResult:
    block = block_size or int(budget.limit("sample_block_size", 64 * 1024))
    sample = sample_text(path, size, budget=budget, block_size=block)
    result = ParseResult(parser="generic_text", text=sample.text, bytes_read=sample.bytes_read)
    if sample.termination_reason == "unreadable":
        result.coverage = COVERAGE_FAILED
        result.termination_reason = "unreadable"
        result.note = sample.warning
        return result
    if sample.termination_reason == "complete" and sample.coverage == COVERAGE_COMPLETE:
        result.coverage = COVERAGE_COMPLETE
    else:
        result.coverage = COVERAGE_PARTIAL
        result.termination_reason = sample.termination_reason
        result.note = f"sampled at offsets {sample.positions[:8]}"
    # A single "column" lets the generic path reuse the same column-level
    # evidence pipeline as the structured parsers.
    result.sheets.append(SheetSample(name="", columns=[], rows_read=len(sample.text.splitlines())))
    result.rows_read = len(sample.text.splitlines())
    budget.spend_rows(result.rows_read)
    return result


__all__ = ["parse", "sample_text", "BudgetExceeded"]
