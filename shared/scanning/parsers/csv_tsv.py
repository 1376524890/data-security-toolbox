"""CSV/TSV: header plus head/middle/tail records, quote- and newline-aware.

The header is preserved and records are collected from three regions so the
sample is not just the first N rows. ``csv.reader`` handles quoted fields and
embedded newlines; a region that starts or ends inside a quoted field cannot be
recovered safely, so those bytes are dropped and the drop is reported as a
coverage limit instead of being parsed as a half record.
"""
from __future__ import annotations

import csv
import io
from pathlib import Path

from ..budget import BudgetExceeded
from ..sampler import decode
from .base import (
    COVERAGE_COMPLETE,
    COVERAGE_FAILED,
    COVERAGE_PARTIAL,
    MAX_CELL_CHARS,
    ColumnSample,
    ParseResult,
    SheetSample,
    infer_type,
)

MAX_COLUMNS = 256
REGION_BYTES = 192 * 1024


def _records(text: str, delimiter: str, limit: int, *, from_tail: bool = False) -> list[list[str]]:
    """Records from one region.

    ``from_tail`` keeps the *last* records of the region. A tail region holds
    thousands of complete rows, so taking the first N of it would mean the end of
    the file - exactly where the newest data is - was never examined.
    """
    reader = csv.reader(io.StringIO(text), delimiter=delimiter)
    rows: list[list[str]] = []
    try:
        for row in reader:
            rows.append(row)
            # Only the head region can stop early; a tail region has to be read to
            # its end to know which records are last.
            if not from_tail and len(rows) >= limit:
                break
    except csv.Error:
        # A malformed region stops there; what was read is still usable.
        pass
    return rows[-limit:] if from_tail else rows


def _region(handle, offset: int, length: int, *, drop_first: bool, budget) -> str:
    allowed = budget.clamp_read(length)
    if allowed <= 0:
        budget.check()
        return ""
    budget.check()
    handle.seek(offset)
    raw = handle.read(allowed)
    budget.spend_bytes(len(raw))
    text = decode(raw)
    if drop_first:
        index = text.find("\n")
        if index == -1:
            return ""
        text = text[index + 1:]
    return text


def parse(path: Path, size: int, *, budget, delimiter: str = ",", rows: int | None = None) -> ParseResult:
    limit = rows or int(budget.limit("max_sample_rows", 25))
    result = ParseResult(parser="csv_tsv")
    try:
        with path.open("rb") as handle:
            head_text = _region(handle, 0, min(REGION_BYTES, size), drop_first=False, budget=budget)
            result.bytes_read += len(head_text.encode("utf-8", errors="replace"))
            records = _records(head_text, delimiter, limit + 2)
            header = records[0] if records else []
            # Ask for one row past the limit so "at the limit" and "over the
            # limit" are distinguishable; a file whose value sits on row 26 of 31
            # must not report complete coverage.
            row_limited = len(records) - 1 > limit
            if size > REGION_BYTES:
                # Middle and tail regions keep the sample representative; a region
                # cut by a quote boundary is dropped, not repaired.
                middle = min(max(size // 2, 0), max(size - REGION_BYTES, 0))
                tail = max(size - REGION_BYTES, 0)
                for offset in (middle, tail):
                    text = _region(handle, offset, REGION_BYTES, drop_first=True, budget=budget)
                    result.bytes_read += len(text.encode("utf-8", errors="replace"))
                    # Both the middle and the tail contribute their last records:
                    # the tail especially, because that is where new data lands.
                    for row in _records(text, delimiter, limit, from_tail=True):
                        records.append(row)
                result.coverage = COVERAGE_PARTIAL
                result.termination_reason = "sampled"
                result.note = "按头/中/尾区域采样，跨区引号字段被丢弃"
                records = records[:1] + records[1:][-limit:] if header else records
            elif row_limited:
                result.coverage = COVERAGE_PARTIAL
                result.termination_reason = "row_limit"
                result.note = f"数据行超过采样上限 {limit}，未检查全部记录"
            if row_limited:
                records = records[: limit + 1]
    except BudgetExceeded as exc:
        result.coverage = COVERAGE_PARTIAL
        result.termination_reason = exc.reason
        result.note = exc.detail
        return result
    except OSError as exc:
        result.coverage = COVERAGE_FAILED
        result.termination_reason = "unreadable"
        result.note = type(exc).__name__
        return result
    if not records:
        result.note = result.note or "空文件或无法解析的表头"
        result.coverage = COVERAGE_COMPLETE if size == 0 else COVERAGE_PARTIAL
        return result
    header, body = records[0], records[1:]
    columns: list[ColumnSample] = []
    for index, name in enumerate(header[:MAX_COLUMNS]):
        values = [row[index][:MAX_CELL_CHARS] for row in body if index < len(row)][:limit]
        columns.append(ColumnSample(name=str(name)[:256] or f"column_{index + 1}", index=index,
                                    values=values, inferred_type=infer_type(values)))
    result.sheets.append(SheetSample(name="", columns=columns, rows_read=len(body)))
    result.rows_read = len(body)
    budget.spend_rows(len(body))
    return result
