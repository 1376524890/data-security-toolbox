"""JSON and JSONL.

A small JSON document is parsed whole. A large one is *not* parsed from an
arbitrary byte offset: a slice of a JSON object is not a valid object, so the
parser degrades to bounded generic-text scanning and says so, instead of
inventing keys from a fragment. JSONL is line-oriented, so head/middle/tail lines
are individually valid records and can be parsed as such.
"""
from __future__ import annotations

import json
from pathlib import Path

from ..budget import BudgetExceeded
from ..sampler import decode, sample_text
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
WHOLE_PARSE_LIMIT = 4 * 1024 * 1024
REGION_BYTES = 192 * 1024


def _records_to_columns(records: list[dict], limit: int) -> list[ColumnSample]:
    names: list[str] = []
    for record in records[:limit]:
        for key in record:
            if key not in names:
                names.append(str(key))
    columns: list[ColumnSample] = []
    for index, name in enumerate(names[:MAX_COLUMNS]):
        values = [str(record.get(name, ""))[:MAX_CELL_CHARS] for record in records[:limit]
                  if isinstance(record, dict)]
        columns.append(ColumnSample(name=name[:256], index=index, values=values,
                                    inferred_type=infer_type(values)))
    return columns


def parse(path: Path, size: int, *, budget, jsonl: bool, rows: int | None = None) -> ParseResult:
    limit = rows or int(budget.limit("max_sample_rows", 25))
    result = ParseResult(parser="json_like")
    if size == 0:
        result.note = "空文件"
        return result
    try:
        whole_limit = min(WHOLE_PARSE_LIMIT, int(budget.limit("max_single_file_size", WHOLE_PARSE_LIMIT)))
        if not jsonl and size <= whole_limit and budget.clamp_read(size) >= size:
            budget.check()
            with path.open("rb") as handle:
                raw = handle.read(size)
            budget.spend_bytes(len(raw))
            result.bytes_read = len(raw)
            data = json.loads(decode(raw))
            records = data if isinstance(data, list) else [data]
            records = [row for row in records if isinstance(row, dict)]
            if not records:
                result.note = "JSON 顶层不是对象数组，按通用文本处理"
                return _degrade(path, size, budget, result)
            result.sheets.append(SheetSample(name="", columns=_records_to_columns(records, limit),
                                             rows_read=len(records[:limit])))
            result.rows_read = len(records[:limit])
            budget.spend_rows(result.rows_read)
            return result
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
    except (ValueError, TypeError) as exc:
        # Malformed JSON: fall back to text scanning so the file is still examined,
        # and record that the structure was not understood.
        result.note = f"JSON 解析失败({type(exc).__name__})，降级通用文本"
        return _degrade(path, size, budget, result)

    # Large JSONL: head/middle/tail lines, each one a complete record.
    if jsonl:
        sample = sample_text(path, size, budget=budget, block_size=REGION_BYTES)
        result.bytes_read = sample.bytes_read
        # The sampler walks head -> tail, so the *last* parsable lines are the
        # newest records; keep those instead of stopping at the first N.
        records: list[dict] = []
        for line in sample.text.splitlines():
            stripped = line.strip()
            if not stripped:
                continue
            try:
                item = json.loads(stripped)
            except ValueError:
                continue
            if isinstance(item, dict):
                records.append(item)
        records = records[-limit:]
        if records:
            result.sheets.append(SheetSample(name="", columns=_records_to_columns(records, limit),
                                            rows_read=len(records)))
            result.rows_read = len(records)
            budget.spend_rows(len(records))
        result.coverage = COVERAGE_PARTIAL
        result.termination_reason = sample.termination_reason if sample.termination_reason != "complete" else "sampled"
        result.note = "大文件按头/中/尾行采样"
        if not records:
            return _degrade(path, size, budget, result)
        return result

    result.note = "大 JSON 不按偏移切片解析，降级通用文本"
    return _degrade(path, size, budget, result)


def _degrade(path: Path, size: int, budget, result: ParseResult) -> ParseResult:
    from . import generic_text

    fallback = generic_text.parse(path, size, budget=budget)
    fallback.parser = "json_like"
    fallback.degraded_to = "generic_text"
    fallback.bytes_read += result.bytes_read
    if fallback.coverage == COVERAGE_COMPLETE and result.note:
        fallback.coverage = COVERAGE_PARTIAL
    fallback.note = "; ".join(item for item in (result.note, fallback.note) if item)
    return fallback
