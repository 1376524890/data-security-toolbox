"""SQL dumps, with a bounded streaming decompressor for `.sql.gz`.

The head of a dump carries DDL (so column names are visible) while the data sits
in INSERT statements spread through the file, so head/middle/tail regions are all
scanned. `.sql.gz` cannot be seeked, so it is decompressed as a stream with both
an input and an output cap - a gzip bomb stops at the limit instead of expanding
into memory. Arbitrary SQL dialects and multi-line procedural bodies are out of
scope and are not claimed.
"""
from __future__ import annotations

import gzip
import re
from pathlib import Path

from ..budget import BudgetExceeded
from ..sampler import decode
from .base import (
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
#: Cap on the decompressed output of a `.sql.gz`, independent of the input size.
MAX_DECOMPRESSED_BYTES = 8 * 1024 * 1024
_INSERT_HEAD_RE = re.compile(r"\bINSERT\s+INTO\s+[`\"\[]?(\w+)[`\"\]]?\s*\(", re.IGNORECASE)
_DDL_HEAD_RE = re.compile(r"\bCREATE\s+TABLE\b[^(]*\(", re.IGNORECASE)
_COLUMN_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}")


def _parenthesised(text: str, start: int) -> str:
    """Body of the parenthesis group that opens just before ``start``.

    A regex like ``\\(([^)]*)\\)`` stops at the first ``)``, so a perfectly normal
    definition such as ``phone varchar(20), id_card varchar(18)`` loses every
    column after the first nested type. Scanning with a depth counter keeps them.
    """
    depth = 0
    for index in range(start, len(text)):
        character = text[index]
        if character == "(":
            depth += 1
        elif character == ")":
            depth -= 1
            if depth == 0:
                return text[start + 1:index]
    return ""


def _column_names(tokens: list[str]) -> list[str]:
    names: list[str] = []
    for token in tokens:
        cleaned = token.strip().strip('`"[]').split()[0] if token.strip() else ""
        cleaned = cleaned.strip('`"[]')
        if _COLUMN_RE.fullmatch(cleaned or "") and cleaned not in names:
            names.append(cleaned)
    return names


def _column_groups(text: str) -> list[str]:
    blocks: list[str] = []
    for match in list(_DDL_HEAD_RE.finditer(text)) + list(_INSERT_HEAD_RE.finditer(text)):
        body = _parenthesised(text, match.end() - 1)
        if body:
            blocks.append(body)
    return blocks


def sql_columns(text: str) -> list[str]:
    names: list[str] = []
    for block in _column_groups(text):
        for name in _column_names(block.split(",")):
            if name not in names:
                names.append(name)
    return names[:MAX_COLUMNS]


def _regions_plain(handle, size: int, budget) -> tuple[list[str], int, bool]:
    regions: list[str] = []
    read = 0
    for offset, length in ((0, min(REGION_BYTES, size)),):
        allowed = budget.clamp_read(length)
        if allowed <= 0:
            budget.check()
            return regions, read, size > 0
        budget.check()
        handle.seek(offset)
        raw = handle.read(allowed)
        budget.spend_bytes(len(raw))
        read += len(raw)
        regions.append(decode(raw))
    sampled = size > REGION_BYTES
    if sampled:
        for offset in (max(size // 2, 0), max(size - REGION_BYTES, 0)):
            allowed = budget.clamp_read(REGION_BYTES)
            if allowed <= 0:
                budget.check()
                return regions, read, True
            budget.check()
            handle.seek(offset)
            raw = handle.read(allowed)
            budget.spend_bytes(len(raw))
            read += len(raw)
            regions.append(decode(raw))
    return regions, read, sampled


def _regions_gzip(path: Path, budget) -> tuple[list[str], int, bool, str]:
    """Stream-decompress with a hard output cap; never expands unbounded."""
    cap = min(MAX_DECOMPRESSED_BYTES, max(int(budget.limit("max_bytes_read", MAX_DECOMPRESSED_BYTES)), 1024))
    regions: list[str] = []
    read = 0
    head = bytearray()
    middle = bytearray()
    tail = bytearray()
    warning = ""
    try:
        with gzip.open(path, "rb") as handle:
            while True:
                budget.check()
                allowed = budget.clamp_read(64 * 1024)
                if allowed <= 0:
                    warning = "达到字节预算上限，停止解压"
                    break
                chunk = handle.read(allowed)
                if not chunk:
                    break
                read += len(chunk)
                budget.spend_bytes(len(chunk))
                if len(head) < REGION_BYTES:
                    head.extend(chunk[: REGION_BYTES - len(head)])
                    continue
                middle.extend(chunk)
                if len(middle) > 2 * REGION_BYTES:
                    tail.extend(middle[:REGION_BYTES])
                    del middle[:REGION_BYTES]
                if read >= cap:
                    warning = f"解压达到上限 {cap} 字节，仅覆盖已处理部分"
                    break
    except (OSError, EOFError) as exc:
        warning = f"gzip 读取失败({type(exc).__name__})"
    except BudgetExceeded as exc:
        warning = f"{exc.reason}: {exc.detail}"
    regions.extend(decode(bytes(item)) for item in (head, middle[:REGION_BYTES], tail) if item)
    return regions, read, True, warning


def parse(path: Path, size: int, *, budget, gzipped: bool = False, rows: int | None = None) -> ParseResult:
    result = ParseResult(parser="sql")
    try:
        if gzipped:
            regions, read, sampled, warning = _regions_gzip(path, budget)
            for item in ([warning] if warning else []):
                result.note = "; ".join(part for part in (result.note, item) if part)
        else:
            with path.open("rb") as handle:
                regions, read, sampled = _regions_plain(handle, size, budget)
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
    result.bytes_read = read
    if sampled:
        result.coverage = COVERAGE_PARTIAL
        result.termination_reason = "sampled"
    names = sql_columns("\n".join(regions))
    columns = [ColumnSample(name=name, index=index, values=[], inferred_type="unknown")
               for index, name in enumerate(names[:MAX_COLUMNS])]
    result.sheets.append(SheetSample(name="", columns=columns, rows_read=0))
    if not columns:
        result.note = result.note or "未识别到 CREATE TABLE / INSERT 列名"
    return result


__all__ = ["parse", "sql_columns", "MAX_CELL_CHARS", "infer_type"]
