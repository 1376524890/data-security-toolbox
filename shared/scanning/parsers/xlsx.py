"""XLSX: a deliberately bounded streaming reader for the one container we open.

Every other archive (zip/rar/7z/tar) is listed, never unpacked. XLSX is the
exception because the platform must be able to read a spreadsheet, and that
exception is fenced by its own budget: ZIP entry count, per-entry uncompressed
size, overall compression ratio, sharedStrings count, sheet count, column count,
row count, bytes read and wall time. A file that trips any of these is reported
as Partial with the reason - it is never allowed to exhaust the probe.

``read_only`` streams rows but is not by itself a memory guarantee (sharedStrings
and the style table are still loaded by the library), which is exactly why the
container is inspected before the workbook is opened.
"""
from __future__ import annotations

import zipfile
from pathlib import Path

from ..budget import BudgetExceeded
from .base import (
    COVERAGE_FAILED,
    COVERAGE_PARTIAL,
    MAX_CELL_CHARS,
    ColumnSample,
    ParseResult,
    SheetSample,
    infer_type,
)

REQUIRED_PARTS = ("[Content_Types].xml", "xl/workbook.xml")
MAX_ROWS_PER_SHEET = 200
MAX_COLUMNS = 256


def _container_limits(budget) -> dict:
    return {
        "max_entries": int(budget.limit("xlsx_max_entries", 512)),
        "max_uncompressed": int(budget.limit("xlsx_max_uncompressed_bytes", 64 * 1024 * 1024)),
        "max_ratio": float(budget.limit("xlsx_max_compression_ratio", 200.0)),
        "max_shared_strings": int(budget.limit("xlsx_max_shared_strings", 200_000)),
        "max_sheets": int(budget.limit("xlsx_max_sheets", 32)),
        "max_rows": int(budget.limit("xlsx_max_rows", MAX_ROWS_PER_SHEET)),
        "max_columns": int(budget.limit("xlsx_max_columns", MAX_COLUMNS)),
    }


def inspect_container(path: Path, budget) -> tuple[bool, str, dict]:
    """Cheap structural check before any XML is parsed."""
    limits = _container_limits(budget)
    stats = {"entries": 0, "uncompressed_bytes": 0, "max_ratio": 0.0, "shared_strings": 0}
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            stats["entries"] = len(infos)
            if len(infos) > limits["max_entries"]:
                return False, f"ZIP entry 数 {len(infos)} 超过上限 {limits['max_entries']}", stats
            for info in infos:
                stats["uncompressed_bytes"] += info.file_size
                if info.compress_size:
                    stats["max_ratio"] = max(stats["max_ratio"], info.file_size / info.compress_size)
            if stats["uncompressed_bytes"] > limits["max_uncompressed"]:
                return False, f"解压后大小 {stats['uncompressed_bytes']} 超过上限", stats
            if stats["max_ratio"] > limits["max_ratio"]:
                return False, f"压缩比 {stats['max_ratio']:.0f} 超过上限 {limits['max_ratio']:.0f}", stats
            names = set(archive.namelist())
            if not all(part in names for part in REQUIRED_PARTS):
                return False, "不是有效的 XLSX 容器", stats
            if "xl/sharedStrings.xml" in names:
                # Counting "<si>" occurrences gives the shared-string count without
                # building the whole DOM.
                with archive.open("xl/sharedStrings.xml") as handle:
                    counted = 0
                    carry = b""
                    while True:
                        budget.check()
                        chunk = handle.read(64 * 1024)
                        if not chunk:
                            break
                        budget.spend_bytes(len(chunk))
                        counted += (carry + chunk).count(b"<si>") + (carry + chunk).count(b"<si ")
                        carry = chunk[-4:]
                        if counted > limits["max_shared_strings"]:
                            return False, f"sharedStrings 超过上限 {limits['max_shared_strings']}", stats
                    stats["shared_strings"] = counted
    except BudgetExceeded:
        raise
    except (zipfile.BadZipFile, OSError) as exc:
        return False, f"容器读取失败({type(exc).__name__})", stats
    return True, "", stats


def parse(path: Path, size: int, *, budget, rows: int | None = None) -> ParseResult:
    limits = _container_limits(budget)
    limit = rows or limits["max_rows"]
    result = ParseResult(parser="xlsx")
    try:
        ok, reason, stats = inspect_container(path, budget)
    except BudgetExceeded as exc:
        result.coverage = COVERAGE_PARTIAL
        result.termination_reason = exc.reason
        result.note = exc.detail
        return result
    result.bytes_read = stats.get("uncompressed_bytes", 0)
    if not ok:
        result.coverage = COVERAGE_FAILED
        result.termination_reason = "container_rejected"
        result.note = reason
        return result

    try:
        from openpyxl import load_workbook
    except ImportError:
        # Missing optional dependency is reported as a capability gap, never
        # swallowed into an empty-but-successful result.
        result.coverage = COVERAGE_FAILED
        result.termination_reason = "parser_unavailable"
        result.note = "openpyxl 未安装，无法解析 XLSX"
        return result

    try:
        workbook = load_workbook(filename=str(path), read_only=True, data_only=True, keep_links=False)
    except Exception as exc:  # openpyxl raises a wide range of parse errors
        result.coverage = COVERAGE_FAILED
        result.termination_reason = "parse_error"
        result.note = f"{type(exc).__name__}"
        return result
    try:
        names = list(workbook.sheetnames)
        if len(names) > limits["max_sheets"]:
            result.note = f"工作表 {len(names)} 超过上限 {limits['max_sheets']}，仅解析前 {limits['max_sheets']} 个"
            names = names[: limits["max_sheets"]]
            result.coverage = COVERAGE_PARTIAL
            result.termination_reason = "sheet_limit"
        for sheet_name in names:
            budget.check()
            sheet = workbook[sheet_name]
            rows_iter = sheet.iter_rows(values_only=True)
            try:
                header = next(rows_iter)
            except StopIteration:
                result.sheets.append(SheetSample(name=str(sheet_name)[:128], columns=[], rows_read=0))
                continue
            headers = [str(cell)[:256] if cell is not None else "" for cell in header][: limits["max_columns"]]
            buckets: list[list[str]] = [[] for _ in headers]
            read_rows = 0
            for row in rows_iter:
                if read_rows >= limit:
                    result.coverage = COVERAGE_PARTIAL
                    result.termination_reason = "row_limit"
                    result.note = result.note or f"行数超过上限 {limit}"
                    break
                budget.check()
                for index in range(len(headers)):
                    if index < len(row) and row[index] is not None:
                        buckets[index].append(str(row[index])[:MAX_CELL_CHARS])
                read_rows += 1
                budget.spend_bytes(1)
            columns = [
                ColumnSample(name=name or f"column_{index + 1}", index=index, values=values,
                             inferred_type=infer_type(values))
                # `buckets` is built one-per-header, so strict=True only asserts it.
                for index, (name, values) in enumerate(zip(headers, buckets, strict=True))
            ]
            result.sheets.append(SheetSample(name=str(sheet_name)[:128], columns=columns, rows_read=read_rows))
            result.rows_read += read_rows
            budget.spend_rows(read_rows)
    except BudgetExceeded as exc:
        result.coverage = COVERAGE_PARTIAL
        result.termination_reason = exc.reason
        result.note = exc.detail
    except Exception as exc:  # malformed XML partway through a sheet
        result.coverage = COVERAGE_PARTIAL
        result.termination_reason = "parse_error"
        result.note = f"{type(exc).__name__}"
    finally:
        try:
            workbook.close()
        except Exception:
            pass
    if result.bytes_read == 0 and not result.sheets:
        result.coverage = COVERAGE_FAILED
    return result
