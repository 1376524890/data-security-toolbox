"""Parser dispatch, driven by the bounded type probe in :mod:`shared.scanning.magic`."""
from __future__ import annotations

from pathlib import Path

from ..magic import (
    KIND_BINARY,
    KIND_SQL_GZ,
    KIND_TABLE,
    KIND_XLSX,
    FileType,
)
from .base import COVERAGE_FAILED, ParseResult  # noqa: F401  (re-exported)


def parse_file(path: Path, size: int, file_type: FileType, *, budget) -> ParseResult:
    """Parse ``path`` according to ``file_type``; never raise for scan-level stops."""
    if file_type.kind == KIND_BINARY:
        result = ParseResult(parser="", coverage="complete")
        result.note = "二进制文件仅登记元数据，不做文本解码"
        return result
    if file_type.kind == KIND_XLSX:
        from . import xlsx

        return xlsx.parse(path, size, budget=budget)
    if file_type.kind == KIND_SQL_GZ:
        from . import sql

        return sql.parse(path, size, budget=budget, gzipped=True)
    if file_type.kind == KIND_TABLE:
        suffix = path.suffix.lower()
        if file_type.parser == "csv_tsv":
            from . import csv_tsv

            return csv_tsv.parse(path, size, budget=budget, delimiter="\t" if suffix == ".tsv" else ",")
        if file_type.parser == "json_like":
            from . import json_like

            return json_like.parse(path, size, budget=budget, jsonl=suffix in {".jsonl", ".ndjson"})
        if file_type.parser == "sql":
            from . import sql

            return sql.parse(path, size, budget=budget, gzipped=False)
    from . import generic_text

    return generic_text.parse(path, size, budget=budget)


__all__ = ["parse_file", "ParseResult", "COVERAGE_FAILED"]
