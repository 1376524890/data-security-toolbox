"""Parser output shape.

A parser never performs detection and never returns a matched value. It reports
the *structure* it could observe (sheet, column, header, sample cells) plus what
it cost and how much of the file it actually covered, so the caller can merge
that with engine Detections and report an honest coverage statement.

Sample values live in ``ColumnSample.values`` for the engine call only. The
report builder must translate them into counts; ``as_evidence()`` exists to make
that the path of least resistance.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

COVERAGE_COMPLETE = "complete"
COVERAGE_PARTIAL = "partial"
COVERAGE_FAILED = "failed"

#: Caps sample cells so one absurd cell cannot dominate memory.
MAX_CELL_CHARS = 512
#: Longest sample text handed to the engine for one column.
MAX_COLUMN_SAMPLE_CHARS = 4096


@dataclass(slots=True)
class ColumnSample:
    name: str
    index: int
    values: list[str] = field(default_factory=list)
    inferred_type: str = "unknown"

    def sample_text(self) -> str:
        return " ".join(value[:MAX_CELL_CHARS] for value in self.values)[:MAX_COLUMN_SAMPLE_CHARS]

    def as_evidence(self) -> dict[str, Any]:
        """Column metadata without a single sample value."""
        return {
            "name": self.name,
            "column_index": self.index,
            "sample_size": len(self.values),
            "sample_values_count": len([value for value in self.values if value]),
            "inferred_type": self.inferred_type,
        }


@dataclass(slots=True)
class SheetSample:
    name: str
    columns: list[ColumnSample] = field(default_factory=list)
    rows_read: int = 0

    def as_evidence(self) -> dict[str, Any]:
        return {"sheet_name": self.name, "rows_read": self.rows_read,
                "columns": [column.as_evidence() for column in self.columns]}


@dataclass(slots=True)
class ParseResult:
    parser: str = ""
    sheets: list[SheetSample] = field(default_factory=list)
    #: Text for whole-file scanning (GenericTextParser and degraded paths only).
    text: str = ""
    bytes_read: int = 0
    rows_read: int = 0
    coverage: str = COVERAGE_COMPLETE
    termination_reason: str = "complete"
    #: Set when a structured parser had to fall back, e.g. "generic_text".
    degraded_to: str = ""
    note: str = ""

    @property
    def complete(self) -> bool:
        return self.coverage == COVERAGE_COMPLETE and self.termination_reason == "complete"

    def columns(self) -> list[ColumnSample]:
        return [column for sheet in self.sheets for column in sheet.columns]

    def as_evidence(self) -> dict[str, Any]:
        return {
            "parser": self.parser,
            "bytes_read": self.bytes_read,
            "rows_read": self.rows_read,
            "coverage": self.coverage,
            "termination_reason": self.termination_reason,
            "degraded_to": self.degraded_to,
            "sheet_count": len(self.sheets),
            "column_count": len(self.columns()),
            "sheets": [sheet.as_evidence() for sheet in self.sheets],
            "note": self.note,
        }


def infer_type(values: list[str]) -> str:
    """A conservative, non-personal type guess used only for display."""
    present = [value for value in values if value]
    if not present:
        return "empty"
    if all(value.strip().lstrip("-").isdigit() for value in present):
        return "integer"
    try:
        for value in present:
            float(value)
        return "number"
    except ValueError:
        pass
    lowered = {value.strip().lower() for value in present}
    if lowered <= {"true", "false", "0", "1"}:
        return "boolean"
    return "text"
