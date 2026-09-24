"""One vocabulary for coverage, and the console table that has to agree with it.

The live data this module was written against contained ``partial`` + ``complete``
rows (``complete`` is both a status and the reason field's default) and a
``failed`` + ``SSHException`` row that printed a third-party class name into the
operator's reason column. Both are shape errors, not data errors, so both are
pinned here.

The console keeps its own copy of the labels because it cannot import Python.
That copy is checked against this one whenever the repository is on disk, so the
two cannot drift apart in a developer checkout; inside the backend image the
console source is not present and the check is skipped rather than faked.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from shared import coverage

REPO_ROOT = Path(__file__).resolve().parents[3]
FORMAT_TS = REPO_ROOT / "frontend" / "src" / "utils" / "format.ts"


# --------------------------------------------------------------------------
# Status and reason vocabulary
# --------------------------------------------------------------------------

def test_the_leftover_default_reason_is_not_reported_as_a_reason() -> None:
    """``partial`` + ``complete`` means nobody recorded why the read stopped."""
    assert coverage.normalize_reason("partial", "complete") == "unspecified"
    assert coverage.normalize_reason("complete", "complete") == "complete"
    assert coverage.normalize_reason("failed", "") == "unspecified"
    assert coverage.normalize_reason("partial", None) == "unspecified"


def test_an_exception_class_name_never_reaches_the_reader() -> None:
    """A library name tells the operator nothing about their data."""
    assert coverage.is_exception_name("SSHException")
    assert coverage.is_exception_name("UnicodeDecodeError")
    assert not coverage.is_exception_name("source_error")
    assert coverage.label("SSHException") == coverage.REASON_LABELS["source_error"]


def test_an_unknown_reason_stays_visible() -> None:
    """A new code must show up the day it is introduced, not be swallowed."""
    assert coverage.label("some_future_code") == "some_future_code"
    assert coverage.label("") == "-"
    assert coverage.status_label("some_future_status") == "some_future_status"


def test_listed_is_not_inspected() -> None:
    """A binary we inventoried was never read; it is not a covered item."""
    assert coverage.is_inspected("complete")
    assert coverage.is_inspected("partial")
    for status in ("unsupported", "unavailable", "failed", ""):
        assert not coverage.is_inspected(status)


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------

def test_a_partial_read_is_not_counted_as_covered() -> None:
    block = coverage.summarize([("partial", "sampled", "a"), ("partial", "sampled", "b")])
    assert block["coverage_percent"] == 0.0
    assert (block["inspected"], block["not_inspected"]) == (2, 0)


def test_the_row_by_row_and_the_grouped_path_agree() -> None:
    rows = [("complete", "complete", "a"), ("partial", "line_truncated", "b"),
            ("unsupported", "binary_metadata_only", "c"), ("failed", "source_error", "d")]
    grouped = [("complete", "complete", 1), ("partial", "line_truncated", 1),
               ("unsupported", "binary_metadata_only", 1), ("failed", "source_error", 1)]
    from_rows = coverage.summarize(rows)
    from_counts = coverage.summarize_counts(grouped)
    for key in ("total", "complete", "partial", "inspected", "not_inspected",
                "coverage_percent", "by_status", "reasons", "miss_reasons", "statement"):
        assert from_rows[key] == from_counts[key], key


def test_the_miss_table_never_lists_the_rows_that_were_read_in_full() -> None:
    """A "未完整读取的原因" table that also said ``正常完成 3`` contradicted itself."""
    block = coverage.summarize(
        [("complete", "complete", "a")] * 3 + [("partial", "sampled", "b")]
    )
    assert [row["label"] for row in block["reasons"]] == ["正常完成", "按头/中/尾采样"]
    assert [row["label"] for row in block["miss_reasons"]] == ["按头/中/尾采样"]


def test_two_codes_with_one_label_are_one_row_and_are_not_counted_twice() -> None:
    """``row_limit`` caps one file, ``row_budget`` caps the run; both read alike."""
    block = coverage.summarize([("partial", "row_limit", "a"), ("partial", "row_budget", "b")])
    assert len(block["reasons"]) == 1
    assert block["reasons"][0]["count"] == 2
    assert block["reasons"][0]["codes"] == ["row_budget", "row_limit"]


def test_merging_sources_re_derives_counts_instead_of_averaging_them() -> None:
    """A 100-file source must not outvote a 15 000-file one."""
    small = coverage.summarize([("complete", "complete", "a")])
    large = coverage.summarize([("complete", "complete", "b")] * 3
                               + [("unsupported", "binary_metadata_only", "c")])
    merged = coverage.merge([small, large])
    # Averaging the two sources' percentages would say 87.5%; re-deriving the
    # counts from the parts says 4 of 5.
    assert merged["total"] == 5
    assert merged["complete"] == 4
    assert merged["coverage_percent"] == 80.0


def test_merging_keeps_one_row_per_label() -> None:
    """The bug this pins: splitting a group back over its codes doubled it."""
    first = coverage.summarize([("partial", "row_limit", "a")] * 2)
    second = coverage.summarize([("partial", "row_budget", "b")] * 3)
    merged = coverage.merge([first, second])
    assert len(merged["reasons"]) == 1
    assert merged["reasons"][0]["count"] == 5
    assert merged["miss_reasons"][0]["count"] == 5


def test_an_empty_scope_says_so_instead_of_printing_a_percentage() -> None:
    block = coverage.merge([])
    assert block["total"] == 0
    assert block["coverage_percent"] == 0.0
    assert "未产生可统计" in block["statement"]


# --------------------------------------------------------------------------
# The console's copy of the table
# --------------------------------------------------------------------------

def _ts_labels(source: str, name: str) -> dict[str, str]:
    start = source.index(f"const {name}")
    body = source[start:source.index("}", start)]
    return dict(re.findall(r"([A-Za-z_][A-Za-z0-9_]*)\s*:\s*'([^']*)'", body))


@pytest.mark.skipif(not FORMAT_TS.exists(), reason="控制台源码不在镜像内")
def test_the_console_labels_every_code_the_platform_can_emit() -> None:
    source = FORMAT_TS.read_text(encoding="utf-8")
    console_reasons = _ts_labels(source, "TERMINATION_LABELS")
    missing = sorted(set(coverage.REASON_LABELS) - set(console_reasons))
    assert not missing, f"控制台缺少原因码的中文标签：{missing}"
    disagree = {
        code: (coverage.REASON_LABELS[code], console_reasons[code])
        for code in coverage.REASON_LABELS
        if code in console_reasons and console_reasons[code] != coverage.REASON_LABELS[code]
    }
    assert not disagree, f"两端标签不一致：{disagree}"

    console_statuses = _ts_labels(source, "COVERAGE_LABELS")
    missing_status = sorted(set(coverage.STATUS_LABELS) - set(console_statuses))
    assert not missing_status, f"控制台缺少覆盖率状态的中文标签：{missing_status}"
    disagree_status = {
        status: (coverage.STATUS_LABELS[status], console_statuses[status])
        for status in coverage.STATUS_LABELS
        if status in console_statuses and console_statuses[status] != coverage.STATUS_LABELS[status]
    }
    assert not disagree_status, f"两端状态标签不一致：{disagree_status}"
