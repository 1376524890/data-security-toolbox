"""One vocabulary for "how much of this did we actually get to look at?".

Three collectors answer that question - the file-share scan, the probe's
data-asset inventory and the direct database scan - and each of them grew its
own words for it: a coverage status, a termination reason from
``shared.scanning.budget``, and (on the database path) a bare ``covered``
boolean that was flattened into ``complete``/``partial`` on the way to the row.

Storing those in the two columns ``asset_instances.coverage`` and
``asset_instances.termination_reason`` produced exactly the drift you would
expect from two fields that never had to agree. The live data contains, among
11 000+ rows:

- ``partial`` + ``complete`` - "we read part of it" next to "nothing stopped
  us", because ``complete`` is both a status and the default value of a reason
  field that was never told why the read stopped;
- ``failed`` + ``SSHException`` - a third-party exception class name, printed to
  the operator (and into the report) telling them which library failed and
  nothing about their data.

This module is the single place that decides what a status means, what a reason
is called in Chinese, and how a set of rows collapses into one sentence a report
can carry. It imports nothing from ``app`` so the probe, the backend and the
report template all read the same table.

Two rules it exists to enforce:

**Nothing unread is ever reported as clean.** ``unsupported`` (a binary with no
text layer) and ``unavailable`` (the OCR toolchain is missing) are *listed, not
inspected*, and are counted apart from ``complete``; a percentage that folded
them in would be the false capability claim this codebase keeps warning about.

**An unknown reason stays visible.** ``label`` falls through to the raw code
rather than to a friendly generic, so a new reason shows up in the report the
day it is introduced instead of being silently swallowed. The single exception
is an exception *class name*, which is neutralised: the operator needs to know
that reading failed, not which Python library raised.
"""
from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

# --------------------------------------------------------------------------
# Status
# --------------------------------------------------------------------------

COMPLETE = "complete"
PARTIAL = "partial"
#: Listed, but there is nothing for the parser to read (a binary, an archive we
#: do not open, an encrypted container). Inventoried is not inspected.
UNSUPPORTED = "unsupported"
#: We would have read it, but the tool to do so is not installed.
UNAVAILABLE = "unavailable"
#: We tried to read it and the read raised.
FAILED = "failed"

STATUSES = (COMPLETE, PARTIAL, UNSUPPORTED, UNAVAILABLE, FAILED)

#: ``complete`` doubles as the "no reason recorded" sentinel - see
#: ``normalize_reason``. Kept as a named constant because that double duty is
#: the root cause of the ``partial``/``complete`` rows.
NO_REASON = "complete"

#: Statuses whose *content* was read, wholly or in part. Everything else was
#: listed and not inspected, and must not be counted into a coverage percentage.
INSPECTED = frozenset({COMPLETE, PARTIAL})

STATUS_LABELS: dict[str, str] = {
    COMPLETE: "内容完整",
    PARTIAL: "部分内容",
    UNSUPPORTED: "未解析内容",
    UNAVAILABLE: "缺少工具链",
    FAILED: "读取失败",
}

# --------------------------------------------------------------------------
# Reason
# --------------------------------------------------------------------------

#: Reason codes, both families in one table. The budget/cancellation half comes
#: from ``shared.scanning.budget`` (the scanner stopped early); the content half
#: comes from the samplers and parsers (this one file was read incompletely).
#: A code that is missing here is not an error - it is printed verbatim so it
#: cannot hide - but adding it here is what makes it readable.
REASON_LABELS: dict[str, str] = {
    # Scope-level: the walk stopped early.
    NO_REASON: "正常完成",
    "timeout": "执行超时",
    "time_budget": "执行超时",
    "cancelled": "已取消",
    "file_budget": "达到文件上限",
    "directory_budget": "达到目录上限",
    "byte_budget": "达到读取字节上限",
    "row_budget": "达到行数上限",
    "depth_or_exclude": "达到目录深度上限或排除规则",
    "depth_limit": "达到目录深度上限",
    "resource_limit": "达到资源上限",
    "unconfigured": "未配置扫描范围",
    "unreadable": "内容无法读取",
    "source_error": "读取来源出错",
    "unspecified": "未记录具体原因",
    # Content-level: the file itself was read incompletely.
    "sampled": "按头/中/尾采样",
    "row_limit": "达到行数上限",
    "line_truncated": "行内容被截断",
    "single_file_limit": "单文件超过上限",
    "binary_metadata_only": "二进制文件仅登记元数据",
    "file_changed_during_read": "读取期间文件发生变化",
    "ocr_read": "经 OCR 补读（原无文本层）",
    "ocr_unavailable": "OCR 工具链缺失",
    "ocr_error": "OCR 识别出错",
    "render_failed": "页面渲染失败",
    "unsupported_format": "格式不支持解析",
    "file_too_large": "文件超过解析上限",
    "scoped": "仅按范围指纹识别",
    # Database path.
    "partial_scan": "未读完（达到扫描上限）",
    "row_budget_exceeded": "达到行数上限",
}

#: Shape of a Python exception class name (``SSHException``, ``KeyError``,
#: ``UnicodeDecodeError``). Matched so a class name can never reach a report:
#: it names a library, not a finding.
_EXCEPTION_NAME = re.compile(r"^[A-Z][A-Za-z0-9]*(Error|Exception|Warning|Exit)$")


def is_exception_name(code: str) -> bool:
    """Whether a stored reason is really a leaked exception class name."""
    return bool(_EXCEPTION_NAME.match(str(code or "").strip()))


def normalize_reason(status: str, reason: str | None) -> str:
    """The reason that should be *stored* for this (status, reason) pair.

    The two fields were independent, so a row could say ``partial`` and
    ``complete`` at once. Rather than pick a winner silently, the leftover
    default is rewritten to ``unspecified``: the row genuinely does not record
    why the read stopped, and saying so is the honest answer.
    """
    code = str(reason or "").strip()
    if code == NO_REASON and str(status or "") != COMPLETE:
        return "unspecified"
    return code or "unspecified"


def label(code: str | None) -> str:
    """A report-safe Chinese label for a reason code.

    Unknown codes fall through unchanged (a new reason must be visible, not
    hidden). Exception class names are the one thing that does not fall
    through: they carry a library name and no information about the data.
    """
    raw = str(code or "").strip()
    if not raw:
        return "-"
    if is_exception_name(raw):
        return REASON_LABELS["source_error"]
    return REASON_LABELS.get(raw, raw)


def status_label(status: str | None) -> str:
    raw = str(status or "").strip()
    if not raw:
        return "-"
    return STATUS_LABELS.get(raw, raw)


def is_inspected(status: str | None) -> bool:
    """Whether the content was read at all (wholly or in part)."""
    return str(status or "") in INSPECTED


def describe(status: str | None, reason: str | None) -> str:
    """One phrase for one row, coherent even when the stored pair is not."""
    status_text = status_label(status)
    code = normalize_reason(str(status or ""), reason)
    if str(status or "") == COMPLETE and code == NO_REASON:
        return status_text
    return f"{status_text}（{label(code)}）"


# --------------------------------------------------------------------------
# Aggregation
# --------------------------------------------------------------------------


def _row_pair(row: Any) -> tuple[str, str]:
    """Accept an ORM row, a mapping, or a plain (status, reason) pair.

    The collectors hand back different shapes and the report must not care, but
    the two column names are fixed so a caller cannot quietly rename a field and
    have the coverage table come back empty.
    """
    if isinstance(row, Mapping):
        status = row.get("coverage", row.get("status"))
        reason = row.get("termination_reason", row.get("reason"))
        return str(status or ""), str(reason or "")
    if isinstance(row, (tuple, list)) and len(row) >= 2:
        return str(row[0] or ""), str(row[1] or "")
    return (str(getattr(row, "coverage", "") or ""),
            str(getattr(row, "termination_reason", "") or ""))


def _row_name(row: Any) -> str:
    if isinstance(row, Mapping):
        return str(row.get("name") or row.get("path") or "")
    if isinstance(row, (tuple, list)):
        return str(row[2]) if len(row) > 2 else ""
    return str(getattr(row, "name", "") or getattr(row, "path", "") or "")


def _sample(status: str, code: str, name: str) -> dict[str, str]:
    return {
        "name": name,
        "status": status,
        "status_label": status_label(status),
        "reason": code,
        "reason_label": label(code),
    }


def _sample_parts(entry: Any) -> tuple[str, str, str]:
    status, reason = _row_pair(entry)
    return status, normalize_reason(status, reason), _row_name(entry)


def _absorb_reason_rows(target: dict[str, dict[str, Any]],
                        rows: Iterable[Mapping[str, Any]]) -> None:
    """Fold label-grouped reason rows into an accumulating map.

    Grouped by *label*, not by code. Two codes can share one label -
    ``row_limit`` caps a single file, ``row_budget`` caps the whole run, and
    both read as "达到行数上限" - so counting the group once is what keeps a
    merged total equal to the sum of its parts. Splitting a group's count back
    over its codes would count the same objects twice.
    """
    for item in rows or []:
        name = str(item.get("label") or "")
        if not name:
            continue
        entry = target.setdefault(name, {"label": name, "count": 0, "codes": []})
        entry["count"] += int(item.get("count") or 0)
        codes = item.get("codes") or ([item.get("code")] if item.get("code") else [])
        for code in codes:
            text = str(code or "")
            if text and text not in entry["codes"]:
                entry["codes"].append(text)


def _reason_list(target: Mapping[str, dict[str, Any]]) -> list[dict[str, Any]]:
    """The rows of a reason table, most common first, ties broken by label."""
    return [
        {"label": entry["label"], "count": entry["count"], "codes": sorted(entry["codes"])}
        for entry in sorted(target.values(), key=lambda item: (-item["count"], item["label"]))
    ]


def _reason_rows(counts: Mapping[str, int]) -> list[dict[str, Any]]:
    """Reason rows grouped by label, keeping the codes that produced them.

    Printing two identical lines - one for each code behind "达到行数上限" -
    makes a report look like it counted something twice. The codes are kept on
    the row so the console can still say which one it was.
    """
    grouped: dict[str, dict[str, Any]] = {}
    for code, count in counts.items():
        _absorb_reason_rows(grouped, [{"label": label(code), "count": count, "codes": [code]}])
    return _reason_list(grouped)


def _block_from_rows(status_counts: Mapping[str, int],
                     reasons: list[dict[str, Any]],
                     miss_reasons: list[dict[str, Any]],
                     samples: list[dict[str, str]]) -> dict[str, Any]:
    """Assemble the block from parts that are already counted and grouped.

    The one place the block's shape is set; ``_block`` and ``merge`` only differ
    in how they get here, so a merged block and a single-source block can never
    disagree about what a field means.
    """
    total = sum(status_counts.values())
    complete = status_counts.get(COMPLETE, 0)
    partial = status_counts.get(PARTIAL, 0)
    inspected = complete + partial
    block: dict[str, Any] = {
        "total": total,
        "complete": complete,
        "partial": partial,
        "inspected": inspected,
        "not_inspected": total - inspected,
        #: Share read *in full*. A partial read is deliberately left out: a file
        #: whose long lines were clipped, or one sampled head/middle/tail, is not
        #: covered, and a headline that counted it as such would be exactly the
        #: false claim this module exists to prevent. (An earlier version of this
        #: function reported "100%" for a source whose six items were all partial.)
        "coverage_percent": round(complete * 100.0 / total, 1) if total else 0.0,
        "by_status": [
            {"status": status, "label": status_label(status), "count": count}
            for status, count in sorted(status_counts.items(), key=lambda item: (-item[1], item[0]))
        ],
        #: Every reason, including the ones on fully-read rows.
        "reasons": reasons,
        #: Only the reasons belonging to rows that were not read in full - the
        #: table a report puts under "未完整读取的原因". A breakdown that also
        #: listed "正常完成 11376" under that heading contradicted itself.
        "miss_reasons": miss_reasons,
        "samples": samples[:20],
    }
    block["statement"] = statement(block)
    return block


def _block(status_counts: Mapping[str, int], reason_counts: Mapping[str, int],
           miss_reason_counts: Mapping[str, int],
           samples: list[dict[str, str]]) -> dict[str, Any]:
    """Build a block from reason->count maps (the per-row and triple paths)."""
    return _block_from_rows(status_counts, _reason_rows(reason_counts),
                            _reason_rows(miss_reason_counts), samples)


def _tally(pairs: Iterable[Any]) -> tuple[dict[str, int], dict[str, int], dict[str, int], int]:
    """(status counts, reason counts, miss-reason counts, total) from triples."""
    status_counts: dict[str, int] = {}
    reason_counts: dict[str, int] = {}
    miss_reason_counts: dict[str, int] = {}
    total = 0
    for item in pairs:
        status, reason, count = str(item[0] or ""), str(item[1] or ""), int(item[2] or 0)
        if not count:
            continue
        total += count
        status_counts[status] = status_counts.get(status, 0) + count
        code = normalize_reason(status, reason)
        reason_counts[code] = reason_counts.get(code, 0) + count
        if status != COMPLETE:
            miss_reason_counts[code] = miss_reason_counts.get(code, 0) + count
    return status_counts, reason_counts, miss_reason_counts, total


def summarize_counts(pairs: Iterable[Any], *, samples: Iterable[Any] | None = None) -> dict[str, Any]:
    """The coverage block for ``(status, reason, count)`` triples.

    The aggregate path reads grouped counts rather than rows - eleven groups
    stand for fifteen thousand instances - and it still has to produce the same
    block as the row-by-row path. Both go through ``_block`` so the two can
    never disagree.
    """
    status_counts, reason_counts, miss_reason_counts, _ = _tally(pairs)
    extra = [_sample(*_sample_parts(entry)) for entry in (samples or [])]
    return _block(status_counts, reason_counts, miss_reason_counts, extra)


def summarize(rows: Iterable[Any], *, sample: int = 20) -> dict[str, Any]:
    """Collapse rows into the coverage block a report or a card can render.

    ``rows`` may be ORM rows, mappings or ``(status, reason, name)`` tuples.
    Returns counts, a reason breakdown and a bounded sample of the rows that
    were *not* fully inspected - the list an operator needs in order to say
    which items are still open.
    """
    triples: list[tuple[str, str, int]] = []
    missing: list[dict[str, str]] = []
    for row in rows:
        status, reason = _row_pair(row)
        triples.append((status, reason, 1))
        if status != COMPLETE and len(missing) < sample:
            missing.append(_sample(status, normalize_reason(status, reason), _row_name(row)))
    status_counts, reason_counts, miss_reason_counts, _ = _tally(triples)
    return _block(status_counts, reason_counts, miss_reason_counts, missing)


def merge(blocks: Iterable[Mapping[str, Any]]) -> dict[str, Any]:
    """One coverage block for several sources, so the report prints one headline.

    Counts are re-derived from the parts rather than averaged: an average of
    percentages would let a 100-file source outvote a 10 000-file one.
    """
    by_status: dict[str, int] = {}
    reasons: dict[str, dict[str, Any]] = {}
    miss_reasons: dict[str, dict[str, Any]] = {}
    samples: list[dict[str, str]] = []
    for block in blocks:
        if not block or not block.get("total"):
            continue
        for item in block.get("by_status") or []:
            status = str(item.get("status") or "")
            by_status[status] = by_status.get(status, 0) + int(item.get("count") or 0)
        _absorb_reason_rows(reasons, block.get("reasons") or [])
        _absorb_reason_rows(miss_reasons, block.get("miss_reasons") or [])
        samples.extend(block.get("samples") or [])
    return _block_from_rows(by_status, _reason_list(reasons), _reason_list(miss_reasons), samples)


def statement(block: Mapping[str, Any]) -> str:
    """The one sentence a report puts under 检查覆盖.

    Deliberately states the not-inspected remainder even when it is zero: a
    reader who is told "全部已检查" only because the sentence omits the rest
    cannot tell the difference between a complete run and a silent cap.
    """
    total = int(block.get("total") or 0)
    if not total:
        return "本次未产生可统计的检查对象。"
    complete = int(block.get("complete") or 0)
    partial = int(block.get("partial") or 0)
    not_inspected = int(block.get("not_inspected") or 0)
    percent = block.get("coverage_percent") or 0.0
    if not partial and not not_inspected:
        tail = "本次全部对象均已完整读取。"
    else:
        tail = ("部分读取只说明读到了内容的一部分，未读取说明内容没有参与检测；"
                "两者都不代表其中没有敏感数据，需单独复核。")
    return (
        f"共登记 {total} 项：完整读取 {complete} 项（{percent}%）、"
        f"部分读取 {partial} 项、未读取 {not_inspected} 项。{tail}"
    )
