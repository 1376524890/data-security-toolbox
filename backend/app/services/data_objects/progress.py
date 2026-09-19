"""progress responsibilities."""

from __future__ import annotations

PROGRESS_FIELDS = (
    ("files_discovered", "已发现文件"),
    ("files_analyzed", "已分析文件"),
    ("directories_scanned", "已扫描目录"),
    ("bytes_read", "已读取字节"),
)


def progress_percent(coverage: dict) -> dict:
    """A bounded estimate, labelled as one, or explicitly unknown.

    ``max_files`` is the only total both sides know without a second walk, so the
    percentage is ``files_analyzed / max_files`` - an upper bound on how far the
    scan has come, never a claim about how much data exists. With no usable
    denominator the progress is reported as unknown instead of invented.
    """
    limit = coverage.get("max_files") or coverage.get("files_expected")
    analyzed = coverage.get("files_analyzed")
    try:
        limit, analyzed = int(limit), int(analyzed)
    except (TypeError, ValueError):
        return {"percent": 0, "estimated": True, "basis": "unknown"}
    if limit <= 0 or analyzed < 0:
        return {"percent": 0, "estimated": True, "basis": "unknown"}
    basis = "files_analyzed/max_files"
    if coverage.get("files_expected"):
        basis = "files_analyzed/files_expected"
        return {
            "percent": max(0, min(int(analyzed * 100 / limit), 99)),
            "estimated": False,
            "basis": basis,
        }
    # Capped below 100: only the final report may declare the scan finished.
    return {
        "percent": max(0, min(int(analyzed * 100 / limit), 99)),
        "estimated": True,
        "basis": basis,
    }


def progress_stage(coverage: dict, current_path: str) -> str:
    parts = [
        f"{label} {coverage.get(key)}"
        for key, label in PROGRESS_FIELDS
        if coverage.get(key) is not None
    ]
    detail = "，".join(parts)
    if current_path:
        detail = f"{detail}，当前 {current_path}" if detail else f"当前 {current_path}"
    return (detail or "探针数据资产采集中")[:255]
