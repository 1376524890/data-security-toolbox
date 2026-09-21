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


TERMINATION_LABELS = {
    "row_budget": "达到读取行数上限",
    "file_budget": "达到文件数量上限",
    "directory_budget": "达到目录数量上限",
    "byte_budget": "达到读取字节上限",
    "timeout": "达到执行时间上限",
    "cancelled": "采集已取消",
    "single_file_limit": "达到单文件读取上限",
    "depth_or_exclude": "达到目录深度或范围限制",
    "resource_limit": "达到资源使用上限",
    "unreadable": "存在不可读取的文件或目录",
    "unconfigured": "未配置采集目录",
}

#: Reasons that only limit how much of a file was read. The tree was still walked,
#: so the wording must not read like a directory that was never listed.
CONTENT_TRUNCATION_LABELS = {
    "row_budget": "部分文件内容达到读取行数上限",
    "single_file_limit": "部分文件内容达到单文件读取上限",
}


def collection_outcome(status: str, result: dict, error: str = "") -> tuple[str, str]:
    """Present old and new reports without rewriting historical facts."""
    stages = {
        "Success": "探针数据资产采集成功",
        "Partial": "探针数据资产采集部分完成",
        "Failed": "探针数据资产采集失败",
        "Cancelled": "探针数据资产采集已取消",
    }
    coverage = result.get("coverage") or result.get("budget") or {}
    reason = str(coverage.get("termination_reason") or "")
    detail = str(coverage.get("termination_detail") or "")
    message = error or ""
    if not message and status == "Partial":
        label = TERMINATION_LABELS.get(reason, reason) if reason != "complete" else ""
        if reason in CONTENT_TRUNCATION_LABELS and coverage.get("enumeration_complete") is True:
            # The walk reached the end of the scope; only the content of some
            # files was sampled past the limit.
            label = CONTENT_TRUNCATION_LABELS[reason]
        message = label
        message = message or "采集范围未完整覆盖"
        if detail:
            message += f"：{detail}"
    return stages.get(status, ""), message
