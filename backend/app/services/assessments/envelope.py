"""The shared "five-段式" envelope every assessment returns.

结论条 (conclusion) → KPI（每张带分母）→ 主视图 (sections) → 明细 (rows) →
口径与缺口 (caliber + gaps). Keeping the shape in one place means a page can
render any assessment from the same skeleton, and a number can never be shown
without the denominator and coverage boundary it was computed against.
"""
from __future__ import annotations

from typing import Any

#: The coverage boundary that is true of the whole platform, stated once so every
#: assessment carries the same honest limits instead of each page inventing its own.
CALIBER_NOTES = (
    "旁路被动采集，不解密 TLS；加密流量与加密文件的内容不可见。",
    "文件权限 permission 未被探针上报的实例不参与权限统计，按“未上报”单列。",
    "FIELD_ONLY 类型（仅字段名/关键字命中，无值命中）不计入敏感值命中数。",
    "探针 /tmp 的 PrivateTmp 隔离尚未处理，临时文件清理存在残留风险。",
)


def caliber(*, truncated: bool = False, region_table_present: bool = False,
            notes: tuple[str, ...] = (), extra: dict[str, Any] | None = None) -> dict[str, Any]:
    """The 口径 object: machine-readable flags plus the human notes."""
    data: dict[str, Any] = {
        "mode": "passive",
        "tls_decryption": False,
        "permission_reported": False,
        "field_only_excluded": True,
        "probe_tmp_isolated": False,
        "region_table_present": region_table_present,
        "truncated": truncated,
        "notes": [*CALIBER_NOTES, *notes],
    }
    if extra:
        data.update(extra)
    return data


def kpi(key: str, label: str, value: Any, denominator: Any, *,
        unit: str = "", tone: str = "default") -> dict[str, Any]:
    """One metric card. ``denominator`` is mandatory: a card always shows "X / Y"."""
    return {"key": key, "label": label, "value": value, "denominator": denominator,
            "unit": unit, "tone": tone}


def gap(key: str, label: str, status: str, detail: str) -> dict[str, str]:
    """One honest "尚未接入 / 无法判定" row; the single home for these placeholders."""
    return {"key": key, "label": label, "status": status, "detail": detail}


def envelope(*, title: str, conclusion: str, kpis: list[dict[str, Any]],
             sections: dict[str, Any], caliber_data: dict[str, Any],
             gaps: list[dict[str, str]] | None = None) -> dict[str, Any]:
    return {
        "title": title,
        "conclusion": conclusion,
        "kpis": kpis,
        "sections": sections,
        "gaps": gaps or [],
        "caliber": caliber_data,
    }
