"""评估总览: one page over the five dimension assessments, no second fact source."""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from app.services.assessments import classification, compliance, egress, exposure, flow
from app.services.assessments.envelope import caliber, envelope, kpi

#: The five dimensions, in the order the overview and the tabs present them.
DIMENSIONS: tuple[tuple[str, str], ...] = (
    ("classification", "数据分级"),
    ("exposure", "数据脆弱性"),
    ("flow", "数据流动"),
    ("egress", "数据出境"),
    ("compliance", "合规基线"),
)

#: Which KPI of each dimension the overview surfaces, and why it is the headline.
HEADLINE: dict[str, str] = {
    "classification": "high_sensitive",
    "exposure": "open_vulnerabilities",
    "flow": "external_flows",
    "egress": "country",
    "compliance": "rules_failed",
}


def _headline(part: dict[str, Any], key: str) -> dict[str, Any] | None:
    for item in part["kpis"]:
        if item["key"] == key:
            return item
    return part["kpis"][0] if part["kpis"] else None


def build(db: Session) -> dict[str, Any]:
    parts = {
        "classification": classification.build(db),
        "exposure": exposure.build(db),
        "flow": flow.build(db),
        "egress": egress.build(db),
        "compliance": compliance.build(db),
    }

    kpis: list[dict[str, Any]] = []
    for key, label in DIMENSIONS:
        part = parts[key]
        headline = _headline(part, HEADLINE[key])
        if headline:
            kpis.append(kpi(f"{key}.{headline['key']}", f"{label}｜{headline['label']}",
                            headline["value"], headline["denominator"],
                            unit=headline.get("unit", ""), tone=headline.get("tone", "default")))

    sections = {
        "dimensions": [
            {"key": key, "label": label, "title": parts[key]["title"],
             "conclusion": parts[key]["conclusion"], "kpis": parts[key]["kpis"]}
            for key, label in DIMENSIONS
        ],
        "gaps": [gap for key, _label in DIMENSIONS for gap in parts[key]["gaps"]],
    }

    caliber_data = caliber(
        region_table_present=parts["egress"]["caliber"]["region_table_present"],
        notes=("总览逐项复用五个维度的同一份聚合，指标不可跨维度相加。",))

    conclusion = "；".join(f"{label}：{parts[key]['conclusion']}" for key, label in DIMENSIONS)
    return envelope(title="数据安全评估总览", conclusion=conclusion, kpis=kpis,
                    sections=sections, caliber_data=caliber_data, gaps=sections["gaps"])
