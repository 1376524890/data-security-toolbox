"""合规基线评估: which shipped compliance rules fire, over the existing findings."""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import DetectionFinding
from app.services.assessments.envelope import caliber, envelope, gap, kpi

RULES_DIR = Path(__file__).resolve().parents[2] / "rules" / "compliance"


def rule_catalog() -> list[dict[str, Any]]:
    """The shipped compliance rules; the pass/fail denominator is their count."""
    out: list[dict[str, Any]] = []
    for path in sorted(RULES_DIR.glob("*.yaml")):
        try:
            data = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError):
            continue
        if isinstance(data, dict) and data.get("rule_id"):
            out.append({"rule_id": str(data["rule_id"]), "title": str(data.get("title", "")),
                        "severity": str(data.get("severity", "Medium"))})
    return out


def build(db: Session) -> dict[str, Any]:
    rules = rule_catalog()
    total_rules = len(rules)

    rows = db.execute(
        select(DetectionFinding.rule_id, DetectionFinding.severity,
               func.count(DetectionFinding.id))
        .where(DetectionFinding.engine == "compliance_engine")
        .group_by(DetectionFinding.rule_id, DetectionFinding.severity)
    ).all()
    fired = {rule_id for rule_id, _severity, _count in rows}
    findings_total = sum(count for _rule, _severity, count in rows)
    failed = len(fired)
    passed = max(total_rules - failed, 0)
    affected = len({rule_id for rule_id, _severity, _count in rows})
    max_risk = db.scalar(select(func.max(DetectionFinding.risk_score))
                         .where(DetectionFinding.engine == "compliance_engine")) or 0.0

    kpis = [
        kpi("rules_total", "适用合规项", total_rules, max(total_rules, 1)),
        kpi("rules_passed", "通过项", passed, max(total_rules, 1), tone="primary"),
        kpi("rules_failed", "未通过项", failed, max(total_rules, 1), tone="danger"),
        kpi("findings", "合规发现", findings_total, max(findings_total, 1), tone="warning"),
        kpi("affected_rules", "命中规则数", affected, max(total_rules, 1)),
        kpi("max_risk", "最高风险分", round(float(max_risk), 1), 100, unit="分"),
        kpi("coverage_baseline", "基线项", total_rules, max(total_rules, 1)),
        kpi("evidence", "证据条数", findings_total, max(findings_total, 1)),
    ]

    sections = {
        "rules": rules,
        "findings": [
            {"rule_id": rule_id, "severity": severity, "count": count}
            for rule_id, severity, count in rows
        ],
    }

    gaps = [
        gap("baseline_scope", "合规基线范围", "固定",
            "仅评估随包基线规则，未覆盖客户自定义等保/行业条款映射。"),
        gap("tls", "加密通道核查", "未接入",
            "旁路不解密 TLS，加密通道内的合规问题不可见。"),
    ]

    conclusion = (
        f"{total_rules} 项适用合规规则中 {failed} 项未通过、{passed} 项通过；"
        f"共 {findings_total} 条合规发现。"
    )
    return envelope(
        title="合规基线评估",
        conclusion=conclusion,
        kpis=kpis,
        sections=sections,
        caliber_data=caliber(notes=("通过 = 基线规则未命中，不等同于人工核查通过。",)),
        gaps=gaps,
    )
