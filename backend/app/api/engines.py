# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Detection-engine catalogue and manual pipeline domain.

The HTTP boundary only: the engines, their metadata and the rule inventory live
in ``app/engine`` and ``app/rules``; this module owns the registry view, the
engine-name presentation map and the manual pipeline trigger.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.rule_presenter import rule_file_entries
from app.core.database import get_db
from app.engine import registry
from app.engine.core.context import DetectionContext
from app.engine.core.pipeline import DetectionPipeline
from app.engine.risk_engine.engine import RiskEngine
from app.models import DetectionFinding
from app.rules.catalog import CATALOG

router = APIRouter()


# Internal engine name -> (UI slug, display label). The console routes predate
# the engine names (``/engines/sigma`` vs ``sigma_log_engine``), so the mapping
# lives server-side: every view that lists engines or filters findings by
# engine reads it from ``/engine/registry`` instead of hard-coding a list.
ENGINE_PRESENTATION: dict[str, tuple[str, str]] = {
    "asset_engine": ("asset", "资产引擎"),
    "protocol_engine": ("protocol", "协议引擎"),
    "traffic_engine": ("traffic", "流量引擎"),
    "data_engine": ("data", "数据引擎"),
    "sigma_log_engine": ("sigma", "Sigma 日志引擎"),
    "compliance_engine": ("compliance", "合规引擎"),
    "dlp_engine": ("dlp", "数据防泄露引擎"),
    "threat_intel": ("ioc", "威胁情报引擎"),
}


@router.get("/engine/registry")
def engine_registry(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """Every detection engine with its real rule inventory and finding count.

    ``rule_count`` is the number of rule files backing the engine and
    ``detection_count`` the findings it has actually produced, so the UI never
    has to guess which ``detection_findings.engine`` value an engine writes --
    the internal engine name and the value stored on a finding are not always
    the same string (for example the built-in rule interpreter is registered as
    ``sigma_log_engine``), and the UI routes predate both.
    """
    # Count each engine's own rule files so the number always matches the rule
    # list the console renders for that engine.
    rule_counts: dict[str, int] = {}
    inventory = rule_file_entries(db, include_content=False)
    for item in inventory:
        rule_key = str(item.get("engine") or "")
        rule_counts[rule_key] = rule_counts.get(rule_key, 0) + 1
    finding_counts = {
        str(name): int(total)
        for name, total in db.execute(
            select(DetectionFinding.engine, func.count(DetectionFinding.id)).group_by(
                DetectionFinding.engine
            )
        ).all()
    }
    items: list[dict[str, Any]] = []
    for engine in registry.all():
        entry = dict(engine.metadata())
        name = str(entry.get("name") or "")
        slug, label = ENGINE_PRESENTATION.get(name, (name, name))
        rule_count = rule_counts.get(name)
        source = next((item for item in CATALOG if item.engine == name), None)
        entry.update(
            {
                "slug": slug,
                "label": label,
                "rule_count": int(rule_count or 0),
                "active_rule_files": sum(
                    item["execution"] == "active" for item in inventory if item["engine"] == name
                ),
                "rule_source": source.source_name or "平台检查规则" if source else "平台检查规则",
                "refreshable": bool(source and source.refreshable),
                "detection_engine": name,
                "detection_count": finding_counts.get(name, 0),
            }
        )
        items.append(entry)
    return items


@router.post("/engine/pipeline")
def run_engine_pipeline(payload: dict[str, Any]) -> dict[str, Any]:
    context = DetectionContext(
        target_type=payload.get("target_type", "manual"),
        target_id=payload.get("target_id"),
        data=payload.get("data", {}),
        assets=payload.get("assets", []),
        flows=payload.get("flows", []),
        packets=payload.get("packets", []),
        metadata=payload.get("metadata", {}),
        log_lines=payload.get("log_lines", []),
    )
    pipeline = DetectionPipeline(registry, RiskEngine())
    return pipeline.run(context).to_dict()
