"""数据分级评估: the L1–L4 picture over the de-duplicated object model."""
from __future__ import annotations

from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models import AssetInstance, DataObject
from app.services import sensitivity_map
from app.services.assessments.envelope import caliber, envelope, gap, kpi
from app.services.data_objects import queries


def build(db: Session) -> dict[str, Any]:
    mapping = sensitivity_map.overrides(db)
    summary = queries.data_type_summary(db)
    type_rows = queries.data_type_rows(db, mapping=mapping)
    objects = db.scalars(select(DataObject)).all()

    distribution = {level: 0 for level in sensitivity_map.LEVELS}
    protected_objects = 0
    for obj in objects:
        distribution[sensitivity_map.worst_level(obj.categories, mapping=mapping)] += 1
        if any(sensitivity_map.is_protected(category) for category in (obj.categories or [])):
            protected_objects += 1

    total_objects = len(objects)
    total_instances = db.scalar(select(func.count()).select_from(AssetInstance)) or 0
    full_hash = sum(1 for obj in objects if obj.hash_type == "full_sha256")
    catalog_size = len(sensitivity_map.catalog(mapping=mapping))
    high = distribution.get("L4", 0) + distribution.get("L3", 0)

    kpis = [
        kpi("sensitive_objects", "敏感数据对象", protected_objects, max(total_objects, 1),
            tone="warning"),
        kpi("active_instances", "活跃实例", summary["instances"], max(total_instances, 1),
            tone="primary"),
        kpi("high_sensitive", "高敏对象（L3+L4）", high, max(protected_objects, 1), tone="danger"),
        kpi("confirmed_duplicates", "确认副本", summary["confirmed_duplicates"],
            max(full_hash, 1), tone="warning"),
        kpi("sensitive_types", "敏感类型", summary["types"], max(catalog_size, 1)),
        kpi("sources", "观测来源", summary["hosts"], max(summary["hosts"], 1)),
        kpi("candidate_duplicates", "疑似副本", summary["candidate_duplicates"],
            max(len(objects), 1)),
        kpi("identity_pending", "待确认身份", summary["identity_pending"], max(len(objects), 1)),
    ]

    sections = {
        "level_distribution": [
            {"level": level, "name": sensitivity_map.LEVEL_META.get(level, {}).get("name", ""),
             "count": distribution.get(level, 0)} for level in sensitivity_map.LEVELS
        ],
        "types": [
            {"category": row["category"], "level": row["level"],
             "level_name": row["level_name"], "object_count": row["object_count"],
             "active_instance_count": row["active_instance_count"],
             "field_only": row.get("field_only", False)}
            for row in type_rows
        ],
        "dedup": {
            "confirmed_duplicates": summary["confirmed_duplicates"],
            "candidate_duplicates": summary["candidate_duplicates"],
            "identity_pending": summary["identity_pending"],
            "rule": ("确认副本按完整 SHA256 相同的对象计 max(实例数-1,0)；"
                     "部分指纹≥2 实例计疑似副本，单实例只算待确认身份，不称副本。"),
        },
    }

    gaps = [
        gap("permission", "文件权限评估", "未接入",
            "探针未上报 permission 的实例不参与权限统计，权限越权风险无法判定。"),
        gap("field_only", "仅字段名命中", "已排除",
            "FIELD_ONLY 类型照常上报但不计敏感值命中，也不单独提升分级。"),
    ]

    conclusion = (
        f"共 {protected_objects} 个敏感对象（跨类型去重），其中高敏 {high} 个；"
        f"观测来源 {summary['hosts']} 个。分级口径见下，数值不可与类型表逐行相加。"
    )
    return envelope(
        title="数据分级评估",
        conclusion=conclusion,
        kpis=kpis,
        sections=sections,
        caliber_data=caliber(truncated=bool(summary.get("truncated")),
                             notes=("分级基于共享敏感引擎的 L1–L4 映射，可由平台覆盖配置调整。",)),
        gaps=gaps,
    )
