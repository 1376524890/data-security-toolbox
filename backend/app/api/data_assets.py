# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""data assets responsibilities."""

from __future__ import annotations

from collections import Counter
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.finding_presenter import _serialize_detection as _serialize_detection
from app.api.pagination import page_response, paginate
from app.core.database import get_db
from app.models import AssetInstance, DataAsset, Detection, DetectionFinding
from app.services.data_objects.definitions import INSTANCE_ACTIVE

router = APIRouter()


def _serialize_data_asset(item: DataAsset) -> dict[str, Any]:
    extra = item.extra or {}
    return {
        "id": item.id,
        "name": item.name,
        "asset_type": item.asset_type,
        "sensitivity": item.sensitivity,
        "source": item.source,
        "columns": item.columns,
        "probe_id": extra.get("probe_id"),
        "probe": extra.get("probe", ""),
        "host": extra.get("host", ""),
        "path": extra.get("path", ""),
        "size": extra.get("size", 0),
        "categories": extra.get("categories", []),
        "candidate_categories": extra.get("candidate_categories", []),
        "status": extra.get("status", "observed"),
        "observed_at": extra.get("observed_at", ""),
        "extra": extra,
        "created_at": item.created_at,
    }


@router.get("/data/assets")
def data_assets(
    search: str | None = None,
    sensitivity: str | None = None,
    asset_type: str | None = None,
    source: str | None = None,
    probe_id: int | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(DataAsset)
    if search:
        query = query.where(DataAsset.name.ilike(f"%{search}%"))
    if sensitivity:
        query = query.where(DataAsset.sensitivity == sensitivity)
    if asset_type:
        query = query.where(DataAsset.asset_type == asset_type)
    if source:
        query = query.where(DataAsset.source == source)
    if probe_id:
        query = query.where(DataAsset.extra["probe_id"].as_integer() == probe_id)
    result = paginate(db, query.order_by(DataAsset.id.desc()), page, page_size)
    return page_response(
        [_serialize_data_asset(item) for item in result["items"]], page, page_size, result["total"]
    )


@router.get("/data/assets/{data_asset_id}")
def data_asset_detail(data_asset_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(DataAsset, data_asset_id)
    if not item:
        raise HTTPException(404, "data asset not found")
    extra = item.extra or {}
    # Explicit association: a file finding is bound to the file record, never by
    # comparing the display name ("data.csv" or "probe:host") to an absolute
    # path, which could never match. Probe-collected assets carry their evidence
    # in the object model instead, so they report no file finding rather than a
    # wrong one.
    findings: list[DetectionFinding] = []
    file_id = extra.get("file_id")
    if file_id:
        findings = [
            row
            for row in db.scalars(
                select(DetectionFinding)
                .where(
                    DetectionFinding.target_type == "file",
                    DetectionFinding.target_id == str(file_id),
                )
                .order_by(DetectionFinding.risk_score.desc())
            ).all()
            if not (row.evidence or {}).get("superseded")
        ]
    # Fields and hits are different units: one column can hold 100 matching
    # values. Reporting only the field count made a text file look empty.
    pii_fields: Counter = Counter()
    for column in item.columns or []:
        for category in column.get("categories") or []:
            pii_fields[str(category)] += 1
    pii_hits: Counter = Counter()
    for category, value in (extra.get("counts") or {}).items():
        try:
            pii_hits[str(category)] += int(value or 0)
        except (TypeError, ValueError):
            continue
    categories = sorted(set(pii_fields) | set(pii_hits))
    return {
        "data_asset": _serialize_data_asset(item),
        "findings": [_serialize_detection(row) for row in findings],
        # Kept as the field count for existing callers; the detail map below
        # carries both units.
        "pii_summary": {category: pii_fields.get(category, 0) for category in categories},
        "pii_summary_detail": {
            category: {
                "fields": pii_fields.get(category, 0),
                "sample_hits": pii_hits.get(category, 0),
            }
            for category in categories
        },
        "summary": {
            "asset_type": item.asset_type,
            "sensitive_field_count": sum(pii_fields.values()),
            "sample_hits": sum(pii_hits.values()),
            "units": "fields=敏感字段数；sample_hits=本次样本内命中次数（非字段数）",
            "note": (
                "目录为子项汇总，不与文件重复计数"
                if item.asset_type == "directory"
                else "命中次数限于本次采集样本，不代表全量数据"
            ),
        },
    }


SENSITIVE_RULE_BUCKETS = {"DATA_SECRET_001": "secret", "DATA_PII_001": "pii"}


def _sensitive_bucket(engine: str, rule_id: str) -> str:
    if engine == "dlp_engine":
        return "network_dlp"
    return SENSITIVE_RULE_BUCKETS.get(rule_id, "yara")


@router.get("/sensitive/findings")
def sensitive_findings(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Sensitive-data findings whose totals come from whole-table aggregates.

    Cards, the category chart and the paged detail list all read the same
    engines, so a 447-asset tenant is never summarised as the 200-row page it
    happens to fit in. Object-model probe detections and the legacy
    ``data_assets`` projection are reported as their own sources instead of
    being silently added together, and legacy rows still marked
    ``not_observed`` stay apart from the assets still in place.
    """
    engines = ["data_engine", "dlp_engine"]
    grouped = db.execute(
        select(
            DetectionFinding.engine,
            DetectionFinding.rule_id,
            func.count(DetectionFinding.id),
            func.max(DetectionFinding.risk_score),
            func.max(DetectionFinding.severity),
        )
        .where(DetectionFinding.engine.in_(engines))
        .group_by(DetectionFinding.engine, DetectionFinding.rule_id)
    ).all()
    categories: dict[str, dict[str, Any]] = {}
    source_counts = {engine: 0 for engine in engines}
    total_findings = 0
    for engine, rule_id, count, risk_score, severity in grouped:
        count = int(count or 0)
        total_findings += count
        source_counts[engine] = source_counts.get(engine, 0) + count
        cat = _sensitive_bucket(engine, rule_id)
        entry = categories.setdefault(
            cat, {"category": cat, "count": 0, "severity": severity, "risk_score": 0.0}
        )
        entry["count"] += count
        if float(risk_score or 0) >= entry["risk_score"]:
            entry["risk_score"] = round(float(risk_score or 0), 2)
            entry["severity"] = severity
    detail_query = (
        select(DetectionFinding)
        .where(DetectionFinding.engine.in_(engines))
        .order_by(DetectionFinding.risk_score.desc(), DetectionFinding.id.desc())
    )
    result = paginate(db, detail_query, page, page_size)
    details: list[dict[str, Any]] = []
    for item in result["items"]:
        evidence = item.evidence or {}
        regex = evidence.get("regex")
        file_name = evidence.get("file", evidence.get("filename", ""))
        counts = regex.get("counts", {}) if isinstance(regex, dict) else {}
        secret_count = evidence.get("secret_count")
        if not isinstance(secret_count, int):
            secret_count = regex.get("secret_count", 0) if isinstance(regex, dict) else 0
        details.append(
            {
                "id": item.id,
                "engine": item.engine,
                "rule_id": item.rule_id,
                "severity": item.severity,
                "risk_level": item.risk_level,
                "risk_score": round(float(item.risk_score or 0), 2),
                "file": file_name,
                "target_id": item.target_id,
                "counts": counts,
                "secret_count": secret_count,
                # Sanitised summary only: never the matched raw value.
                "evidence": {"file": file_name, "counts": counts, "secret_count": secret_count},
            }
        )
    # Object model (probe detections): the entity is the sensitive category, so
    # phone/email/... appear here instead of the three coarse engine buckets.
    active = (AssetInstance.status == INSTANCE_ACTIVE) & (
        Detection.object_id == AssetInstance.object_id
    )
    entity_rows = db.execute(
        select(Detection.category, func.count(Detection.id))
        .join(AssetInstance, AssetInstance.id == Detection.instance_id)
        .where(active)
        .group_by(Detection.category)
        .order_by(func.count(Detection.id).desc())
    ).all()
    entities = [{"category": name, "count": int(count or 0)} for name, count in entity_rows]
    detection_total = sum(item["count"] for item in entities)
    # Only the objects that actually carry a current detection are counted: a
    # global "active objects" number next to "detections" reads as "objects with
    # findings" and would be the same kind of mixed-unit claim this page is
    # fixing.
    detected_objects = set(
        db.scalars(
            select(Detection.object_id)
            .join(AssetInstance, AssetInstance.id == Detection.instance_id)
            .where(active)
            .distinct()
        ).all()
    )
    object_total = len(detected_objects)
    detected_ids = sorted(detected_objects)
    instance_total = (
        int(
            db.scalar(
                select(func.count(AssetInstance.id)).where(
                    AssetInstance.status == INSTANCE_ACTIVE,
                    AssetInstance.object_id.in_(detected_ids),
                )
            )
            or 0
        )
        if detected_ids
        else 0
    )
    observed: dict[str, int] = {}
    not_observed: dict[str, int] = {}
    asset_total = 0
    for asset in db.scalars(select(DataAsset)).all():
        asset_total += 1
        bucket = not_observed if (asset.extra or {}).get("status") == "not_observed" else observed
        bucket[asset.sensitivity] = bucket.get(asset.sensitivity, 0) + 1
    by_sensitivity: dict[str, int] = {}
    for part in (observed, not_observed):
        for name, value in part.items():
            by_sensitivity[name] = by_sensitivity.get(name, 0) + value
    page_size = result["page_size"]
    return {
        "categories": sorted(categories.values(), key=lambda item: -item["risk_score"]),
        "entities": entities,
        "details": details,
        "sources": [
            {
                "source": "data_engine",
                "kind": "file_scan",
                "count": source_counts.get("data_engine", 0),
            },
            {
                "source": "dlp_engine",
                "kind": "network_dlp",
                "count": source_counts.get("dlp_engine", 0),
            },
            {"source": "object_model", "kind": "probe_detection", "count": detection_total},
            {"source": "data_assets", "kind": "legacy_projection", "count": asset_total},
        ],
        "totals": {
            "findings": total_findings,
            "categories": len(categories),
            "entities": len(entities),
            "objects": object_total,
            "instances": instance_total,
            "detections": detection_total,
            "data_assets": asset_total,
        },
        "pagination": {
            "page": result["page"],
            "page_size": page_size,
            "total": result["total"],
            "pages": (result["total"] + page_size - 1) // page_size,
        },
        "data_assets": {
            "total": asset_total,
            "by_sensitivity": by_sensitivity,
            "observed": {"total": sum(observed.values()), "by_sensitivity": observed},
            "not_observed": {"total": sum(not_observed.values()), "by_sensitivity": not_observed},
        },
        "note": "总数来自全表聚合；未观测资产单独统计，不与在位资产相加",
    }
