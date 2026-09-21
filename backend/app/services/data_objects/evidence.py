"""Detection evidence merge rules; no HTTP or task dispatch."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AssetInstance, DataObject, Detection, DetectionEvidence
from app.services.data_objects.persistence import _get_or_create
from app.services.data_objects.values import _float, _int, _newest, _text, category_name

#: Mirrors the probe's engine caps: the platform stores what the report carried
#: and never widens it.
MAX_RETURNED_MATCHES = 3
MAX_MATCH_CHARS = 120
MAX_CONTEXT_CHARS = 240


def evidence_key(entry: dict[str, Any]) -> str:
    parts = (
        entry.get("rule_id", ""),
        entry.get("rule_source", ""),
        entry.get("evidence_type", ""),
        entry.get("field_name", ""),
        entry.get("sheet_name", ""),
        "" if entry.get("column_index") is None else entry.get("column_index"),
    )
    return "|".join(str(item)[:48] for item in parts)[:200]


def _evidence_rows(asset: dict[str, Any]) -> list[dict[str, Any]]:
    """Flatten the report's hits into one row per (rule, kind, field, sheet)."""
    evidence = asset.get("evidence") if isinstance(asset.get("evidence"), dict) else {}
    rows: list[dict[str, Any]] = []
    for hit in evidence.get("hits") or []:
        if not isinstance(hit, dict):
            continue
        category = category_name(hit.get("category") or hit.get("entity"))
        entries = hit.get("evidence") if isinstance(hit.get("evidence"), list) else []
        for item in entries:
            if not isinstance(item, dict):
                continue
            rows.append(
                {
                    "category": category,
                    "rule_id": _text(item.get("rule_id"), 128),
                    "rule_name": _text(item.get("rule_name"), 255),
                    "rule_source": _text(item.get("rule_source"), 32),
                    "recognizer": _text(item.get("recognizer"), 64),
                    "evidence_type": _text(item.get("evidence_type"), 32),
                    "field_name": _text(hit.get("field_name"), 128),
                    "sheet_name": _text(hit.get("sheet_name"), 128),
                    "column_index": hit.get("column_index")
                    if isinstance(hit.get("column_index"), int)
                    else None,
                    "confidence": _float(item.get("confidence")),
                    "hit_count": max(_int(hit.get("count")), 0),
                    "matches": _returned_matches(hit),
                }
            )
    return rows


def _returned_matches(hit: dict[str, Any]) -> list[dict[str, str]]:
    """The原文 the probe returned for one hit, re-bounded and shape-checked.

    The report is data from a host, so the bounds are enforced here as well:
    a payload that carried more, or longer, strings than the engine emits is
    trimmed to the documented shape instead of being stored as-is.
    """
    items = hit.get("matches")
    if not isinstance(items, list):
        return []
    rows: list[dict[str, str]] = []
    for item in items[:MAX_RETURNED_MATCHES]:
        if not isinstance(item, dict):
            continue
        value = _text(item.get("value"), MAX_MATCH_CHARS)
        if not value:
            continue
        rows.append({"value": value, "context": _text(item.get("context"), MAX_CONTEXT_CHARS)})
    return rows


def _merge_evidence(
    db: Session,
    detection: Detection,
    row: dict[str, Any],
    *,
    engine_version: str,
    ruleset_version: str,
) -> None:
    key = evidence_key(row)
    existing = db.scalar(
        select(DetectionEvidence).where(
            DetectionEvidence.detection_id == detection.id, DetectionEvidence.evidence_key == key
        )
    )
    if existing is not None:
        # Never lower a stored value: a late report must not weaken current proof.
        # Never lower a stored value: a weaker or partial re-observation must not
        # erase proof that was already collected for this object.
        existing.confidence = max(_float(existing.confidence), row["confidence"])
        existing.hit_count = max(_int(existing.hit_count), row["hit_count"])
        if row["matches"]:
            # 原文 belongs to the scan that produced it: keep the newest set, but
            # never let an empty one erase text that was already returned.
            existing.extra = {**(existing.extra or {}), "matches": row["matches"]}
        return
    db.add(
        DetectionEvidence(
            detection_id=detection.id,
            evidence_key=key,
            rule_id=row["rule_id"],
            rule_name=row["rule_name"],
            rule_source=row["rule_source"],
            recognizer=row["recognizer"],
            evidence_type=row["evidence_type"],
            field_name=row["field_name"],
            sheet_name=row["sheet_name"],
            column_index=row["column_index"],
            confidence=row["confidence"],
            hit_count=row["hit_count"],
            engine_version=engine_version,
            ruleset_version=ruleset_version,
            extra={"matches": row["matches"]} if row["matches"] else {},
        )
    )


def _merge_detection(
    db: Session,
    *,
    instance: AssetInstance,
    obj: DataObject,
    #: NULL for a database-sourced finding: that path has no probe.
    probe_id: int | None,
    source_kind: str = "file",
    scan_id: str,
    category: str,
    counts: dict[str, Any],
    evidence_rows: list[dict[str, Any]],
    engine_version: str,
    ruleset_version: str,
    observed_at: datetime,
    sample_size: int,
    sample_limit: int,
    confidence: float,
    severity: str,
    level: str,
) -> Detection:
    current_count = _int(counts.get(category))
    detection, created = _get_or_create(
        db,
        Detection,
        {"instance_id": instance.id, "category": category, "object_id": obj.id},
        {
            "probe_id": probe_id,
            "source_kind": source_kind,
            "scan_id": scan_id,
            "sensitivity_level": level,
            "severity": severity,
            "confidence": confidence,
            "sample_size": sample_size,
            "sample_limit": sample_limit,
            "sample_hit_count": current_count,
            "hit_count": current_count,
            "engine_version": engine_version,
            "ruleset_version": ruleset_version,
            "first_seen_at": observed_at,
            "last_seen_at": observed_at,
        },
    )
    if not created:
        # One scan is one result: the count, confidence, evidence and version all
        # come from this observation. Anything larger seen earlier is preserved in
        # ``extra`` as history instead of being presented as the current value,
        # which is what made ``hit_count`` claim 10 hits while ``scan_id`` pointed
        # at the scan that found 2.
        history = dict(detection.extra or {})
        confidence_history = max(
            _float(history.get("confidence_history")), _float(detection.confidence), confidence
        )
        hit_history = max(
            _int(history.get("hit_count_history")), _int(detection.hit_count), current_count
        )
        detection.confidence = confidence
        # A row created before this column existed reads as "file"; a database
        # finding corrects itself on its next write instead of staying wrong.
        detection.source_kind = source_kind
        detection.sensitivity_level = level
        detection.severity = severity
        detection.sample_size = sample_size
        detection.sample_limit = sample_limit
        detection.scan_id = scan_id
        detection.engine_version = engine_version
        detection.ruleset_version = ruleset_version
        detection.hit_count = current_count
        detection.sample_hit_count = current_count
        detection.last_seen_at = _newest(detection.last_seen_at, observed_at) or observed_at
        detection.extra = {
            **history,
            "confidence_history": round(confidence_history, 3),
            "hit_count_history": hit_history,
        }
    for row in evidence_rows:
        if row["category"] != category:
            continue
        _merge_evidence(
            db, detection, row, engine_version=engine_version, ruleset_version=ruleset_version
        )
    return detection
