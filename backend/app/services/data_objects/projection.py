"""Derived legacy views; never a second source of truth."""

from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AssetInstance, DataAsset, DataObject, Detection, Probe
from app.services import sensitivity_map
from app.services.data_objects.definitions import (
    _SEVERITY_RANK,
    HASH_FULL,
    HASH_SCOPED,
    IDENTITY_SCOPED,
    INSTANCE_ACTIVE,
    SCOPED_KEY_SALT,
)
from app.services.data_objects.identity import normalise_path
from app.services.data_objects.persistence import _get_or_create, recount_object
from app.services.data_objects.values import _float, _int, _parse_time, _text, category_name


def _reported_sensitivity(entry: dict[str, Any]) -> str:
    """The legacy ``sensitivity`` the projection may write for one entry.

    The platform owns the category-to-severity mapping, and a probe's local map
    can lag the ruleset it just downloaded: a 3.4.1 probe reported
    ``se_organisationsnummer`` as ``Low`` while the detection it uploaded for the
    same file says ``Medium``. The projection must never be *less* severe than the
    platform's own mapping of the categories it was given, so the stricter of the
    two wins. Anything that is not a legacy severity (``Unknown`` for candidate or
    port-inferred entries) is kept exactly as reported.
    """
    reported = _text(entry.get("sensitivity"), 16) or "Unknown"
    categories = [category_name(item) for item in (entry.get("categories") or [])]
    if not categories:
        return reported
    rank = _SEVERITY_RANK.get(reported.lower(), 0)
    if not rank:
        return reported
    mapped = sensitivity_map.worst_severity(categories)
    return mapped if _SEVERITY_RANK.get(mapped.lower(), 0) > rank else reported


def project_asset(
    db: Session,
    probe: Probe,
    entry: dict[str, Any],
    *,
    scan_id: str,
    modified_at: str,
    scanner: str,
    observed_at: datetime,
) -> DataAsset | None:
    """Keep the legacy ``data_assets`` row in step with one reported entry.

    The projection is derived from the reported fields, so it can always be
    rebuilt from the new tables - it is never a second source of truth.
    """
    path = _text(entry.get("path"), 1024)
    asset_type = _text(entry.get("asset_type"), 64) or "file"
    name = _text(entry.get("name"), 512) or path
    sensitivity = _reported_sensitivity(entry)
    row = db.scalar(
        select(DataAsset).where(
            DataAsset.asset_type == asset_type,
            DataAsset.extra["probe_id"].as_integer() == probe.id,
            DataAsset.extra["path"].as_string() == path,
        )
    )
    if row is None:
        row = DataAsset(
            name=name,
            asset_type=asset_type,
            sensitivity=sensitivity,
            source=f"probe:{probe.name}",
            columns=[],
            extra={},
        )
        db.add(row)
    row.name = name
    row.sensitivity = sensitivity
    row.source = f"probe:{probe.name}"
    row.columns = [column for column in (entry.get("columns") or []) if isinstance(column, dict)][
        :256
    ]
    row.extra = {
        "probe_id": probe.id,
        "probe": probe.name,
        "host": probe.ip_address or probe.hostname,
        "path": path,
        "size": _int(entry.get("size")),
        "sha256": _text(entry.get("sha256"), 64),
        "modified_at": _text(modified_at, 64),
        "categories": list(entry.get("categories") or []),
        # Header/port hints stay separate from confirmed categories so a page can
        # show "candidate" without counting it as discovered sensitive data.
        "candidate_categories": list(entry.get("candidate_categories") or []),
        "counts": dict(entry.get("counts") or {}),
        "evidence": dict(entry.get("evidence") or {}),
        "status": "observed",
        "scanner": scanner,
        "observed_at": observed_at.isoformat(),
        "scan_id": scan_id,
    }
    return row


def mark_projection_not_observed(
    db: Session, probe_id: int, paths: set[str], when: datetime
) -> int:
    """Mirror the instance sweep onto the legacy rows for the same paths."""
    if not paths:
        return 0
    rows = db.scalars(
        select(DataAsset).where(DataAsset.extra["probe_id"].as_integer() == probe_id)
    ).all()
    marked = 0
    for row in rows:
        extra = row.extra or {}
        if extra.get("status") != "observed":
            continue
        if _text(extra.get("path"), 1024) not in paths:
            continue
        row.extra = {**extra, "status": "not_observed", "checked_at": when.isoformat()}
        marked += 1
    return marked


def rebuild_projection(db: Session, probe_id: int | None = None) -> dict[str, int]:
    """Regenerate the legacy projection from the new tables.

    This is the recovery path for the derived table: if the projection and the
    object model ever disagree, the projection is rebuilt instead of merged.
    """
    query = (
        select(AssetInstance).where(AssetInstance.probe_id == probe_id)
        if probe_id
        else select(AssetInstance)
    )
    instances = db.scalars(query).all()
    rebuilt = 0
    for instance in instances:
        probe = db.get(Probe, instance.probe_id)
        if probe is None:
            continue
        stored = instance.extra or {}
        asset_type = _text(stored.get("asset_type"), 64) or _asset_type_for(instance.instance_type)
        # Restore from the scan snapshot taken at ingest. When the snapshot is
        # absent (a pre-snapshot instance) the previous projection row keeps its
        # columns and evidence: writing detection categories in the "columns"
        # field would fabricate field names that were never observed.
        existing = db.scalar(
            select(DataAsset).where(
                DataAsset.asset_type == asset_type,
                DataAsset.extra["probe_id"].as_integer() == instance.probe_id,
                DataAsset.extra["path"].as_string() == instance.path,
            )
        )
        columns = [column for column in (stored.get("columns") or []) if isinstance(column, dict)]
        evidence = stored.get("evidence") if isinstance(stored.get("evidence"), dict) else {}
        structure_restored = bool(columns) or bool(evidence)
        if not columns and existing is not None:
            columns = [column for column in (existing.columns or []) if isinstance(column, dict)]
        if not evidence and existing is not None:
            evidence = dict((existing.extra or {}).get("evidence") or {})
        entry = {
            "name": instance.name,
            "asset_type": asset_type,
            "sensitivity": instance.sensitivity,
            "path": instance.path,
            "size": instance.size,
            "sha256": instance.content_hash if instance.hash_type == HASH_FULL else "",
            "categories": list(instance.categories or []),
            "columns": columns[:256],
            "evidence": evidence,
            "counts": dict(stored.get("counts") or {}),
        }
        row = project_asset(
            db,
            probe,
            entry,
            scan_id=instance.last_scan_id,
            modified_at=_text(stored.get("modified_at"), 64),
            scanner=_text(stored.get("scanner"), 64),
            observed_at=instance.last_seen_at or datetime.now(UTC),
        )
        if row is None:
            continue
        if instance.status != INSTANCE_ACTIVE:
            row.extra = {**(row.extra or {}), "status": "not_observed"}
        # The legacy projection shows the *current* detections of the instance.
        detections = db.scalars(
            select(Detection).where(
                Detection.instance_id == instance.id, Detection.object_id == instance.object_id
            )
        ).all()
        row.columns = columns[:256]
        row.extra = {
            **(row.extra or {}),
            "detections": [
                {
                    "category": detection.category,
                    "severity": detection.severity,
                    "confidence": _float(detection.confidence),
                    "hit_count": _int(detection.hit_count),
                    "sensitivity_level": detection.sensitivity_level,
                    "scan_id": detection.scan_id,
                }
                for detection in detections
            ],
        }
        rebuild_meta: dict[str, Any] = {"structure_restored": structure_restored}
        notes: list[str] = []
        if not structure_restored:
            notes.append("扫描快照缺失，已保留原投影的字段与证据")
        if columns and all(_looks_like_category(column.get("name")) for column in columns):
            # A pre-fix rebuild wrote detection categories into ``columns`` and
            # overwrote the real names, which were never stored anywhere else.
            # They cannot be recovered, so the row keeps its values but is
            # labelled: a page must not present fabricated field names as
            # observed structure.
            rebuild_meta["fabricated_columns"] = True
            notes.append("列名疑似由敏感类别写成，真实字段名未保存、无法还原")
        if notes:
            rebuild_meta["note"] = "；".join(notes)
        row.extra = {**row.extra, "rebuild": rebuild_meta}
        rebuilt += 1
    return {"instances": len(instances), "rebuilt": rebuilt}


def _looks_like_category(name: Any) -> bool:
    """True when a column name is exactly a known sensitive category.

    ``legacy_name`` returns "" for anything that is not one of the shipped
    entities, so a real field such as ``mobile`` is never mistaken for a
    fabricated one while ``phone``/``id_card`` are recognised.
    """
    return bool(sensitivity_map.engine.legacy_name(str(name or "").strip()))


def _asset_type_for(instance_type: str) -> str:
    if instance_type == "directory":
        return "directory"
    if instance_type == "database_service":
        return "database"
    return "file"


def backfill_legacy(db: Session, *, limit: int = 20_000) -> dict[str, int]:
    """Project pre-existing ``data_assets`` rows into the object model.

    Records that never had a path, a probe or a hash keep ``hash_type='scoped'``
    and ``identity_confidence=0``; nothing is invented - no hash, no level, no
    detection and above all no new scan time. A row that cannot even be tied to a
    probe stays legacy-only and is counted as skipped.
    """
    rows = db.scalars(select(DataAsset).order_by(DataAsset.id).limit(limit)).all()
    created = 0
    skipped = 0
    for row in rows:
        extra = row.extra or {}
        probe_id = _int(extra.get("probe_id"))
        probe = db.get(Probe, probe_id) if probe_id else None
        if probe is None:
            skipped += 1
            continue
        path = normalise_path(extra.get("path") or row.name)
        exists = db.scalar(
            select(AssetInstance.id).where(
                AssetInstance.probe_id == probe.id, AssetInstance.path == path
            )
        )
        if exists:
            skipped += 1
            continue
        object_type = row.asset_type or "file"
        digest = hashlib.sha256(f"{SCOPED_KEY_SALT}:legacy:{probe.id}:{path}".encode()).hexdigest()
        obj, _ = _get_or_create(
            db,
            DataObject,
            {"object_key": f"scoped:{probe.id}:{digest[:40]}"},
            {
                "object_type": object_type,
                "hash_type": HASH_SCOPED,
                "identity_confidence": IDENTITY_SCOPED,
                "categories": list(extra.get("categories") or []),
                "sensitivity": row.sensitivity or "Unknown",
                "extra": {"backfilled": True, "legacy_asset_id": row.id},
            },
        )
        when = _parse_time(extra.get("observed_at")) or row.created_at or datetime.now(UTC)
        db.add(
            AssetInstance(
                probe_id=probe.id,
                object_id=obj.id,
                path=path,
                name=_text(row.name, 512),
                instance_type="file",
                size=_int(extra.get("size")),
                status=INSTANCE_ACTIVE,
                first_seen_at=row.created_at or when,
                last_seen_at=when,
                last_scan_at=None,
                last_scan_id="",
                scope_key="",
                sensitivity=row.sensitivity or "Unknown",
                categories=list(extra.get("categories") or []),
                extra={
                    "backfilled": True,
                    "legacy_asset_id": row.id,
                    "asset_type": row.asset_type,
                    "metadata": "unknown",
                },
            )
        )
        db.flush()
        recount_object(db, obj)
        created += 1
    db.flush()
    return {"legacy_rows": len(rows), "created": created, "skipped": skipped}
