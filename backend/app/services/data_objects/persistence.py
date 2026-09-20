"""Database primitives shared by ingestion and projection; no commits."""

from __future__ import annotations

from typing import Any

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import AssetInstance, DataObject, Detection, DetectionEvidence
from app.services import sensitivity_map
from app.services.data_objects.definitions import INSTANCE_ACTIVE
from app.services.data_objects.values import _int


def _get_or_create(
    db: Session, model: Any, keys: dict[str, Any], defaults: dict[str, Any]
) -> tuple[Any, bool]:
    """The unique constraint decides, not a prior SELECT.

    Two reports uploading the same object at the same time must converge on one
    row; a savepoint makes the loser re-read instead of failing the whole report.
    """
    row = db.scalar(select(model).filter_by(**keys))
    if row is not None:
        return row, False
    try:
        with db.begin_nested():
            row = model(**keys, **defaults)
            db.add(row)
            db.flush()
        return row, True
    except IntegrityError:
        db.expunge_all()
        row = db.scalar(select(model).filter_by(**keys))
        if row is None:
            raise
        return row, False


def forget_probe(db: Session, probe_id: int) -> dict[str, int]:
    """Drop one probe's observation state when the probe itself is deleted.

    An instance identity is ``(probe_id, path)``; once the probe is gone that
    identity cannot be reconstructed, so keeping a half-detached copy would
    invent a host that no longer exists. The *logical* objects stay, because a
    second probe may still hold the same content, and the legacy
    ``data_assets`` projection is untouched - the existing
    "keep collected records, clear the foreign key" behaviour of
    ``DELETE /probes/{id}`` is unchanged for every legacy table.
    """
    instance_ids = list(
        db.scalars(select(AssetInstance.id).where(AssetInstance.probe_id == probe_id))
    )
    object_ids = list(
        db.scalars(
            select(AssetInstance.object_id.distinct()).where(AssetInstance.probe_id == probe_id)
        )
    )
    detections = 0
    if instance_ids:
        detection_ids = select(Detection.id).where(Detection.instance_id.in_(instance_ids))
        db.execute(
            delete(DetectionEvidence).where(DetectionEvidence.detection_id.in_(detection_ids))
        )
        detections = _int(
            db.scalar(
                select(func.count())
                .select_from(Detection)
                .where(Detection.instance_id.in_(instance_ids))
            )
        )
        db.execute(delete(Detection).where(Detection.instance_id.in_(instance_ids)))
        db.execute(delete(AssetInstance).where(AssetInstance.id.in_(instance_ids)))
    db.flush()
    for object_id in object_ids:
        obj = db.get(DataObject, object_id)
        if obj is not None:
            recount_object(db, obj)
    return {
        "instances": len(instance_ids),
        "detections": detections,
        "objects_recounted": len(object_ids),
    }


def recount_object(db: Session, obj: DataObject) -> DataObject:
    """Recompute the counters - and the current categories - from live instances.

    Trusting incremental arithmetic left the copy counts stale after a migration
    or a sweep, and keeping the categories as a permanent union meant a file that
    had become clean still advertised its old sensitive type. The current set is
    therefore derived from the ACTIVE instances that still carry the object; when
    none remain, the stored value is left as history instead of being erased.
    """
    rows = db.execute(
        select(AssetInstance.status, AssetInstance.categories).where(
            AssetInstance.object_id == obj.id
        )
    ).all()
    obj.instance_count = len(rows)
    obj.active_instance_count = sum(1 for status, _ in rows if status == INSTANCE_ACTIVE)
    live: list[str] = []
    for status, categories in rows:
        if status != INSTANCE_ACTIVE:
            continue
        for category in categories or []:
            if category not in live:
                live.append(category)
    if obj.active_instance_count:
        # A live copy speaks for the object - even when it has nothing sensitive
        # left, which is how a rule revision or a cleaned file revokes its old
        # label. With no live copy at all the stored value is history and stays.
        obj.categories = live[:24]
    obj.sensitivity = sensitivity_map.worst_severity(obj.categories or [])
    return obj
