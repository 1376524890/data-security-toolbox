"""Read-side data type and object presentation."""

from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AssetInstance, DataObject, Detection, Probe
from app.services import sensitivity_map
from app.services.data_objects.definitions import (
    HASH_FULL,
    HASH_PARTIAL,
    INSTANCE_ACTIVE,
    MAX_SUMMARY_ROWS,
)
from app.services.data_objects.values import _float, _iso


def owner_key_of(probe_id: Any, owner_key: Any) -> str:
    """Who observed this copy: ``probe:<id>`` for files, ``db:<id>`` for a table.

    A database-sourced instance carries no ``probe_id``, so counting that column
    alone crashed on the NULL and, worse, would have merged every configured
    target database into one nameless host. ``owner_key`` decides; the probe
    fallback keeps rows written before the column existed - and SQLite test
    databases, where it defaults to an empty string - attributing to the probe
    that actually observed them.
    """
    key = str(owner_key or "").strip()
    if key:
        return key
    return f"probe:{int(probe_id)}" if probe_id is not None else ""


def data_type_rows(
    db: Session, *, mapping: dict[str, str] | None = None, probe_id: int | None = None
) -> list[dict[str, Any]]:
    """One row per sensitive type, with the documented de-duplication rules.

    Confirmed duplicates are counted **per object** as
    ``max(instance_count - 1, 0)`` over that object's instances *in the requested
    scope* and summed, so a category observed on several instances of one object
    is still one duplicate - not one per row, and a probe filter never borrows
    another host's copies. ``object_count``/``active_instance_count`` here are
    per-type relations: one object holding two types appears in both rows, which
    is exactly why they must never be summed into a total.
    """
    scope = _type_scope(db, probe_id)
    objects = scope["objects"]
    instances = scope["instances"]
    hosts = scope["hosts"]
    full = scope["full"]
    partial = scope["partial"]
    instance_counts = scope["scope_instance_counts"]
    candidate_duplicates = scope["candidate_duplicates"]
    identity_pending = scope["identity_pending"]
    rows: list[dict[str, Any]] = []
    for category in sorted(set(objects) | set(partial)):
        explanation = sensitivity_map.explain(category, mapping=mapping)
        rows.append(
            {
                **explanation,
                "object_count": len(objects.get(category, ())),
                "active_instance_count": len(instances.get(category, ())),
                "host_count": len(hosts.get(category, ())),
                "confirmed_duplicate_count": sum(
                    max(instance_counts.get(obj_id, 0) - 1, 0) for obj_id in full.get(category, ())
                ),
                # A partial fingerprint only becomes a *suspected copy* once the same
                # content is seen on two instances; a lone one is an unresolved
                # identity, not a duplicate.
                "candidate_duplicate_count": len(
                    partial.get(category, set()) & candidate_duplicates
                ),
                "identity_pending_count": len(partial.get(category, set()) & identity_pending),
                "candidate_count": len(partial.get(category, ())),
                "truncated": scope["truncated"],
            }
        )
    return rows


def _type_scope(db: Session, probe_id: int | None) -> dict[str, Any]:
    """The join shared by the type rows and the de-duplicated totals."""
    joined = (
        select(
            Detection.category,
            Detection.object_id,
            DataObject.hash_type,
            DataObject.active_instance_count,
            Detection.instance_id,
            AssetInstance.probe_id,
            AssetInstance.owner_key,
        )
        .join(DataObject, DataObject.id == Detection.object_id)
        .join(AssetInstance, AssetInstance.id == Detection.instance_id)
        # A detection belongs to the object that was current when it was
        # produced. Without this predicate a renamed or changed file counted
        # its *historical* detection for the live instance and the type
        # centre kept reporting a category the current content no longer has.
        .where(
            AssetInstance.status == INSTANCE_ACTIVE, Detection.object_id == AssetInstance.object_id
        )
        .limit(MAX_SUMMARY_ROWS)
    )
    if probe_id:
        joined = joined.where(AssetInstance.probe_id == probe_id)
    objects: dict[str, set[int]] = {}
    instances: dict[str, set[int]] = {}
    hosts: dict[str, set[str]] = {}
    full: dict[str, set[int]] = {}
    partial: dict[str, set[int]] = {}
    object_ids: set[int] = set()
    hash_by_object: dict[int, str] = {}
    truncated = False
    count = 0
    for row in db.execute(joined).all():
        count += 1
        category = str(row[0])
        obj_id = int(row[1])
        objects.setdefault(category, set()).add(obj_id)
        instances.setdefault(category, set()).add(int(row[4]))
        # ``host_count`` counts where a copy was observed, which is not always a
        # probe: a database table has no ``probe_id`` at all. Counting the column
        # directly both crashed on the NULL and would have merged every target
        # database into one nameless host, so the owner key decides.
        owner = owner_key_of(row[5], row[6])
        if owner:
            hosts.setdefault(category, set()).add(owner)
        object_ids.add(obj_id)
        hash_by_object[obj_id] = str(row[2])
        if row[2] == HASH_FULL:
            full.setdefault(category, set()).add(obj_id)
        elif row[2] == HASH_PARTIAL:
            partial.setdefault(category, set()).add(obj_id)
    if count >= MAX_SUMMARY_ROWS:
        truncated = True
    # How many active instances each of those objects has *inside the requested
    # scope*: the copy count is a property of the object, never of a category and
    # never of another probe's view.
    scope_instances = select(AssetInstance.object_id, AssetInstance.id).where(
        AssetInstance.status == INSTANCE_ACTIVE
    )
    if probe_id:
        scope_instances = scope_instances.where(AssetInstance.probe_id == probe_id)
    scope_instance_counts: dict[int, int] = {}
    for object_id, _instance_id in db.execute(scope_instances).all():
        object_id = int(object_id)
        if object_id in object_ids:
            scope_instance_counts[object_id] = scope_instance_counts.get(object_id, 0) + 1
    candidate_duplicates: set[int] = set()
    identity_pending: set[int] = set()
    for obj_id in object_ids:
        if hash_by_object.get(obj_id) != HASH_PARTIAL:
            continue
        if scope_instance_counts.get(obj_id, 0) >= 2:
            candidate_duplicates.add(obj_id)
        else:
            identity_pending.add(obj_id)
    return {
        "objects": objects,
        "instances": instances,
        "hosts": hosts,
        "full": full,
        "partial": partial,
        "object_ids": object_ids,
        "truncated": truncated,
        "hash_by_object": hash_by_object,
        "scope_instance_counts": scope_instance_counts,
        "candidate_duplicates": candidate_duplicates,
        "identity_pending": identity_pending,
    }


def data_type_summary(db: Session, *, probe_id: int | None = None) -> dict[str, Any]:
    """Cross-type totals over de-duplicated object/instance sets.

    Adding the per-type rows up counted a file that holds both an email address
    and a credential twice; these numbers are computed over sets instead, so
    ``objects`` is a real object count and ``confirmed_duplicates`` counts each
    duplicated object once regardless of how many types it carries.
    """
    scope = _type_scope(db, probe_id)
    object_ids = scope["object_ids"]
    instance_counts = scope["scope_instance_counts"]
    confirmed = [
        max(instance_counts.get(obj_id, 0) - 1, 0)
        for obj_id in object_ids
        if scope["hash_by_object"][obj_id] == HASH_FULL
    ]
    all_hosts: set[str] = set()
    for host_ids in scope["hosts"].values():
        all_hosts |= host_ids
    return {
        "types": len(set(scope["objects"]) | set(scope["partial"])),
        "objects": len(object_ids),
        "instances": sum(instance_counts.get(obj_id, 0) for obj_id in object_ids),
        "hosts": len(all_hosts),
        "confirmed_duplicates": sum(confirmed),
        "candidate_duplicates": len(scope["candidate_duplicates"]),
        "identity_pending": len(scope["identity_pending"]),
        "truncated": scope["truncated"],
    }


def object_detail(db: Session, object_id: int) -> dict[str, Any] | None:
    obj = db.get(DataObject, object_id)
    if obj is None:
        return None
    mapping = sensitivity_map.overrides(db)
    return {
        "id": obj.id,
        "object_key": obj.object_key,
        "object_type": obj.object_type,
        "content_hash": obj.content_hash,
        "hash_type": obj.hash_type,
        "identity_confidence": _float(obj.identity_confidence),
        "identity_kind": (
            "confirmed"
            if obj.hash_type == HASH_FULL
            else "candidate"
            if obj.hash_type == HASH_PARTIAL
            else "scoped"
        ),
        "partial_version": obj.partial_version,
        "partial_layout": dict(obj.partial_layout or {}),
        "size": obj.size,
        "categories": list(obj.categories or []),
        "sensitivity": obj.sensitivity,
        "level": sensitivity_map.worst_level(obj.categories, mapping=mapping),
        "level_source": "settings_override" if mapping else "builtin_default",
        "instance_count": obj.instance_count,
        "active_instance_count": obj.active_instance_count,
        "first_seen_at": _iso(obj.first_seen_at),
        "last_seen_at": _iso(obj.last_seen_at),
        "extra": dict(obj.extra or {}),
    }


def instance_detail(db: Session, instance_id: int) -> dict[str, Any] | None:
    instance = db.get(AssetInstance, instance_id)
    if instance is None:
        return None
    probe = db.get(Probe, instance.probe_id) if instance.probe_id is not None else None
    obj = db.get(DataObject, instance.object_id)
    mapping = sensitivity_map.overrides(db)
    extra = dict(instance.extra or {})
    # A shared-file or database instance has no probe row, so the collector that
    # did observe it is named from the evidence it wrote: showing an empty source
    # would read as "came from nowhere" on the very page that answers "来自哪里".
    source_name = extra.get("source_name") or (probe.name if probe else "")
    host = (probe.ip_address or probe.hostname) if probe else extra.get("host", "")
    return {
        "id": instance.id,
        "probe_id": instance.probe_id,
        "probe_name": probe.name if probe else "",
        "host": host,
        "owner_key": instance.owner_key or (f"probe:{instance.probe_id}" if probe else ""),
        "source_kind": instance.source_kind or "file",
        "source_name": source_name,
        "path": instance.path,
        "name": instance.name,
        "instance_type": instance.instance_type,
        "size": instance.size,
        "content_hash": instance.content_hash,
        "hash_type": instance.hash_type,
        "status": instance.status,
        "owner": instance.owner,
        "group": instance.group,
        "permission": instance.permission,
        "inode": instance.inode,
        "device": instance.device,
        "mtime_ns": instance.mtime_ns,
        "object_id": instance.object_id,
        "object_key": obj.object_key if obj else "",
        "identity_kind": (
            "confirmed"
            if obj and obj.hash_type == HASH_FULL
            else "candidate"
            if obj and obj.hash_type == HASH_PARTIAL
            else "scoped"
        ),
        "sensitivity": instance.sensitivity,
        "level": sensitivity_map.worst_level(instance.categories, mapping=mapping),
        "level_source": "settings_override" if mapping else "builtin_default",
        "categories": list(instance.categories or []),
        "coverage": instance.coverage,
        "termination_reason": instance.termination_reason,
        "ruleset_version": instance.ruleset_version,
        "engine_version": instance.engine_version,
        "profile_version": instance.profile_version,
        "last_scan_id": instance.last_scan_id,
        "first_seen_at": _iso(instance.first_seen_at),
        "last_seen_at": _iso(instance.last_seen_at),
        "last_scan_at": _iso(instance.last_scan_at),
        "extra": extra,
    }
