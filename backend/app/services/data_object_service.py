"""Object / instance / detection storage: the platform's own data-asset model.

The probe reports *what is on that host*; this module decides what it means for
the platform. Three rules drive every decision here:

1. **Identity is explicit.** Equal full SHA256 is the only thing that may merge
   two files into one ``DataObject``. A versioned partial fingerprint can only
   produce a clearly labelled candidate. Without a reliable hash the object gets
   a scope-local identity instead of being merged by name or size.
2. **A stop is not a disappearance.** Instances in a scope are only marked
   ``NOT_OBSERVED`` when that exact scope was covered completely; a timeout, a
   cancel or a partial walk never does it.
3. **Nothing is overwritten away.** ``Detection`` is keyed by
   ``(instance, category, object)``, so when the content at a path changes the
   instance moves to a new object and the previous object keeps its own
   detections as history.

``data_assets`` stays as a **derived projection** for the legacy pages. It is
written in the same transaction as the new rows, and
:func:`rebuild_projection` can regenerate it from the new tables, so a divergence
is recoverable rather than permanent.
"""
from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any, Iterable

from sqlalchemy import delete, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models import AssetInstance, DataAsset, DataObject, Detection, DetectionEvidence, Probe
from app.services import sensitivity_map

# --- identity kinds ---------------------------------------------------------
HASH_FULL = "full_sha256"
HASH_PARTIAL = "partial_fingerprint"
HASH_SCOPED = "scoped"

#: `identity_confidence` states the strength of the *identity* evidence only.
IDENTITY_FULL = 1.0
IDENTITY_PARTIAL = 0.5
IDENTITY_SCOPED = 0.0

INSTANCE_ACTIVE = "ACTIVE"
INSTANCE_NOT_OBSERVED = "NOT_OBSERVED"
#: Reserved, never inferred: "not observed" is not proof of deletion.
INSTANCE_RESERVED = ("STALE", "DISAPPEARED")

SCOPED_KEY_SALT = "dst-object-v1"
MAX_SUMMARY_ROWS = 50_000
_HEX64 = re.compile(r"^[0-9a-f]{64}$")
#: A partial fingerprint digest. Shorter than 64 hex characters is still a real
#: digest, but anything that is not hex at all (a redaction placeholder, a
#: truncated paste) must never become an object key.
_HEX_DIGEST = re.compile(r"^[0-9a-f]{32,64}$")

#: Report schema the ingestion understands. An older probe sends no version and
#: is handled by the legacy branch instead of being guessed at.
REPORT_SCHEMA_SUPPORTED = ("1.0", "1.1")


class DataObjectError(ValueError):
    """Raised for a payload the ingestion refuses to interpret."""


def category_name(value: Any) -> str:
    """One stable category name for a type, whatever alias the caller used.

    The platform keeps the existing lowercase names (``phone``, ``id_card``) so
    the legacy pages and the new type centre cannot disagree about what "the same
    type" means; an analyst-authored type with no legacy alias keeps its own name
    in lowercase instead of being dropped.
    """
    canonical = sensitivity_map.engine.canonical_entity(value)
    return (sensitivity_map.engine.legacy_name(canonical) or canonical.lower())[:64]


# --- small helpers ----------------------------------------------------------
def _text(value: Any, limit: int) -> str:
    return str(value or "")[:limit]


def _int(value: Any, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def _float(value: Any, default: float = 0.0) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return default


def _parse_time(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=UTC)
    text = str(value or "").strip()
    if not text:
        return None
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)


def _aware(value: datetime | None) -> datetime | None:
    """SQLite hands back naive datetimes; treat them as UTC, never as local time."""
    if value is None:
        return None
    return value if value.tzinfo else value.replace(tzinfo=UTC)


def _newest(*values: datetime | None) -> datetime | None:
    present = [_aware(value) for value in values if value is not None]
    return max(present) if present else None


def _iso(value: datetime | None) -> str:
    aware = _aware(value)
    return aware.isoformat() if aware else ""


def normalise_path(path: Any) -> str:
    """Absolute, collapsed path. Never resolved through symlinks: a symlink is a
    different instance from its target, and the probe already refuses to follow
    them."""
    text = str(path or "").strip()
    if not text:
        return ""
    if not text.startswith("/"):
        # Not a filesystem path (e.g. a `host:port` database service); keep it as
        # an opaque, stable identifier instead of pretending it is absolute.
        return text[:1024]
    parts: list[str] = []
    for part in text.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/" + "/".join(parts)


def instance_type_for(entry: dict[str, Any], *, from_databases: bool) -> str:
    if from_databases:
        return "database_service"
    if str(entry.get("asset_type") or "") == "directory":
        return "directory"
    return "file"


def object_type_for(entry: dict[str, Any], instance_type: str) -> str:
    asset_type = str(entry.get("asset_type") or "").strip()
    if instance_type == "directory":
        return "directory"
    if instance_type == "database_service":
        return "database"
    return asset_type or "file"


def resolve_identity(entry: dict[str, Any], *, probe_id: int, object_type: str,
                     path: str) -> dict[str, Any]:
    """The object key plus the identity evidence behind it.

    A fabricated hash is never produced: with no digest the key is explicitly
    scope-local, which is what keeps two unrelated files from silently becoming
    one object.
    """
    full = _text(entry.get("sha256"), 128).strip().lower()
    if _HEX64.match(full):
        return {"object_key": f"full:{object_type}:{full}", "hash_type": HASH_FULL,
                "content_hash": full, "identity_confidence": IDENTITY_FULL,
                "partial_version": "", "partial_layout": {}}
    fingerprint = entry.get("evidence") if isinstance(entry.get("evidence"), dict) else {}
    fingerprint = fingerprint.get("fingerprint") if isinstance(fingerprint.get("fingerprint"), dict) else {}
    value = _text(fingerprint.get("value"), 128).strip().lower()
    if value and not fingerprint.get("is_full") and _HEX_DIGEST.match(value):
        version = _text(fingerprint.get("version"), 32)
        return {"object_key": f"partial:{version}:{value}", "hash_type": HASH_PARTIAL,
                "content_hash": "", "identity_confidence": IDENTITY_PARTIAL,
                "partial_version": version,
                "partial_layout": {key: fingerprint.get(key) for key in
                                   ("algorithm", "size", "blocks", "positions")
                                   if fingerprint.get(key) is not None}}
    digest = hashlib.sha256(f"{SCOPED_KEY_SALT}:{probe_id}:{path}".encode("utf-8")).hexdigest()
    return {"object_key": f"scoped:{probe_id}:{digest[:40]}", "hash_type": HASH_SCOPED,
            "content_hash": "", "identity_confidence": IDENTITY_SCOPED,
            "partial_version": "", "partial_layout": {}}


def scope_key_for(payload: dict[str, Any], *, probe_id: int) -> str:
    """A scope is only comparable to itself: roots, depth, profile and probe."""
    roots = sorted({normalise_path(item) for item in (payload.get("scanned_paths") or [])
                    if str(item).strip()})
    blob = json.dumps({"probe": probe_id, "roots": roots,
                       "depth": payload.get("max_depth"),
                       "profile": _text(payload.get("profile_version"), 64)},
                      sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:48]


def in_scope(path: str, roots: Iterable[str], max_depth: Any, instance_type: str) -> bool:
    """Reproduce the pre-existing scope test so the sweep cannot widen by accident.

    Only absolute paths beneath an actually scanned root count, and the depth
    allowance matches what the walker would have visited.

    Configured exclusions and the type allow-list are deliberately *not* consulted
    here: a path the operator excluded is still inside the scanned tree, so a
    complete run that no longer reports it has genuinely stopped seeing it and must
    retire it. Treating an excluded path as outside the sweep's authority is what
    would freeze it as ACTIVE forever.
    """
    depth = _int(max_depth, -1)
    if depth < 0 or not str(path or "").startswith("/"):
        return False
    allowance = depth + (0 if instance_type == "directory" else 1)
    target = PurePosixPath(path)
    for root in roots:
        if not str(root or "").startswith("/"):
            continue
        try:
            relative = target.relative_to(PurePosixPath(root))
        except ValueError:
            continue
        if len(relative.parts) <= allowance:
            return True
    return False


def complete_scope(payload: dict[str, Any]) -> bool:
    """Whether *this* report covered the whole scope it declared.

    A 1.1 report states it outright. A legacy 3.3.1 report has only ``complete``,
    so it keeps exactly the meaning it always had - that is the compatibility
    branch, not a guess about its coverage metadata.

    ``complete`` defaults to ``True`` in the 3.3.1 schema, so an absent field
    means "the walk finished". Requiring it to be present would silently stop
    sweeping for every old probe: a file that really was deleted would stay
    ``observed`` forever, which is the one outcome this model must not produce.
    """
    stated = payload.get("completed_scope")
    if isinstance(stated, bool):
        return stated
    return bool(payload.get("complete", True)) and not _text(payload.get("error"), 500)


# --- transactional upserts --------------------------------------------------
def _get_or_create(db: Session, model: Any, keys: dict[str, Any],
                   defaults: dict[str, Any]) -> tuple[Any, bool]:
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


def _is_late(instance: AssetInstance, observed_at: datetime) -> bool:
    """True when a newer report has already been applied to this instance."""
    previous = _aware(instance.last_scan_at)
    if previous is None:
        return False
    return observed_at < previous


def evidence_key(entry: dict[str, Any]) -> str:
    parts = (entry.get("rule_id", ""), entry.get("rule_source", ""), entry.get("evidence_type", ""),
             entry.get("field_name", ""), entry.get("sheet_name", ""),
             "" if entry.get("column_index") is None else entry.get("column_index"))
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
            rows.append({
                "category": category,
                "rule_id": _text(item.get("rule_id"), 128),
                "rule_name": _text(item.get("rule_name"), 255),
                "rule_source": _text(item.get("rule_source"), 32),
                "recognizer": _text(item.get("recognizer"), 64),
                "evidence_type": _text(item.get("evidence_type"), 32),
                "field_name": _text(hit.get("field_name"), 128),
                "sheet_name": _text(hit.get("sheet_name"), 128),
                "column_index": hit.get("column_index") if isinstance(hit.get("column_index"), int) else None,
                "confidence": _float(item.get("confidence")),
                "hit_count": max(_int(hit.get("count")), 0),
            })
    return rows


def _merge_evidence(db: Session, detection: Detection, row: dict[str, Any],
                    *, engine_version: str, ruleset_version: str) -> None:
    key = evidence_key(row)
    existing = db.scalar(select(DetectionEvidence).where(
        DetectionEvidence.detection_id == detection.id,
        DetectionEvidence.evidence_key == key))
    if existing is not None:
        # Never lower a stored value: a late report must not weaken current proof.
        # Never lower a stored value: a weaker or partial re-observation must not
        # erase proof that was already collected for this object.
        existing.confidence = max(_float(existing.confidence), row["confidence"])
        existing.hit_count = max(_int(existing.hit_count), row["hit_count"])
        return
    db.add(DetectionEvidence(
        detection_id=detection.id, evidence_key=key, rule_id=row["rule_id"],
        rule_name=row["rule_name"], rule_source=row["rule_source"],
        recognizer=row["recognizer"], evidence_type=row["evidence_type"],
        field_name=row["field_name"], sheet_name=row["sheet_name"],
        column_index=row["column_index"], confidence=row["confidence"],
        hit_count=row["hit_count"], engine_version=engine_version,
        ruleset_version=ruleset_version))


def _merge_detection(db: Session, *, instance: AssetInstance, obj: DataObject, probe_id: int,
                     scan_id: str, category: str, counts: dict[str, Any],
                     evidence_rows: list[dict[str, Any]], engine_version: str,
                     ruleset_version: str, observed_at: datetime,
                     sample_size: int, confidence: float, severity: str, level: str) -> Detection:
    detection, created = _get_or_create(
        db, Detection,
        {"instance_id": instance.id, "category": category, "object_id": obj.id},
        {"probe_id": probe_id, "scan_id": scan_id, "sensitivity_level": level,
         "severity": severity, "confidence": confidence, "sample_size": sample_size,
         "sample_hit_count": _int(counts.get(category)), "hit_count": _int(counts.get(category)),
         "engine_version": engine_version, "ruleset_version": ruleset_version,
         "first_seen_at": observed_at, "last_seen_at": observed_at})
    if not created:
        detection.confidence = max(_float(detection.confidence), confidence)
        detection.sensitivity_level = level
        detection.severity = severity
        detection.sample_size = max(_int(detection.sample_size), sample_size)
        # One effective scan result per (instance, category, object): the newest
        # observation replaces the count rather than accumulating it, so several
        # recognisers agreeing on one fragment cannot inflate the number.
        detection.scan_id = scan_id
        detection.engine_version = engine_version
        detection.ruleset_version = ruleset_version
        detection.hit_count = max(_int(detection.hit_count), _int(counts.get(category)))
        detection.sample_hit_count = _int(counts.get(category))
        detection.last_seen_at = _newest(detection.last_seen_at, observed_at) or observed_at
    for row in evidence_rows:
        if row["category"] != category:
            continue
        _merge_evidence(db, detection, row, engine_version=engine_version,
                        ruleset_version=ruleset_version)
    return detection


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
    instance_ids = list(db.scalars(select(AssetInstance.id).where(
        AssetInstance.probe_id == probe_id)))
    object_ids = list(db.scalars(select(AssetInstance.object_id.distinct()).where(
        AssetInstance.probe_id == probe_id)))
    detections = 0
    if instance_ids:
        detection_ids = select(Detection.id).where(Detection.instance_id.in_(instance_ids))
        db.execute(delete(DetectionEvidence).where(
            DetectionEvidence.detection_id.in_(detection_ids)))
        detections = _int(db.scalar(select(func.count()).select_from(Detection).where(
            Detection.instance_id.in_(instance_ids))))
        db.execute(delete(Detection).where(Detection.instance_id.in_(instance_ids)))
        db.execute(delete(AssetInstance).where(AssetInstance.id.in_(instance_ids)))
    db.flush()
    for object_id in object_ids:
        obj = db.get(DataObject, object_id)
        if obj is not None:
            recount_object(db, obj)
    return {"instances": len(instance_ids), "detections": detections,
            "objects_recounted": len(object_ids)}


def recount_object(db: Session, obj: DataObject) -> DataObject:
    """Recompute the counters instead of trusting incremental arithmetic."""
    obj.instance_count = _int(db.scalar(select(func.count()).select_from(AssetInstance).where(
        AssetInstance.object_id == obj.id)))
    obj.active_instance_count = _int(db.scalar(select(func.count()).select_from(AssetInstance).where(
        AssetInstance.object_id == obj.id, AssetInstance.status == INSTANCE_ACTIVE)))
    return obj


def ingest_report(db: Session, probe: Probe, payload: dict[str, Any],
                  task: Any = None) -> dict[str, Any]:
    """Store one probe inventory and return what it meant.

    Runs inside the caller's transaction, so the new rows and the legacy
    projection can never land separately.
    """
    probe_id = probe.id
    observed_at = _parse_time(payload.get("observed_at")) or datetime.now(UTC)
    scan_id = _text(payload.get("scan_id") or payload.get("report_id"), 64)
    roots = [normalise_path(item) for item in (payload.get("scanned_paths") or [])
             if str(item).strip()]
    scope_key = scope_key_for(payload, probe_id=probe_id)
    covered = complete_scope(payload)
    engine_version = _text(payload.get("engine_version"), 64)
    ruleset_version = _text(payload.get("ruleset_version"), 64)
    profile_version = _text(payload.get("profile_version"), 64)
    schema_version = _text(payload.get("schema_version"), 16) or "1.0"

    assets = [item for item in (payload.get("assets") or []) if isinstance(item, dict)]
    databases = [item for item in (payload.get("databases") or []) if isinstance(item, dict)]
    entries = [(item, False) for item in assets] + [(item, True) for item in databases]

    stored = 0
    late_skipped = 0
    seen_paths: set[tuple[str, str]] = set()
    touched_objects: dict[int, DataObject] = {}
    for entry, from_databases in entries:
        instance_type = instance_type_for(entry, from_databases=from_databases)
        path = normalise_path(entry.get("path") or entry.get("name"))
        object_type = object_type_for(entry, instance_type)
        identity = resolve_identity(entry, probe_id=probe_id, object_type=object_type, path=path)
        categories = list(dict.fromkeys(category_name(item) for item in
                                        (entry.get("categories") or [])))[:16]
        counts = {category_name(key): _int(value)
                  for key, value in (entry.get("counts") or {}).items()}
        severity = sensitivity_map.worst_severity(categories)
        size = _int(entry.get("size"))

        obj, _ = _get_or_create(
            db, DataObject, {"object_key": identity["object_key"]},
            {"object_type": object_type, "content_hash": identity["content_hash"],
             "hash_type": identity["hash_type"], "identity_confidence": identity["identity_confidence"],
             "partial_version": identity["partial_version"],
             "partial_layout": identity["partial_layout"], "size": size,
             "first_seen_at": observed_at, "last_seen_at": observed_at,
             "categories": categories, "sensitivity": severity,
             "extra": {"first_probe_id": probe_id, "schema_version": schema_version}})
        # A hash never shrinks: an object seen with a full hash keeps it.
        if identity["hash_type"] == HASH_FULL and obj.hash_type != HASH_FULL:
            obj.hash_type = HASH_FULL
            obj.content_hash = identity["content_hash"]
            obj.identity_confidence = IDENTITY_FULL
        obj.last_seen_at = _newest(obj.last_seen_at, observed_at) or observed_at
        merged_categories = list(dict.fromkeys([*(obj.categories or []), *categories]))[:24]
        obj.categories = merged_categories
        obj.sensitivity = sensitivity_map.worst_severity(merged_categories)
        if size:
            obj.size = size

        instance, _ = _get_or_create(
            db, AssetInstance, {"probe_id": probe_id, "path": path},
            {"object_id": obj.id, "name": _text(entry.get("name"), 512),
             "instance_type": instance_type, "size": size,
             "content_hash": identity["content_hash"], "hash_type": identity["hash_type"],
             "status": INSTANCE_ACTIVE, "first_seen_at": observed_at,
             "last_seen_at": observed_at, "last_scan_at": observed_at,
             "last_scan_id": scan_id, "scope_key": scope_key,
             "ruleset_version": ruleset_version, "engine_version": engine_version,
             "profile_version": profile_version, "sensitivity": severity,
             "categories": categories, "extra": {}})
        evidence_block = entry.get("evidence") if isinstance(entry.get("evidence"), dict) else {}
        if _is_late(instance, observed_at):
            # A report older than the one already applied must not roll back
            # last_seen, the current object (content), or the current Detection.
            # It is counted so the stale upload is visible instead of silent.
            late_skipped += 1
            instance.extra = {**(instance.extra or {}),
                              "stale_reports_ignored": _int((instance.extra or {}).get(
                                  "stale_reports_ignored")) + 1}
            continue
        instance.object_id = obj.id
        instance.status = INSTANCE_ACTIVE
        instance.last_seen_at = _newest(instance.last_seen_at, observed_at) or observed_at
        instance.name = _text(entry.get("name"), 512) or instance.name
        instance.size = size
        instance.content_hash = identity["content_hash"]
        instance.hash_type = identity["hash_type"]
        instance.inode = _int(evidence_block.get("inode")) or None
        instance.device = _int(evidence_block.get("device")) or None
        instance.mtime_ns = _int(evidence_block.get("mtime_ns")) or None
        instance.owner = _text(evidence_block.get("owner"), 64)
        instance.group = _text(evidence_block.get("group"), 64)
        instance.permission = _text(evidence_block.get("permission"), 16)
        instance.coverage = _text(evidence_block.get("coverage"), 16) or "complete"
        instance.termination_reason = _text(evidence_block.get("termination_reason"), 64) or "complete"
        instance.last_scan_at = observed_at
        instance.last_scan_id = scan_id
        instance.scope_key = scope_key
        instance.ruleset_version = ruleset_version
        instance.engine_version = engine_version
        instance.profile_version = profile_version
        instance.sensitivity = sensitivity_map.worst_severity(
            list(dict.fromkeys([*(instance.categories or []), *categories]))[:24])
        instance.categories = list(dict.fromkeys([*(instance.categories or []), *categories]))[:24]
        instance.extra = {**(instance.extra or {}), "scanner": _text(payload.get("scanner"), 64),
                          # The reported asset_type is what the legacy projection is keyed
                          # on, so it has to survive a rebuild verbatim.
                          "asset_type": _text(entry.get("asset_type"), 64) or "file",
                          "modified_at": _text(entry.get("modified_at"), 64),
                          "counts": dict(entry.get("counts") or {}),
                          "last_observed_at": _iso(observed_at)}
        db.flush()

        evidence_rows = _evidence_rows(entry)
        confidence = max([_float(item.get("confidence")) for item in
                          (evidence_block.get("hits") or []) if isinstance(item, dict)] + [0.0])
        for category in categories:
            _merge_detection(db, instance=instance, obj=obj, probe_id=probe_id, scan_id=scan_id,
                             category=category, counts=counts, evidence_rows=evidence_rows,
                             engine_version=engine_version, ruleset_version=ruleset_version,
                             observed_at=observed_at,
                             sample_size=_int(evidence_block.get("sample_rows")),
                             confidence=confidence, severity=sensitivity_map.severity_for(category),
                             level=sensitivity_map.level_for(category))
        project_asset(db, probe, entry, scan_id=scan_id,
                      modified_at=entry.get("modified_at") or "",
                      scanner=_text(payload.get("scanner"), 64), observed_at=observed_at)
        touched_objects[obj.id] = obj
        seen_paths.add((path, instance_type))
        stored += 1

    swept = sweep_scope(db, probe_id=probe_id, scope_key=scope_key, roots=roots,
                        max_depth=payload.get("max_depth"),
                        seen_paths={path for path, _ in seen_paths},
                        observed_at=observed_at, scan_id=scan_id, allow_sweep=covered)
    mark_projection_not_observed(db, probe_id, set(swept), observed_at)
    # ``autoflush`` is off in this application's session, so the status changes the
    # sweep just made are invisible to the COUNT below. Without this flush an object
    # keeps claiming every copy it had before the sweep and only corrects itself on
    # a later report.
    if swept:
        db.flush()
    # Counters are recomputed after the sweep: an instance belonging to a touched
    # object may itself have just become NOT_OBSERVED.
    for obj in db.scalars(select(DataObject).where(
            DataObject.id.in_(list(touched_objects)))).all() if touched_objects else []:
        recount_object(db, obj)
    db.flush()
    return {"scan_id": scan_id, "scope_key": scope_key, "schema_version": schema_version,
            "stored": stored, "complete_scope": covered, "not_observed": len(swept),
            "late_skipped": late_skipped, "databases": len(databases)}


# --- scope-aware lifecycle --------------------------------------------------
def sweep_scope(db: Session, *, probe_id: int, scope_key: str, roots: list[str],
                max_depth: Any, seen_paths: set[str], observed_at: datetime,
                scan_id: str, allow_sweep: bool) -> list[str]:
    """Mark this scope's unseen instances NOT_OBSERVED - only on a complete run.

    Everything else (partial, failed, cancelled, timeout, or a path outside the
    reported roots) leaves the rows alone, because "we did not look" is not
    "it is gone".

    The authority is :func:`in_scope` against *this* report's roots and depth,
    not the stored ``scope_key``: a probe may legitimately shrink its root list
    (``['/a', '/b']`` then ``['/a']``), and the covered part of ``/a`` really was
    walked to completion, so a file that is now absent there must become
    ``NOT_OBSERVED``. Comparing scope keys instead would freeze it as
    ``observed`` forever. ``scope_key`` is still stored and reported, but only
    for provenance.

    Returns the swept paths so the legacy projection can follow.
    """
    if not allow_sweep:
        return []
    rows = db.scalars(select(AssetInstance).where(
        AssetInstance.probe_id == probe_id,
        AssetInstance.status == INSTANCE_ACTIVE)).all()
    swept: list[str] = []
    for instance in rows:
        if instance.path in seen_paths:
            continue
        if not in_scope(instance.path, roots, max_depth, instance.instance_type):
            continue
        instance.status = INSTANCE_NOT_OBSERVED
        instance.extra = {**(instance.extra or {}), "not_observed_at": _iso(observed_at),
                          "not_observed_scan_id": scan_id, "not_observed_scope": scope_key}
        swept.append(instance.path)
    return swept


def project_asset(db: Session, probe: Probe, entry: dict[str, Any], *,
                  scan_id: str, modified_at: str, scanner: str,
                  observed_at: datetime) -> DataAsset | None:
    """Keep the legacy ``data_assets`` row in step with one reported entry.

    The projection is derived from the reported fields, so it can always be
    rebuilt from the new tables - it is never a second source of truth.
    """
    path = _text(entry.get("path"), 1024)
    asset_type = _text(entry.get("asset_type"), 64) or "file"
    name = _text(entry.get("name"), 512) or path
    row = db.scalar(select(DataAsset).where(
        DataAsset.asset_type == asset_type,
        DataAsset.extra["probe_id"].as_integer() == probe.id,
        DataAsset.extra["path"].as_string() == path))
    if row is None:
        row = DataAsset(name=name, asset_type=asset_type,
                        sensitivity=_text(entry.get("sensitivity"), 16) or "Unknown",
                        source=f"probe:{probe.name}", columns=[], extra={})
        db.add(row)
    row.name = name
    row.sensitivity = _text(entry.get("sensitivity"), 16) or "Unknown"
    row.source = f"probe:{probe.name}"
    row.columns = [column for column in (entry.get("columns") or []) if isinstance(column, dict)][:256]
    row.extra = {
        "probe_id": probe.id, "probe": probe.name,
        "host": probe.ip_address or probe.hostname, "path": path,
        "size": _int(entry.get("size")), "sha256": _text(entry.get("sha256"), 64),
        "modified_at": _text(modified_at, 64),
        "categories": list(entry.get("categories") or []),
        "counts": dict(entry.get("counts") or {}),
        "evidence": dict(entry.get("evidence") or {}),
        "status": "observed", "scanner": scanner,
        "observed_at": observed_at.isoformat(), "scan_id": scan_id,
    }
    return row


def mark_projection_not_observed(db: Session, probe_id: int, paths: set[str],
                                 when: datetime) -> int:
    """Mirror the instance sweep onto the legacy rows for the same paths."""
    if not paths:
        return 0
    rows = db.scalars(select(DataAsset).where(
        DataAsset.extra["probe_id"].as_integer() == probe_id)).all()
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
    query = select(AssetInstance).where(AssetInstance.probe_id == probe_id) if probe_id \
        else select(AssetInstance)
    instances = db.scalars(query).all()
    rebuilt = 0
    for instance in instances:
        probe = db.get(Probe, instance.probe_id)
        if probe is None:
            continue
        entry = {
            "name": instance.name,
            "asset_type": _text((instance.extra or {}).get("asset_type"), 64)
            or _asset_type_for(instance.instance_type),
            "sensitivity": instance.sensitivity, "path": instance.path, "size": instance.size,
            "sha256": instance.content_hash if instance.hash_type == HASH_FULL else "",
            "categories": list(instance.categories or []),
            "columns": [], "evidence": {},
            "counts": dict((instance.extra or {}).get("counts") or {}),
        }
        row = project_asset(db, probe, entry, scan_id=instance.last_scan_id,
                            modified_at=_text((instance.extra or {}).get("modified_at"), 64),
                            scanner=_text((instance.extra or {}).get("scanner"), 64),
                            observed_at=instance.last_seen_at or datetime.now(UTC))
        if row is None:
            continue
        if instance.status != INSTANCE_ACTIVE:
            row.extra = {**(row.extra or {}), "status": "not_observed"}
        # The legacy projection shows the *current* detections of the instance.
        detections = db.scalars(select(Detection).where(
            Detection.instance_id == instance.id,
            Detection.object_id == instance.object_id)).all()
        row.columns = [{"name": detection.category, "detected_type": detection.category,
                        "sensitivity": detection.severity,
                        "confidence": _float(detection.confidence),
                        "categories": [detection.category],
                        "count": _int(detection.hit_count)}
                       for detection in detections]
        rebuilt += 1
    return {"instances": len(instances), "rebuilt": rebuilt}


def _asset_type_for(instance_type: str) -> str:
    if instance_type == "directory":
        return "directory"
    if instance_type == "database_service":
        return "database"
    return "file"


# --- legacy backfill --------------------------------------------------------
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
        exists = db.scalar(select(AssetInstance.id).where(
            AssetInstance.probe_id == probe.id, AssetInstance.path == path))
        if exists:
            skipped += 1
            continue
        object_type = row.asset_type or "file"
        digest = hashlib.sha256(f"{SCOPED_KEY_SALT}:legacy:{probe.id}:{path}".encode()).hexdigest()
        obj, _ = _get_or_create(
            db, DataObject, {"object_key": f"scoped:{probe.id}:{digest[:40]}"},
            {"object_type": object_type, "hash_type": HASH_SCOPED,
             "identity_confidence": IDENTITY_SCOPED,
             "categories": list(extra.get("categories") or []),
             "sensitivity": row.sensitivity or "Unknown",
             "extra": {"backfilled": True, "legacy_asset_id": row.id}})
        when = _parse_time(extra.get("observed_at")) or row.created_at or datetime.now(UTC)
        db.add(AssetInstance(probe_id=probe.id, object_id=obj.id, path=path,
                             name=_text(row.name, 512), instance_type="file",
                             size=_int(extra.get("size")), status=INSTANCE_ACTIVE,
                             first_seen_at=row.created_at or when, last_seen_at=when,
                             last_scan_at=None, last_scan_id="", scope_key="",
                             sensitivity=row.sensitivity or "Unknown",
                             categories=list(extra.get("categories") or []),
                             extra={"backfilled": True, "legacy_asset_id": row.id,
                                    "asset_type": row.asset_type,
                                    "metadata": "unknown"}))
        db.flush()
        recount_object(db, obj)
        created += 1
    db.flush()
    return {"legacy_rows": len(rows), "created": created, "skipped": skipped}


# --- read model -------------------------------------------------------------
def detect_report_schema(payload: dict[str, Any]) -> str:
    """The schema version a payload claims; anything unknown is treated as 1.0."""
    claimed = _text(payload.get("schema_version"), 16)
    return claimed if claimed in REPORT_SCHEMA_SUPPORTED else "1.0"


def data_type_rows(db: Session, *, mapping: dict[str, str] | None = None,
                   probe_id: int | None = None) -> list[dict[str, Any]]:
    """One row per sensitive type, with the documented de-duplication rules.

    Confirmed duplicates are counted **per object** as
    ``max(active_instance_count - 1, 0)`` and summed, so a category observed on
    several instances of one object is still one duplicate - not one per row.
    Candidates from a partial fingerprint are counted separately and can never
    inflate the confirmed number.
    """
    joined = (select(Detection.category, Detection.object_id, DataObject.hash_type,
                     DataObject.active_instance_count, Detection.instance_id,
                     AssetInstance.probe_id)
              .join(DataObject, DataObject.id == Detection.object_id)
              .join(AssetInstance, AssetInstance.id == Detection.instance_id)
              .where(AssetInstance.status == INSTANCE_ACTIVE)
              .limit(MAX_SUMMARY_ROWS))
    if probe_id:
        joined = joined.where(AssetInstance.probe_id == probe_id)
    objects: dict[str, set[int]] = {}
    instances: dict[str, set[int]] = {}
    hosts: dict[str, set[int]] = {}
    confirmed: dict[str, dict[int, int]] = {}
    candidates: dict[str, set[int]] = {}
    truncated = False
    count = 0
    for row in db.execute(joined).all():
        count += 1
        category = str(row[0])
        objects.setdefault(category, set()).add(int(row[1]))
        instances.setdefault(category, set()).add(int(row[4]))
        hosts.setdefault(category, set()).add(int(row[5]))
        if row[2] == HASH_FULL:
            confirmed.setdefault(category, {})[int(row[1])] = max(_int(row[3]) - 1, 0)
        elif row[2] == HASH_PARTIAL:
            candidates.setdefault(category, set()).add(int(row[1]))
    if count >= MAX_SUMMARY_ROWS:
        truncated = True
    rows: list[dict[str, Any]] = []
    for category in sorted(set(objects) | set(candidates)):
        explanation = sensitivity_map.explain(category, mapping=mapping)
        rows.append({
            **explanation,
            "object_count": len(objects.get(category, ())),
            "active_instance_count": len(instances.get(category, ())),
            "host_count": len(hosts.get(category, ())),
            "confirmed_duplicate_count": sum(confirmed.get(category, {}).values()),
            "candidate_count": len(candidates.get(category, ())),
            "truncated": truncated,
        })
    return rows


def object_detail(db: Session, object_id: int) -> dict[str, Any] | None:
    obj = db.get(DataObject, object_id)
    if obj is None:
        return None
    return {
        "id": obj.id, "object_key": obj.object_key, "object_type": obj.object_type,
        "content_hash": obj.content_hash, "hash_type": obj.hash_type,
        "identity_confidence": _float(obj.identity_confidence),
        "identity_kind": ("confirmed" if obj.hash_type == HASH_FULL
                          else "candidate" if obj.hash_type == HASH_PARTIAL else "scoped"),
        "partial_version": obj.partial_version, "partial_layout": dict(obj.partial_layout or {}),
        "size": obj.size, "categories": list(obj.categories or []),
        "sensitivity": obj.sensitivity,
        "level": sensitivity_map.worst_level(obj.categories),
        "instance_count": obj.instance_count, "active_instance_count": obj.active_instance_count,
        "first_seen_at": _iso(obj.first_seen_at),
        "last_seen_at": _iso(obj.last_seen_at),
        "extra": dict(obj.extra or {}),
    }


def instance_detail(db: Session, instance_id: int) -> dict[str, Any] | None:
    instance = db.get(AssetInstance, instance_id)
    if instance is None:
        return None
    probe = db.get(Probe, instance.probe_id)
    obj = db.get(DataObject, instance.object_id)
    return {
        "id": instance.id, "probe_id": instance.probe_id,
        "probe_name": probe.name if probe else "",
        "host": (probe.ip_address or probe.hostname) if probe else "",
        "path": instance.path, "name": instance.name, "instance_type": instance.instance_type,
        "size": instance.size, "content_hash": instance.content_hash,
        "hash_type": instance.hash_type, "status": instance.status,
        "owner": instance.owner, "group": instance.group, "permission": instance.permission,
        "inode": instance.inode, "device": instance.device, "mtime_ns": instance.mtime_ns,
        "object_id": instance.object_id,
        "object_key": obj.object_key if obj else "",
        "identity_kind": ("confirmed" if obj and obj.hash_type == HASH_FULL
                          else "candidate" if obj and obj.hash_type == HASH_PARTIAL else "scoped"),
        "sensitivity": instance.sensitivity,
        "level": sensitivity_map.worst_level(instance.categories),
        "categories": list(instance.categories or []),
        "coverage": instance.coverage, "termination_reason": instance.termination_reason,
        "ruleset_version": instance.ruleset_version, "engine_version": instance.engine_version,
        "profile_version": instance.profile_version,
        "last_scan_id": instance.last_scan_id,
        "first_seen_at": _iso(instance.first_seen_at),
        "last_seen_at": _iso(instance.last_seen_at),
        "last_scan_at": _iso(instance.last_scan_at),
        "extra": dict(instance.extra or {}),
    }