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
                     sample_size: int, sample_limit: int, confidence: float,
                     severity: str, level: str) -> Detection:
    current_count = _int(counts.get(category))
    detection, created = _get_or_create(
        db, Detection,
        {"instance_id": instance.id, "category": category, "object_id": obj.id},
        {"probe_id": probe_id, "scan_id": scan_id, "sensitivity_level": level,
         "severity": severity, "confidence": confidence, "sample_size": sample_size,
         "sample_limit": sample_limit,
         "sample_hit_count": current_count, "hit_count": current_count,
         "engine_version": engine_version, "ruleset_version": ruleset_version,
         "first_seen_at": observed_at, "last_seen_at": observed_at})
    if not created:
        # One scan is one result: the count, confidence, evidence and version all
        # come from this observation. Anything larger seen earlier is preserved in
        # ``extra`` as history instead of being presented as the current value,
        # which is what made ``hit_count`` claim 10 hits while ``scan_id`` pointed
        # at the scan that found 2.
        history = dict(detection.extra or {})
        confidence_history = max(_float(history.get("confidence_history")),
                                 _float(detection.confidence), confidence)
        hit_history = max(_int(history.get("hit_count_history")),
                          _int(detection.hit_count), current_count)
        detection.confidence = confidence
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
        detection.extra = {**history, "confidence_history": round(confidence_history, 3),
                           "hit_count_history": hit_history}
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
    """Recompute the counters - and the current categories - from live instances.

    Trusting incremental arithmetic left the copy counts stale after a migration
    or a sweep, and keeping the categories as a permanent union meant a file that
    had become clean still advertised its old sensitive type. The current set is
    therefore derived from the ACTIVE instances that still carry the object; when
    none remain, the stored value is left as history instead of being erased.
    """
    rows = db.execute(select(AssetInstance.status, AssetInstance.categories).where(
        AssetInstance.object_id == obj.id)).all()
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
    # Every object whose counters may have moved: the ones this report observed,
    # the ones an instance migrated away from, and the ones the sweep retired.
    affected_objects: set[int] = set()
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
        # Only a parser reports its own per-entry coverage. A directory roll-up (or a
        # port-inferred database service) carries none, so it must not fall back to
        # "complete": this report may itself have stopped at the file or row budget,
        # and a truncated walk must not be presented as a finished one.
        coverage_block = payload.get("coverage")
        report_coverage = coverage_block if isinstance(coverage_block, dict) else {}
        default_coverage = "complete" if covered else "partial"
        default_termination = (_text(report_coverage.get("termination_reason"), 64)
                               or default_coverage)
        scan_coverage = _text(evidence_block.get("coverage"), 16) or default_coverage
        if _is_late(instance, observed_at):
            # A report older than the one already applied must not roll back
            # last_seen, the current object (content), or the current Detection.
            # It is counted so the stale upload is visible instead of silent.
            late_skipped += 1
            instance.extra = {**(instance.extra or {}),
                              "stale_reports_ignored": _int((instance.extra or {}).get(
                                  "stale_reports_ignored")) + 1}
            # The path was still observed by this report, so the sweep must not
            # read "not in seen_paths" as "it is gone" and retire the live row.
            seen_paths.add((path, instance_type))
            continue
        if instance.object_id and instance.object_id != obj.id:
            affected_objects.add(int(instance.object_id))
        instance.object_id = obj.id
        affected_objects.add(int(obj.id))
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
        instance.coverage = scan_coverage
        instance.termination_reason = (_text(evidence_block.get("termination_reason"), 64)
                                       or default_termination)
        instance.last_scan_at = observed_at
        instance.last_scan_id = scan_id
        instance.scope_key = scope_key
        instance.ruleset_version = ruleset_version
        instance.engine_version = engine_version
        instance.profile_version = profile_version
        # A completed scan of this path speaks for the instance's *current*
        # content: it replaces the category set, so a file that became clean stops
        # advertising the old label. A partial or failed scan may only add, since
        # "we did not finish looking" is not "it is no longer there". Everything
        # ever seen stays in ``category_history`` for the history view.
        category_history = list(dict.fromkeys([
            *((instance.extra or {}).get("category_history") or []),
            *(instance.categories or []), *categories]))[:48]
        if scan_coverage == "complete":
            instance.categories = list(dict.fromkeys(categories))[:24]
        else:
            instance.categories = list(dict.fromkeys(
                [*(instance.categories or []), *categories]))[:24]
        instance.sensitivity = sensitivity_map.worst_severity(instance.categories)
        instance.extra = {**(instance.extra or {}), "scanner": _text(payload.get("scanner"), 64),
                          # The reported asset_type is what the legacy projection is keyed
                          # on, so it has to survive a rebuild verbatim.
                          "asset_type": _text(entry.get("asset_type"), 64) or "file",
                          "modified_at": _text(entry.get("modified_at"), 64),
                          "counts": dict(entry.get("counts") or {}),
                          "last_observed_at": _iso(observed_at),
                          "category_history": category_history,
                          # The immutable slice a projection rebuild needs: the real
                          # columns and evidence. Without it a rebuild can only
                          # invent field names out of detection categories.
                          "columns": [column for column in (entry.get("columns") or [])
                                      if isinstance(column, dict)][:256],
                          "evidence": dict(entry.get("evidence") or {})}
        db.flush()

        evidence_rows = _evidence_rows(entry)
        # Confidence is a per-category value: one file can hold a verified email
        # (0.85) next to a keyword-only credential clue (0.3), and copying the
        # file's maximum onto both made the weak category look as strong as the
        # proven one.
        category_confidence: dict[str, float] = {}
        for hit in evidence_block.get("hits") or []:
            if not isinstance(hit, dict):
                continue
            name = category_name(hit.get("category") or hit.get("entity"))
            category_confidence[name] = max(category_confidence.get(name, 0.0),
                                            _float(hit.get("confidence")))
        for row in evidence_rows:
            category_confidence[row["category"]] = max(
                category_confidence.get(row["category"], 0.0), _float(row["confidence"]))
        fallback_confidence = max(category_confidence.values(), default=0.0)
        # ``rows_read`` is what the probe actually examined; ``sample_rows`` is the
        # configured ceiling. Keeping them apart stops a 2-row file from claiming a
        # 50-row sample, and both stay visible.
        sample_size = _int(evidence_block.get("rows_read")) or _int(evidence_block.get("sample_size"))
        sample_limit = _int(evidence_block.get("sample_rows")) or _int(evidence_block.get("max_sample_rows"))
        # A category only becomes a Detection when the probe reported a hit count
        # for it. A directory entry advertises the union of its children's
        # categories as a roll-up label while ``counts`` stays empty; without this
        # guard the roll-up was stored as an independent finding with
        # ``hit_count=0``, which is not evidence of anything and inflated both the
        # object's type count and the type centre.
        reportable = [category for category in categories if category in counts]
        for category in reportable:
            _merge_detection(db, instance=instance, obj=obj, probe_id=probe_id, scan_id=scan_id,
                             category=category, counts=counts, evidence_rows=evidence_rows,
                             engine_version=engine_version, ruleset_version=ruleset_version,
                             observed_at=observed_at,
                             sample_size=sample_size, sample_limit=sample_limit,
                             confidence=category_confidence.get(category, fallback_confidence),
                             severity=sensitivity_map.severity_for(category),
                             level=sensitivity_map.level_for(category))
        project_asset(db, probe, entry, scan_id=scan_id,
                      modified_at=entry.get("modified_at") or "",
                      scanner=_text(payload.get("scanner"), 64), observed_at=observed_at)
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
        # An instance the sweep retired moves its object's counters too, and the
        # object it used to belong to may not be the object of any stored entry.
        affected_objects.update(int(item) for item in db.scalars(
            select(AssetInstance.object_id).where(
                AssetInstance.probe_id == probe_id,
                AssetInstance.path.in_(swept))).all())
    # Counters are recomputed after the sweep: an instance belonging to an
    # affected object may itself have just become NOT_OBSERVED.
    for object_id in sorted(affected_objects):
        obj = db.get(DataObject, object_id)
        if obj is not None:
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
        last_scan = _aware(instance.last_scan_at)
        if last_scan is not None and last_scan > observed_at:
            # A newer report has already re-observed this instance, so this older
            # "complete" run has no authority to declare it gone.
            continue
        instance.status = INSTANCE_NOT_OBSERVED
        instance.extra = {**(instance.extra or {}), "not_observed_at": _iso(observed_at),
                          "not_observed_scan_id": scan_id, "not_observed_scope": scope_key}
        swept.append(instance.path)
    return swept


# The legacy four-step severity, ordered so a stricter claim can win. ``Unknown``
# is deliberately absent: it is not a severity, it is the absence of one.
_SEVERITY_RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}


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
    sensitivity = _reported_sensitivity(entry)
    row = db.scalar(select(DataAsset).where(
        DataAsset.asset_type == asset_type,
        DataAsset.extra["probe_id"].as_integer() == probe.id,
        DataAsset.extra["path"].as_string() == path))
    if row is None:
        row = DataAsset(name=name, asset_type=asset_type,
                        sensitivity=sensitivity,
                        source=f"probe:{probe.name}", columns=[], extra={})
        db.add(row)
    row.name = name
    row.sensitivity = sensitivity
    row.source = f"probe:{probe.name}"
    row.columns = [column for column in (entry.get("columns") or []) if isinstance(column, dict)][:256]
    row.extra = {
        "probe_id": probe.id, "probe": probe.name,
        "host": probe.ip_address or probe.hostname, "path": path,
        "size": _int(entry.get("size")), "sha256": _text(entry.get("sha256"), 64),
        "modified_at": _text(modified_at, 64),
        "categories": list(entry.get("categories") or []),
        # Header/port hints stay separate from confirmed categories so a page can
        # show "candidate" without counting it as discovered sensitive data.
        "candidate_categories": list(entry.get("candidate_categories") or []),
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
        stored = instance.extra or {}
        asset_type = _text(stored.get("asset_type"), 64) or _asset_type_for(instance.instance_type)
        # Restore from the scan snapshot taken at ingest. When the snapshot is
        # absent (a pre-snapshot instance) the previous projection row keeps its
        # columns and evidence: writing detection categories in the "columns"
        # field would fabricate field names that were never observed.
        existing = db.scalar(select(DataAsset).where(
            DataAsset.asset_type == asset_type,
            DataAsset.extra["probe_id"].as_integer() == instance.probe_id,
            DataAsset.extra["path"].as_string() == instance.path))
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
            "sensitivity": instance.sensitivity, "path": instance.path, "size": instance.size,
            "sha256": instance.content_hash if instance.hash_type == HASH_FULL else "",
            "categories": list(instance.categories or []),
            "columns": columns[:256], "evidence": evidence,
            "counts": dict(stored.get("counts") or {}),
        }
        row = project_asset(db, probe, entry, scan_id=instance.last_scan_id,
                            modified_at=_text(stored.get("modified_at"), 64),
                            scanner=_text(stored.get("scanner"), 64),
                            observed_at=instance.last_seen_at or datetime.now(UTC))
        if row is None:
            continue
        if instance.status != INSTANCE_ACTIVE:
            row.extra = {**(row.extra or {}), "status": "not_observed"}
        # The legacy projection shows the *current* detections of the instance.
        detections = db.scalars(select(Detection).where(
            Detection.instance_id == instance.id,
            Detection.object_id == instance.object_id)).all()
        row.columns = columns[:256]
        row.extra = {**(row.extra or {}), "detections": [
            {"category": detection.category, "severity": detection.severity,
             "confidence": _float(detection.confidence),
             "hit_count": _int(detection.hit_count),
             "sensitivity_level": detection.sensitivity_level,
             "scan_id": detection.scan_id}
            for detection in detections]}
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
        rows.append({
            **explanation,
            "object_count": len(objects.get(category, ())),
            "active_instance_count": len(instances.get(category, ())),
            "host_count": len(hosts.get(category, ())),
            "confirmed_duplicate_count": sum(max(instance_counts.get(obj_id, 0) - 1, 0)
                                             for obj_id in full.get(category, ())),
            # A partial fingerprint only becomes a *suspected copy* once the same
            # content is seen on two instances; a lone one is an unresolved
            # identity, not a duplicate.
            "candidate_duplicate_count": len(partial.get(category, set()) & candidate_duplicates),
            "identity_pending_count": len(partial.get(category, set()) & identity_pending),
            "candidate_count": len(partial.get(category, ())),
            "truncated": scope["truncated"],
        })
    return rows


def _type_scope(db: Session, probe_id: int | None) -> dict[str, Any]:
    """The join shared by the type rows and the de-duplicated totals."""
    joined = (select(Detection.category, Detection.object_id, DataObject.hash_type,
                     DataObject.active_instance_count, Detection.instance_id,
                     AssetInstance.probe_id)
              .join(DataObject, DataObject.id == Detection.object_id)
              .join(AssetInstance, AssetInstance.id == Detection.instance_id)
              # A detection belongs to the object that was current when it was
              # produced. Without this predicate a renamed or changed file counted
              # its *historical* detection for the live instance and the type
              # centre kept reporting a category the current content no longer has.
              .where(AssetInstance.status == INSTANCE_ACTIVE,
                     Detection.object_id == AssetInstance.object_id)
              .limit(MAX_SUMMARY_ROWS))
    if probe_id:
        joined = joined.where(AssetInstance.probe_id == probe_id)
    objects: dict[str, set[int]] = {}
    instances: dict[str, set[int]] = {}
    hosts: dict[str, set[int]] = {}
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
        hosts.setdefault(category, set()).add(int(row[5]))
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
    scope_instances = (select(AssetInstance.object_id, AssetInstance.id)
                       .where(AssetInstance.status == INSTANCE_ACTIVE))
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
    return {"objects": objects, "instances": instances, "hosts": hosts, "full": full,
            "partial": partial, "object_ids": object_ids, "truncated": truncated,
            "hash_by_object": hash_by_object,
            "scope_instance_counts": scope_instance_counts,
            "candidate_duplicates": candidate_duplicates,
            "identity_pending": identity_pending}


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
    confirmed = [max(instance_counts.get(obj_id, 0) - 1, 0)
                 for obj_id in object_ids if scope["hash_by_object"][obj_id] == HASH_FULL]
    all_hosts: set[int] = set()
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
        "id": obj.id, "object_key": obj.object_key, "object_type": obj.object_type,
        "content_hash": obj.content_hash, "hash_type": obj.hash_type,
        "identity_confidence": _float(obj.identity_confidence),
        "identity_kind": ("confirmed" if obj.hash_type == HASH_FULL
                          else "candidate" if obj.hash_type == HASH_PARTIAL else "scoped"),
        "partial_version": obj.partial_version, "partial_layout": dict(obj.partial_layout or {}),
        "size": obj.size, "categories": list(obj.categories or []),
        "sensitivity": obj.sensitivity,
        "level": sensitivity_map.worst_level(obj.categories, mapping=mapping),
        "level_source": "settings_override" if mapping else "builtin_default",
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
    mapping = sensitivity_map.overrides(db)
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
        "level": sensitivity_map.worst_level(instance.categories, mapping=mapping),
        "level_source": "settings_override" if mapping else "builtin_default",
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
