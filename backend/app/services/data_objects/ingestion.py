"""Apply a report using the caller-owned transaction."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AssetInstance, DataObject, Probe
from app.services import detection_gate, fingerprint_candidates, sensitivity_map
from app.services.data_objects.coverage import _is_late, complete_scope, in_scope
from app.services.data_objects.definitions import (
    HASH_FULL,
    IDENTITY_FULL,
    INSTANCE_ACTIVE,
    INSTANCE_NOT_OBSERVED,
)
from app.services.data_objects.evidence import _evidence_rows, _merge_detection
from app.services.data_objects.identity import (
    instance_type_for,
    normalise_path,
    object_type_for,
    resolve_identity,
    scope_key_for,
)
from app.services.data_objects.persistence import _get_or_create, recount_object
from app.services.data_objects.projection import mark_projection_not_observed, project_asset
from app.services.data_objects.values import (
    _aware,
    _float,
    _int,
    _iso,
    _newest,
    _parse_time,
    _text,
    category_name,
)


def ingest_report(
    db: Session, probe: Probe, payload: dict[str, Any], task: Any = None
) -> dict[str, Any]:
    """Store one probe inventory and return what it meant.

    Runs inside the caller's transaction, so the new rows and the legacy
    projection can never land separately.
    """
    probe_id = probe.id
    #: Instance identity is (owner_key, path); a probe-owned row is ``probe:<id>``
    #: so a database table can use ``db:<connection_id>`` without borrowing a probe.
    owner_key = f"probe:{probe_id}"
    observed_at = _parse_time(payload.get("observed_at")) or datetime.now(UTC)
    scan_id = _text(payload.get("scan_id") or payload.get("report_id"), 64)
    roots = [
        normalise_path(item) for item in (payload.get("scanned_paths") or []) if str(item).strip()
    ]
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
    instance_ids: set[int] = set()
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
        categories = list(
            dict.fromkeys(category_name(item) for item in (entry.get("categories") or []))
        )[:16]
        counts = {
            category_name(key): _int(value) for key, value in (entry.get("counts") or {}).items()
        }
        evidence_rows = _evidence_rows(entry)
        # Every count in this report is the probe's judgement about its own rule
        # set, and a probe keeps the score it was shipped with. Re-derive it with
        # the rules this platform scans with before a category is written into
        # anything: a category the current rules would not raise moves to
        # ``candidate_categories`` -- still visible to an operator, no longer
        # counted as discovered data -- instead of becoming a finding.
        demoted = detection_gate.demoted_categories(categories, evidence_rows)
        if demoted:
            categories = [category for category in categories if category not in demoted]
            entry["categories"] = categories
            entry["candidate_categories"] = list(
                dict.fromkeys([*(entry.get("candidate_categories") or []), *demoted])
            )[:16]
        severity = sensitivity_map.worst_severity(categories)
        size = _int(entry.get("size"))

        obj, _ = _get_or_create(
            db,
            DataObject,
            {"object_key": identity["object_key"]},
            {
                "object_type": object_type,
                "content_hash": identity["content_hash"],
                "hash_type": identity["hash_type"],
                "identity_confidence": identity["identity_confidence"],
                "partial_version": identity["partial_version"],
                "partial_layout": identity["partial_layout"],
                "size": size,
                "first_seen_at": observed_at,
                "last_seen_at": observed_at,
                "categories": categories,
                "sensitivity": severity,
                "extra": {"first_probe_id": probe_id, "schema_version": schema_version},
            },
        )
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
            db,
            AssetInstance,
            {"owner_key": owner_key, "path": path},
            {
                "object_id": obj.id,
                "probe_id": probe_id,
                "source_kind": "file",
                "name": _text(entry.get("name"), 512),
                "instance_type": instance_type,
                "size": size,
                "content_hash": identity["content_hash"],
                "hash_type": identity["hash_type"],
                "status": INSTANCE_ACTIVE,
                "first_seen_at": observed_at,
                "last_seen_at": observed_at,
                "last_scan_at": observed_at,
                "last_scan_id": scan_id,
                "scope_key": scope_key,
                "ruleset_version": ruleset_version,
                "engine_version": engine_version,
                "profile_version": profile_version,
                "sensitivity": severity,
                "categories": categories,
                "extra": {},
            },
        )
        evidence_block = entry.get("evidence") if isinstance(entry.get("evidence"), dict) else {}
        # Only a parser reports its own per-entry coverage. A directory roll-up (or a
        # port-inferred database service) carries none, so it must not fall back to
        # "complete": this report may itself have stopped at the file or row budget,
        # and a truncated walk must not be presented as a finished one.
        coverage_block = payload.get("coverage")
        report_coverage = coverage_block if isinstance(coverage_block, dict) else {}
        default_coverage = "complete" if covered else "partial"
        default_termination = (
            _text(report_coverage.get("termination_reason"), 64) or default_coverage
        )
        scan_coverage = _text(evidence_block.get("coverage"), 16) or default_coverage
        if _is_late(instance, observed_at):
            # A report older than the one already applied must not roll back
            # last_seen, the current object (content), or the current Detection.
            # It is counted so the stale upload is visible instead of silent.
            late_skipped += 1
            instance.extra = {
                **(instance.extra or {}),
                "stale_reports_ignored": _int((instance.extra or {}).get("stale_reports_ignored"))
                + 1,
            }
            # The path was still observed by this report, so the sweep must not
            # read "not in seen_paths" as "it is gone" and retire the live row.
            seen_paths.add((path, instance_type))
            continue
        if instance.object_id and instance.object_id != obj.id:
            affected_objects.add(int(instance.object_id))
        instance.object_id = obj.id
        instance.probe_id = probe_id
        instance.owner_key = owner_key
        instance.source_kind = "file"
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
        instance.termination_reason = (
            _text(evidence_block.get("termination_reason"), 64) or default_termination
        )
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
        category_history = list(
            dict.fromkeys(
                [
                    *((instance.extra or {}).get("category_history") or []),
                    *(instance.categories or []),
                    *categories,
                ]
            )
        )[:48]
        if scan_coverage == "complete":
            instance.categories = list(dict.fromkeys(categories))[:24]
        else:
            instance.categories = list(dict.fromkeys([*(instance.categories or []), *categories]))[
                :24
            ]
        instance.sensitivity = sensitivity_map.worst_severity(instance.categories)
        # A high-risk file becomes a *candidate* fingerprint; it only becomes a
        # rule when an operator accepts it in 采集与规则.
        fingerprint_candidates.record(
            db, sha256=instance.content_hash, path=instance.path, name=instance.name,
            source_name=(instance.extra or {}).get("probe_name") or instance.owner_key,
            level=sensitivity_map.worst_level(instance.categories),
            severity=instance.sensitivity, task_id=task.id if task else None)
        instance.extra = {
            **(instance.extra or {}),
            "scanner": _text(payload.get("scanner"), 64),
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
            "columns": [
                column for column in (entry.get("columns") or []) if isinstance(column, dict)
            ][:256],
            "evidence": dict(entry.get("evidence") or {}),
        }
        db.flush()

        # Confidence is a per-category value: one file can hold a verified email
        # (0.85) next to a keyword-only credential clue (0.3), and copying the
        # file's maximum onto both made the weak category look as strong as the
        # proven one.
        category_confidence: dict[str, float] = {}
        for hit in evidence_block.get("hits") or []:
            if not isinstance(hit, dict):
                continue
            name = category_name(hit.get("category") or hit.get("entity"))
            category_confidence[name] = max(
                category_confidence.get(name, 0.0), _float(hit.get("confidence"))
            )
        for row in evidence_rows:
            category_confidence[row["category"]] = max(
                category_confidence.get(row["category"], 0.0), _float(row["confidence"])
            )
        fallback_confidence = max(category_confidence.values(), default=0.0)
        # ``rows_read`` is what the probe actually examined; ``sample_rows`` is the
        # configured ceiling. Keeping them apart stops a 2-row file from claiming a
        # 50-row sample, and both stay visible.
        sample_size = _int(evidence_block.get("rows_read")) or _int(
            evidence_block.get("sample_size")
        )
        sample_limit = _int(evidence_block.get("sample_rows")) or _int(
            evidence_block.get("max_sample_rows")
        )
        # A category only becomes a Detection when the probe reported a hit count
        # for it. A directory entry advertises the union of its children's
        # categories as a roll-up label while ``counts`` stays empty; without this
        # guard the roll-up was stored as an independent finding with
        # ``hit_count=0``, which is not evidence of anything and inflated both the
        # object's type count and the type centre.
        reportable = [category for category in categories if category in counts]
        for category in reportable:
            _merge_detection(
                db,
                instance=instance,
                obj=obj,
                probe_id=probe_id,
                scan_id=scan_id,
                category=category,
                counts=counts,
                evidence_rows=evidence_rows,
                engine_version=engine_version,
                ruleset_version=ruleset_version,
                observed_at=observed_at,
                sample_size=sample_size,
                sample_limit=sample_limit,
                confidence=category_confidence.get(category, fallback_confidence),
                severity=sensitivity_map.severity_for(category),
                level=sensitivity_map.level_for(category),
            )
        project_asset(
            db,
            probe,
            entry,
            scan_id=scan_id,
            modified_at=entry.get("modified_at") or "",
            scanner=_text(payload.get("scanner"), 64),
            observed_at=observed_at,
        )
        seen_paths.add((path, instance_type))
        stored += 1
        instance_ids.add(instance.id)

    swept = sweep_scope(
        db,
        probe_id=probe_id,
        scope_key=scope_key,
        roots=roots,
        max_depth=payload.get("max_depth"),
        seen_paths={path for path, _ in seen_paths},
        observed_at=observed_at,
        scan_id=scan_id,
        allow_sweep=covered,
    )
    mark_projection_not_observed(db, probe_id, set(swept), observed_at)
    # ``autoflush`` is off in this application's session, so the status changes the
    # sweep just made are invisible to the COUNT below. Without this flush an object
    # keeps claiming every copy it had before the sweep and only corrects itself on
    # a later report.
    if swept:
        db.flush()
        # An instance the sweep retired moves its object's counters too, and the
        # object it used to belong to may not be the object of any stored entry.
        affected_objects.update(
            int(item)
            for item in db.scalars(
                select(AssetInstance.object_id).where(
                    AssetInstance.probe_id == probe_id, AssetInstance.path.in_(swept)
                )
            ).all()
        )
    # Counters are recomputed after the sweep: an instance belonging to an
    # affected object may itself have just become NOT_OBSERVED.
    for object_id in sorted(affected_objects):
        obj = db.get(DataObject, object_id)
        if obj is not None:
            recount_object(db, obj)
    db.flush()
    return {
        "scan_id": scan_id,
        "scope_key": scope_key,
        "schema_version": schema_version,
        "stored": stored,
        "asset_instance_ids": sorted(instance_ids),
        "complete_scope": covered,
        "not_observed": len(swept),
        "late_skipped": late_skipped,
        "databases": len(databases),
    }


def sweep_scope(
    db: Session,
    *,
    probe_id: int,
    scope_key: str,
    roots: list[str],
    max_depth: Any,
    seen_paths: set[str],
    observed_at: datetime,
    scan_id: str,
    allow_sweep: bool,
) -> list[str]:
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
    rows = db.scalars(
        select(AssetInstance).where(
            AssetInstance.probe_id == probe_id, AssetInstance.status == INSTANCE_ACTIVE
        )
    ).all()
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
        instance.extra = {
            **(instance.extra or {}),
            "not_observed_at": _iso(observed_at),
            "not_observed_scan_id": scan_id,
            "not_observed_scope": scope_key,
        }
        swept.append(instance.path)
    return swept
