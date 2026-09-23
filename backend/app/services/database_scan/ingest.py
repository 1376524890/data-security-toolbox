"""Persist a database table scan into the existing object model.

A table becomes one ``DataObject`` (the table itself) plus one ``AssetInstance``
owned by ``db:<connection_id>`` - never a fabricated probe or file path - and the
confirmed hits become ``Detection`` + ``DetectionEvidence`` rows through exactly
the writer the probe path uses, so the原文 caps and the merge rules cannot drift.

Identity is the qualified table name, not a content hash: two business tables
with identical rows are two assets, and re-scanning a table updates the same
instance instead of stacking a new one.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import AssetInstance, DataObject
from app.services import detection_gate, sensitivity_map
from app.services.data_objects.definitions import (
    HASH_SCOPED,
    IDENTITY_SCOPED,
    INSTANCE_ACTIVE,
    INSTANCE_NOT_OBSERVED,
    SCOPED_KEY_SALT,
)
from app.services.data_objects.evidence import _evidence_rows, _merge_detection
from app.services.data_objects.persistence import _get_or_create, recount_object
from app.services.data_objects.values import (
    _float,
    _int,
    _iso,
    _newest,
    _text,
    category_name,
)

SOURCE_KIND = "database"
OBJECT_TYPE = "database_table"
INSTANCE_TYPE = "database_table"
MAX_COLUMNS = 256
MAX_CATEGORIES = 24


@dataclass(slots=True)
class ScanContext:
    """Everything one scan writes with; frozen for the whole run."""

    connection_id: int
    connection_name: str
    engine: str
    host: str
    port: int
    database: str
    scan_id: str
    task_id: int | None
    engine_version: str
    ruleset_version: str
    observed_at: datetime
    sample_limit: int
    covered: bool = False

    @property
    def owner_key(self) -> str:
        return f"db:{self.connection_id}"

    @property
    def scope_key(self) -> str:
        return f"db:{self.connection_id}:{self.database}"


def table_path(schema: str, table: str) -> str:
    """``schema.table``; the database itself is part of the owner key."""
    schema, table = str(schema or "").strip(), str(table or "").strip()
    return f"{schema}.{table}" if schema else table


def object_key(ctx: ScanContext, path: str) -> str:
    digest = hashlib.sha256(f"{SCOPED_KEY_SALT}:db:{ctx.connection_id}:{path}".encode()).hexdigest()
    return f"dbscoped:{ctx.connection_id}:{digest[:40]}"


def _category_confidence(scan: dict[str, Any]) -> dict[str, float]:
    confidence: dict[str, float] = {}
    for hit in scan.get("hits") or []:
        if not isinstance(hit, dict):
            continue
        name = category_name(hit.get("category") or hit.get("entity"))
        confidence[name] = max(confidence.get(name, 0.0), _float(hit.get("confidence")))
        for item in hit.get("evidence") or []:
            if isinstance(item, dict):
                confidence[name] = max(confidence.get(name, 0.0), _float(item.get("confidence")))
    return confidence


def _column_rows(scan: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for column in (scan.get("columns") or [])[:MAX_COLUMNS]:
        if not isinstance(column, dict):
            continue
        rows.append({
            "name": _text(column.get("name"), 256),
            "type": _text(column.get("type"), 64),
            "sample_size": _int(column.get("sample_size")),
            "nulls": _int(column.get("nulls")),
            "sensitivity": _text(column.get("sensitivity"), 16) or "Unknown",
            "confirmed_categories": [
                category_name(item) for item in (column.get("confirmed_categories") or [])
            ][:16],
            # A header-only clue: visible as inference, never as a content hit.
            "candidate_categories": [
                category_name(item) for item in (column.get("candidate_categories") or [])
            ][:16],
        })
    return rows


def ingest_table(db: Session, ctx: ScanContext, scan: dict[str, Any]) -> dict[str, Any]:
    """Write one sampled table; returns the counts the scan reports."""
    schema = _text(scan.get("schema"), 128)
    table = _text(scan.get("table"), 256)
    path = table_path(schema, table)
    counts = {
        category_name(key): _int(value) for key, value in (scan.get("counts") or {}).items()
    }
    confirmed = [category for category in counts if counts.get(category)]
    candidates = [
        category_name(item) for item in (scan.get("candidates") or [])
        if category_name(item) not in confirmed
    ]
    evidence_rows = _evidence_rows({"evidence": {"hits": scan.get("hits") or []}})
    # The scan runs where the probe is and carries that probe's rule set, which may
    # be older than this platform's. Re-derive its score before anything is
    # labelled, so a pack that over-scores its own pattern cannot mark a column as
    # discovered data here; a category the current rules would not raise stays
    # visible as a candidate instead.
    demoted = detection_gate.demoted_categories(confirmed, evidence_rows)
    if demoted:
        confirmed = [category for category in confirmed if category not in demoted]
        candidates = list(dict.fromkeys([*candidates, *demoted]))
    # A label comes from content only. A field name (``phone``) is recorded as
    # inference in ``field_only_categories`` and in the column metadata, so a
    # table whose column is *named* for personal data is never presented as a
    # table that *contains* it.
    categories = list(dict.fromkeys(confirmed))[:MAX_CATEGORIES]
    severity = sensitivity_map.worst_severity(categories)
    rows_read = _int(scan.get("rows_read"))
    columns = _column_rows(scan)
    values_scanned = sum(item["sample_size"] for item in columns)

    obj, _ = _get_or_create(
        db,
        DataObject,
        {"object_key": object_key(ctx, path)},
        {
            "object_type": OBJECT_TYPE,
            "content_hash": "",
            "hash_type": HASH_SCOPED,
            "identity_confidence": IDENTITY_SCOPED,
            "size": 0,
            "first_seen_at": ctx.observed_at,
            "last_seen_at": ctx.observed_at,
            "categories": categories,
            "sensitivity": severity,
            "extra": {
                "identity": "connection+database+schema+table",
                "source_kind": SOURCE_KIND,
                "connection_id": ctx.connection_id,
                "database": ctx.database,
                "schema": schema,
                "table": table,
            },
        },
    )
    obj.last_seen_at = _newest(obj.last_seen_at, ctx.observed_at) or ctx.observed_at
    merged = list(dict.fromkeys([*(obj.categories or []), *categories]))[:MAX_CATEGORIES]
    obj.categories = merged
    obj.sensitivity = sensitivity_map.worst_severity(merged)

    instance, _ = _get_or_create(
        db,
        AssetInstance,
        {"owner_key": ctx.owner_key, "path": path},
        {
            "object_id": obj.id,
            "probe_id": None,
            "source_kind": SOURCE_KIND,
            "name": path,
            "instance_type": INSTANCE_TYPE,
            "size": 0,
            "content_hash": "",
            "hash_type": HASH_SCOPED,
            "status": INSTANCE_ACTIVE,
            "first_seen_at": ctx.observed_at,
            "last_seen_at": ctx.observed_at,
            "last_scan_at": ctx.observed_at,
            "last_scan_id": ctx.scan_id,
            "scope_key": ctx.scope_key,
            "ruleset_version": ctx.ruleset_version,
            "engine_version": ctx.engine_version,
            "coverage": "complete" if ctx.covered else "partial",
            "termination_reason": "complete" if ctx.covered else "partial_scan",
            "sensitivity": severity,
            "categories": categories,
            "extra": {},
        },
    )
    history = list(dict.fromkeys([
        *((instance.extra or {}).get("category_history") or []),
        *(instance.categories or []),
        *categories,
    ]))[:48]
    instance.object_id = obj.id
    instance.probe_id = None
    instance.source_kind = SOURCE_KIND
    instance.owner_key = ctx.owner_key
    instance.status = INSTANCE_ACTIVE
    instance.name = path
    instance.instance_type = INSTANCE_TYPE
    instance.last_seen_at = _newest(instance.last_seen_at, ctx.observed_at) or ctx.observed_at
    instance.last_scan_at = ctx.observed_at
    instance.last_scan_id = ctx.scan_id
    instance.scope_key = ctx.scope_key
    instance.ruleset_version = ctx.ruleset_version
    instance.engine_version = ctx.engine_version
    instance.coverage = "complete" if ctx.covered else "partial"
    instance.termination_reason = "complete" if ctx.covered else "partial_scan"
    # A completed read speaks for the table's current content; a truncated one may
    # only add, because "we did not finish looking" is not "it is no longer there".
    if ctx.covered:
        instance.categories = list(dict.fromkeys(categories))[:MAX_CATEGORIES]
    else:
        instance.categories = list(
            dict.fromkeys([*(instance.categories or []), *categories])
        )[:MAX_CATEGORIES]
    instance.sensitivity = sensitivity_map.worst_severity(instance.categories)
    instance.extra = {
        **(instance.extra or {}),
        "source": "database_scan",
        "source_kind": SOURCE_KIND,
        "connection_id": ctx.connection_id,
        "connection_name": ctx.connection_name,
        "engine": ctx.engine,
        "host": ctx.host,
        "port": ctx.port,
        "database": ctx.database,
        "schema": schema,
        "table": table,
        "columns": columns,
        "column_count": len(columns),
        "rows_read": rows_read,
        "sample_rows": ctx.sample_limit,
        # The ceiling was reached, so the count is a sample and is labelled as one.
        "sample_mode": "sampled" if rows_read >= ctx.sample_limit else "full",
        "values_scanned": values_scanned,
        "field_only_categories": candidates,
        "category_history": history,
        "last_observed_at": _iso(ctx.observed_at),
    }
    db.flush()

    confidence = _category_confidence(scan)
    fallback = max(confidence.values(), default=0.0)
    detections = 0
    for category in confirmed:
        written = _merge_detection(
            db,
            instance=instance,
            obj=obj,
            probe_id=None,
            source_kind=SOURCE_KIND,
            scan_id=ctx.scan_id,
            category=category,
            counts=counts,
            evidence_rows=evidence_rows,
            engine_version=ctx.engine_version,
            ruleset_version=ctx.ruleset_version,
            observed_at=ctx.observed_at,
            sample_size=rows_read,
            sample_limit=ctx.sample_limit,
            confidence=confidence.get(category, fallback),
            severity=sensitivity_map.severity_for(category),
            level=sensitivity_map.level_for(category),
        )
        # ``None`` means the platform's own rules refuse to raise it.
        detections += 1 if written is not None else 0
    recount_object(db, obj)
    db.flush()
    return {
        "path": path, "schema": schema, "table": table,
        "rows_read": rows_read, "values_scanned": values_scanned,
        "columns": len(columns), "hits": len(scan.get("hits") or []),
        "detections": detections, "categories": confirmed, "candidates": candidates,
    }


def retire_unseen(
    db: Session,
    ctx: ScanContext,
    *,
    scope_schemas: set[str],
    seen_paths: set[str],
    scope_tables: set[str] | None = None,
) -> list[str]:
    """Mark tables a *complete* scan of this scope no longer saw.

    Only a run that finished reading everything it selected has the authority to
    say "this table is gone"; a partial, failed or truncated run retires nothing.
    Tables outside the selected scope are never touched, so scanning one schema
    cannot retire another's findings. The scope is the *schema* the run covered -
    a table that still exists is either seen or genuinely gone, but a table in a
    schema this run never opened is simply out of scope.
    """
    if not ctx.covered:
        return []
    rows = db.scalars(
        select(AssetInstance).where(
            AssetInstance.owner_key == ctx.owner_key,
            AssetInstance.source_kind == SOURCE_KIND,
            AssetInstance.status == INSTANCE_ACTIVE,
        )
    ).all()
    retired: list[str] = []
    for instance in rows:
        if instance.path in seen_paths:
            continue
        stored = instance.extra or {}
        schema = _text(stored.get("schema"), 128) or instance.path.rpartition(".")[0]
        if scope_schemas and schema not in scope_schemas:
            continue
        if scope_tables is not None and instance.path not in scope_tables:
            continue
        instance.status = INSTANCE_NOT_OBSERVED
        instance.extra = {
            **(instance.extra or {}),
            "not_observed_at": _iso(ctx.observed_at),
            "not_observed_scan_id": ctx.scan_id,
            "not_observed_scope": ctx.scope_key,
        }
        retired.append(instance.path)
    if retired:
        db.flush()
        for instance in rows:
            if instance.path in retired:
                obj = db.get(DataObject, instance.object_id)
                if obj is not None:
                    recount_object(db, obj)
    return retired


__all__ = [
    "INSTANCE_TYPE",
    "MAX_COLUMNS",
    "OBJECT_TYPE",
    "SOURCE_KIND",
    "ScanContext",
    "ingest_table",
    "object_key",
    "retire_unseen",
    "table_path",
]
