"""One queued database scan: connect, read a bounded sample, match, persist.

The worker calls :func:`run_scan` with the Task row it was dispatched for. The
task payload carries a *frozen* configuration snapshot and the credential id it
was queued under, so a password or user changed afterwards fails loudly here
instead of reading the target as somebody else.

Budgets are enforced on the server side of the connection: a table count, a wall
clock, a per-table row ceiling and a per-value character ceiling. Anything cut
short is reported as a partial scan with the reason, and a partial scan never
retires a table it did not look at.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import DatabaseConnection, RuleSet, Task
from app.services import sensitive_engine
from app.services.data_objects.values import _int, _iso, _text
from app.services.database_scan import adapters, detect, ingest
from app.services.database_scan.adapters import DatabaseError
from app.services.database_scan.connection_service import (
    config_from_snapshot,
    mark_scanned,
    password_from_snapshot,
)
from app.services.database_scan.credentials import CredentialError
from app.services.task_service import update_task


class ScanError(DatabaseError):
    """A scan that cannot continue, with the reason the task row will show."""


def ENGINES_NEEDS_HOST(engine_name: str) -> bool:
    """Whether an engine is useless without a target address.

    Every networked engine is; the flag exists so a fixture engine that reads a
    file cannot be mistaken for permission to connect without an address.
    """
    return bool(adapters.ENGINES.get(engine_name, {}).get("needs_host", True))


def ruleset_version(db: Session) -> str:
    """The active published rule version; read-only, so a scan creates nothing."""
    try:
        from app.services import ruleset_service

        rule_set = db.scalar(select(RuleSet).order_by(RuleSet.id).limit(1))
        if rule_set is None:
            return ""
        row = ruleset_service.active_version(db, rule_set)
        return str(row.version) if row else ""
    except Exception:  # pragma: no cover - a missing rule set is not a scan failure
        return ""


def default_schemas(engine: Any, engine_name: str, config: adapters.ConnectionConfig) -> list[str]:
    """The schemas a scan covers when the caller did not choose any.

    ``config.database`` is the natural scope for MySQL (where a schema *is* a
    database) and ``public`` for PostgreSQL; when neither exists in the listing
    the whole visible set is used, because an empty picker must not silently mean
    "scan nothing".
    """
    names = adapters.schemas_of(engine, engine_name)
    if not names:
        return []
    preferred = config.database if engine_name == "mysql" else "public"
    if preferred and preferred in names:
        return [preferred]
    return names


def _select_tables(
    enumerated: list[dict[str, Any]], requested: list[str]
) -> list[dict[str, Any]]:
    if not requested:
        return list(enumerated)
    wanted = set(requested)
    selected = [
        item for item in enumerated
        if ingest.table_path(item["schema"], item["name"]) in wanted or item["name"] in wanted
    ]
    return selected


def _stop_requested(db: Session, task: Task) -> bool:
    """A stop is honoured between tables, never in the middle of a statement."""
    try:
        db.refresh(task)
    except Exception:  # pragma: no cover - an unreadable row must not stop a scan
        return False
    return str(task.status or "") == "Cancelled"


def _limits(payload: dict[str, Any]) -> dict[str, int]:
    limits = dict(payload.get("limits") or {})
    return {
        "max_tables": max(1, _int(limits.get("max_tables")) or settings.database_scan_max_tables),
        "max_seconds": max(5, _int(limits.get("max_seconds"))
                           or settings.database_scan_max_seconds),
        "sample_rows": max(1, _int(limits.get("sample_rows"))
                           or settings.database_scan_sample_rows),
        "value_chars": max(16, _int(limits.get("value_chars"))
                           or settings.database_scan_value_chars),
    }


def run_scan(db: Session, task: Task) -> dict[str, Any]:
    """Execute one database scan in the caller's transaction."""
    payload = dict(task.payload or {})
    config_raw = dict(payload.get("config") or {})
    limits = _limits(payload)
    scope = dict(payload.get("scope") or {})
    requested_schemas = [
        _text(item, 128) for item in (scope.get("schemas") or []) if str(item).strip()
    ]
    requested_tables = [
        _text(item, 256) for item in (scope.get("tables") or []) if str(item).strip()
    ]
    connection_id = _int(config_raw.get("connection_id") or payload.get("connection_id"))
    row = db.get(DatabaseConnection, connection_id) if connection_id else None
    if row is None:
        raise ScanError("连接不存在或已被删除，无法执行采集", status="connection_missing")
    config = config_from_snapshot(config_raw)
    if not config.engine:
        raise ScanError("任务缺少引擎快照，无法执行采集", status="invalid_snapshot")
    if ENGINES_NEEDS_HOST(config.engine) and not config.host:
        # Refusing here is what keeps a broken snapshot from silently becoming
        # "connect to the platform container's own localhost".
        raise ScanError("任务缺少目标地址快照，无法执行采集", status="invalid_snapshot")
    try:
        password = password_from_snapshot(row, config_raw)
    except CredentialError as exc:
        raise ScanError(str(exc), status="credential_changed") from exc

    engine_name = adapters.normalise_engine(config.engine)
    started = time.monotonic()
    notes: list[str] = []
    table_errors: list[dict[str, Any]] = []
    scan_id = f"dbscan-{task.id}"
    ctx = ingest.ScanContext(
        connection_id=row.id,
        connection_name=row.name,
        engine=engine_name,
        host=config.host,
        port=config.port or int(adapters.ENGINES[engine_name]["default_port"]),
        database=config.database,
        scan_id=scan_id,
        task_id=task.id,
        engine_version=str(sensitive_engine.ENGINE_VERSION),
        ruleset_version=ruleset_version(db),
        observed_at=datetime.now(UTC),
        sample_limit=limits["sample_rows"],
    )

    engine = adapters.make_engine(config, password)
    try:
        try:
            info = adapters.open_read_only(engine, engine_name)
        except DatabaseError as exc:
            raise ScanError(f"无法连接目标数据库：{exc}", status=exc.status) from exc
        update_task(
            task.id, progress=10,
            current_stage=f"已连接 {ctx.host}:{ctx.port}（{info['server_version']}）",
        )
        schemas = requested_schemas or default_schemas(engine, engine_name, config)
        if not schemas:
            raise ScanError(
                "目标数据库没有可见的 schema/数据库，请检查账号的元数据读取权限",
                status="permission",
            )
        enumerated: list[dict[str, Any]] = []
        schema_failed = False
        for schema in schemas:
            try:
                rows = adapters.tables_of(engine, engine_name, schema, config.database)
            except DatabaseError as exc:
                schema_failed = True
                table_errors.append({"schema": schema, "error": str(exc), "status": exc.status})
                notes.append(f"schema {schema} 元数据读取失败：{exc}")
                continue
            enumerated.extend({**item, "schema": schema} for item in rows)

        selected = _select_tables(enumerated, requested_tables)
        truncated = len(selected) > limits["max_tables"]
        if truncated:
            notes.append(
                f"表数量超过上限 {limits['max_tables']}，本次只扫描前 {limits['max_tables']} 张表"
            )
        selected = selected[: limits["max_tables"]]
        if requested_tables:
            # A selection may name a table with or without its schema; both forms
            # resolve to the same qualified path, so a requested table that has
            # disappeared can still be retired.
            scope_tables = {
                name if "." in name else ingest.table_path(schema, name)
                for name in requested_tables for schema in schemas
            }
            scope_tables |= {
                ingest.table_path(item["schema"], item["name"]) for item in selected
            }
            missing = sorted(scope_tables - {
                ingest.table_path(item["schema"], item["name"]) for item in enumerated
            })
            if missing:
                notes.append(f"选择的表在目标库中不存在或不可见：{', '.join(missing[:8])}")
        else:
            scope_tables = None
        scope_schemas = set(schemas)

        budget_exceeded = False
        cancelled = False
        failed = 0
        scans: list[dict[str, Any]] = []
        total = max(1, len(selected))
        for index, item in enumerate(selected, start=1):
            if time.monotonic() - started > limits["max_seconds"]:
                budget_exceeded = True
                notes.append(f"达到时间上限 {limits['max_seconds']}s，剩余表未读取")
                break
            if _stop_requested(db, task):
                cancelled = True
                notes.append("任务已被停止，已读取的结果保留")
                break
            path = ingest.table_path(item["schema"], item["name"])
            update_task(
                task.id, progress=min(95, 10 + int(85 * (index - 1) / total)),
                current_stage=f"读取 {path}（{index}/{len(selected)}）",
            )
            try:
                sample = adapters.sample_table(
                    engine, item["schema"], item["name"],
                    limit_rows=limits["sample_rows"], value_chars=limits["value_chars"],
                )
            except DatabaseError as exc:
                failed += 1
                table_errors.append({"path": path, "error": str(exc), "status": exc.status})
                notes.append(f"{path} 读取失败：{exc}")
                continue
            scans.append(detect.scan_table(sample))

        covered = bool(selected) and not truncated and not budget_exceeded \
            and not cancelled and not failed and not schema_failed
        ctx.covered = covered
        ingested: list[dict[str, Any]] = []
        for item in scans:
            ingested.append(ingest.ingest_table(db, ctx, item))
        seen = {item["path"] for item in ingested}
        retired = ingest.retire_unseen(
            db, ctx, scope_schemas=scope_schemas, scope_tables=scope_tables,
            seen_paths=seen,
        )
        categories: dict[str, int] = {}
        for item in ingested:
            for category in item["categories"]:
                categories[category] = categories.get(category, 0) + 1
        categories_all: dict[str, int] = {}
        for item in scans:
            for category, count in (item.get("counts") or {}).items():
                name = _text(category, 64)
                categories_all[name] = categories_all.get(name, 0) + _int(count)
        if cancelled:
            reason = "cancelled"
        elif budget_exceeded:
            reason = "time_budget"
        elif truncated:
            reason = "table_budget"
        elif failed or schema_failed:
            reason = "read_error"
        elif not selected:
            reason = "no_tables"
        else:
            reason = "complete"
        finished_at = datetime.now(UTC)
        summary = {
            "connection_id": row.id,
            "connection_name": row.name,
            "engine": engine_name,
            "host": ctx.host,
            "port": ctx.port,
            "database": config.database,
            "server_version": info["server_version"],
            "read_only": info["read_only"],
            "schemas": schemas,
            "scan_id": scan_id,
            "tables_total": len(enumerated),
            "tables_selected": len(selected),
            "tables_scanned": len(ingested),
            "tables_failed": failed,
            "rows_read": sum(item["rows_read"] for item in ingested),
            "values_scanned": sum(item["values_scanned"] for item in ingested),
            "hits": sum(item["hits"] for item in ingested),
            "detections": sum(item["detections"] for item in ingested),
            "objects": len(ingested),
            "categories": categories,
            "hit_counts": categories_all,
            "not_observed": retired,
            "complete_scope": covered,
            "termination_reason": reason,
            "truncated": truncated,
            "cancelled": cancelled,
            "table_errors": table_errors[:32],
            "notes": notes[:16],
            "sample_rows": limits["sample_rows"],
            "max_tables": limits["max_tables"],
            "max_seconds": limits["max_seconds"],
            "engine_version": ctx.engine_version,
            "ruleset_version": ctx.ruleset_version,
            "config_hash": _text(payload.get("config_hash"), 64),
            "duration_seconds": round(time.monotonic() - started, 2),
            "observed_at": _iso(ctx.observed_at),
            "finished_at": _iso(finished_at),
            "tables": [
                {"path": item["path"], "rows_read": item["rows_read"],
                 "values_scanned": item["values_scanned"], "hits": item["hits"],
                 "detections": item["detections"], "categories": item["categories"],
                 "candidates": item["candidates"]}
                for item in ingested
            ][: limits["max_tables"]],
        }
        mark_scanned(db, row.id, finished_at)
        # The caller owns the transaction: it commits the findings, the task
        # result and the analysis row together, or none of them.
        db.flush()
        return summary
    finally:
        adapters.disconnect(engine)


__all__ = ["ScanError", "default_schemas", "ruleset_version", "run_scan"]
