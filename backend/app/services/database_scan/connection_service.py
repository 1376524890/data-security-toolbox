"""Connection management: validation, credentials and scan bookkeeping.

The HTTP layer owns request shapes; this module owns the rules that must hold
whoever calls it:

* only an allow-listed engine, a real host and a sane port are ever stored;
* a password is encrypted before it is written and is never read back out
  through any response shape (``serialize`` only reports whether one is set);
* one connection runs at most one scan at a time, and a scan carries a frozen
  configuration snapshot plus the credential id it was queued under, so a
  password or user changed afterwards fails loudly instead of silently reading
  the target as somebody else;
* deleting a connection refuses to race a running scan, and keeps the
  observations that were already collected (they are findings, not config).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.models import AssetInstance, DatabaseConnection, Task
from app.services.data_objects.values import _iso, _parse_time, _text
from app.services.database_scan import adapters
from app.services.database_scan.adapters import DatabaseError, normalise_engine
from app.services.database_scan.credentials import (
    CredentialError,
    decrypt_password,
    encrypt_password,
)

SCAN_TASK_KIND = "database_scan"
ACTIVE_STATUSES = ("Pending", "Running")
TERMINAL_STATUSES = ("Success", "Failed", "Partial", "Cancelled")
#: An empty value means "let the driver decide", which is what a plain TCP
#: connection to a lab database needs.
TLS_MODES = ("", "disable", "prefer", "require", "verify-full")
#: A queued scan nobody picked up is not a scan.
PENDING_EXPIRY_SECONDS = 900


class ConnectionNotFound(ValueError):
    """The connection row does not exist."""


class ConnectionConflict(ValueError):
    """The requested action contradicts the connection's current state."""


class ConnectionInvalid(ValueError):
    """The submitted configuration is not something the platform will store."""


def validate_engine(value: Any) -> str:
    try:
        return normalise_engine(value)
    except DatabaseError as exc:
        raise ConnectionInvalid(str(exc)) from exc


def validate_fields(
    data: dict[str, Any], *, current: DatabaseConnection | None = None
) -> dict[str, Any]:
    """Merge a payload onto the current row and refuse anything unsupported.

    Every field is validated here as well as in the request schema: a service
    caller (a script, a test, a future endpoint) must not be able to store a
    configuration the adapters would later refuse to use.
    """
    merged: dict[str, Any] = {}
    engine_source = data.get("engine", current.engine if current else "")
    engine = validate_engine(engine_source)
    merged["engine"] = engine

    if "name" in data or current is None:
        name = _text(data.get("name"), 128).strip()
        if not name:
            raise ConnectionInvalid("连接名称不能为空")
        merged["name"] = name
    if "host" in data or current is None:
        host = _text(data.get("host"), 255).strip()
        if not host or any(ch in host for ch in " \t\n/\\"):
            raise ConnectionInvalid("主机地址不能为空，且不能包含空格或路径分隔符")
        merged["host"] = host
    if "port" in data or current is None:
        try:
            port = int(data.get("port") or 0)
        except (TypeError, ValueError) as exc:
            raise ConnectionInvalid("端口必须是数字") from exc
        if not port:
            port = int(adapters.ENGINES[engine]["default_port"])
        if not 1 <= port <= 65535:
            raise ConnectionInvalid("端口超出 1-65535")
        merged["port"] = port
    if "database" in data or current is None:
        merged["database"] = _text(data.get("database"), 128).strip()
    if "username" in data or current is None:
        merged["username"] = _text(data.get("username"), 128).strip()
    if "tls_mode" in data or current is None:
        tls = _text(data.get("tls_mode"), 16).strip().lower()
        if tls not in TLS_MODES:
            allowed = ", ".join(item or "default" for item in TLS_MODES)
            raise ConnectionInvalid(f"TLS 模式只支持 {allowed}")
        merged["tls_mode"] = tls
    if "options" in data or current is None:
        merged["options"] = adapters.clean_options(engine, data.get("options"))
    if "enabled" in data:
        merged["enabled"] = bool(data.get("enabled"))
    return merged


def serialize(row: DatabaseConnection) -> dict[str, Any]:
    """The only connection shape that leaves the platform; never a secret."""
    spec = adapters.ENGINES.get(row.engine) or {}
    return {
        "id": row.id,
        "name": row.name,
        "engine": row.engine,
        "engine_label": spec.get("label", row.engine),
        "host": row.host,
        "port": row.port,
        "database": row.database,
        "username": row.username,
        # The password itself is write-only: callers learn only whether one exists.
        "password_set": bool(row.password_ciphertext),
        "tls_mode": row.tls_mode,
        "options": dict(row.options or {}),
        "enabled": bool(row.enabled),
        "last_test_at": _iso(row.last_test_at),
        "last_test_status": row.last_test_status,
        "last_test_error": row.last_test_error,
        "last_scan_at": _iso(row.last_scan_at),
        "created_at": _iso(row.created_at),
        "updated_at": _iso(row.updated_at),
    }


def snapshot(row: DatabaseConnection) -> dict[str, Any]:
    """The immutable configuration a task carries instead of the row itself."""
    return {
        "connection_id": row.id,
        "name": row.name,
        "engine": row.engine,
        "host": row.host,
        "port": row.port,
        "database": row.database,
        "username": row.username,
        "tls_mode": row.tls_mode,
        "options": dict(row.options or {}),
        "password_key_id": row.password_key_id,
        "password_set": bool(row.password_ciphertext),
    }


def snapshot_hash(config: dict[str, Any]) -> str:
    blob = json.dumps(config, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()[:24]


def config_of(row: DatabaseConnection) -> adapters.ConnectionConfig:
    return adapters.ConnectionConfig(
        id=row.id, engine=row.engine, host=row.host, port=row.port,
        database=row.database, username=row.username, tls_mode=row.tls_mode,
        options=dict(row.options or {}),
    )


def config_from_snapshot(config: dict[str, Any]) -> adapters.ConnectionConfig:
    return adapters.ConnectionConfig(
        id=int(config.get("connection_id") or 0),
        engine=str(config.get("engine") or ""),
        host=str(config.get("host") or ""),
        port=int(config.get("port") or 0),
        database=str(config.get("database") or ""),
        username=str(config.get("username") or ""),
        tls_mode=str(config.get("tls_mode") or ""),
        options=dict(config.get("options") or {}),
    )


def password_of(row: DatabaseConnection) -> str:
    """The stored password for one row; raises when it cannot be decrypted."""
    return decrypt_password(
        row.id, row.username, row.password_key_id, row.password_nonce,
        row.password_ciphertext,
    )


def password_from_snapshot(row: DatabaseConnection, config: dict[str, Any]) -> str:
    """Decrypt using the *snapshot's* user and key id.

    The AAD binds ciphertext to (connection, username, key id), so a task queued
    before a credential change cannot read with the new one by accident: the
    mismatch surfaces as an explicit error the operator can act on.
    """
    username = str(config.get("username") or "")
    key_id = str(config.get("password_key_id") or "")
    if username != row.username or key_id != row.password_key_id:
        raise CredentialError(
            "连接的用户名或凭据密钥在任务排队后已变更，请重新发起采集"
        )
    return password_of(row)


def _encrypt_into(row: DatabaseConnection, password: str) -> None:
    """Seal the password under this row's identity; empty means "no secret"."""
    ciphertext, nonce, key_id = encrypt_password(row.id, row.username, password)
    row.password_ciphertext, row.password_nonce, row.password_key_id = ciphertext, nonce, key_id


def create(db: Session, data: dict[str, Any]) -> DatabaseConnection:
    fields = validate_fields(data, current=None)
    fields["enabled"] = bool(data.get("enabled", True))
    row = DatabaseConnection(**fields)
    db.add(row)
    db.flush()
    _encrypt_into(row, str(data.get("password") or ""))
    db.commit()
    db.refresh(row)
    return row


def update(db: Session, row: DatabaseConnection, data: dict[str, Any]) -> DatabaseConnection:
    fields = validate_fields(data, current=row)
    previous_username = row.username
    password_supplied = "password" in data
    password = str(data.get("password") or "")
    for key, value in fields.items():
        setattr(row, key, value)
    if password_supplied:
        _encrypt_into(row, password)
    elif previous_username and previous_username != row.username and row.password_ciphertext:
        # The AAD contains the username, so a rename must re-seal the same secret
        # under the new identity - otherwise the next scan cannot decrypt it.
        plaintext = decrypt_password(
            row.id, previous_username, row.password_key_id, row.password_nonce,
            row.password_ciphertext,
        )
        _encrypt_into(row, plaintext)
    db.commit()
    db.refresh(row)
    return row


def orphan_instances(db: Session, connection_id: int) -> int:
    rows = db.scalars(
        select(AssetInstance).where(AssetInstance.owner_key == f"db:{connection_id}")
    ).all()
    stamp = _iso(datetime.now(UTC))
    for row in rows:
        row.extra = {**(row.extra or {}), "connection_deleted_at": stamp}
    return len(rows)


def delete(db: Session, row: DatabaseConnection) -> dict[str, Any]:
    """Remove the configuration, keep the observations it already produced."""
    active = active_scan(db, row.id)
    if active is not None:
        raise ConnectionConflict(
            f"连接仍有未完成的采集任务（任务 {active.id}），请先停止或等待任务结束后再删除"
        )
    connection_id, name = row.id, row.name
    orphaned = orphan_instances(db, connection_id)
    db.delete(row)
    db.commit()
    return {"deleted": True, "connection_id": connection_id, "name": name,
            "kept_instances": orphaned}


def active_scan(db: Session, connection_id: int) -> Task | None:
    return db.scalar(
        select(Task).where(
            Task.kind == SCAN_TASK_KIND,
            Task.payload["connection_id"].as_integer() == connection_id,
            Task.status.in_(list(ACTIVE_STATUSES)),
        )
    )


def expire_scans(db: Session) -> int:
    """Fail scans the worker never finished; a task must not stay活跃 forever."""
    now = datetime.now(UTC)
    rows = db.scalars(
        select(Task).where(
            Task.kind == SCAN_TASK_KIND, Task.status.in_(list(ACTIVE_STATUSES))
        )
    ).all()
    expired = 0
    for task in rows:
        origin = (task.created_at if task.status == "Pending"
                  else (task.started_at or task.updated_at))
        origin = origin.replace(tzinfo=UTC) if origin and origin.tzinfo is None else origin
        if origin is None:
            continue
        budget = PENDING_EXPIRY_SECONDS if task.status == "Pending" else (
            int((task.payload.get("limits") or {}).get("max_seconds",
                settings.database_scan_max_seconds)) + 300
        )
        if now - origin <= timedelta(seconds=budget):
            continue
        task.error = (
            "数据库采集任务排队超时，未有 worker 领取"
            if task.status == "Pending" else "数据库采集任务执行超时"
        )
        task.status, task.current_stage, task.finished_at = "Failed", "timeout", now
        expired += 1
    if expired:
        db.flush()
    return expired


def schedule_scan(
    db: Session, row: DatabaseConnection, *, schemas: list[str] | None = None,
    tables: list[str] | None = None, requested_by: str = "",
) -> Task:
    """Create the queued task with a frozen snapshot; the caller dispatches it."""
    if not row.enabled:
        raise ConnectionConflict("连接已停用，请先启用再发起采集")
    expire_scans(db)
    active = active_scan(db, row.id)
    if active is not None:
        raise ConnectionConflict(
            f"该连接已有进行中的采集任务（任务 {active.id}），请等待其结束或先停止"
        )
    # A credential the worker cannot use must fail here, not inside the worker.
    password_of(row)
    config = snapshot(row)
    limits = {
        "max_tables": int(settings.database_scan_max_tables),
        "max_seconds": int(settings.database_scan_max_seconds),
        "sample_rows": int(settings.database_scan_sample_rows),
        "value_chars": int(settings.database_scan_value_chars),
        "connect_timeout": int(settings.database_scan_connect_timeout),
    }
    task = Task(
        kind=SCAN_TASK_KIND,
        status="Pending",
        progress=0,
        current_stage="已排队",
        payload={
            "connection_id": row.id,
            "connection_name": row.name,
            "config": config,
            "config_hash": snapshot_hash(config),
            "scope": {"schemas": list(schemas or []), "tables": list(tables or [])},
            "limits": limits,
            "requested_at": _iso(datetime.now(UTC)),
            "requested_by": str(requested_by)[:128],
        },
    )
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def mark_scanned(db: Session, connection_id: int, when: datetime | None = None) -> None:
    row = db.get(DatabaseConnection, connection_id)
    if row is not None:
        row.last_scan_at = when or datetime.now(UTC)
        db.flush()


def recent_scans(db: Session, connection_id: int, limit: int = 20) -> list[Task]:
    return list(
        db.scalars(
            select(Task)
            .where(
                Task.kind == SCAN_TASK_KIND,
                Task.payload["connection_id"].as_integer() == connection_id,
                Task.payload["deleted"].as_boolean().is_not(True),
            )
            .order_by(Task.id.desc())
            .limit(max(1, min(int(limit), 100)))
        ).all()
    )


def scan_summary(task: Task) -> dict[str, Any]:
    """One history row: the task plus the counts the scan reported."""
    result = dict(task.result or {})
    started = _parse_time(task.started_at)
    finished = _parse_time(task.finished_at)
    return {
        "task_id": task.id,
        "status": task.status,
        "stage": task.current_stage,
        "progress": task.progress,
        "error": task.error,
        "created_at": _iso(task.created_at),
        "started_at": _iso(task.started_at),
        "finished_at": _iso(task.finished_at),
        "duration_seconds": round((finished - started).total_seconds(), 1)
        if started and finished else None,
        "connection_id": (task.payload or {}).get("connection_id"),
        "scope": dict((task.payload or {}).get("scope") or {}),
        "config_hash": (task.payload or {}).get("config_hash", ""),
        "server_version": result.get("server_version", ""),
        "engine": result.get("engine", ""),
        "host": result.get("host", ""),
        "port": result.get("port", 0),
        "database": result.get("database", ""),
        "schemas": list(result.get("schemas") or []),
        "tables_total": result.get("tables_total", 0),
        "tables_selected": result.get("tables_selected", 0),
        "tables_scanned": result.get("tables_scanned", 0),
        "tables_failed": result.get("tables_failed", 0),
        "rows_read": result.get("rows_read", 0),
        "values_scanned": result.get("values_scanned", 0),
        "hits": result.get("hits", 0),
        "objects": result.get("objects", 0),
        "detections": result.get("detections", 0),
        "complete_scope": result.get("complete_scope"),
        "termination_reason": result.get("termination_reason", ""),
        "read_only": result.get("read_only"),
        "categories": list(result.get("categories") or []),
        "not_observed": result.get("not_observed", 0),
        "engine_version": result.get("engine_version", ""),
        "ruleset_version": result.get("ruleset_version", ""),
        "sample_rows": result.get("sample_rows", 0),
        "notes": list(result.get("notes") or []),
    }


def test(db: Session, row: DatabaseConnection) -> dict[str, Any]:
    """Really connect through this row and record what happened."""
    now = datetime.now(UTC)
    try:
        result = adapters.test_connection(config_of(row), password_of(row))
    except CredentialError as exc:
        row.last_test_at, row.last_test_status = now, "credential_error"
        row.last_test_error = _text(str(exc), 500)
        db.commit()
        return {"status": "credential_error", "error": str(exc)}
    except DatabaseError as exc:
        row.last_test_at, row.last_test_status = now, exc.status
        row.last_test_error = _text(str(exc), 500)
        db.commit()
        return {"status": exc.status, "error": str(exc)}
    except Exception as exc:  # pragma: no cover - driver-specific surprise
        row.last_test_at, row.last_test_status = now, "error"
        row.last_test_error = _text(f"{type(exc).__name__}: {exc}", 500)
        db.commit()
        return {"status": "error", "error": _text(str(exc), 500)}
    row.last_test_at, row.last_test_status, row.last_test_error = now, "ok", ""
    db.commit()
    return result


__all__ = [
    "ACTIVE_STATUSES",
    "ConnectionConflict",
    "ConnectionInvalid",
    "ConnectionNotFound",
    "SCAN_TASK_KIND",
    "TERMINAL_STATUSES",
    "TLS_MODES",
    "active_scan",
    "config_from_snapshot",
    "config_of",
    "create",
    "delete",
    "expire_scans",
    "mark_scanned",
    "password_from_snapshot",
    "password_of",
    "recent_scans",
    "scan_summary",
    "schedule_scan",
    "serialize",
    "snapshot",
    "snapshot_hash",
    "test",
    "update",
    "validate_engine",
    "validate_fields",
]
