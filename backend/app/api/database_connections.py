# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Target-database connections: manage, verify, browse and collect.

The platform connects to the target itself (no probe proxy, no SSH tunnel), so
every response here is about a *configuration* until a real connection attempt
says otherwise: ``test`` reports what the server answered, ``schemas``/``tables``
are read from the target, and a scan is queued with a frozen snapshot.

Secrets never travel outward: a connection is serialised with ``password_set``
only, and the audit trail records identifiers, never a password or a value.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field, field_validator
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.dependencies import dispatch_task
from app.api.pagination import page_response, paginate
from app.api.task_presenter import serialize_task
from app.core.database import get_db
from app.core.security import require_active_admin
from app.models import DatabaseConnection, User
from app.services import database_scan
from app.services.audit_service import record_audit
from app.services.database_scan import adapters, connection_service
from app.services.task_dispatch import DATABASE_SCAN

router = APIRouter(tags=["database-connections"])


class ConnectionPayload(BaseModel):
    """Create/update body. ``port`` 0 means "the engine's default port"."""

    name: str = Field(min_length=1, max_length=128)
    engine: str = Field(min_length=1, max_length=32)
    host: str = Field(min_length=1, max_length=255)
    port: int = Field(default=0, ge=0, le=65535)
    database: str = Field(default="", max_length=128)
    username: str = Field(default="", max_length=128)
    #: Write-only: it is encrypted before storage and never returned.
    password: str | None = Field(default=None, max_length=512)
    tls_mode: str = Field(default="", max_length=16)
    options: dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True

    @field_validator("engine")
    @classmethod
    def engine_supported(cls, value: str) -> str:
        return connection_service.validate_engine(value)

    @field_validator("tls_mode")
    @classmethod
    def tls_supported(cls, value: str) -> str:
        cleaned = str(value or "").strip().lower()
        if cleaned not in connection_service.TLS_MODES:
            raise ValueError("TLS 模式只支持 default/disable/prefer/require/verify-full")
        return cleaned


class ConnectionPatch(BaseModel):
    """A partial update: an absent key is left exactly as it was."""

    name: str | None = Field(default=None, min_length=1, max_length=128)
    engine: str | None = Field(default=None, max_length=32)
    host: str | None = Field(default=None, min_length=1, max_length=255)
    port: int | None = Field(default=None, ge=0, le=65535)
    database: str | None = Field(default=None, max_length=128)
    username: str | None = Field(default=None, max_length=128)
    password: str | None = Field(default=None, max_length=512)
    tls_mode: str | None = Field(default=None, max_length=16)
    options: dict[str, Any] | None = None
    enabled: bool | None = None


class ScanRequest(BaseModel):
    """Which schemas/tables to collect; empty means "the connection default"."""

    schemas: list[str] = Field(default_factory=list, max_length=32)
    tables: list[str] = Field(default_factory=list, max_length=512)

    @field_validator("schemas", "tables")
    @classmethod
    def identifiers_clean(cls, values: list[str]) -> list[str]:
        cleaned: list[str] = []
        for value in values:
            item = str(value).strip()
            if not item:
                continue
            if len(item) > 256 or any(ch in item for ch in "\x00\n\r"):
                raise ValueError("schema/表名不合法")
            if item not in cleaned:
                cleaned.append(item)
        return cleaned


def _connection_or_404(db: Session, connection_id: int) -> DatabaseConnection:
    row = db.get(DatabaseConnection, connection_id)
    if row is None:
        raise HTTPException(404, "数据库连接不存在")
    return row


def _database_error(exc: Exception) -> HTTPException:
    """One place that turns a classified target failure into an HTTP answer."""
    status = getattr(exc, "status", "error")
    detail = {"error": status, "message": str(exc)}
    if status == "unreachable":
        # The platform cannot route to the target: say so, do not blame the user.
        return HTTPException(502, detail={"error": status,
                                          "message": f"平台无法连接目标数据库：{exc}"})
    if status in {"credential_changed", "credential_error"}:
        return HTTPException(409, detail)
    return HTTPException(400, detail)


def _guard(callable_):
    """Run a service call and translate its domain errors into HTTP ones."""
    try:
        return callable_()
    except connection_service.ConnectionNotFound as exc:
        raise HTTPException(404, str(exc)) from exc
    except connection_service.ConnectionConflict as exc:
        raise HTTPException(409, str(exc)) from exc
    except connection_service.ConnectionInvalid as exc:
        raise HTTPException(422, str(exc)) from exc
    except (database_scan.CredentialError, database_scan.DatabaseError) as exc:
        raise _database_error(exc) from exc


@router.get("/database-connections")
def list_connections(
    search: str | None = None, enabled: bool | None = None,
    page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Configured targets plus the engine catalogue the form needs."""
    connection_service.expire_scans(db)
    query = select(DatabaseConnection)
    if search:
        query = query.where(DatabaseConnection.name.ilike(f"%{search}%"))
    if enabled is not None:
        query = query.where(DatabaseConnection.enabled.is_(bool(enabled)))
    result = paginate(db, query.order_by(DatabaseConnection.id.desc()), page, page_size)
    engines = [
        {"engine": name, "label": spec["label"], "default_port": spec["default_port"]}
        for name, spec in sorted(adapters.ENGINES.items())
    ]
    payload = page_response(
        [connection_service.serialize(item) for item in result["items"]],
        page, page_size, result["total"],
    )
    payload["engines"] = engines
    payload["note"] = (
        "由服务端 worker 直接连接目标数据库；连通性测试与采集使用同一执行网络。"
        "密码只写不读，响应仅返回 password_set。"
    )
    return payload


@router.post("/database-connections", dependencies=[Depends(require_active_admin)])
def create_connection(
    payload: ConnectionPayload, request: Request, user: User = Depends(require_active_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    row = _guard(lambda: connection_service.create(db, payload.model_dump()))
    record_audit(db, request, action="database_connection.create", target=row.name,
                 details={"id": row.id, "engine": row.engine, "host": row.host,
                          "port": row.port, "database": row.database,
                          "username": row.username, "actor": user.username,
                          "password_set": bool(row.password_ciphertext)})
    db.commit()
    return connection_service.serialize(row)


@router.get("/database-connections/scans/{task_id}")
def scan_detail(task_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """One scan task: progress, counts and the per-table breakdown."""
    from app.models import Task

    task = db.get(Task, task_id)
    if task is None or task.kind != connection_service.SCAN_TASK_KIND:
        raise HTTPException(404, "数据库采集任务不存在")
    payload = serialize_task(task)
    payload["summary"] = connection_service.scan_summary(task)
    result = dict(task.result or {})
    # The per-table breakdown is only worth sending for one task at a time.
    payload["summary"]["tables"] = list(result.get("tables") or [])
    payload["summary"]["table_errors"] = list(result.get("table_errors") or [])
    return payload


@router.get("/database-connections/{connection_id}")
def connection_detail(connection_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    row = _connection_or_404(db, connection_id)
    payload = connection_service.serialize(row)
    payload["scans"] = [
        connection_service.scan_summary(item)
        for item in connection_service.recent_scans(db, connection_id, limit=10)
    ]
    return payload


@router.patch("/database-connections/{connection_id}",
              dependencies=[Depends(require_active_admin)])
def update_connection(
    connection_id: int, payload: ConnectionPatch, request: Request,
    user: User = Depends(require_active_admin), db: Session = Depends(get_db),
) -> dict[str, Any]:
    row = _connection_or_404(db, connection_id)
    data = payload.model_dump(exclude_unset=True)
    fields = ", ".join(sorted(data)) or "(no change)"
    updated = _guard(lambda: connection_service.update(db, row, data))
    record_audit(db, request, action="database_connection.update", target=updated.name,
                 details={"id": updated.id, "fields": fields, "actor": user.username,
                          "password_changed": "password" in data})
    db.commit()
    return connection_service.serialize(updated)


@router.delete("/database-connections/{connection_id}",
               dependencies=[Depends(require_active_admin)])
def delete_connection(
    connection_id: int, request: Request, user: User = Depends(require_active_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Remove the configuration; the findings it produced stay as history."""
    row = _connection_or_404(db, connection_id)
    result = _guard(lambda: connection_service.delete(db, row))
    record_audit(db, request, action="database_connection.delete", target=result["name"],
                 severity="Medium",
                 details={**result, "actor": user.username})
    db.commit()
    return result


@router.post("/database-connections/{connection_id}/test",
             dependencies=[Depends(require_active_admin)])
def test_connection(
    connection_id: int, request: Request, user: User = Depends(require_active_admin),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Really connect, read the version and record the outcome on the row."""
    row = _connection_or_404(db, connection_id)
    result = _guard(lambda: connection_service.test(db, row))
    record_audit(db, request, action="database_connection.test", target=row.name,
                 details={"id": row.id, "status": result.get("status"), "actor": user.username})
    db.commit()
    return {**connection_service.serialize(row), "result": result}


@router.get("/database-connections/{connection_id}/schemas",
            dependencies=[Depends(require_active_admin)])
def connection_schemas(connection_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    row = _connection_or_404(db, connection_id)
    names = _guard(lambda: adapters.list_schemas(
        connection_service.config_of(row), connection_service.password_of(row)))
    return {"connection_id": row.id, "schemas": names, "count": len(names),
            "default": row.database if row.database in names else (names[0] if names else "")}


@router.get("/database-connections/{connection_id}/tables",
            dependencies=[Depends(require_active_admin)])
def connection_tables(
    connection_id: int, schema: str = Query(default=""),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    row = _connection_or_404(db, connection_id)
    rows = _guard(lambda: adapters.list_tables(
        connection_service.config_of(row), connection_service.password_of(row), schema))
    return {"connection_id": row.id, "schema": schema or row.database, "tables": rows,
            "count": len(rows)}


@router.post("/database-connections/{connection_id}/scans",
             dependencies=[Depends(require_active_admin)])
def start_scan(
    connection_id: int, payload: ScanRequest, request: Request,
    user: User = Depends(require_active_admin), db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Queue a bounded collection of the selected schemas/tables."""
    row = _connection_or_404(db, connection_id)
    task = _guard(lambda: connection_service.schedule_scan(
        db, row, schemas=payload.schemas, tables=payload.tables, requested_by=user.username))
    record_audit(db, request, action="database_connection.scan", target=row.name,
                 details={"id": row.id, "task_id": task.id, "engine": row.engine,
                          "host": row.host, "port": row.port, "database": row.database,
                          "schemas": payload.schemas[:8], "tables": len(payload.tables),
                          "actor": user.username})
    db.commit()
    dispatch_task(task.id, DATABASE_SCAN, row.id)
    return {"id": task.id, "status": task.status, "location": "platform",
            "connection_id": row.id, "config_hash": task.payload.get("config_hash", "")}


@router.get("/database-connections/{connection_id}/scans")
def scan_history(
    connection_id: int, limit: int = Query(20, ge=1, le=100), db: Session = Depends(get_db),
) -> dict[str, Any]:
    _connection_or_404(db, connection_id)
    connection_service.expire_scans(db)
    db.commit()
    rows = connection_service.recent_scans(db, connection_id, limit=limit)
    return {"connection_id": connection_id,
            "items": [connection_service.scan_summary(item) for item in rows],
            "count": len(rows)}


__all__ = ["router"]
