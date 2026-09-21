"""HTTP boundary: CRUD, verification, scope browsing and scan queueing."""
from __future__ import annotations

import json
from typing import Any
from uuid import uuid4

import pytest
from app.api import database_connections as api
from app.core.database import SessionLocal
from app.main import app
from app.models import AuditLog, DatabaseConnection, Task
from app.services.database_scan import connection_service
from fastapi.testclient import TestClient
from sqlalchemy import select

BASE = "/api/v1/database-connections"
PASSWORD = "pw-Only-Inside-The-Vault"


@pytest.fixture()
def client():
    with TestClient(app) as test_client:
        yield test_client


@pytest.fixture()
def queued(monkeypatch) -> list[tuple[int, str, tuple[Any, ...]]]:
    """Record dispatches instead of running the worker inside the request."""
    calls: list[tuple[int, str, tuple[Any, ...]]] = []
    monkeypatch.setattr(
        api, "dispatch_task",
        lambda task_id, name, *args: calls.append((task_id, name, args)),
    )
    return calls


@pytest.fixture()
def connection(client) -> int:
    created = client.post(BASE, json=_payload())
    assert created.status_code == 200, created.text
    connection_id = created.json()["id"]
    yield connection_id
    _cleanup(connection_id)


def _payload(**overrides) -> dict[str, Any]:
    body: dict[str, Any] = {
        "name": f"dst-api-{uuid4().hex[:8]}",
        "engine": "mysql",
        "host": "192.168.191.130",
        "port": 3306,
        "database": "dst_demo",
        "username": "dst_ro",
        "password": PASSWORD,
        "tls_mode": "",
    }
    body.update(overrides)
    return body


def _cleanup(connection_id: int) -> None:
    with SessionLocal() as db:
        for task in db.scalars(select(Task)).all():
            if (task.payload or {}).get("connection_id") == connection_id:
                db.delete(task)
        row = db.get(DatabaseConnection, connection_id)
        if row is not None:
            db.delete(row)
        db.commit()


def _row(connection_id: int) -> DatabaseConnection:
    with SessionLocal() as db:
        return db.get(DatabaseConnection, connection_id)


def test_creating_a_connection_encrypts_the_password_and_never_returns_it(client) -> None:
    response = client.post(BASE, json=_payload())
    assert response.status_code == 200
    body = response.json()
    connection_id = body["id"]
    try:
        assert body["password_set"] is True
        assert "password" not in body
        assert "password_ciphertext" not in body
        assert PASSWORD not in response.text
        row = _row(connection_id)
        assert row.password_ciphertext and PASSWORD.encode() not in row.password_ciphertext
        assert row.password_key_id == connection_service.settings.database_credential_key_id
        assert connection_service.password_of(row) == PASSWORD
    finally:
        _cleanup(connection_id)


@pytest.mark.parametrize(
    "overrides",
    [
        {"engine": "oracle"},
        {"engine": "sqlite"},
        {"host": ""},
        {"host": "10.0.0.1/db"},
        {"port": 70000},
        {"tls_mode": "always"},
        {"name": ""},
    ],
)
def test_unsupported_or_invalid_fields_are_refused(client, overrides: dict[str, Any]) -> None:
    response = client.post(BASE, json=_payload(**overrides))
    assert response.status_code == 422, response.text


def test_an_unknown_option_key_is_dropped_instead_of_stored(client) -> None:
    response = client.post(BASE, json=_payload(
        options={"charset": "utf8mb4", "init_command": "DROP TABLE customers"}
    ))
    assert response.status_code == 200
    connection_id = response.json()["id"]
    try:
        assert response.json()["options"] == {"charset": "utf8mb4"}
        assert _row(connection_id).options == {"charset": "utf8mb4"}
    finally:
        _cleanup(connection_id)


def test_listing_and_reading_a_connection_never_exposes_a_secret(client, connection) -> None:
    listing = client.get(BASE, params={"search": "dst-api-"})
    assert listing.status_code == 200
    assert PASSWORD not in listing.text
    assert any(item["id"] == connection for item in listing.json()["items"])
    assert sorted(item["engine"] for item in listing.json()["engines"]) == [
        "mysql", "postgresql"
    ]
    detail = client.get(f"{BASE}/{connection}")
    assert detail.status_code == 200
    assert detail.json()["password_set"] is True
    assert PASSWORD not in detail.text


def test_updating_the_account_re_seals_the_same_password(client, connection) -> None:
    response = client.patch(f"{BASE}/{connection}", json={"username": "dst_ro_2"})
    assert response.status_code == 200
    row = _row(connection)
    assert row.username == "dst_ro_2"
    # AAD binds the ciphertext to the user, so the rename must have re-sealed it.
    assert connection_service.password_of(row) == PASSWORD
    cleared = client.patch(f"{BASE}/{connection}", json={"password": ""})
    assert cleared.status_code == 200
    assert cleared.json()["password_set"] is False
    assert connection_service.password_of(_row(connection)) == ""


def test_a_test_against_an_unreachable_target_reports_unreachable_and_records_it(
    client, connection
) -> None:
    with SessionLocal() as db:
        row = db.get(DatabaseConnection, connection)
        row.host, row.port = "127.0.0.1", 1
        db.commit()
    response = client.post(f"{BASE}/{connection}/test")
    assert response.status_code == 200
    assert response.json()["result"]["status"] == "unreachable"
    assert PASSWORD not in response.text
    recorded = _row(connection)
    assert recorded.last_test_status == "unreachable"
    assert recorded.last_test_error
    assert recorded.last_test_at is not None


def test_schemas_and_tables_are_read_from_the_target_or_reported_as_unreachable(
    client, connection
) -> None:
    assert client.get(f"{BASE}/999999/schemas").status_code == 404
    with SessionLocal() as db:
        row = db.get(DatabaseConnection, connection)
        row.host, row.port = "127.0.0.1", 1
        db.commit()
    response = client.get(f"{BASE}/{connection}/schemas")
    assert response.status_code == 502
    assert response.json()["detail"]["error"] == "unreachable"
    assert "平台无法连接目标数据库" in response.json()["detail"]["message"]


def test_starting_a_scan_queues_a_frozen_snapshot_without_the_password(
    client, connection, queued
) -> None:
    response = client.post(f"{BASE}/{connection}/scans",
                           json={"schemas": ["dst_demo"], "tables": ["dst_demo.customers"]})
    assert response.status_code == 200, response.text
    task_id = response.json()["id"]
    assert response.json()["status"] == "Pending"
    assert queued and queued[-1][0] == task_id
    with SessionLocal() as db:
        task = db.get(Task, task_id)
        payload = dict(task.payload or {})
        assert task.kind == "database_scan"
        assert payload["connection_id"] == connection
        assert payload["scope"] == {"schemas": ["dst_demo"], "tables": ["dst_demo.customers"]}
        assert payload["config"]["username"] == "dst_ro"
        assert payload["config"]["password_set"] is True
        assert payload["config_hash"]
        assert payload["limits"]["sample_rows"] >= 1
        assert PASSWORD not in json.dumps(payload)
        assert "password_ciphertext" not in json.dumps(payload)
    history = client.get(f"{BASE}/{connection}/scans")
    assert history.status_code == 200
    assert [item["task_id"] for item in history.json()["items"]] == [task_id]
    detail = client.get(f"{BASE}/scans/{task_id}")
    assert detail.status_code == 200
    assert detail.json()["summary"]["connection_id"] == connection
    assert detail.json()["summary"]["complete_scope"] is None


def test_a_second_scan_is_refused_while_one_is_still_queued(client, connection, queued) -> None:
    first = client.post(f"{BASE}/{connection}/scans", json={})
    assert first.status_code == 200
    second = client.post(f"{BASE}/{connection}/scans", json={})
    assert second.status_code == 409
    assert "进行中的采集任务" in second.json()["detail"]


def test_a_disabled_connection_cannot_be_scanned(client, connection, queued) -> None:
    assert client.patch(f"{BASE}/{connection}", json={"enabled": False}).status_code == 200
    response = client.post(f"{BASE}/{connection}/scans", json={})
    assert response.status_code == 409
    assert "已停用" in response.json()["detail"]


def test_deleting_refuses_while_a_scan_runs_and_keeps_the_findings(
    client, connection, queued
) -> None:
    task_id = client.post(f"{BASE}/{connection}/scans", json={}).json()["id"]
    refused = client.delete(f"{BASE}/{connection}")
    assert refused.status_code == 409
    assert "未完成的采集任务" in refused.json()["detail"]
    with SessionLocal() as db:
        task = db.get(Task, task_id)
        task.status = "Success"
        db.commit()
    accepted = client.delete(f"{BASE}/{connection}")
    assert accepted.status_code == 200
    assert accepted.json()["deleted"] is True
    assert "kept_instances" in accepted.json()
    assert _row(connection) is None
    # The task keeps its history: a deleted connection is not a deleted finding.
    assert client.get(f"{BASE}/scans/{task_id}").status_code == 200


def test_every_write_leaves_an_audit_row_without_a_credential(client) -> None:
    created = client.post(BASE, json=_payload())
    connection_id = created.json()["id"]
    try:
        client.post(f"{BASE}/{connection_id}/test")
        client.patch(f"{BASE}/{connection_id}", json={"database": "dst_demo"})
        client.delete(f"{BASE}/{connection_id}")
        with SessionLocal() as db:
            rows = db.scalars(
                select(AuditLog).where(AuditLog.action.like("database_connection.%"))
            ).all()
        actions = {row.action for row in rows}
        assert actions >= {
            "database_connection.create", "database_connection.test",
            "database_connection.update", "database_connection.delete",
        }
        for row in rows:
            assert PASSWORD not in json.dumps(row.details)
            # Identifiers and counts only: never a secret, never a value.
            assert row.details["actor"] == "admin"
            target = row.details.get("id", row.details.get("connection_id"))
            assert target == connection_id
    finally:
        _cleanup(connection_id)


def test_a_non_database_task_is_not_a_scan_detail(client) -> None:
    with SessionLocal() as db:
        task = Task(kind="scan", status="Success", payload={})
        db.add(task)
        db.commit()
        db.refresh(task)
        task_id = task.id
    assert client.get(f"{BASE}/scans/{task_id}").status_code == 404
    assert client.get(f"{BASE}/scans/999999").status_code == 404
