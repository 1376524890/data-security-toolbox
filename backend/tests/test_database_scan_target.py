"""The real target database: the MySQL/MariaDB host the operator pointed us at.

Gated on a local, gitignored ``.local/db-target.env``; without that file the
module is skipped, so a normal run never depends on a lab host and the password
never enters the repository. Nothing here is mocked, which is the point: this is
what the SQLite fixture cannot prove.

What it proves:

* a real driver talks to a real server, and the server itself enforces the
  read-only session (a write is refused by MariaDB, not by our own check);
* real reflection survives Chinese identifiers and a table name with a space;
* the seeded rows match the real rules, the returned原文 is the seeded value,
  and the negative-control table stays clean;
* the same path works through the HTTP surface, end to end, with a queued task.
"""
from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from app.api import database_connections as api
from app.core.database import SessionLocal
from app.main import app
from app.models import (
    AssetInstance,
    DatabaseConnection,
    DataObject,
    Detection,
    DetectionEvidence,
    Task,
)
from app.services.database_scan import adapters, connection_service, scan
from app.workers.analysis_tasks import database_scan_task
from fastapi.testclient import TestClient
from sqlalchemy import select, text
from sqlalchemy.exc import SQLAlchemyError

ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = ROOT / ".local" / "db-target.env"

pytestmark = pytest.mark.skipif(
    not ENV_FILE.exists(),
    reason="real target not configured (.local/db-target.env is absent)",
)

BASE = "/api/v1/database-connections"
#: Seeded tables whose values must match, and the one that must not.
CLEAN_TABLE = "clean_notes"
EMPTY_TABLES = ("empty_table", "nulls_only")
CHINESE_TABLE = "订单明细"
SPACED_TABLE = "order detail"
PHONE_RE = re.compile(r"^1\d{10}$")


class _Secret:
    """The target credential, printed as ``<redacted>`` by pytest.

    A failing assertion echoes the fixture it used, so holding the raw string in
    a dict would put the password in the log. This is the same rule the platform
    applies to its own responses, applied to the test that checks it.
    """

    __slots__ = ("_value",)

    def __init__(self, value: str) -> None:
        self._value = value

    def reveal(self) -> str:
        return self._value

    def __repr__(self) -> str:
        return "<redacted>"


def _env() -> dict[str, str]:
    values: dict[str, str] = {}
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _purge(connection_id: int) -> None:
    """Remove everything this module created; the target is never written to."""
    with SessionLocal() as db:
        for instance in db.scalars(
            select(AssetInstance).where(AssetInstance.owner_key == f"db:{connection_id}")
        ).all():
            detection_ids = select(Detection.id).where(Detection.instance_id == instance.id)
            db.execute(DetectionEvidence.__table__.delete().where(
                DetectionEvidence.detection_id.in_(detection_ids)))
            db.execute(Detection.__table__.delete().where(Detection.instance_id == instance.id))
            obj = db.get(DataObject, instance.object_id)
            db.delete(instance)
            db.flush()
            if obj is not None:
                db.delete(obj)
        db.execute(Task.__table__.delete().where(
            Task.payload["connection_id"].as_integer() == connection_id))
        row = db.get(DatabaseConnection, connection_id)
        if row is not None:
            db.delete(row)
        db.commit()


@pytest.fixture(scope="module")
def target() -> dict[str, Any]:
    env = _env()
    password = env.get("DST_DB_PASSWORD", "")
    with SessionLocal() as db:
        row = connection_service.create(db, {
            "name": f"dst-target-{uuid4().hex[:8]}", "engine": "mysql",
            "host": env["DST_DB_HOST"], "port": int(env["DST_DB_PORT"]),
            "database": env["DST_DB_NAME"], "username": env["DST_DB_USER"],
            "password": password, "tls_mode": "", "options": {}, "enabled": True,
        })
        connection_id = row.id
    yield {"id": connection_id, "password": _Secret(password), "database": env["DST_DB_NAME"],
           "host": env["DST_DB_HOST"], "port": int(env["DST_DB_PORT"]),
           "username": env["DST_DB_USER"]}
    _purge(connection_id)


def _row(db, connection_id: int) -> DatabaseConnection:
    return db.get(DatabaseConnection, connection_id)


def _instance(connection_id: int, schema: str, table: str) -> AssetInstance | None:
    with SessionLocal() as db:
        return db.scalar(select(AssetInstance).where(
            AssetInstance.owner_key == f"db:{connection_id}",
            AssetInstance.path == f"{schema}.{table}",
        ))


def _matches(instance: AssetInstance, category: str) -> list[dict[str, str]]:
    with SessionLocal() as db:
        detection = db.scalar(select(Detection).where(
            Detection.instance_id == instance.id, Detection.category == category))
        if detection is None:
            return []
        rows = db.scalars(select(DetectionEvidence).where(
            DetectionEvidence.detection_id == detection.id)).all()
        return [item for row in rows for item in (row.extra or {}).get("matches", [])]


def _run_scan(connection_id: int) -> dict[str, Any]:
    """Run one whole scan through the orchestrator, as the worker does."""
    with SessionLocal() as db:
        row = _row(db, connection_id)
        task = connection_service.schedule_scan(db, row, requested_by="target-test")
        summary = scan.run_scan(db, task)
        db.commit()
        return summary


def test_the_credential_is_encrypted_at_rest_and_never_serialised(target) -> None:
    secret = target["password"].reveal()
    with SessionLocal() as db:
        row = _row(db, target["id"])
        assert row.password_ciphertext, "the password must be stored, not dropped"
        assert secret.encode() not in bytes(row.password_ciphertext)
        assert secret.encode() not in bytes(row.password_nonce or b"")
        assert connection_service.password_of(row) == secret
        payload = connection_service.serialize(row)
    blob = json.dumps(payload, ensure_ascii=False, default=str)
    assert secret not in blob
    assert payload["password_set"] is True
    assert [key for key in payload if "password" in key] == ["password_set"]


def test_a_real_session_is_read_only_and_the_server_refuses_writes(target) -> None:
    with SessionLocal() as db:
        row = _row(db, target["id"])
        config, password = connection_service.config_of(row), connection_service.password_of(row)
        result = connection_service.test(db, row)
        assert result["status"] == "ok", result
        assert result["read_only"] is True
        assert "MariaDB" in result["server_version"] or "MySQL" in result["server_version"]
        assert row.last_test_status == "ok"

    engine = adapters.make_engine(config, password)
    try:
        # The target refuses the write; if this ever succeeds the platform has a
        # path that can modify a customer database, which must fail loudly here.
        with pytest.raises(SQLAlchemyError) as failure:
            with engine.begin() as conn:
                conn.execute(text("CREATE TABLE dst_readonly_probe (id INT)"))
        assert "read only" in str(failure.value).lower()
    finally:
        adapters.disconnect(engine)


def test_a_real_password_failure_is_classified_not_swallowed(target) -> None:
    with SessionLocal() as db:
        config = connection_service.config_of(_row(db, target["id"]))
    with pytest.raises(adapters.DatabaseError) as failure:
        adapters.test_connection(config, "definitely-not-the-password")
    assert failure.value.status == "auth_error"


def _all_match_values(instance: AssetInstance) -> list[str]:
    with SessionLocal() as db:
        rows = db.scalars(select(DetectionEvidence).where(
            DetectionEvidence.detection_id.in_(
                select(Detection.id).where(Detection.instance_id == instance.id)))).all()
    return [item["value"] for row in rows
            for item in (row.extra or {}).get("matches", []) if item.get("value")]


def test_a_real_scan_matches_seeded_values_and_leaves_clean_tables_alone(target) -> None:
    connection_id, database = target["id"], target["database"]
    summary = _run_scan(connection_id)

    assert summary["read_only"] is True
    assert summary["server_version"]
    assert summary["tables_failed"] == 0, summary["table_errors"]
    assert summary["complete_scope"] is True
    assert summary["termination_reason"] == "complete"
    assert summary["hits"] > 0

    # Every seeded table is accounted for, including the awkward names.
    paths = {item["path"] for item in summary["tables"]}
    for table in ("customers", "payments", "secrets", CLEAN_TABLE, CHINESE_TABLE,
                  SPACED_TABLE, *EMPTY_TABLES):
        assert f"{database}.{table}" in paths

    customers = _instance(connection_id, database, "customers")
    assert customers is not None
    assert {"phone", "id_card"} <= set(customers.categories)
    assert customers.source_kind == "database"
    assert customers.probe_id is None
    phones = _matches(customers, "phone")
    assert phones, "the seeded phone column must be confirmed by value"
    assert any(PHONE_RE.match(item["value"]) for item in phones)
    for item in phones:
        assert item["value"] and len(item["value"]) <= 120
        assert len(item.get("context", "")) <= 240

    payments = _instance(connection_id, database, "payments")
    assert payments is not None
    assert payments.categories, "the seeded card numbers must confirm a type"
    assert any(value.isdigit() and len(value) >= 12
               for value in _all_match_values(payments))

    secrets = _instance(connection_id, database, "secrets")
    assert secrets is not None
    assert secrets.categories, "the seeded keys must confirm a type"
    assert any("AKIA" in value or value.startswith("ghp_")
               for value in _all_match_values(secrets))

    # The negative control: a rule that fires here is not a rule.
    clean = _instance(connection_id, database, CLEAN_TABLE)
    assert clean is not None
    assert clean.categories == []
    assert _all_match_values(clean) == []

    empty, nulls = (_instance(connection_id, database, name) for name in EMPTY_TABLES)
    assert empty is not None and nulls is not None
    assert empty.extra["rows_read"] == 0 and empty.categories == []
    assert nulls.categories == [] and _all_match_values(nulls) == []

    chinese = _instance(connection_id, database, CHINESE_TABLE)
    assert chinese is not None, "a Chinese table name must survive reflection and quoting"
    assert chinese.categories
    assert any(PHONE_RE.match(value) for value in _all_match_values(chinese))
    assert _instance(connection_id, database, SPACED_TABLE) is not None


def test_the_http_surface_drives_a_real_scan_end_to_end(target, monkeypatch) -> None:
    """The same path an operator takes: configure, test, browse, collect, read."""
    queued: list[tuple[int, str, tuple[Any, ...]]] = []
    monkeypatch.setattr(api, "dispatch_task",
                        lambda task_id, name, *args: queued.append((task_id, name, args)))
    password, database = target["password"].reveal(), target["database"]
    with TestClient(app) as client:
        created = client.post(BASE, json={
            "name": f"dst-http-{uuid4().hex[:8]}", "engine": "mysql", "host": target["host"],
            "port": target["port"], "database": database, "username": target["username"],
            "password": password, "tls_mode": "",
        })
        assert created.status_code == 200, created.text
        assert password not in created.text
        connection_id = created.json()["id"]
        try:
            tested = client.post(f"{BASE}/{connection_id}/test")
            assert tested.status_code == 200, tested.text
            assert tested.json()["result"]["status"] == "ok"
            assert tested.json()["result"]["read_only"] is True
            assert password not in tested.text

            schemas = client.get(f"{BASE}/{connection_id}/schemas")
            assert schemas.status_code == 200
            assert database in schemas.json()["schemas"]

            tables = client.get(f"{BASE}/{connection_id}/tables", params={"schema": database})
            assert tables.status_code == 200
            names = {item["name"] for item in tables.json()["tables"]}
            assert {CHINESE_TABLE, SPACED_TABLE, CLEAN_TABLE} <= names

            started = client.post(f"{BASE}/{connection_id}/scans",
                                  json={"schemas": [database], "tables": []})
            assert started.status_code == 200, started.text
            task_id = int(started.json()["id"])
            assert started.json()["config_hash"]
            assert queued == [(task_id, "security_toolbox.database_scan", (connection_id,))]

            # Run the queued work exactly as the worker would.
            database_scan_task(connection_id, task_id)

            detail = client.get(f"{BASE}/scans/{task_id}")
            assert detail.status_code == 200, detail.text
            payload = detail.json()
            assert payload["status"] == "Success", payload
            summary = payload["summary"]
            assert summary["hits"] > 0 and summary["read_only"] is True
            assert summary["tables"] and summary["complete_scope"] is True
            assert password not in detail.text

            history = client.get(f"{BASE}/{connection_id}/scans")
            assert history.status_code == 200
            assert [item["task_id"] for item in history.json()["items"]] == [task_id]

            listed = client.get(BASE)
            assert listed.status_code == 200
            assert password not in listed.text
            assert password not in str(client.get(f"{BASE}/{connection_id}").text)
        finally:
            _purge(connection_id)
