"""The whole database path: connect, reflect, sample, match, persist.

The target is a real SQLAlchemy database file. SQLite is not in the production
allow-list, so the fixture adds a *test-only* engine entry: the point is to run
the orchestrator against a real driver, real reflection and real SQL, without a
server. MySQL/PostgreSQL themselves are verified against a real target in
tests/test_database_scan_target.py.
"""
from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

import pytest
from app.core.database import SessionLocal
from app.models import (
    AnalysisResult,
    AssetInstance,
    DatabaseConnection,
    DataObject,
    Detection,
    DetectionEvidence,
    Task,
)
from app.services.data_objects.definitions import INSTANCE_ACTIVE, INSTANCE_NOT_OBSERVED
from app.services.database_scan import adapters, connection_service, scan
from app.services.task_dispatch import _task
from app.workers.analysis_tasks import database_scan_task
from app.workers.task_names import DATABASE_SCAN
from sqlalchemy import create_engine, select, text

SCHEMA = "main"

PEOPLE = [
    (1, "张三", "13800138000", "110101199003072316", "zhangsan@example.com"),
    (2, "李四", "13900139000", "110101199003072316", "lisi@example.com"),
    (3, "王五", "13700137000", "110101199003072316", "wangwu@example.com"),
]


def _build_target(path: Path) -> None:
    engine = create_engine(f"sqlite+pysqlite:///{path}")
    with engine.begin() as conn:
        conn.execute(text(
            "CREATE TABLE customers (id INTEGER PRIMARY KEY, name TEXT, phone TEXT, "
            "id_card TEXT, email TEXT)"
        ))
        for row in PEOPLE:
            conn.execute(
                text("INSERT INTO customers VALUES (:id, :name, :phone, :id_card, :email)"),
                {"id": row[0], "name": row[1], "phone": row[2], "id_card": row[3],
                 "email": row[4]},
            )
        # A negative control: text with no personal data at all.
        conn.execute(text("CREATE TABLE clean_notes (id INTEGER PRIMARY KEY, note TEXT)"))
        for index in range(200):
            conn.execute(
                text("INSERT INTO clean_notes VALUES (:id, :note)"),
                {"id": index, "note": f"note {index}: quarterly report line, no personal data"},
            )
        conn.execute(text("CREATE TABLE empty_table (phone TEXT, id_card TEXT)"))
        conn.execute(text("CREATE TABLE big_table (id INTEGER PRIMARY KEY, phone TEXT)"))
        for index in range(100):
            conn.execute(
                text("INSERT INTO big_table VALUES (:id, :phone)"),
                {"id": index, "phone": "13800138000"},
            )
        # Chinese identifiers and a space in a name must survive quoting.
        conn.execute(text('CREATE TABLE "订单明细" (id INTEGER PRIMARY KEY, "客户手机号" TEXT)'))
        conn.execute(text('INSERT INTO "订单明细" VALUES (1, \'13800138000\')'))
        conn.execute(text('CREATE TABLE "order detail" (id INTEGER PRIMARY KEY, note TEXT)'))
        conn.execute(
            text('INSERT INTO "order detail" VALUES (1, '
                 '\'aws_access_key_id = AKIAIOSFODNN7EXAMPLE\')')
        )
        conn.execute(text("CREATE TABLE nulls_only (phone TEXT, id_card TEXT)"))
        conn.execute(text("INSERT INTO nulls_only VALUES (NULL, '')"))
    engine.dispose()


@pytest.fixture()
def target(tmp_path, monkeypatch) -> dict[str, Any]:
    """A test-only engine entry plus a connection row pointing at a real file."""
    path = tmp_path / "target.db"
    _build_target(path)
    monkeypatch.setitem(adapters.ENGINES, "sqlite", {
        "driver": "sqlite+pysqlite", "default_port": 0, "label": "SQLite (test fixture)",
        "version_query": "SELECT sqlite_version()", "read_only": "PRAGMA query_only = ON",
        "read_only_check": "PRAGMA query_only", "schemas_are_databases": False,
        "needs_host": False,
    })
    original = adapters.normalise_engine

    def _normalise(value: Any) -> str:
        if str(value or "").strip().lower() in {"sqlite", "sqlite3"}:
            return "sqlite"
        return original(value)

    monkeypatch.setattr(adapters, "normalise_engine", _normalise)
    with SessionLocal() as session:
        row = DatabaseConnection(
            name=f"pipeline-{uuid4().hex[:8]}", engine="sqlite", host="", port=0,
            database=str(path), username="", enabled=True,
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        connection_id = row.id
    yield {"path": path, "connection_id": connection_id, "url": f"sqlite+pysqlite:///{path}"}
    _purge(connection_id)


def _purge(connection_id: int) -> None:
    with SessionLocal() as db:
        owner = f"db:{connection_id}"
        for instance in db.scalars(
            select(AssetInstance).where(AssetInstance.owner_key == owner)
        ).all():
            detection_ids = select(Detection.id).where(Detection.instance_id == instance.id)
            db.execute(
                DetectionEvidence.__table__.delete().where(
                    DetectionEvidence.detection_id.in_(detection_ids)
                )
            )
            db.execute(Detection.__table__.delete().where(Detection.instance_id == instance.id))
            obj = db.get(DataObject, instance.object_id)
            db.delete(instance)
            db.flush()
            if obj is not None:
                db.delete(obj)
        db.execute(Task.__table__.delete().where(
            Task.payload["connection_id"].as_integer() == connection_id
        ))
        row = db.get(DatabaseConnection, connection_id)
        if row is not None:
            db.delete(row)
        db.commit()


def _run(
    connection_id: int, *, limits: dict[str, Any] | None = None,
    scope: dict[str, Any] | None = None, monkeypatch=None,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    """Run one scan through the orchestrator and return its summary."""
    progress: list[dict[str, Any]] = []
    if monkeypatch is not None:
        # The task-progress writer opens its own session; SQLite would lock the
        # test's read transaction. Progress is asserted from what was recorded.
        monkeypatch.setattr(scan, "update_task", lambda _id, **kw: progress.append(kw))
    with SessionLocal() as db:
        row = db.get(DatabaseConnection, connection_id)
        payload = {
            "connection_id": row.id,
            "connection_name": row.name,
            "config": connection_service.snapshot(row),
            "config_hash": connection_service.snapshot_hash(connection_service.snapshot(row)),
            "scope": scope or {"schemas": [], "tables": []},
            "limits": limits or {},
            "requested_at": datetime.now(UTC).isoformat(),
        }
        task = Task(kind=connection_service.SCAN_TASK_KIND, status="Running",
                    payload=payload, progress=0, current_stage="queued")
        db.add(task)
        db.commit()
        db.refresh(task)
        summary = scan.run_scan(db, task)
        db.commit()
        return summary, progress


def _instance(connection_id: int, path: str) -> AssetInstance | None:
    with SessionLocal() as db:
        return db.scalar(
            select(AssetInstance).where(
                AssetInstance.owner_key == f"db:{connection_id}",
                AssetInstance.path == path,
            )
        )


def test_a_full_scan_finds_the_expected_hits_and_leaves_clean_tables_alone(
    target, monkeypatch
) -> None:
    summary, progress = _run(target["connection_id"], monkeypatch=monkeypatch)
    assert summary["complete_scope"] is True
    assert summary["termination_reason"] == "complete"
    assert summary["tables_failed"] == 0
    assert summary["server_version"]
    assert summary["read_only"] is True
    assert progress and progress[0]["current_stage"].startswith("已连接")

    customers = _instance(target["connection_id"], f"{SCHEMA}.customers")
    assert customers is not None
    assert "phone" in customers.categories
    assert "email" in customers.categories
    assert customers.extra["rows_read"] == 3
    assert customers.sensitivity in ("Medium", "High", "Critical")

    # 原文 comes back through the very same evidence writer the probe uses.
    with SessionLocal() as db:
        detection = db.scalar(
            select(Detection).where(
                Detection.instance_id == customers.id, Detection.category == "phone"
            )
        )
        assert detection is not None and detection.source_kind == "database"
        evidence = db.scalars(
            select(DetectionEvidence).where(DetectionEvidence.detection_id == detection.id)
        ).all()
        values = [
            item["value"] for row in evidence
            for item in (row.extra or {}).get("matches", [])
        ]
        assert "13800138000" in values
        for row in evidence:
            assert len((row.extra or {}).get("matches") or []) <= 3
            for item in (row.extra or {}).get("matches") or []:
                assert len(item["value"]) <= 120
                assert len(item["context"]) <= 240

    # The negative control must stay clean - a rule that fires on everything is
    # not a rule.
    clean = _instance(target["connection_id"], f"{SCHEMA}.clean_notes")
    assert clean is not None
    assert clean.categories == []
    # The read is bounded at the configured ceiling and says so.
    assert clean.extra["rows_read"] == 50
    assert clean.extra["sample_mode"] == "sampled"
    with SessionLocal() as db:
        assert db.scalar(select(Detection).where(Detection.instance_id == clean.id)) is None

    # Empty, all-NULL and unusual identifiers still become metadata assets.
    empty = _instance(target["connection_id"], f"{SCHEMA}.empty_table")
    assert empty is not None and empty.extra["rows_read"] == 0
    nulls = _instance(target["connection_id"], f"{SCHEMA}.nulls_only")
    assert nulls is not None
    # NULL is skipped, the empty string is a value that matches nothing.
    assert nulls.extra["values_scanned"] == 1
    assert nulls.extra["columns"][0]["nulls"] == 1
    assert nulls.categories == []
    chinese = _instance(target["connection_id"], f"{SCHEMA}.订单明细")
    assert chinese is not None and "phone" in chinese.categories
    spaced = _instance(target["connection_id"], f"{SCHEMA}.order detail")
    assert spaced is not None and spaced.categories, "the AWS key was not detected"


def test_the_row_ceiling_is_reported_as_a_sample(target, monkeypatch) -> None:
    summary, _ = _run(target["connection_id"], limits={"sample_rows": 5},
                      monkeypatch=monkeypatch)
    assert summary["complete_scope"] is True
    big = _instance(target["connection_id"], f"{SCHEMA}.big_table")
    assert big is not None
    assert big.extra["rows_read"] == 5
    assert big.extra["sample_rows"] == 5
    assert big.extra["sample_mode"] == "sampled"
    with SessionLocal() as db:
        detection = db.scalar(select(Detection).where(Detection.instance_id == big.id))
        assert detection is not None
        assert detection.sample_size == 5
        assert detection.sample_limit == 5


def test_the_table_ceiling_truncates_and_says_so(target, monkeypatch) -> None:
    summary, _ = _run(target["connection_id"], limits={"max_tables": 2},
                      monkeypatch=monkeypatch)
    assert summary["truncated"] is True
    assert summary["complete_scope"] is False
    assert summary["termination_reason"] == "table_budget"
    assert summary["tables_scanned"] == 2
    assert any("上限" in note for note in summary["notes"])


def test_a_selected_scope_only_reads_and_retires_that_scope(target, monkeypatch) -> None:
    _run(target["connection_id"], monkeypatch=monkeypatch)
    assert _instance(target["connection_id"], f"{SCHEMA}.clean_notes") is not None
    summary, _ = _run(
        target["connection_id"], scope={"schemas": [SCHEMA], "tables": [f"{SCHEMA}.customers"]},
        monkeypatch=monkeypatch,
    )
    assert summary["tables_scanned"] == 1
    assert summary["complete_scope"] is True
    assert summary["not_observed"] == []
    assert _instance(target["connection_id"], f"{SCHEMA}.clean_notes").status == INSTANCE_ACTIVE


def test_a_second_scan_retires_a_table_that_disappeared(target, monkeypatch) -> None:
    _run(target["connection_id"], monkeypatch=monkeypatch)
    assert _instance(target["connection_id"], f"{SCHEMA}.clean_notes").status == INSTANCE_ACTIVE
    dropped = create_engine(target["url"])
    with dropped.begin() as conn:
        conn.execute(text("DROP TABLE clean_notes"))
    dropped.dispose()
    summary, _ = _run(target["connection_id"], monkeypatch=monkeypatch)
    assert f"{SCHEMA}.clean_notes" in summary["not_observed"]
    retired = _instance(target["connection_id"], f"{SCHEMA}.clean_notes")
    assert retired.status == INSTANCE_NOT_OBSERVED


def test_a_credential_changed_after_queueing_fails_loudly(target) -> None:
    with SessionLocal() as db:
        row = db.get(DatabaseConnection, target["connection_id"])
        payload = {
            "connection_id": row.id, "connection_name": row.name,
            "config": connection_service.snapshot(row), "scope": {}, "limits": {},
        }
        task = Task(kind=connection_service.SCAN_TASK_KIND, status="Running",
                    payload=payload, progress=0, current_stage="queued")
        db.add(task)
        db.commit()
        db.refresh(task)
        # The operator edits the account while the task sits in the queue.
        row.username = "someone_else"
        db.commit()
        with pytest.raises(scan.ScanError) as excinfo:
            scan.run_scan(db, task)
        assert excinfo.value.status == "credential_changed"
        db.rollback()


def test_a_missing_connection_fails_instead_of_scanning_localhost(target) -> None:
    with SessionLocal() as db:
        task = Task(kind=connection_service.SCAN_TASK_KIND, status="Running", progress=0,
                    payload={"connection_id": 999_999, "config": {}, "scope": {}, "limits": {}})
        db.add(task)
        db.commit()
        db.refresh(task)
        with pytest.raises(scan.ScanError) as excinfo:
            scan.run_scan(db, task)
        assert excinfo.value.status == "connection_missing"
        db.rollback()


def _queue(connection_id: int) -> int:
    """Create a queued scan task the way the API does, without dispatching it."""
    with SessionLocal() as db:
        row = db.get(DatabaseConnection, connection_id)
        config = connection_service.snapshot(row)
        task = Task(
            kind=connection_service.SCAN_TASK_KIND, status="Pending", progress=0,
            current_stage="已排队",
            payload={
                "connection_id": row.id, "connection_name": row.name, "config": config,
                "config_hash": connection_service.snapshot_hash(config),
                "scope": {"schemas": [], "tables": []}, "limits": {},
            },
        )
        db.add(task)
        db.commit()
        db.refresh(task)
        return task.id


def test_the_worker_task_is_registered_under_its_published_name() -> None:
    assert DATABASE_SCAN == "security_toolbox.database_scan"
    assert _task(DATABASE_SCAN).name == DATABASE_SCAN


def test_the_worker_task_collects_and_finishes_its_task_row(target, monkeypatch) -> None:
    task_id = _queue(target["connection_id"])
    database_scan_task(target["connection_id"], task_id)
    with SessionLocal() as db:
        task = db.get(Task, task_id)
        assert task.status == "Success"
        assert task.progress == 100
        assert task.error == ""
        assert task.result["tables_scanned"] >= 1
        assert task.result["complete_scope"] is True
        assert task.result["tables"], "the per-table breakdown must be reported"
        analysis = db.scalar(select(AnalysisResult).where(AnalysisResult.task_id == task_id))
        assert analysis is not None and analysis.module == "database_scan"
        assert analysis.content["connection_id"] == target["connection_id"]
    assert _instance(target["connection_id"], f"{SCHEMA}.customers") is not None


def test_the_worker_task_refuses_a_payload_for_another_connection(target, monkeypatch) -> None:
    task_id = _queue(target["connection_id"])
    database_scan_task(target["connection_id"] + 1, task_id)
    with SessionLocal() as db:
        task = db.get(Task, task_id)
        assert task.status == "Failed"
        assert "不一致" in task.error
        assert task.result["error"] == "connection_mismatch"
    assert _instance(target["connection_id"], f"{SCHEMA}.customers") is None


def test_the_worker_task_fails_a_deleted_connection(monkeypatch) -> None:
    with SessionLocal() as db:
        task = Task(
            kind=connection_service.SCAN_TASK_KIND, status="Pending", progress=0,
            current_stage="已排队",
            payload={"connection_id": 999_999, "config": {}, "scope": {}, "limits": {}},
        )
        db.add(task)
        db.commit()
        db.refresh(task)
        task_id = task.id
    database_scan_task(999_999, task_id)
    with SessionLocal() as db:
        task = db.get(Task, task_id)
        assert task.status == "Failed"
        assert task.result["error"] == "connection_missing"
