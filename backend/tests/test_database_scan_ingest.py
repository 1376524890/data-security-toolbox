"""A table scan becomes a database-sourced object, instance and detection."""
from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from app.core.database import SessionLocal
from app.main import app
from app.models import (
    AssetInstance,
    DatabaseConnection,
    DataObject,
    Detection,
    DetectionEvidence,
)
from app.services.data_objects.definitions import (
    HASH_SCOPED,
    IDENTITY_SCOPED,
    INSTANCE_ACTIVE,
    INSTANCE_NOT_OBSERVED,
)
from app.services.database_scan import ingest
from fastapi.testclient import TestClient
from sqlalchemy import select

PHONE_HIT = {
    "entity": "PHONE",
    "category": "phone",
    "count": 2,
    "confidence": 0.8,
    "confirmed": True,
    "field_only": False,
    "level": "L2",
    "severity": "Medium",
    "rule_ids": ["SD_PHONE_001"],
    "rule_sources": ["builtin"],
    "evidence": [
        {
            "rule_id": "SD_PHONE_001",
            "rule_name": "手机号",
            "rule_source": "builtin",
            "recognizer": "",
            "evidence_type": "regex",
            "confidence": 0.8,
        }
    ],
    "matches": [{"value": "13800138000", "context": "phone=13800138000"}],
    "field_name": "phone",
    "sheet_name": "customers",
    "column_index": 2,
}

BANK_CARD_HIT = {
    **PHONE_HIT,
    "entity": "BANK_CARD",
    "category": "bank_card",
    "field_name": "card_number",
    "matches": [{"value": "6222020200112233", "context": "card_number=6222020200112233"}],
}

COLUMNS = [
    {"name": "id", "type": "INTEGER", "sample_size": 3, "nulls": 0,
     "sensitivity": "Unknown", "confirmed_categories": [], "candidate_categories": []},
    {"name": "phone", "type": "VARCHAR(32)", "sample_size": 3, "nulls": 1,
     "sensitivity": "High", "confirmed_categories": ["phone"],
     "candidate_categories": []},
]


@pytest.fixture()
def db():
    with SessionLocal() as session:
        yield session
        session.rollback()


@pytest.fixture()
def connection(db):
    row = DatabaseConnection(
        name=f"ingest-{uuid4().hex[:8]}", engine="mysql", host="10.0.0.5", port=3306,
        database="dst_demo", username="dst_ro",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    yield row
    _purge(db, row.id)
    db.delete(row)
    db.commit()


def _purge(db, connection_id: int) -> None:
    owner = f"db:{connection_id}"
    instances = db.scalars(
        select(AssetInstance).where(AssetInstance.owner_key == owner)
    ).all()
    for instance in instances:
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
    db.commit()


def _ctx(connection, **overrides) -> ingest.ScanContext:
    base = {
        "connection_id": connection.id,
        "connection_name": connection.name,
        "engine": "mysql",
        "host": connection.host,
        "port": connection.port,
        "database": connection.database,
        "scan_id": "dbscan-1",
        "task_id": 11,
        "engine_version": "1.0.0",
        "ruleset_version": "",
        "observed_at": datetime.now(UTC),
        "sample_limit": 50,
        "covered": True,
    }
    return ingest.ScanContext(**{**base, **overrides})


def _scan(**overrides) -> dict:
    base = {
        "schema": "dst_demo",
        "table": "customers",
        "rows_read": 3,
        "hits": [PHONE_HIT],
        "columns": COLUMNS,
        "categories": ["phone"],
        "candidates": [],
        "counts": {"phone": 2},
        "summary": {},
    }
    return {**base, **overrides}


def _instance(db, connection, path: str) -> AssetInstance:
    return db.scalar(
        select(AssetInstance).where(
            AssetInstance.owner_key == f"db:{connection.id}", AssetInstance.path == path
        )
    )


def test_a_table_becomes_a_database_instance_without_a_probe(db, connection) -> None:
    outcome = ingest.ingest_table(db, _ctx(connection), _scan())
    db.commit()
    instance = _instance(db, connection, "dst_demo.customers")
    assert instance is not None
    assert instance.probe_id is None
    assert instance.source_kind == "database"
    assert instance.owner_key == f"db:{connection.id}"
    assert instance.instance_type == "database_table"
    assert instance.status == INSTANCE_ACTIVE
    assert instance.coverage == "complete"
    assert instance.categories == ["phone"]
    assert instance.extra["source"] == "database_scan"
    assert instance.extra["connection_id"] == connection.id
    assert instance.extra["schema"] == "dst_demo"
    assert instance.extra["table"] == "customers"
    assert instance.extra["rows_read"] == 3
    assert instance.extra["values_scanned"] == 6
    assert instance.extra["sample_mode"] == "full"
    assert instance.extra["column_count"] == 2
    assert [column["name"] for column in instance.extra["columns"]] == ["id", "phone"]
    # The sampled values themselves are never stored on the instance.
    assert "values" not in instance.extra
    assert outcome["detections"] == 1

    obj = db.get(DataObject, instance.object_id)
    assert obj.object_type == "database_table"
    assert obj.hash_type == HASH_SCOPED
    assert obj.identity_confidence == IDENTITY_SCOPED
    assert obj.content_hash == ""
    assert obj.object_key.startswith(f"dbscoped:{connection.id}:")
    assert obj.categories == ["phone"]


def test_the_hit_becomes_a_detection_with_bounded原文_evidence(db, connection) -> None:
    ingest.ingest_table(db, _ctx(connection), _scan())
    db.commit()
    instance = _instance(db, connection, "dst_demo.customers")
    detection = db.scalar(
        select(Detection).where(Detection.instance_id == instance.id)
    )
    assert detection is not None
    assert detection.category == "phone"
    assert detection.source_kind == "database"
    assert detection.probe_id is None
    assert detection.hit_count == 2
    assert detection.sample_size == 3
    assert detection.sample_limit == 50
    assert detection.severity == "Medium"
    evidence = db.scalars(
        select(DetectionEvidence).where(DetectionEvidence.detection_id == detection.id)
    ).all()
    assert len(evidence) == 1
    assert evidence[0].field_name == "phone"
    assert evidence[0].rule_id == "SD_PHONE_001"
    assert evidence[0].extra["matches"] == [
        {"value": "13800138000", "context": "phone=13800138000"}
    ]


def test_the_evidence_table_has_no_column_that_stores_a_value() -> None:
    names = {column.name for column in DetectionEvidence.__table__.columns}
    assert names == {
        "id", "detection_id", "evidence_key", "rule_id", "rule_name", "rule_source",
        "recognizer", "evidence_type", "field_name", "sheet_name", "column_index",
        "confidence", "hit_count", "engine_version", "ruleset_version", "extra",
        "created_at", "updated_at",
    }


def test_a_field_only_clue_is_recorded_as_inference_not_as_a_detection(db, connection) -> None:
    scan = _scan(
        hits=[{**PHONE_HIT, "count": 0, "confirmed": False, "field_only": True,
               "matches": [], "evidence": []}],
        categories=["phone"],
        candidates=["phone"],
        counts={},
    )
    outcome = ingest.ingest_table(db, _ctx(connection), scan)
    db.commit()
    instance = _instance(db, connection, "dst_demo.customers")
    assert instance.extra["field_only_categories"] == ["phone"]
    assert db.scalar(select(Detection).where(Detection.instance_id == instance.id)) is None
    assert outcome["detections"] == 0


def test_an_empty_table_keeps_its_metadata_and_claims_nothing(db, connection) -> None:
    scan = _scan(table="empty_table", rows_read=0, hits=[], categories=[], counts={},
                 columns=[{"name": "phone", "type": "VARCHAR(32)", "sample_size": 0,
                           "nulls": 0, "sensitivity": "Unknown",
                           "confirmed_categories": [], "candidate_categories": []}])
    ingest.ingest_table(db, _ctx(connection), scan)
    db.commit()
    instance = _instance(db, connection, "dst_demo.empty_table")
    assert instance is not None
    assert instance.categories == []
    assert instance.extra["rows_read"] == 0
    assert instance.extra["values_scanned"] == 0
    assert db.scalar(select(Detection).where(Detection.instance_id == instance.id)) is None


def test_rescanning_a_table_updates_one_instance(db, connection) -> None:
    ingest.ingest_table(db, _ctx(connection), _scan())
    db.commit()
    first = _instance(db, connection, "dst_demo.customers")
    second_scan = _scan(
        rows_read=5,
        counts={"phone": 4},
        hits=[{**PHONE_HIT, "count": 4}],
    )
    ingest.ingest_table(db, _ctx(connection, scan_id="dbscan-2"), second_scan)
    db.commit()
    rows = db.scalars(
        select(AssetInstance).where(
            AssetInstance.owner_key == f"db:{connection.id}",
            AssetInstance.path == "dst_demo.customers",
        )
    ).all()
    assert len(rows) == 1
    assert rows[0].id == first.id
    assert rows[0].last_scan_id == "dbscan-2"
    assert rows[0].extra["rows_read"] == 5
    assert db.scalar(select(Detection).where(Detection.instance_id == first.id)).hit_count == 4


def test_a_partial_scan_retires_nothing(db, connection) -> None:
    ingest.ingest_table(db, _ctx(connection), _scan(table="gone_next_time"))
    db.commit()
    ctx = _ctx(connection, covered=False)
    retired = ingest.retire_unseen(
        db, ctx, scope_schemas={"dst_demo"}, seen_paths=set()
    )
    db.commit()
    assert retired == []
    assert _instance(db, connection, "dst_demo.gone_next_time").status == INSTANCE_ACTIVE


def test_a_complete_scan_retires_only_its_own_scope(db, connection) -> None:
    ingest.ingest_table(db, _ctx(connection), _scan(table="dropped_table"))
    ingest.ingest_table(db, _ctx(connection), _scan(table="other_schema_table",
                                                   schema="other_db"))
    db.commit()
    ctx = _ctx(connection, covered=True, scan_id="dbscan-3")
    retired = ingest.retire_unseen(
        db, ctx,
        scope_schemas={"dst_demo"},
        seen_paths={"dst_demo.customers"},
    )
    db.commit()
    assert retired == ["dst_demo.dropped_table"]
    dropped = _instance(db, connection, "dst_demo.dropped_table")
    assert dropped.status == INSTANCE_NOT_OBSERVED
    assert dropped.extra["not_observed_scan_id"] == "dbscan-3"
    assert _instance(db, connection, "other_db.other_schema_table").status == INSTANCE_ACTIVE


# --- the type centre must survive a copy that has no probe -------------------
def _another_connection(db) -> DatabaseConnection:
    row = DatabaseConnection(
        name=f"types-{uuid4().hex[:8]}", engine="mysql", host="10.0.0.6", port=3306,
        database="dst_demo", username="dst_ro",
    )
    db.add(row)
    db.commit()
    db.refresh(row)
    return row


def _bank_card_scan(table: str) -> dict:
    return _scan(table=table, hits=[{**BANK_CARD_HIT}], categories=["bank_card"],
                 counts={"bank_card": 2})


def test_the_type_centre_counts_a_connection_as_a_host(db) -> None:
    """A target-database copy has no probe and the type centre must not 500.

    Two configured connections observed the same category, so ``host_count`` is
    two even though both rows carry ``probe_id IS NULL``. Counting that column
    directly raised ``TypeError`` on the NULL - the reported HTTP 500 on the
    data-type centre - and, had it survived the crash, would have merged every
    configured target database into one nameless host.
    """
    first = _another_connection(db)
    second = _another_connection(db)
    try:
        ingest.ingest_table(db, _ctx(first, scan_id="dbscan-types-a"),
                            _bank_card_scan("cards_a"))
        ingest.ingest_table(db, _ctx(second, scan_id="dbscan-types-b"),
                            _bank_card_scan("cards_b"))
        db.commit()
        assert _instance(db, first, "dst_demo.cards_a").probe_id is None
        assert _instance(db, second, "dst_demo.cards_b").probe_id is None

        with TestClient(app) as client:
            listed = client.get("/api/v1/data-types")
            assert listed.status_code == 200, listed.text
            row = next(
                item for item in listed.json()["items"] if item["category"] == "bank_card"
            )
            assert row["host_count"] == 2, "one connection is one host, not one NULL"
            assert row["active_instance_count"] == 2
            assert row["object_count"] == 2
            assert row["level"] == "L3"

            detail = client.get("/api/v1/data-types/bank_card")
            assert detail.status_code == 200, detail.text
            assert detail.json()["category"] == "bank_card"
            assert detail.json()["host_count"] == 2

            for connection, table in ((first, "cards_a"), (second, "cards_b")):
                instance = _instance(db, connection, f"dst_demo.{table}")
                payload = client.get(f"/api/v1/data-objects/{instance.object_id}")
                assert payload.status_code == 200, payload.text
                body = payload.json()
                assert body["host_count"] == 1
                assert [item["owner_key"] for item in body["instances"]] == [
                    f"db:{connection.id}"
                ]
                assert body["instances"][0]["probe_id"] is None
    finally:
        for connection in (first, second):
            _purge(db, connection.id)
            db.delete(db.get(DatabaseConnection, connection.id))
        db.commit()
