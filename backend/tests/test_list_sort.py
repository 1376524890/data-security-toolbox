"""``order_by`` is whitelisted, and an unknown column is refused, not ignored.

A silently ignored sort is worse than no sort: the page shows a header arrow it
never applied. These tests pin the shared helper's contract plus two endpoints
that use it - the rejection shape, and that a real sort actually reorders rows.
"""
from __future__ import annotations

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from sqlalchemy import delete

from app.api.list_sort import order_rows, resolve_order
from app.core.database import SessionLocal
from app.integrations.offline_manager import list_local_cves
from app.main import app
from app.models import LocalCve

SORTABLE = {"id": object(), "name": object()}


def test_a_leading_minus_means_descending() -> None:
    assert resolve_order("name", SORTABLE, default="id") == ("name", False)
    assert resolve_order("-name", SORTABLE, default="id") == ("name", True)


def test_an_empty_key_falls_back_to_the_endpoint_default() -> None:
    assert resolve_order(None, SORTABLE, default="id") == ("id", False)
    assert resolve_order("  ", SORTABLE, default="id") == ("id", False)
    assert resolve_order("-", SORTABLE, default="id") == ("id", True)


def test_an_unknown_column_is_rejected_with_the_allowed_list() -> None:
    with pytest.raises(HTTPException) as exc:
        resolve_order("secret", SORTABLE, default="id")
    assert exc.value.status_code == 400
    assert exc.value.detail["error"] == "unsupported_sort"
    assert exc.value.detail["allowed"] == ["id", "name"]


def test_order_rows_keeps_the_natural_order_when_unsorted() -> None:
    rows = [{"id": 3}, {"id": 1}]
    keys = {"id": lambda row: row["id"]}
    assert order_rows(rows, None, keys, default="id") == rows


def test_order_rows_sorts_both_directions() -> None:
    rows = [{"id": 3}, {"id": 1}, {"id": 2}]
    keys = {"id": lambda row: row["id"]}
    assert [row["id"] for row in order_rows(rows, "id", keys, default="id")] == [1, 2, 3]
    assert [row["id"] for row in order_rows(rows, "-id", keys, default="id")] == [3, 2, 1]


def test_order_rows_puts_missing_values_last_in_both_directions() -> None:
    """A null is "no data", not "least"; it must not jump to the top on desc."""
    rows = [{"id": None}, {"id": 2}, {"id": 1}]
    keys = {"id": lambda row: row["id"]}
    assert [row["id"] for row in order_rows(rows, "id", keys, default="id")] == [1, 2, None]
    assert [row["id"] for row in order_rows(rows, "-id", keys, default="id")] == [2, 1, None]


def test_the_tasks_endpoint_refuses_an_unknown_sort_column() -> None:
    with TestClient(app) as client:
        response = client.get("/api/v1/tasks", params={"order_by": "nope"})
    assert response.status_code == 400
    body = response.json()["detail"]
    assert body["error"] == "unsupported_sort"
    assert "created_at" in body["allowed"]


def test_the_tasks_endpoint_accepts_a_whitelisted_sort() -> None:
    with TestClient(app) as client:
        assert client.get("/api/v1/tasks", params={"order_by": "-created_at"}).status_code == 200


def _seed_cves(rows: list[dict]) -> None:
    with SessionLocal() as db:
        db.execute(delete(LocalCve))
        db.add_all([LocalCve(**row) for row in rows])
        db.commit()


@pytest.fixture()
def cve_rows() -> None:
    _seed_cves([
        {"cve_id": "CVE-2099-3001", "severity": "Low", "cvss_score": 2.1, "source": "nvd"},
        {"cve_id": "CVE-2099-3002", "severity": "Critical", "cvss_score": 9.8, "source": "offline"},
        {"cve_id": "CVE-2099-3003", "severity": "Medium", "cvss_score": 5.0, "source": "nvd"},
    ])
    yield
    _seed_cves([])


def test_local_cves_sort_by_the_requested_column(cve_rows) -> None:
    with SessionLocal() as db:
        ascending = list_local_cves(db, order_by="severity")
        descending = list_local_cves(db, order_by="-cvss_score")
        filtered = list_local_cves(db, severity="Critical")
    assert [row["severity"] for row in ascending] == ["Critical", "Low", "Medium"]
    assert [row["cve_id"] for row in descending] == [
        "CVE-2099-3002", "CVE-2099-3003", "CVE-2099-3001",
    ]
    assert [row["cve_id"] for row in filtered] == ["CVE-2099-3002"]
