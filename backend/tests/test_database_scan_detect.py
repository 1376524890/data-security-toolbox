"""Rule matching for one sampled table: shared engine, bounded原文."""
from __future__ import annotations

from typing import Any

from app.services.database_scan import detect


def _sample(
    columns: list[str], values: dict[str, list[str]], *, table: str = "customers",
    schema: str = "dst_demo", rows_read: int = 2,
) -> dict[str, Any]:
    return {
        "schema": schema,
        "table": table,
        "rows_read": rows_read,
        "columns": [
            {"name": name, "type": "TEXT", "nulls": 0,
             "sample_size": len(values.get(name) or [])}
            for name in columns
        ],
        "values": values,
    }


def test_a_column_of_phones_is_confirmed_and_returns_the原文() -> None:
    phones = [f"1380013800{index}" for index in range(5)]
    scan = detect.scan_table(_sample(["phone"], {"phone": phones}, rows_read=5))
    assert scan["categories"] == ["phone"]
    assert scan["counts"] == {"phone": 5}
    assert scan["candidates"] == []
    assert len(scan["hits"]) == 1
    hit = scan["hits"][0]
    assert hit["field_name"] == "phone"
    assert hit["sheet_name"] == "customers"
    assert hit["column_index"] == 0
    assert hit["confirmed"] is True
    assert hit["category"] == "phone"
    assert hit["rule_ids"] and hit["rule_sources"] and hit["evidence"]
    # 原文 comes back, capped at three samples per hit.
    assert len(hit["matches"]) == 3
    assert all(item["value"] in phones for item in hit["matches"])
    assert all(item["context"] for item in hit["matches"])
    assert scan["columns"][0]["sensitivity"] == "High"
    assert scan["columns"][0]["confirmed_categories"] == ["phone"]
    # The sample itself is never handed back wholesale.
    assert "values" not in scan


def test_a_clean_column_matches_nothing() -> None:
    scan = detect.scan_table(_sample(
        ["note"], {"note": ["quarterly report line", "no personal data here"]}, rows_read=2
    ))
    assert scan["hits"] == []
    assert scan["counts"] == {}
    assert scan["categories"] == []
    assert scan["candidates"] == []
    assert scan["columns"][0]["sensitivity"] == "Unknown"
    assert scan["columns"][0]["categories"] == []


def test_a_field_name_alone_is_inference_not_a_detection() -> None:
    """An empty table with a ``phone`` column must not read as a phone table."""
    scan = detect.scan_table(_sample(["phone", "id_card"], {"phone": [], "id_card": []},
                                     rows_read=0))
    assert scan["categories"] == []
    assert scan["counts"] == {}
    assert scan["hits"] == []
    assert sorted(scan["candidates"]) == ["id_card", "phone"]
    assert scan["columns"][0]["candidate_categories"] == ["phone"]
    assert scan["columns"][0]["confirmed_categories"] == []
    assert scan["columns"][0]["categories"] == ["phone"]


def test_a_long_line_is_capped_but_keeps_the_matched_value() -> None:
    line = ("filler " * 60) + "user@example.com"
    scan = detect.scan_table(_sample(["contact"], {"contact": [line]}, rows_read=1))
    assert scan["categories"] == ["email"]
    hit = scan["hits"][0]
    assert hit["matches"][0]["value"] == "user@example.com"
    for item in hit["matches"]:
        assert len(item["value"]) <= 120
        assert len(item["context"]) <= 240


def test_chinese_identifiers_survive_as_field_and_sheet_names() -> None:
    scan = detect.scan_table(_sample(
        ["客户手机号"], {"客户手机号": ["13800138000"]}, table="订单明细", rows_read=1
    ))
    hit = scan["hits"][0]
    assert hit["field_name"] == "客户手机号"
    assert hit["sheet_name"] == "订单明细"
    assert hit["category"] == "phone"
    assert scan["columns"][0]["name"] == "客户手机号"


def test_the_secret_families_are_found_by_content_too() -> None:
    scan = detect.scan_table(_sample(
        ["token"],
        {"token": ["ghp_" + "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8", "AKIAIOSFODNN7EXAMPLE"]},
        rows_read=2,
    ))
    assert scan["categories"], "a GitHub token and an AWS key must be detected"
    assert scan["counts"]
