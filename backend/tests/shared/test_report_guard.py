"""Report safety: structure whitelist, nested raw-value rejection and redaction.

The pure functions are covered here; the HTTP boundary that uses them, and the
proof that probe authentication is not affected, live in test_engine_wiring.py.
"""
from shared.sensitive_detection.report_guard import (
    MAX_FREE_LIST_ITEMS,
    MAX_STRING_CHARS,
    REDACTION_PLACEHOLDER,
    looks_like_raw_value,
    report_is_safe,
    sanitize_report,
    validate_report,
)

PHONE = "13800138000"
ID_CARD = "110101199003076173"

# A real 3.3.1-shaped report: every key here is one the probe actually sends.
LEGACY_REPORT = {
    "report_id": "abc123",
    "task_id": 7,
    "assets": [{
        "name": "customers.csv",
        "asset_type": "table",
        "sensitivity": "High",
        "path": "/srv/data/customers.csv",
        "size": 2048,
        "sha256": "a" * 64,
        "modified_at": "2026-09-15T00:00:00+00:00",
        "categories": ["phone", "id_card"],
        "counts": {"phone": 2},
        "columns": [{"name": "phone", "detected_type": "phone", "sensitivity": "Medium",
                     "confidence": 0.9, "categories": ["phone"], "count": 2}],
        "evidence": {"extension": ".csv", "hits": [{"entity": "PHONE", "count": 2}]},
    }],
    "databases": [{"name": "mysql@127.0.0.1:3306", "asset_type": "database", "path": "127.0.0.1:3306",
                   "categories": ["database"], "counts": {}, "columns": [],
                   "evidence": {"engine": "mysql", "listening": True}}],
    "scanned_paths": ["/srv/data"],
    "max_depth": 3,
    "complete": True,
    "error": "",
    "observed_at": "2026-09-15T00:00:00+00:00",
    "scanner": "probe-file-inventory",
    "counts": {"phone": 2},
    "engine_version": "1.0.0",
    "duration_ms": 1200,
    "report_guard": {"redacted": 0, "truncated": 0, "dropped_keys": 0},
}


def test_legacy_report_shape_passes_validation() -> None:
    assert validate_report(LEGACY_REPORT) == []
    assert report_is_safe(LEGACY_REPORT) is True


def test_nested_forbidden_key_is_rejected() -> None:
    """A whitelist on the top level alone would let evidence smuggle values."""
    payload = {"assets": [{"evidence": {"samples": [PHONE]}}]}
    assert [item.to_dict() for item in validate_report(payload)] == [
        {"path": "$.assets[0].evidence.samples", "code": "forbidden_key"}]


def test_nested_forbidden_key_is_rejected_inside_columns() -> None:
    payload = {"assets": [{"columns": [{"name": "phone", "cell_value": PHONE}]}]}
    assert [item.code for item in validate_report(payload)] == ["forbidden_key"]


def test_unknown_field_is_rejected_without_echoing_the_value() -> None:
    violations = validate_report({"assets": [{"unexpected": "SOMETHING_TO_HIDE"}]})
    assert violations[0].code == "unknown_field"
    assert "SOMETHING_TO_HIDE" not in str(violations[0].to_dict())
    assert violations[0].path == "$.assets[0].unexpected"


def test_a_column_named_password_is_legitimate() -> None:
    """The rule is "describe the column, never the value"."""
    assert validate_report({"header_name": "password", "name": "pwd"}, level="column") == []
    assert validate_report({"assets": [{"columns": [{"header_name": "token", "name": "api_token"}]}]}) == []


def test_a_forbidden_key_is_rejected_even_with_an_innocent_name() -> None:
    assert [item.code for item in validate_report({"access_token": "x"})] == ["forbidden_key"]
    assert [item.code for item in validate_report({"password": "x"})] == ["forbidden_key"]


def test_oversized_values_are_rejected() -> None:
    over_long_name = {"assets": [{"columns": [{"name": "a" * (MAX_STRING_CHARS + 1)}]}]}
    assert [item.code for item in validate_report(over_long_name)] == ["string_too_long"]
    over_long_evidence = {"evidence": [1] * (MAX_FREE_LIST_ITEMS + 1)}
    assert [item.code for item in validate_report(over_long_evidence)] == ["list_too_long"]


def test_deeply_nested_payload_is_rejected() -> None:
    deep: dict = {}
    node = deep
    for _ in range(20):
        node["evidence"] = {}
        node = node["evidence"]
    assert "too_deep" in {item.code for item in validate_report({"assets": [deep]})}


def test_non_object_payload_is_rejected() -> None:
    assert [item.code for item in validate_report(["not", "a", "report"])] == ["payload_not_object"]


def test_sanitize_drops_forbidden_keys_and_counts_them() -> None:
    clean, audit = sanitize_report({"assets": [{"evidence": {"samples": [PHONE], "extension": ".csv"}}]})
    assert clean == {"assets": [{"evidence": {"extension": ".csv"}}]}
    assert audit.dropped_keys == ["$.assets[0].evidence.samples"]
    assert audit.to_dict() == {"redacted": 0, "truncated": 0, "dropped_keys": 1}
    assert validate_report(clean) == []


def test_sanitize_redacts_raw_values_that_hide_in_strings() -> None:
    clean, audit = sanitize_report({"assets": [{"path": f"/srv/{ID_CARD}.csv", "name": "customers.csv"}]})
    assert clean["assets"][0]["path"] == REDACTION_PLACEHOLDER
    assert clean["assets"][0]["name"] == "customers.csv"
    assert audit.redacted_paths == ["$.assets[0].path"]
    assert audit.redacted == 1


def test_sanitize_truncates_oversized_strings() -> None:
    clean, audit = sanitize_report({"assets": [{"columns": [{"name": "a" * (MAX_STRING_CHARS + 20)}]}]})
    assert len(clean["assets"][0]["columns"][0]["name"]) == MAX_STRING_CHARS
    assert audit.truncated == 1


def test_returned_matched_text_survives_sanitize_but_nothing_else_does() -> None:
    """The ``matches`` subtree is the exception, and only that subtree."""
    payload = {"assets": [{"evidence": {"hits": [
        {"category": "phone", "matches": [{"value": PHONE, "context": f"mobile,{PHONE}"}]},
    ]}}]}
    clean, audit = sanitize_report(payload)
    assert clean["assets"][0]["evidence"]["hits"][0]["matches"] == [
        {"value": PHONE, "context": f"mobile,{PHONE}"}]
    assert audit.redacted == 0, "returning the matched value is the point of the field"
    # A value hiding anywhere else is still redacted and still counted.
    other, other_audit = sanitize_report({"path": f"/srv/{PHONE}.csv", "matches": []})
    assert other["path"] == REDACTION_PLACEHOLDER
    assert other_audit.redacted == 1
    # Structure is still enforced: the exemption is not a hole in the whitelist.
    assert [item.code for item in validate_report(
        {"assets": [{"evidence": {"hits": [{"matches": [{"value": PHONE}]}]}}]})] == []


def test_sanitize_strips_control_characters() -> None:
    clean, _ = sanitize_report({"assets": [{"path": "/srv/data\x07/customers.csv"}]})
    assert clean["assets"][0]["path"] == "/srv/data/customers.csv"


def test_looks_like_raw_value_ignores_ordinary_identifiers() -> None:
    assert looks_like_raw_value(PHONE) == "PHONE"
    assert looks_like_raw_value(ID_CARD) == "ID_CARD"
    # Hashes, paths and container identifiers must survive redaction intact.
    assert looks_like_raw_value("a" * 64) == ""
    assert looks_like_raw_value("/var/lib/data-security-toolbox/spool") == ""
    assert looks_like_raw_value("probe-file-inventory") == ""
