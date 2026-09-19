"""Regressions for false positives caused by shape-only or header-only matches."""
from shared.sensitive_detection import build_engine


def test_field_hints_match_tokens_not_substrings() -> None:
    engine = build_engine()
    # "hotel" contains "tel" and "filename" contains "name"; neither is a column.
    assert engine.scan_field("hotel") == []
    assert all(hit.entity != "NAME" for hit in engine.scan_field("filename"))
    # Real aliases still resolve, including snake_case and camelCase spellings.
    assert any(hit.entity == "PHONE" for hit in engine.scan_field("phone_number"))
    assert any(hit.entity == "ID_CARD" for hit in engine.scan_field("id_card"))
    assert any(hit.entity == "PHONE" for hit in engine.scan_field("contactTelephone"))


def test_field_only_header_is_a_candidate_not_confirmed_data() -> None:
    engine = build_engine()
    header_only = engine.scan_field("phone")[0]
    assert header_only.confirmed is False
    assert header_only.count == 0

    with_value = engine.scan_text("13800138000", field_name="phone")[0]
    assert with_value.confirmed is True
    assert with_value.count == 1


def test_api_key_needs_the_full_key_shape() -> None:
    engine = build_engine()
    assert not any(hit.entity == "API_KEY" for hit in engine.scan_text("AKIA"))
    assert not any(hit.entity == "API_KEY" for hit in engine.scan_text("prefix AKIA suffix"))
    hits = [hit for hit in engine.scan_text("AKIAIOSFODNN7EXAMPLE") if hit.entity == "API_KEY"]
    assert hits and hits[0].confidence >= 0.6


def test_low_confidence_value_shapes_are_candidates() -> None:
    engine = build_engine()
    token = engine.scan_text("a" * 64)
    assert all(not hit.confirmed for hit in token if hit.entity == "TOKEN")
    card = engine.scan_text("6222020000000008")
    assert all(not hit.confirmed for hit in card if hit.entity == "BANK_CARD")
