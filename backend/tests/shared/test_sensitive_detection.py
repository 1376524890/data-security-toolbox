"""The shared engine: one rule set for the probe, the platform and NetDLP.

These tests pin the P0 contract both callers depend on: canonical entity names,
value-level validators, evidence merging, bounded regex work and the structural
guarantee that a matched value can never reach a report.
"""
import dataclasses
import json
import subprocess
import sys
from pathlib import Path

import pytest

from shared.sensitive_detection import build_engine
from shared.sensitive_detection.confidence import FIELD_EVIDENCE_CEILING
from shared.sensitive_detection.engine import SensitiveDetectionEngine
from shared.sensitive_detection.entities import canonical_entity, legacy_name
from shared.sensitive_detection.result import DetectionHit, Evidence
from shared.sensitive_detection.validators import (
    validate_bank_card,
    validate_cn_id_card,
    validate_email,
    validate_phone,
)

REPO_ROOT = Path(__file__).resolve().parents[3]

# Deriving the fixtures from the GB 11643 weights keeps them honest: one number
# ends in a digit, one in the letter X, one has a deliberately broken check digit.
ID_CARD_DIGIT = "110101199003076173"
ID_CARD_X = "11010119900307002X"
ID_CARD_BAD_CHECKSUM = "110101199003076170"
LUHN_VALID_CARD = "6222020000000007"
LUHN_INVALID_CARD = "6222020000000008"

P0_ENTITIES = {
    "PHONE", "ID_CARD", "BANK_CARD", "EMAIL",
    "API_KEY", "TOKEN", "CREDENTIAL", "NAME", "ADDRESS", "MEDICAL_RECORD",
}


def test_builtin_pack_declares_the_p0_types_once() -> None:
    engine = build_engine()
    assert P0_ENTITIES <= set(engine.entities)
    rule_ids = [rule["rule_id"] for rule in engine.rules]
    assert len(rule_ids) == len(set(rule_ids))
    assert engine.rule_errors == []


@pytest.mark.parametrize("alias,expected", [
    ("phone", "PHONE"),
    ("PHONE_NUMBER", "PHONE"),
    ("CN_PHONE", "PHONE"),
    ("mobile_number", "PHONE"),
    ("IDCARD", "ID_CARD"),
    ("national_id", "ID_CARD"),
    ("email_address", "EMAIL"),
    ("PASSWORD", "CREDENTIAL"),
    ("access_token", "TOKEN"),
    ("ANALYST_DEFINED", "ANALYST_DEFINED"),
])
def test_entity_aliases_collapse_into_one_canonical_type(alias: str, expected: str) -> None:
    """Otherwise the same type splits into several statistics."""
    assert canonical_entity(alias) == expected


def test_legacy_category_names_stay_stable() -> None:
    assert legacy_name("PHONE_NUMBER") == "phone"
    assert legacy_name("ID_CARD") == "id_card"
    assert legacy_name("PASSWORD") == "credential"
    assert legacy_name("IP_ADDRESS") == ""


@pytest.mark.parametrize("value", [ID_CARD_DIGIT, ID_CARD_X])
def test_id_card_validator_confirms_checksum_and_birth_date(value: str) -> None:
    outcome = validate_cn_id_card(value)
    assert outcome.accepted is True
    assert outcome.confidence == 0.95
    assert outcome.facts == {"checksum_valid": True, "birth_date_valid": True}


def test_id_card_validator_keeps_well_formed_but_unverified_numbers() -> None:
    """A bad check digit lowers confidence; it must not delete the finding."""
    outcome = validate_cn_id_card(ID_CARD_BAD_CHECKSUM)
    assert outcome.accepted is True
    assert outcome.confidence == 0.7
    assert outcome.facts["checksum_valid"] is False


def test_id_card_validator_rejects_impossible_values() -> None:
    for value in ("12345", "", "1101011990030761739", "110101199013076173"):
        assert validate_cn_id_card(value).accepted is False


def test_bank_card_validator_uses_luhn() -> None:
    confirmed = validate_bank_card(LUHN_VALID_CARD)
    assert (confirmed.confidence, confirmed.facts["luhn_valid"]) == (0.9, True)
    unverified = validate_bank_card(LUHN_INVALID_CARD)
    assert (unverified.confidence, unverified.facts["luhn_valid"]) == (0.45, False)
    assert validate_bank_card("1234").accepted is False


def test_phone_and_email_validators_reject_impossible_values() -> None:
    assert validate_phone("13800138000").accepted is True
    assert validate_phone("1380013800").accepted is False
    assert validate_email("user@example.com").accepted is True
    # The host part of a connection string is not an address.
    assert validate_email("security@172.18.0.2").accepted is False


def test_same_span_from_two_rules_is_one_finding() -> None:
    pattern = r"(?<!\d)1[3-9]\d{9}(?!\d)"
    engine = SensitiveDetectionEngine([
        {"rule_id": "R1", "entity": "PHONE", "pattern": pattern},
        {"rule_id": "R2", "entity": "PHONE_NUMBER", "pattern": pattern},
    ])
    hits = engine.scan_text("call 13800138000 now")
    assert [(hit.entity, hit.count) for hit in hits] == [("PHONE", 1)]
    assert hits[0].rule_ids == ["R1", "R2"]


def test_overlapping_spans_from_two_rules_merge() -> None:
    engine = SensitiveDetectionEngine([
        {"rule_id": "A", "entity": "PHONE", "pattern": r"\d{11}"},
        {"rule_id": "B", "entity": "PHONE", "pattern": r"1[3-9]\d{9}"},
    ])
    assert [hit.count for hit in engine.scan_text("x13800138000y")] == [1]


def test_repeated_values_of_one_type_count_separately() -> None:
    engine = build_engine()
    assert [hit.count for hit in engine.scan_text("13800138000 and 13900139000")] == [2]


def test_matched_values_never_reach_the_serialised_result() -> None:
    engine = build_engine()
    secrets = ("13800138000", ID_CARD_DIGIT, LUHN_VALID_CARD, "user@example.com")
    hits = engine.scan_text(f"phone {secrets[0]} id {secrets[1]} card {secrets[2]} mail {secrets[3]}")
    assert {hit.entity for hit in hits} == {"PHONE", "ID_CARD", "BANK_CARD", "EMAIL"}
    serialised = json.dumps([hit.to_dict() for hit in hits], ensure_ascii=False)
    report = json.dumps(engine.last_report.to_dict(), ensure_ascii=False)
    for secret in secrets:
        assert secret not in serialised
        assert secret not in report


def test_result_structures_have_no_field_for_a_matched_value() -> None:
    """The guarantee is structural, not a masking step someone must remember."""
    forbidden = {"text", "value", "values", "match", "matched", "raw", "sample", "samples"}
    for structure in (Evidence, DetectionHit):
        names = {field.name for field in dataclasses.fields(structure)}
        assert not names & forbidden


def test_catastrophic_regex_is_bounded_reported_and_not_fatal() -> None:
    engine = SensitiveDetectionEngine([
        {"rule_id": "SLOW", "entity": "PHONE", "pattern": r"(a+)+$"},
        {"rule_id": "FAST", "entity": "PHONE", "pattern": r"(?<!\d)1[3-9]\d{9}(?!\d)"},
    ], timeout=0.05)
    assert engine.scan_text("a" * 4000 + "!") == []
    assert engine.last_report.timeouts == [r"(a+)+$"]
    # Bounded work must not poison the engine: the next call still answers.
    assert [(hit.entity, hit.count) for hit in engine.scan_text("call 13800138000")] == [("PHONE", 1)]
    assert engine.last_report.timeouts == []


def test_matching_still_works_when_the_optional_regex_wheel_is_absent(monkeypatch) -> None:
    """A distro python without `regex` falls back to `re` and keeps detecting.

    The fallback cannot enforce a per-match timeout, so `capabilities()` reports
    ``regex_timeout: False`` instead of implying the bound still exists.
    """
    from shared.sensitive_detection import matching

    monkeypatch.setattr(matching, "_regex", None)
    scan = matching.matches(r"(?<!\d)1[3-9]\d{9}(?!\d)", "call 13800138000 now")
    assert [interval[1] - interval[0] for interval in scan.intervals] == [11]
    assert scan.timeouts == []
    assert build_engine().capabilities()["regex_timeout"] is matching.SUPPORTS_TIMEOUT


def test_oversized_input_is_truncated_and_reported() -> None:
    engine = SensitiveDetectionEngine(
        [{"rule_id": "F", "entity": "PHONE", "pattern": r"(?<!\d)1[3-9]\d{9}(?!\d)"}],
        max_text_chars=32)
    hits = engine.scan_text("x" * 40 + " 13800138000")
    assert hits == []
    assert engine.last_report.text_truncated is True


def test_unusable_rules_are_skipped_and_reported_not_fatal() -> None:
    engine = SensitiveDetectionEngine([
        {"rule_id": "GOOD", "entity": "PHONE", "pattern": r"(?<!\d)1[3-9]\d{9}(?!\d)"},
        {"rule_id": "NO_VALIDATOR", "entity": "PHONE", "pattern": r"\d{11}", "validator": "os.system"},
        {"rule_id": "EMPTY_MATCH", "entity": "PHONE", "pattern": r"a*"},
        {"entity": "PHONE", "pattern": r"\d{11}"},
    ])
    reasons = {item["rule_id"]: item["reason"] for item in engine.rule_errors}
    assert reasons["NO_VALIDATOR"] == "unknown_validator:os.system"
    assert reasons["EMPTY_MATCH"] == "matches_empty_string"
    assert reasons[""] == "missing_rule_id"
    assert [hit.count for hit in engine.scan_text("call 13800138000")] == [1]
    assert engine.last_report.rules_skipped == engine.rule_errors


def test_rule_count_is_capped() -> None:
    from shared.sensitive_detection import matching

    engine = SensitiveDetectionEngine(
        [{"rule_id": f"R{index}", "entity": "PHONE", "pattern": r"1[3-9]\d{9}"}
         for index in range(matching.MAX_PATTERNS + 3)])
    assert len(engine.rules) == matching.MAX_PATTERNS
    assert {item["reason"] for item in engine.rule_errors} == {"too_many_rules"}


def test_field_name_evidence_is_capped_and_never_claims_ner() -> None:
    engine = build_engine()
    for field_name, entity in (("密码", "CREDENTIAL"), ("password", "CREDENTIAL"), ("姓名", "NAME")):
        hits = engine.scan_field(field_name)
        matched = [hit for hit in hits if hit.entity == entity]
        assert matched, field_name
        hit = matched[0]
        assert hit.confidence <= FIELD_EVIDENCE_CEILING
        assert hit.context_evidence is True
        assert {item.evidence_type for item in hit.evidence} == {"field_name"}


def test_field_only_types_are_flagged_as_low_confidence() -> None:
    engine = build_engine()
    name_hit = engine.scan_field("姓名")[0]
    assert (name_hit.entity, name_hit.field_only, name_hit.level, name_hit.severity) == (
        "NAME", True, "L1", "Low")


def test_structural_metadata_cannot_make_data_sensitive() -> None:
    engine = SensitiveDetectionEngine(
        [{"rule_id": "IP", "entity": "IP_ADDRESS", "pattern": r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"}])
    hits = engine.scan_text("host 10.0.0.5 up")
    assert [(hit.entity, hit.count, hit.sensitive) for hit in hits] == [("IP_ADDRESS", 1, False)]


def test_capabilities_are_declared_without_overclaiming() -> None:
    capabilities = build_engine().capabilities()
    assert capabilities["sensitive_detection_v2"] is True
    assert capabilities["rule_count"] == len(build_engine().rules)
    assert P0_ENTITIES <= set(capabilities["entities"])
    # No NER claim: field-only types exist precisely because P0 has no model.
    assert "ner" not in json.dumps(capabilities).lower()


def test_engine_starts_and_scans_without_optional_nlp_dependencies() -> None:
    """A probe without Presidio or spaCy must still detect values, not crash."""
    script = (
        "import sys;"
        f"sys.path.insert(0, {str(REPO_ROOT)!r});"
        "import shared.sensitive_detection as module;"
        "engine = module.build_engine();"
        "hits = engine.scan_text('13800138000');"
        "print(len(engine.rules), [(hit.entity, hit.count) for hit in hits],"
        " sorted(name for name in sys.modules if 'presidio' in name or 'spacy' in name))"
    )
    completed = subprocess.run([sys.executable, "-c", script], capture_output=True, text=True, check=True)
    assert completed.stdout.strip().endswith("[]")
    assert "('PHONE', 1)" in completed.stdout
