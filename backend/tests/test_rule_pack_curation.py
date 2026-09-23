r"""What an imported rule pack is allowed to switch on by itself.

Importing Presidio is the cheapest way to fill the store with recognizers, and it
is also how the noisiest rule arrived: a Swedish organisation number pattern that
scored itself 0.6 imported itself *enabled*, then matched shell-history
timestamps. The pack's score is not this platform's reading of the rule, and a
rule an analyst has not touched must be judged by that reading -- both when it is
first imported and when the pack is refreshed over it.
"""
from __future__ import annotations

import io
import json
import zipfile

import pytest

from app.core.config import settings
from app.services.rule_library import (
    ANALYST_TOGGLE,
    DIGIT_ONLY_CONFIDENCE,
    atomic_json,
    import_presidio_wheel,
    managed_rules,
    rule_store_directory,
    set_rule_enabled,
)

#: Written as the wheel's own source: the importer parses it and never runs it.
ORGANISATION_NUMBER = r'''
class SeOrganisationsnummerRecognizer:
    PATTERNS = [Pattern("Swedish Organisationsnummer (Medium)", r"\b\d{6}[-]?\d{4}\b", 0.6)]
    def __init__(self, supported_entity="SE_ORGANISATIONSNUMMER"): pass
'''
GSTIN = r'''
class InGstinRecognizer:
    PATTERNS = [Pattern("GSTIN (High)", r"\b\d{2}[A-Z]{5}\d{4}[A-Z]\dZ[A-Z]\b", 0.8)]
    def __init__(self, supported_entity="IN_GSTIN"): pass
'''
IP_ADDRESS = r'''
class IpRecognizer:
    PATTERNS = [Pattern("IPv4", r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", 0.6)]
    def __init__(self, supported_entity="IP_ADDRESS"): pass
'''


@pytest.fixture
def store(tmp_path, monkeypatch):
    """A rule store of this test's own: the import writes into the real layout."""
    monkeypatch.setattr(settings, "integration_dir", tmp_path / "integrations")
    rule_store_directory().mkdir(parents=True, exist_ok=True)
    return rule_store_directory()


def wheel(*sources: str) -> bytes:
    """A wheel-shaped zip: the importer reads the files, it never imports them."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        for index, source in enumerate(sources):
            archive.writestr(
                f"presidio_analyzer/predefined_recognizers/generic/r{index}.py", source
            )
    return buffer.getvalue()


def _rules() -> list[dict]:
    return [rule for rule in managed_rules() if rule.get("source") == "Presidio"]


def _only() -> dict:
    rules = _rules()
    assert len(rules) == 1, rules
    return rules[0]


def test_a_digit_only_recognizer_imports_disabled_at_the_platform_s_cap(store) -> None:
    assert import_presidio_wheel(wheel(ORGANISATION_NUMBER), "test")["imported"] == 1

    rule = _only()

    # 0.6 was the pack's own claim; the platform reads the pattern at the
    # digit-only cap and will not raise anything on it until someone opts in.
    assert rule["confidence"] == DIGIT_ONLY_CONFIDENCE
    assert rule["enabled"] is False


def test_structural_metadata_is_never_switched_on_by_an_import(store) -> None:
    import_presidio_wheel(wheel(IP_ADDRESS), "test")

    # An IP address is infrastructure, not data: it is imported as evidence.
    assert _only()["enabled"] is False


def test_a_confident_recognizer_still_imports_enabled(store) -> None:
    import_presidio_wheel(wheel(GSTIN), "test")

    rule = _only()

    assert rule["confidence"] == 0.8
    assert rule["enabled"] is True


def test_a_pack_refresh_does_not_undo_an_analyst_s_decision(store) -> None:
    content = wheel(GSTIN)
    import_presidio_wheel(content, "v1")
    rule_id = _only()["id"]

    assert set_rule_enabled(rule_id, False) is not None
    import_presidio_wheel(content, "v2")

    rule = _only()
    assert rule["enabled"] is False
    assert rule[ANALYST_TOGGLE] is True


def test_a_rule_the_previous_import_enabled_is_re_judged_on_refresh(store) -> None:
    """The store as the old importer left it: uncapped score, switched on, no marker."""
    import_presidio_wheel(wheel(ORGANISATION_NUMBER), "v1")
    path = rule_store_directory() / "presidio.json"
    document = json.loads(path.read_text(encoding="utf-8"))
    document["rules"][0].update(confidence=0.6, enabled=True)
    document["rules"][0].pop(ANALYST_TOGGLE, None)
    atomic_json(path, document)
    assert _only()["enabled"] is True

    import_presidio_wheel(wheel(ORGANISATION_NUMBER), "v2")

    assert _only()["enabled"] is False
    assert _only()["confidence"] == DIGIT_ONLY_CONFIDENCE
