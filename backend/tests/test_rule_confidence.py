r"""A rule that can only match digits may never confirm a finding on its own.

Imported packs are full of them, and they are the platform's worst offender:
``\b\d{6}[-]?\d{4}\b`` (a Swedish organisation number) matched the
``: 1784680825:0;`` prefix of a shell-history entry, a JSON mtime and a CGI
request id, producing 331 detections and 3194 hits of pure noise on one host. A
rule that cannot tell a number from a counter is still useful *evidence*, but no
score the pack reports can make it conclusive.
"""
from shared.sensitive_detection import build_engine

from app.services import rule_library


def test_digit_only_patterns_are_recognised() -> None:
    assert rule_library.digit_only_pattern(r"\b\d{6}[-]?\d{4}\b")
    assert rule_library.digit_only_pattern(r"\d{3}-\d{2}-\d{4}")
    assert rule_library.digit_only_pattern(r"\d{16}")
    # A class that can also match a letter, or a negated class, is not certain to
    # be looking at a number.
    assert not rule_library.digit_only_pattern(r"(?i)[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}")
    assert not rule_library.digit_only_pattern(r"[A-Z]{2}\d{2}[A-Z0-9]{10,30}")
    assert not rule_library.digit_only_pattern(r"[^\d]")
    assert not rule_library.digit_only_pattern(r"")


def test_an_imported_digit_only_rule_stays_below_the_alert_threshold() -> None:
    rule = {"pattern": r"\b\d{6}[-]?\d{4}\b", "source": "presidio", "confidence": 0.95}
    confidence = rule_library.rule_confidence(rule)
    assert confidence == rule_library.DIGIT_ONLY_CONFIDENCE
    assert confidence < rule_library.MIN_ALERT_CONFIDENCE


def test_an_analyst_written_rule_keeps_its_own_confidence() -> None:
    rule = {"pattern": r"\b\d{6}[-]?\d{4}\b", "source": "manual", "confidence": 0.9}
    assert rule_library.rule_confidence(rule) == 0.9


def test_the_cap_does_not_demote_a_digit_only_rule_that_a_validator_decides() -> None:
    """The builtin phone and bank-card patterns are digit-only but name a
    validator, whose verdict the engine uses instead - so they must still confirm
    a real number."""
    hit = next(item for item in build_engine().scan_text("13800138000")
               if item.entity == "PHONE")
    assert hit.confirmed
