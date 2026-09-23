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


def test_a_credential_is_judged_on_the_value_not_the_keyword() -> None:
    """``password <sep> <value>`` matches source code as often as a real credential.

    ``password: bytes,`` and ``password = str(password)`` were raised at
    L4/Critical across an entire repository. What follows the separator is the
    only evidence available, and shape is never conclusive, so a word-like value
    stays evidence instead of becoming a finding.
    """
    engine = build_engine()
    for source in ('password: bytes,', 'password = str(password)',
                   'password = self.keyring.get_password(url,', 'password = password[:127]'):
        assert not any(hit.entity == 'CREDENTIAL' and hit.confirmed
                       for hit in engine.scan_text(source)), source
    # A type or parameter name is a bare word: kept, never confirmed.
    for word_like in ('password: _PasswordType', 'password = HiddenText'):
        hits = [hit for hit in engine.scan_text(word_like) if hit.entity == 'CREDENTIAL']
        assert hits and not hits[0].confirmed, word_like
    # A configured secret mixes letters with digits or symbols.
    for configured in ('password = Sup3rS3cret!', 'password=admin123', 'password = p@ssw0rd2024'):
        hits = [hit for hit in engine.scan_text(configured) if hit.entity == 'CREDENTIAL']
        assert hits and hits[0].confirmed, configured


def test_a_bare_number_after_a_password_key_is_evidence_only() -> None:
    """The engine hands a validator the whole match, so the keyword and the
    separator have to come off before the value is judged - otherwise a digit run
    that is really a timestamp would be confirmed as a credential."""
    engine = build_engine()
    hits = [hit for hit in engine.scan_text('password: 1784680825') if hit.entity == 'CREDENTIAL']
    assert hits and not hits[0].confirmed
