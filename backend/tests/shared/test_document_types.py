"""The document-type classifier: what it names, and what it refuses to name.

A finding that says "涉密文件" has to be explainable, so these tests pin the two
places where the classifier deliberately abstains: a red band with no 公文 text
is only a letterhead, and a bare 秘密 in ordinary prose is not a marking.
"""
from __future__ import annotations

from shared.scanning.document_types import (
    SIGNAL_CLASSIFIED,
    SIGNAL_OFFICIAL,
    SIGNAL_RED_HEADER,
    SIGNAL_SEAL,
    classify,
    strongest,
)


def _kinds(signals) -> set[str]:
    return {item.kind for item in signals}


def test_a_band_without_official_text_is_only_a_letterhead() -> None:
    """Colour alone must not claim a 公文: a red poster would be one too."""
    plain = classify("某某公司\n产品手册\n", {"red_title_band": True})
    assert _kinds(plain) == {SIGNAL_RED_HEADER}
    assert plain[0].severity == "Low"


def test_band_and_official_markers_agree_on_a_red_header_document() -> None:
    text = "XX市人民政府文件\n〔2023〕12号\n关于做好数据安全工作的通知\n"
    text_only = classify(text, {})
    assert SIGNAL_OFFICIAL in _kinds(text_only)
    assert SIGNAL_RED_HEADER not in _kinds(text_only)

    signals = classify(text, {"red_title_band": True})
    header = [item for item in signals if item.kind == SIGNAL_RED_HEADER]
    assert header and header[0].confidence > 0.8
    assert "〔2023〕12号" in " ".join(header[0].evidence)


def test_the_standard_star_marking_is_critical() -> None:
    signals = classify("机密★10年\n", {})
    classified = [item for item in signals if item.kind == SIGNAL_CLASSIFIED]
    assert classified and classified[0].severity == "Critical"


def test_a_bare_secret_word_is_not_a_marking() -> None:
    assert classify("这是一个秘密地点，适合探险。", {}) == []


def test_two_secrecy_words_without_a_level_are_still_a_marking() -> None:
    signals = classify("涉密载体管理：保密期限届满后依规解密。", {})
    classified = [item for item in signals if item.kind == SIGNAL_CLASSIFIED]
    assert classified and classified[0].severity == "High"
    assert classified[0].label == "涉密文件"


def test_a_label_form_marking_is_read_with_its_level() -> None:
    signals = classify("密级：秘密\n", {})
    classified = [item for item in signals if item.kind == SIGNAL_CLASSIFIED]
    assert classified and classified[0].severity == "High"
    assert "秘密" in classified[0].label


def test_a_seal_comes_from_the_page_colour_or_an_explicit_placeholder() -> None:
    assert SIGNAL_SEAL in _kinds(classify("合同专用章（盖章）", {}))
    assert SIGNAL_SEAL in _kinds(classify("正文", {"red_seal": True}))


def test_empty_input_yields_nothing() -> None:
    assert classify("", {}) == []
    assert classify("   \n", {}) == []


def test_strongest_ranks_by_severity_and_can_be_narrowed() -> None:
    signals = classify("机密★10年\n国务院办公厅文件\n", {})
    assert strongest(signals).severity == "Critical"
    assert strongest(signals, kinds={SIGNAL_OFFICIAL}).kind == SIGNAL_OFFICIAL
    assert strongest(signals, kinds={"no_such_kind"}) is None
