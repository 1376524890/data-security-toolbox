from app.integrations.presidio.adapter import PresidioAdapter
from app.integrations.presidio.recognizers import fallback_scan


def test_presidio_chinese_id() -> None:
    text = "身份证号 110101199003071234"
    result = PresidioAdapter().adapt({"text": text})
    assert any(item.rule_id == "DATA_PRESIDIO_ID_CARD_001" for item in result.findings)


def test_presidio_phone() -> None:
    result = PresidioAdapter().adapt({"text": "手机号 13800138000"})
    assert any(item.rule_id == "DATA_PRESIDIO_PHONE_001" for item in result.findings)


def test_presidio_bank_card() -> None:
    result = PresidioAdapter().adapt({"text": "银行卡 6222021234567890123"})
    assert any(item.rule_id == "DATA_PRESIDIO_BANK_CARD_001" for item in result.findings)


def test_presidio_medical() -> None:
    result = PresidioAdapter().adapt({"text": "病历号：MR-2026-001"})
    assert any(item.rule_id == "DATA_PRESIDIO_MEDICAL_001" for item in result.findings)


def test_presidio_secret() -> None:
    result = PresidioAdapter().adapt({"text": "api_key=sk-1234567890abcdef"})
    assert any(item.rule_id == "DATA_PRESIDIO_SECRET_001" for item in result.findings)


def test_fallback_scan() -> None:
    records = fallback_scan("身份证 110101199003071234")
    assert records
