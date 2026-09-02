from app.services.audit_service import leak_risk_audit, log_analysis


def test_leak_risk_audit() -> None:
    result = leak_risk_audit([{"protocol_summary": {"http": 10, "tcp": 20}}])
    assert result["risk_level"] == "High"
    assert "http" in result["high_risk_protocols"]


def test_log_analysis() -> None:
    result = log_analysis(["login failed for user admin", "SELECT syntax error", "normal line"])
    assert result["line_count"] == 3
    assert result["matches"]["auth_failure"]
    assert result["matches"]["sql_error"]

