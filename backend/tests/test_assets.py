from app.services.asset_service import classify_assets, classify_service, risk_level, sensitive_categories


def test_classify_database() -> None:
    assert classify_service(5432, "postgres") == "database"


def test_risk_for_public_database() -> None:
    assert risk_level("database", "postgres", public_exposed=True) == "High"


def test_sensitive_categories() -> None:
    categories = sensitive_categories("postgres", "customer-payment")
    assert "customer" in categories
    assert "finance" in categories


def test_classify_assets() -> None:
    payload = {"hostname": "db-01", "ip": "10.0.0.5", "os": "Linux", "services": [{"port": 5432, "service": "postgres"}], "metadata": {"description": "customer credentials"}}
    assets = classify_assets(payload)
    assert assets[0]["asset_type"] == "database"
    assert assets[0]["risk_level"] == "High"

