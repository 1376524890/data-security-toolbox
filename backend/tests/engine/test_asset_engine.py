from app.engine.asset_engine.engine import AssetEngine, classify_service
from app.engine.core.context import DetectionContext


def test_classify_service() -> None:
    assert classify_service(6379, "redis") == "redis"
    assert classify_service(9092, "broker") == "kafka"


def test_public_redis_critical() -> None:
    context = DetectionContext(target_type="asset", data={"host": "10.0.0.1", "public_exposed": True, "services": [{"port": 6379, "service": "redis"}]})
    findings = AssetEngine().analyze(context)
    assert any(item.rule_id == "ASSET_PUBLIC_DB_001" and item.severity == "Critical" for item in findings)

