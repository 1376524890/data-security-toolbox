from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult
from app.engine.risk_engine.engine import RiskEngine


def test_risk_level() -> None:
    engine = RiskEngine()
    assert engine.level(90) == "Critical"
    assert engine.level(65) == "High"
    assert engine.level(40) == "Medium"
    assert engine.level(10) == "Low"


def test_risk_score() -> None:
    context = DetectionContext(target_type="pcap", data={"exposure_factor": 4, "data_sensitivity": 4, "threat_factor": 4})
    finding = DetectionResult(engine="test", rule_id="T", severity="Critical", confidence=1.0)
    scored = RiskEngine().score(context, [finding])
    assert scored[0].risk_score == 100.0
    assert scored[0].risk_level == "Critical"

