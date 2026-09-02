from pathlib import Path

from app.engine.core.context import DetectionContext
from app.engine.log_engine import SigmaLogEngine


def test_sigma_auth_rule() -> None:
    context = DetectionContext(target_type="log", log_lines=["login failed for user admin", "failed auth for user admin"])
    findings = SigmaLogEngine().analyze(context)
    assert any(item.rule_id == "LOG_SIGMA_AUTH_001" for item in findings)

