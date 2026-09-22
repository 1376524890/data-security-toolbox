"""A keyword hit is a lead; only a declared version range confirms a CVE."""
from app.engine.core.context import DetectionContext
from app.threat_intel.engine import ThreatIntelEngine


def test_keyword_only_hit_stays_a_candidate(monkeypatch) -> None:
    engine = ThreatIntelEngine()
    monkeypatch.setattr(engine, "cve_lookup", lambda keyword, api_key="", product="": [
        {"cve_id": "CVE-2020-0001", "severity": "High", "description": "ssh issue"},
    ])
    context = DetectionContext(
        target_type="scan", assets=[{"ip": "10.0.0.1", "service": "ssh"}],
        data={"cve_lookup_enabled": True})
    findings = engine.analyze(context)
    assert not any(item.rule_id == "CVE_CVE-2020-0001" for item in findings)
    candidates = [item for item in findings if item.rule_id == "CVE_CANDIDATE_001"]
    assert candidates and candidates[0].evidence["count"] == 1


def test_declared_range_confirms_and_outside_range_is_dropped(monkeypatch) -> None:
    engine = ThreatIntelEngine()
    monkeypatch.setattr(engine, "cve_lookup", lambda keyword, api_key="", product="": [
        {"cve_id": "CVE-2020-1111", "severity": "High", "cvss_score": 9.8,
         "affected_versions": [">=1.0,<1.2.3"]},
        {"cve_id": "CVE-2020-2222", "severity": "High",
         "affected_versions": [">=2.0,<2.5"]},
    ])
    context = DetectionContext(
        target_type="scan",
        assets=[{"ip": "10.0.0.1", "service": "nginx", "version": "1.2.0"}],
        data={"cve_lookup_enabled": True})
    rule_ids = {item.rule_id for item in engine.analyze(context)}
    assert "CVE_CVE-2020-1111" in rule_ids
    # A version known to be outside the declared range must produce nothing at
    # all, not even a candidate.
    assert "CVE_CVE-2020-2222" not in rule_ids
    assert "CVE_CANDIDATE_001" not in rule_ids
