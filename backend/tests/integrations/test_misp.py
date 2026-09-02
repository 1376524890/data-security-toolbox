from pathlib import Path

from app.engine.core.context import DetectionContext
from app.integrations.misp.adapter import MISPAdapter
from app.integrations.misp.client import extract_iocs
from app.integrations.misp.store import MISPStore


def test_misp_offline_import(tmp_path: Path) -> None:
    store = MISPStore(tmp_path / "iocs.json")
    path = tmp_path / "source.json"
    path.write_text('{"iocs":[{"value":"203.0.113.66","type":"ip","source":"offline"}]}', encoding="utf-8")
    records = store.import_file(path)
    assert records[0]["value"] == "203.0.113.66"


def test_misp_ip_match() -> None:
    iocs = [{"value": "203.0.113.66", "type": "ip", "source": "MISP"}]
    context = DetectionContext(target_type="flow", flows=[{"src_ip": "203.0.113.66", "dst_ip": "10.0.0.2"}])
    result = MISPAdapter().adapt({"iocs": iocs}, context)
    assert any(item.rule_id == "MISP_IOC_MATCH_001" for item in result.findings)


def test_misp_domain_match() -> None:
    iocs = [{"value": "evil.example", "type": "domain", "source": "MISP"}]
    context = DetectionContext(target_type="asset", assets=[{"ip": "10.0.0.2", "hostname": "evil.example"}])
    result = MISPAdapter().adapt({"iocs": iocs}, context)
    assert any(item.rule_id == "MISP_IOC_MATCH_001" for item in result.findings)


def test_misp_url_match() -> None:
    iocs = [{"value": "https://evil.example/payload", "type": "url", "source": "MISP"}]
    context = DetectionContext(target_type="log", log_lines=["https://evil.example/payload"])
    result = MISPAdapter().adapt({"iocs": iocs}, context)
    assert any(item.rule_id == "MISP_IOC_MATCH_001" for item in result.findings)


def test_misp_hash_match() -> None:
    iocs = [{"value": "44d88612fea8a8f36de82e1278abb02f", "type": "hash", "source": "MISP"}]
    context = DetectionContext(target_type="manual", data={"hashes": ["44d88612fea8a8f36de82e1278abb02f"]})
    result = MISPAdapter().adapt({"iocs": iocs}, context)
    assert any(item.rule_id == "MISP_IOC_MATCH_001" for item in result.findings)


def test_misp_extract_iocs() -> None:
    events = [{"id": "1", "info": "event", "Attribute": [{"type": "ip-dst", "value": "203.0.113.66"}, {"type": "sha256", "value": "abc123"}]}]
    records = extract_iocs(events)
    assert {item["type"] for item in records} == {"ip", "hash"}
