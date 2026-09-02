from pathlib import Path

from app.integrations.suricata.adapter import SuricataAdapter
from app.integrations.suricata.parser import parse_eve_lines
from app.integrations.suricata.rules import import_et_open_rules


def test_suricata_alert() -> None:
    records = [{"event_type": "alert", "alert": {"signature": "ET EXPLOIT", "signature_id": 2000001, "severity": 1}, "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "timestamp": "2026-01-01T00:00:00Z"}]
    result = SuricataAdapter().adapt(records)
    assert any(item.rule_id == "SURICATA_2000001" for item in result.findings)


def test_suricata_dns_long() -> None:
    records = [{"event_type": "dns", "dns": {"rrname": "x" * 50}, "timestamp": "2026-01-01T00:00:00Z"}]
    result = SuricataAdapter().adapt(records)
    assert any(item.rule_id == "SURICATA_DNS_TUNNEL_001" for item in result.findings)


def test_suricata_http_upload() -> None:
    records = [{"event_type": "http", "http": {"http_method": "POST", "http_uri": "/shell.jsp", "http_user_agent": "Mozilla"}, "timestamp": "2026-01-01T00:00:00Z"}]
    result = SuricataAdapter().adapt(records)
    assert any(item.rule_id == "SURICATA_HTTP_UPLOAD_001" for item in result.findings)


def test_suricata_fileinfo_exec() -> None:
    records = [{"event_type": "fileinfo", "fileinfo": {"filename": "bad.exe", "magic": "PE32 executable"}}]
    result = SuricataAdapter().adapt(records)
    assert any(item.rule_id == "SURICATA_FILE_EXEC_001" for item in result.findings)


def test_suricata_flow_large() -> None:
    records = [{"event_type": "flow", "flow": {"bytes_toserver": 200_000_000, "bytes_toclient": 10}}]
    result = SuricataAdapter().adapt(records)
    assert any(item.rule_id == "SURICATA_FLOW_LARGE_001" for item in result.findings)


def test_parse_eve_lines() -> None:
    records = parse_eve_lines('{"event_type":"alert","alert":{"signature_id":1}}\n')
    assert records[0]["event_type"] == "alert"


def test_import_et_open_rule_file(tmp_path: Path) -> None:
    path = tmp_path / "emerging.rules"
    path.write_text('alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Test"; sid:1; rev:1; classtype:web-application-attack;)\n', encoding="utf-8")
    rules = import_et_open_rules(path)
    assert rules
    assert rules[0]["sid"] == "1"
