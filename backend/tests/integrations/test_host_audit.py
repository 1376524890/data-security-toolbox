from app.integrations.host_audit.osquery_adapter import OsqueryAdapter
from app.integrations.host_audit.wazuh_adapter import WazuhAdapter


def test_osquery_suspicious_process() -> None:
    records = [{"table": "processes", "name": "mimikatz", "cmdline": "mimikatz.exe"}]
    result = OsqueryAdapter().adapt(records)
    assert any(item.rule_id == "HOST_PROCESS_SUSPICIOUS_001" for item in result.findings)


def test_osquery_config() -> None:
    records = [{"table": "ssh_configs", "options": "PermitRootLogin yes"}]
    result = OsqueryAdapter().adapt(records)
    assert any(item.rule_id == "HOST_CONFIG_MISCONFIG_001" for item in result.findings)


def test_osquery_asset() -> None:
    records = [{"table": "system_info", "hostname": "host-01", "platform": "linux"}]
    result = OsqueryAdapter().adapt(records)
    assert any(item.rule_id == "HOST_ASSET_INVENTORY_001" for item in result.findings)


def test_wazuh_high_alert() -> None:
    records = [{"rule": {"id": 100001, "level": 13, "description": "Rootkit detected"}, "timestamp": "2026-01-01T00:00:00Z"}]
    result = WazuhAdapter().adapt(records)
    assert any(item.rule_id == "WAZUH_100001" for item in result.findings)
