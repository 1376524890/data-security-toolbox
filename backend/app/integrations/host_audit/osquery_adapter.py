from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.engine.core.context import DetectionContext
from app.integrations.base import AdapterResult, IntegrationAdapter, finding
from app.integrations.host_audit.parsers import parse_payload
from app.core.config import settings

SUSPICIOUS_PROCESSES = ("mimikatz", "procdump", "wce", "lsass.exe", "rundll32.exe", "powershell.exe", "cmd.exe", "bash", "nc", "ncat", "socat")
SUSPICIOUS_CONFIG = ("permitrootlogin yes", "passwordauthentication yes", "nopasswd", "disable=yes", "selinux=disabled")


class OsqueryAdapter(IntegrationAdapter):
    name = "osquery"
    version = "2.1.0"
    supported_types = ("asset", "process", "user", "config", "log")
    capabilities = ("asset", "process", "user", "config", "log")

    def health(self) -> dict[str, Any]:
        runtime = self._binary_available("osqueryi") or ("socket" if settings.osquery_socket else "")
        healthy = bool(runtime)
        return {
            "name": self.name,
            "adapter_version": self.version,
            "installed": bool(runtime),
            "enabled": bool(settings.osquery_socket or runtime),
            "healthy": healthy,
            "runtime_version": runtime,
            "supported_types": list(self.supported_types),
            "capabilities": list(self.capabilities),
            "last_check": datetime.now(UTC).isoformat(),
            "status": "ready" if healthy else "unavailable",
            "message": "" if healthy else "osquery binary or socket not configured",
        }

    def parse(self, payload: Any) -> list[dict[str, Any]]:
        return parse_payload(payload, "osquery")

    def adapt(self, payload: Any, context: DetectionContext | None = None) -> AdapterResult:
        records = self.parse(payload)
        findings: list[Any] = []
        for record in records:
            table = str(record.get("table") or record.get("query_name") or "").lower()
            findings.extend(self._process(record, table))
            findings.extend(self._user(record, table))
            findings.extend(self._config(record, table))
            findings.extend(self._asset(record, table))
        return AdapterResult(self.name, records, findings, {"records": len(records), "findings": len(findings)})

    def _process(self, record: dict[str, Any], table: str) -> list[Any]:
        if table and "process" not in table and "processes" not in table:
            return []
        name = str(record.get("name") or record.get("path") or "")
        cmdline = str(record.get("cmdline") or record.get("command_line") or "")
        evidence = {"record": record, "name": name, "cmdline": cmdline}
        if any(token in name.lower() or token in cmdline.lower() for token in SUSPICIOUS_PROCESSES):
            return [finding(self.name, "HOST_PROCESS_SUSPICIOUS_001", "High", 0.85, evidence, "排查可疑进程、凭据抓取和持久化行为。")]
        if "encodedcommand" in cmdline.lower() or " -enc " in cmdline.lower() or "-base64" in cmdline.lower():
            return [finding(self.name, "HOST_PROCESS_ENCODED_001", "High", 0.82, evidence, "检查 PowerShell/Shell 编码命令是否用于恶意载荷。")]
        return []

    def _user(self, record: dict[str, Any], table: str) -> list[Any]:
        if table and "user" not in table and "sudo" not in table and "authorized" not in table:
            return []
        username = str(record.get("username") or record.get("name") or "")
        sudoers = str(record.get("sudoers") or record.get("shell") or record.get("privileges") or "")
        if username.lower() in {"root", "administrator"} or "sudo" in sudoers.lower():
            return [finding(self.name, "HOST_USER_PRIVILEGE_001", "Medium", 0.72, {"record": record, "username": username, "sudoers": sudoers}, "审计高权限账号和 sudo 配置。")]
        return []

    def _config(self, record: dict[str, Any], table: str) -> list[Any]:
        if table and "config" not in table and "ssh" not in table and "firewall" not in table:
            return []
        text = str(record)
        if any(token in text.lower() for token in SUSPICIOUS_CONFIG):
            return [finding(self.name, "HOST_CONFIG_MISCONFIG_001", "High", 0.8, {"record": record}, "按 CIS 基线修正主机安全配置。")]
        return []

    def _asset(self, record: dict[str, Any], table: str) -> list[Any]:
        if table and table not in {"system_info", "os_version", "uptime", "routes", "listening_ports"}:
            return []
        hostname = str(record.get("hostname") or record.get("computer_name") or record.get("hostname_name") or "")
        os = str(record.get("platform") or record.get("name") or "")
        if not hostname and not os:
            return []
        return [finding(self.name, "HOST_ASSET_INVENTORY_001", "Low", 0.6, {"record": record, "hostname": hostname, "os": os}, "纳入主机资产台账。")]
