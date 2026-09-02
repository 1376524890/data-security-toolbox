from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from app.engine.core.context import DetectionContext
from app.integrations.base import AdapterResult, IntegrationAdapter, finding, severity_map
from app.integrations.suricata.parser import event_records, parse_eve_payload
from app.integrations.suricata.runner import run_suricata


class SuricataAdapter(IntegrationAdapter):
    name = "suricata"
    version = "2.1.0"
    supported_types = ("alert", "flow", "dns", "http", "fileinfo")
    capabilities = ("pcap", "alert", "flow", "dns", "http", "fileinfo")

    def health(self) -> dict[str, Any]:
        runtime = self._binary_available("suricata")
        return {
            "name": self.name,
            "adapter_version": self.version,
            "installed": bool(runtime),
            "enabled": True,
            "healthy": bool(runtime),
            "runtime_version": runtime,
            "supported_types": list(self.supported_types),
            "capabilities": list(self.capabilities),
            "last_check": datetime.now(UTC).isoformat(),
            "status": "ready" if runtime else "unavailable",
            "message": "" if runtime else "Suricata binary not found",
        }

    def parse(self, payload: Any) -> list[dict[str, Any]]:
        return parse_eve_payload(payload)

    def adapt(self, payload: Any, context: DetectionContext | None = None) -> AdapterResult:
        records: list[dict[str, Any]] = []
        if isinstance(payload, dict) and payload.get("pcap"):
            output_dir = payload.get("output_dir") or (context.path.parent / "suricata" if context and context.path else None)
            if output_dir:
                records = run_suricata(payload["pcap"], output_dir, str(payload.get("binary", "")))
        else:
            records = self.parse(payload)
        records = event_records(records)
        findings: list[Any] = []
        for record in records:
            event_type = str(record.get("event_type", "")).lower()
            if event_type == "alert":
                findings.extend(self._alert(record))
            elif event_type == "dns":
                findings.extend(self._dns(record))
            elif event_type == "http":
                findings.extend(self._http(record))
            elif event_type == "fileinfo":
                findings.extend(self._fileinfo(record))
            elif event_type == "flow":
                findings.extend(self._flow(record))
        return AdapterResult(self.name, records, findings, {"events": len(records), "findings": len(findings)})

    def _alert(self, record: dict[str, Any]) -> list[Any]:
        alert = record.get("alert") or {}
        signature = str(alert.get("signature") or "")
        sid = str(alert.get("signature_id") or alert.get("sid") or "")
        category = str(alert.get("category") or "")
        severity = severity_map(alert.get("severity") or record.get("severity", "Medium"))
        evidence = {
            "record": record,
            "signature": signature,
            "signature_id": sid,
            "category": category,
            "src_ip": record.get("src_ip"),
            "dest_ip": record.get("dest_ip"),
        }
        return [finding(self.name, f"SURICATA_{sid or 'ALERT'}", severity, 0.92, evidence, f"根据 Suricata 规则 {signature} 排查并处置告警。", str(record.get("timestamp", "")))]

    def _dns(self, record: dict[str, Any]) -> list[Any]:
        dns = record.get("dns") or {}
        query = str(dns.get("rrname") or dns.get("query") or "")
        if len(query) >= 40:
            return [finding(self.name, "SURICATA_DNS_TUNNEL_001", "High", 0.82, {"record": record, "query": query}, "排查 DNS 隧道或 DGA 域名。", str(record.get("timestamp", "")))]
        if dns.get("rcode") not in (None, 0, "0", "NOERROR"):
            return [finding(self.name, "SURICATA_DNS_ERROR_001", "Low", 0.6, {"record": record, "query": query}, "确认 DNS 异常响应来源。", str(record.get("timestamp", "")))]
        return []

    def _http(self, record: dict[str, Any]) -> list[Any]:
        http = record.get("http") or {}
        method = str(http.get("http_method") or "").upper()
        uri = str(http.get("http_uri") or http.get("url") or "")
        ua = str(http.get("http_user_agent") or "")
        status = str(http.get("status") or "")
        evidence = {"record": record, "method": method, "uri": uri, "user_agent": ua, "status": status}
        if any(token in ua.lower() for token in ("sqlmap", "nikto", "nmap", "masscan", "python-requests")):
            return [finding(self.name, "SURICATA_HTTP_UA_001", "Medium", 0.8, evidence, "识别扫描或自动化攻击流量。", str(record.get("timestamp", "")))]
        if method in {"POST", "PUT", "PATCH"} and any(uri.lower().endswith(ext) for ext in (".php", ".jsp", ".asp", ".aspx")):
            return [finding(self.name, "SURICATA_HTTP_UPLOAD_001", "High", 0.85, evidence, "审计动态脚本上传请求。", str(record.get("timestamp", "")))]
        if status in {"500", "502", "503", "504"}:
            return [finding(self.name, "SURICATA_HTTP_ERROR_001", "Low", 0.55, evidence, "排查服务端错误与探测行为。", str(record.get("timestamp", "")))]
        return []

    def _fileinfo(self, record: dict[str, Any]) -> list[Any]:
        fileinfo = record.get("fileinfo") or {}
        name = str(fileinfo.get("filename") or fileinfo.get("name") or "")
        mime = str(fileinfo.get("magic") or fileinfo.get("mime") or "")
        evidence = {"record": record, "filename": name, "magic": mime}
        if any(token in mime.lower() for token in ("executable", "msdos", "pe32", "x-msdownload")):
            return [finding(self.name, "SURICATA_FILE_EXEC_001", "High", 0.85, evidence, "对可执行文件进行沙箱和 YARA 检测。", str(record.get("timestamp", "")))]
        if any(name.lower().endswith(ext) for ext in (".exe", ".dll", ".scr", ".bat", ".ps1", ".vbs")):
            return [finding(self.name, "SURICATA_FILE_EXT_001", "High", 0.8, evidence, "限制高风险文件下载执行。", str(record.get("timestamp", "")))]
        return []

    def _flow(self, record: dict[str, Any]) -> list[Any]:
        flow = record.get("flow") or {}
        bytes_tx = int(flow.get("bytes_toserver") or record.get("bytes_toserver") or 0)
        bytes_rx = int(flow.get("bytes_toclient") or record.get("bytes_toclient") or 0)
        if bytes_tx + bytes_rx > 100_000_000:
            return [finding(self.name, "SURICATA_FLOW_LARGE_001", "Medium", 0.6, {"record": record, "bytes_toserver": bytes_tx, "bytes_toclient": bytes_rx}, "大流量会话纳入数据外发审计。", str(record.get("timestamp", "")))]
        return []
