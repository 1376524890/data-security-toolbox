from __future__ import annotations

import math
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from app.engine.core.context import DetectionContext
from app.integrations.base import AdapterResult, IntegrationAdapter, finding, severity_map
from app.integrations.zeek.parser import parse_zeek_payload
from app.integrations.zeek.runner import run_zeek_payload


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())


WEAK_CIPHERS = {
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_MD5",
}

SUSPICIOUS_USER_AGENTS = ("sqlmap", "nikto", "nmap", "python-requests", "curl/", "wget/", "masscan")
FILE_EXTENSIONS = (".exe", ".dll", ".scr", ".bat", ".ps1", ".jar", ".docm", ".xlsm", ".vbs")
SUSPICIOUS_WEIRD = ("dns_question_too_long", "bad_http_request", "ssl_invalid", "ssl_self_signed", "http_unknown_method")


class ZeekAdapter(IntegrationAdapter):
    name = "zeek"
    version = "2.1.0"
    supported_types = ("conn", "dns", "http", "ssl", "files", "weird")
    capabilities = ("pcap", "dns", "tls", "http", "files", "weird")

    def supports(self, context: DetectionContext | None = None) -> bool:
        return bool(context and context.target_type == "pcap" and context.path and context.path.exists())

    def health(self) -> dict[str, Any]:
        runtime = self._binary_available("zeek")
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
            "message": "" if runtime else "Zeek binary not found",
        }

    def parse(self, payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, dict) and payload.get("pcap"):
            return []
        return parse_zeek_payload(payload)

    def adapt(self, payload: Any, context: DetectionContext | None = None) -> AdapterResult:
        if isinstance(payload, dict) and payload.get("pcap"):
            output_dir = payload.get("output_dir") or (context.path.parent / "zeek" if context and context.path else None)
            records = run_zeek_payload(payload, output_dir) if output_dir else []
        else:
            records = self.parse(payload)
        findings = []
        for record in records:
            event_type = str(record.get("event_type", "")).lower()
            if event_type == "dns":
                findings.extend(self._dns(record))
            elif event_type in {"ssl", "tls"}:
                findings.extend(self._tls(record))
            elif event_type == "http":
                findings.extend(self._http(record))
            elif event_type == "files":
                findings.extend(self._files(record))
            elif event_type == "weird":
                findings.extend(self._weird(record))
            elif event_type == "conn":
                findings.extend(self._conn(record))
        return AdapterResult(self.name, records, findings, {"events": len(records), "findings": len(findings)})

    def _dns(self, record: dict[str, Any]) -> list[Any]:
        query = str(record.get("query") or record.get("qname") or record.get("rrname") or "")
        rcode = str(record.get("rcode") or record.get("rcode_name") or "")
        if not query:
            return []
        evidence = {"record": record, "query": query}
        if entropy(query) >= 3.5 or len(query) >= 40:
            return [finding(self.name, "ZEK_DNS_TUNNEL_001", "High", 0.85, evidence, "排查 DNS 隧道、DGA 或异常编码域名。", str(record.get("ts", "")))]
        if rcode.lower() in {"nxdomain", "nx"}:
            return [finding(self.name, "ZEK_DNS_NXDOMAIN_001", "Low", 0.65, evidence, "确认 DNS 解析失败是否由恶意域名、配置错误或 DNS 投毒引起。", str(record.get("ts", "")))]
        return []

    def _tls(self, record: dict[str, Any]) -> list[Any]:
        validation = str(record.get("validation_status") or record.get("validation") or "")
        cipher = str(record.get("cipher") or record.get("cipher_alg") or "")
        sni = str(record.get("server_name") or record.get("sni") or "")
        evidence = {"record": record, "server_name": sni, "validation_status": validation, "cipher": cipher}
        if any(token in validation.lower() for token in ("self signed", "untrusted", "not yet valid", "expired", "certificate", "invalid")):
            return [finding(self.name, "ZEK_TLS_INVALID_001", "High", 0.9, evidence, "检查 TLS 证书链、有效期和服务器身份，避免中间人攻击。", str(record.get("ts", "")))]
        if cipher.upper() in WEAK_CIPHERS:
            return [finding(self.name, "ZEK_TLS_WEAK_001", "Medium", 0.75, evidence, "禁用弱密码套件，启用 TLS 1.2+ 和 AEAD 算法。", str(record.get("ts", "")))]
        return []

    def _http(self, record: dict[str, Any]) -> list[Any]:
        method = str(record.get("method") or "").upper()
        uri = str(record.get("uri") or record.get("host") or "")
        ua = str(record.get("user_agent") or "")
        status = str(record.get("status_code") or record.get("status") or "")
        evidence = {"record": record, "method": method, "uri": uri, "user_agent": ua, "status": status}
        if any(token in ua.lower() for token in SUSPICIOUS_USER_AGENTS):
            return [finding(self.name, "ZEK_HTTP_UA_001", "Medium", 0.8, evidence, "识别自动化工具或扫描器，结合访问序列确认攻击行为。", str(record.get("ts", "")))]
        if method in {"POST", "PUT", "PATCH"} and any(uri.lower().endswith(ext) for ext in (".php", ".jsp", ".asp", ".aspx")):
            return [finding(self.name, "ZEK_HTTP_UPLOAD_001", "High", 0.85, evidence, "审计动态脚本上传，判断是否存在 WebShell 或恶意文件上传。", str(record.get("ts", "")))]
        if status in {"500", "502", "503", "504"}:
            return [finding(self.name, "ZEK_HTTP_ERROR_001", "Low", 0.55, evidence, "排查服务端错误与异常请求，确认是否存在探测或可用性影响。", str(record.get("ts", "")))]
        return []

    def _files(self, record: dict[str, Any]) -> list[Any]:
        filename = str(record.get("filename") or record.get("name") or "")
        mime = str(record.get("mime_type") or record.get("mime") or "")
        source = str(record.get("source") or record.get("total_bytes") or "")
        evidence = {"record": record, "filename": filename, "mime_type": mime}
        suspicious = filename.lower().endswith(FILE_EXTENSIONS) or any(token in mime.lower() for token in ("executable", "x-msdownload", "vnd.microsoft.portable-executable"))
        if suspicious:
            return [finding(self.name, "ZEK_FILE_SUSPICIOUS_001", "High", 0.82, evidence, "对可执行、脚本或宏文件进行 YARA/沙箱检测并限制下载执行。", str(record.get("ts", "")))]
        if str(source).isdigit() and int(source) > 100_000_000:
            return [finding(self.name, "ZEK_FILE_LARGE_001", "Medium", 0.6, evidence, "大文件传输应纳入数据外发审计。", str(record.get("ts", "")))]
        return []

    def _weird(self, record: dict[str, Any]) -> list[Any]:
        name = str(record.get("name") or "")
        evidence = {"record": record, "weird_name": name}
        if any(token in name.lower() for token in SUSPICIOUS_WEIRD):
            return [finding(self.name, "ZEK_WEIRD_001", severity_map("High"), 0.8, evidence, "Zeek 异常事件说明协议解析异常，应结合上下文判断攻击或误报。", str(record.get("ts", "")))]
        return []

    def _conn(self, record: dict[str, Any]) -> list[Any]:
        orig = int(record.get("orig_bytes") or 0)
        resp = int(record.get("resp_bytes") or 0)
        if orig + resp > 100_000_000:
            return [finding(self.name, "ZEK_CONN_LARGE_001", "Medium", 0.6, {"record": record, "orig_bytes": orig, "resp_bytes": resp}, "大流量连接应纳入数据外发或异常传输审计。", str(record.get("ts", "")))]
        return []
