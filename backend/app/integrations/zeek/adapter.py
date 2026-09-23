from __future__ import annotations

import math
from collections import Counter
from datetime import UTC, datetime
from typing import Any

from app.engine.core.context import DetectionContext
from app.integrations.base import AdapterResult, IntegrationAdapter, finding
from app.integrations.zeek.parser import parse_zeek_payload
from app.integrations.zeek.runner import run_zeek_payload


def entropy(text: str) -> float:
    if not text:
        return 0.0
    counter = Counter(text)
    length = len(text)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())


def registered_domain(name: str) -> str:
    """Last two labels of a DNS name, so queries group by operator domain."""
    labels = [label for label in name.rstrip(".").lower().split(".") if label]
    return ".".join(labels[-2:]) if len(labels) > 2 else ".".join(labels)


WEAK_CIPHERS = {
    "TLS_RSA_WITH_AES_128_CBC_SHA",
    "TLS_RSA_WITH_AES_256_CBC_SHA",
    "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    "TLS_RSA_WITH_RC4_128_SHA",
    "TLS_RSA_WITH_RC4_128_MD5",
}

SUSPICIOUS_USER_AGENTS = ("sqlmap", "nikto", "nmap", "python-requests", "curl/", "wget/", "masscan")
FILE_EXTENSIONS = (".exe", ".dll", ".scr", ".bat", ".ps1", ".jar", ".docm", ".xlsm", ".vbs")
#: How much each Zeek ``weird`` name actually means, keyed by the token that is
#: matched against the lower-cased name. A ``weird`` is Zeek's protocol parser
#: saying it could not read something, and grading every one of them ``High``
#: made the platform's own noise: ``bad_http_request`` is a client talking to a
#: proxy or non-HTTP port, and one monitored host produced it 102 times, each
#: raised as High and alerted. Parser-limit names are informational; only the
#: ones that describe a real condition (a broken or self-signed certificate)
#: keep a severity that is worth looking at.
SUSPICIOUS_WEIRD = {
    "bad_http_request": "Low",
    "http_unknown_method": "Low",
    "dns_question_too_long": "Low",
    "ssl_invalid": "Medium",
    "ssl_self_signed": "Medium",
}


class ZeekAdapter(IntegrationAdapter):
    name = "zeek"
    version = "2.1.0"
    supported_types = ("conn", "dns", "http", "ssl", "files", "weird")
    capabilities = ("pcap", "dns", "tls", "http", "files", "weird")

    def supports(self, context: DetectionContext | None = None) -> bool:
        return bool(context and context.target_type == "pcap" and context.path and context.path.exists())

    def health(self) -> dict[str, Any]:
        runtime = self._binary_available("zeek")
        version = self._runtime_version(runtime)
        return {
            "name": self.name,
            "adapter_version": self.version,
            "installed": bool(runtime),
            "enabled": True,
            "healthy": bool(runtime),
            "runtime_version": version,
            "loaded_scripts": ["local"] if runtime else [],
            "last_execution": "",
            "last_error": "" if runtime else "Zeek binary not found",
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
        dns_records: list[dict[str, Any]] = []
        for record in records:
            event_type = str(record.get("event_type", "")).lower()
            if event_type == "dns":
                dns_records.append(record)
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
            elif event_type == "notice" and str(record.get('note', '')).startswith('DST::'):
                findings.append(finding(
                    self.name, 'ZEEK_' + str(record['note']).replace('::', '_'),
                    'Medium', 0.8, {'record': record, 'condition': record.get('msg', '')},
                    '结合原始流量核查异常查询、明文凭据或扫描行为。',
                ))
        findings.extend(self._dns_findings(dns_records))
        return AdapterResult(self.name, records, findings, {"events": len(records), "findings": len(findings)})

    def _dns_findings(self, records: list[dict[str, Any]]) -> list[Any]:
        """One DNS record is a clue; a tunnel is many encoded labels for one domain.

        A full-name entropy/length test flagged ordinary NTP/CDN names such as
        ``3.debian.pool.ntp.org``. The left-most label is the tunnel's payload, so
        only it is scored, and a finding needs a host asking the same registered
        domain many encoded questions.
        """
        findings: list[Any] = []
        groups: dict[tuple[str, str], dict[str, Any]] = {}
        for record in records:
            query = str(record.get("query") or record.get("qname") or record.get("rrname") or "")
            rcode = str(record.get("rcode") or record.get("rcode_name") or "")
            timestamp = str(record.get("ts", ""))
            if not query:
                continue
            src = str(record.get("id.orig_h") or record.get("src_ip") or "")
            evidence = {"record": record, "query": query, "src_ip": src, "attribution": "source" if src else "unknown"}
            if rcode.lower() in {"nxdomain", "nx"}:
                findings.append(finding(self.name, "ZEK_DNS_NXDOMAIN_001", "Low", 0.65, evidence,
                                        "确认 DNS 解析失败是否由恶意域名、配置错误或 DNS 投毒引起。", timestamp))
            labels = [label for label in query.rstrip(".").split(".") if label]
            label = labels[0] if labels else ""
            group = groups.setdefault((src, registered_domain(query)),
                                      {"count": 0, "encoded": 0, "timestamp": timestamp})
            group["count"] += 1
            if label and (entropy(label) >= 3.5 or len(label) >= 40):
                group["encoded"] += 1
                group["timestamp"] = timestamp
        for (src, domain), group in groups.items():
            if group["encoded"] >= 3 and group["count"] >= 20:
                findings.append(finding(
                    self.name, "ZEK_DNS_TUNNEL_001", "High", 0.8,
                    {"src_ip": src, "registered_domain": domain,
                     "query_count": group["count"], "encoded_labels": group["encoded"],
                     "attribution": "source" if src else "unknown"},
                    "排查 DNS 隧道、DGA 或异常编码域名。", group["timestamp"]))
        return findings

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
        filename = str(record.get("filename") or "")
        mime = str(record.get("mime_type") or record.get("mime") or "")
        evidence = {"record": record, "method": method, "uri": uri, "user_agent": ua,
                    "status": status, "filename": filename, "mime_type": mime}
        if any(token in ua.lower() for token in SUSPICIOUS_USER_AGENTS):
            return [finding(self.name, "ZEK_HTTP_UA_001", "Medium", 0.8, evidence, "识别自动化工具或扫描器，结合访问序列确认攻击行为。", str(record.get("ts", "")))]
        # A POST to a script URI is routine; an upload carries a file, so it is
        # only an upload finding when the record names a dynamic script file.
        if method in {"POST", "PUT", "PATCH"} and filename.lower().endswith((".php", ".jsp", ".asp", ".aspx", ".phtml")):
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
        lowered = name.lower()
        severity = next(
            (value for token, value in SUSPICIOUS_WEIRD.items() if token in lowered), None
        )
        if severity is None:
            return []
        return [finding(self.name, "ZEK_WEIRD_001", severity, 0.8, evidence,
                        "Zeek 异常事件：多数为协议解析器自身的限制，应结合上下文判断攻击或误报。",
                        str(record.get("ts", "")))]

    def _conn(self, record: dict[str, Any]) -> list[Any]:
        orig = int(record.get("orig_bytes") or 0)
        resp = int(record.get("resp_bytes") or 0)
        if orig + resp > 100_000_000:
            return [finding(self.name, "ZEK_CONN_LARGE_001", "Medium", 0.6, {"record": record, "orig_bytes": orig, "resp_bytes": resp}, "大流量连接应纳入数据外发或异常传输审计。", str(record.get("ts", "")))]
        return []
