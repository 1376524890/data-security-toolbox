import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult
from app.services.protocol_service import stream_tshark
from app.engine.data_engine.engine import shannon_entropy

# Bounded detail rows kept for the UI / evidence; detection still runs over the
# full stream via streaming aggregation so a large PCAP never grows memory.
MAX_PROTOCOL_DETAIL_ROWS = 10000
MAX_EVIDENCE_ROWS = 100
MAX_PAYLOAD_SIZE = 128 * 1024  # per stream, bytes


def tcp_streams(path: Path, timeout: int = 300) -> list[dict[str, Any]]:
    fields = ["tcp.stream", "tcp.seq", "tcp.len", "tcp.payload", "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport"]
    field_args = [item for field in fields for item in ("-e", field)]
    streams: dict[str, dict[str, Any]] = defaultdict(lambda: {"stream": "", "packets": 0, "bytes": 0, "payload_size": 0, "src_ip": "", "dst_ip": "", "src_port": 0, "dst_port": 0, "start": 0.0, "end": 0.0})
    for line in stream_tshark(["-r", str(path), "-T", "fields", *field_args], timeout):
        parts = line.split("\t")
        if len(parts) < 9:
            continue
        stream_id = parts[0] or "unknown"
        length = int(parts[2] or 0)
        payload_hex = parts[3] or ""
        timestamp = float(parts[4] or 0)
        stream = streams[stream_id]
        stream["stream"] = stream_id
        stream["packets"] += 1
        stream["bytes"] += length
        stream["src_ip"] = parts[5]
        stream["dst_ip"] = parts[6]
        stream["src_port"] = int(parts[7] or 0)
        stream["dst_port"] = int(parts[8] or 0)
        stream["start"] = min(stream["start"], timestamp) if stream["start"] else timestamp
        stream["end"] = max(stream["end"], timestamp)
        if payload_hex:
            # Count payload bytes without buffering the raw bytes into memory.
            stream["payload_size"] = min(stream["payload_size"] + len(payload_hex) // 2, MAX_PAYLOAD_SIZE)
    return [
        {"stream": item["stream"], "packets": item["packets"], "bytes": item["bytes"], "payload_size": item["payload_size"], "src_ip": item["src_ip"], "dst_ip": item["dst_ip"], "src_port": item["src_port"], "dst_port": item["dst_port"], "start": item["start"], "end": item["end"]}
        for item in streams.values()
    ]


def app_analysis(path: Path, max_rows: int = MAX_PROTOCOL_DETAIL_ROWS, timeout: int = 300) -> dict[str, Any]:
    """Streaming DNS/HTTP/TLS analysis in a single tshark pass.

    Only bounded detail rows are retained for the UI; aggregate stats are built
    incrementally over the full stream so detection covers the entire PCAP.
    """
    fields = [
        "dns.qry.name",
        "dns.qry.type",
        "dns.resp.len",
        "dns.txt",
        "http.user_agent",
        "http.request.method",
        "http.request.uri",
        "http.response.code",
        "http.file_data",
        "tls.handshake.type",
        "tls.handshake.extensions_server_name",
        "tls.handshake.ciphersuite",
        "tls.handshake.ja3",
    ]
    field_args = [item for field in fields for item in ("-e", field)]
    dns_rows: list[dict[str, Any]] = []
    http_rows: list[dict[str, Any]] = []
    tls_rows: list[dict[str, Any]] = []
    high_entropy: list[dict[str, Any]] = []
    txt_large: list[dict[str, Any]] = []
    dns_names: Counter[str] = Counter()
    dns_types: Counter[str] = Counter()
    http_ua: Counter[str] = Counter()
    http_methods: Counter[str] = Counter()
    http_status: Counter[str] = Counter()
    tls_sni: Counter[str] = Counter()
    tls_ja3: Counter[str] = Counter()

    for line in stream_tshark(["-r", str(path), "-T", "fields", *field_args], timeout):
        parts = line.split("\t")
        dns_name = parts[0] if len(parts) > 0 else ""
        dns_type = parts[1] if len(parts) > 1 else ""
        dns_resp = parts[2] if len(parts) > 2 else ""
        dns_txt = parts[3] if len(parts) > 3 else ""
        if dns_name or dns_resp:
            row = {"name": dns_name, "type": dns_type, "resp_len": int(dns_resp or 0), "txt": dns_txt}
            if len(dns_rows) < max_rows:
                dns_rows.append(row)
            if dns_name:
                dns_names[dns_name] += 1
            if dns_type:
                dns_types[dns_type] += 1
            if dns_name and (shannon_entropy(dns_name) >= 3.5 or len(dns_name) >= 40) and len(high_entropy) < MAX_EVIDENCE_ROWS:
                high_entropy.append(row)
            if len(dns_txt) > 200 and len(txt_large) < MAX_EVIDENCE_ROWS:
                txt_large.append(row)
        ua = parts[4] if len(parts) > 4 else ""
        method = parts[5] if len(parts) > 5 else ""
        uri = parts[6] if len(parts) > 6 else ""
        status = parts[7] if len(parts) > 7 else ""
        file_data = parts[8] if len(parts) > 8 else ""
        if ua or method or uri:
            row = {"user_agent": ua, "method": method, "uri": uri, "status": status, "file_data": file_data}
            if len(http_rows) < max_rows:
                http_rows.append(row)
            if ua:
                http_ua[ua] += 1
            if method:
                http_methods[method] += 1
            if status:
                http_status[status] += 1
        tls_type = parts[9] if len(parts) > 9 else ""
        sni = parts[10] if len(parts) > 10 else ""
        cipher = parts[11] if len(parts) > 11 else ""
        ja3 = parts[12] if len(parts) > 12 else ""
        if tls_type or sni or ja3:
            row = {"type": tls_type, "sni": sni, "cipher": cipher, "ja3": ja3}
            if len(tls_rows) < max_rows:
                tls_rows.append(row)
            if sni:
                tls_sni[sni] += 1
            if ja3:
                tls_ja3[ja3] += 1

    return {
        "dns": {"queries": dns_rows, "high_entropy": high_entropy, "txt_large": txt_large, "stats": {"names": dns_names.most_common(50), "types": dns_types.most_common(20)}},
        "http": {"requests": http_rows, "stats": {"user_agents": http_ua.most_common(50), "methods": http_methods.most_common(20), "status": http_status.most_common(20)}},
        "tls": {"handshakes": tls_rows, "ja3": dict(tls_ja3.most_common(20)), "sni": dict(tls_sni.most_common(50))},
    }


def dns_analysis(path: Path, timeout: int = 300) -> dict[str, Any]:
    return app_analysis(path, timeout=timeout)["dns"]


def tls_analysis(path: Path, timeout: int = 300) -> dict[str, Any]:
    return app_analysis(path, timeout=timeout)["tls"]


def http_analysis(path: Path, timeout: int = 300) -> dict[str, Any]:
    return app_analysis(path, timeout=timeout)["http"]


class ProtocolEngine(DetectionEngine):
    name = "protocol_engine"
    version = "2.0.0"

    def analyze(self, context: DetectionContext) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        path = context.path
        if not path or not path.exists():
            return findings
        streams = tcp_streams(path)
        app = app_analysis(path)
        dns = app["dns"]
        tls = app["tls"]
        http = app["http"]
        context.data["tcp_streams"] = streams
        context.data["dns"] = dns
        context.data["tls"] = tls
        context.data["http"] = http
        if dns["high_entropy"]:
            findings.append(DetectionResult(
                engine=self.name,
                rule_id="PROTO_DNS_TUNNEL_001",
                severity="High",
                confidence=0.8,
                evidence={"queries": dns["high_entropy"][:20], "count": len(dns["high_entropy"])},
                recommendation="排查是否存在 DNS 隧道、DGA 域名或异常编码域名。",
            ).normalize())
        if dns["txt_large"]:
            findings.append(DetectionResult(
                engine=self.name,
                rule_id="PROTO_DNS_TXT_001",
                severity="Medium",
                confidence=0.75,
                evidence={"txt": dns["txt_large"][:20]},
                recommendation="检查大 TXT 记录是否用于数据外传或隐蔽通信。",
            ).normalize())
        suspicious_ua = [row for row in http["requests"] if re.search(r"(sqlmap|nikto|nmap|python-requests|curl/|wget/)", row["user_agent"], re.I)]
        if suspicious_ua:
            findings.append(DetectionResult(
                engine=self.name,
                rule_id="PROTO_HTTP_UA_001",
                severity="Medium",
                confidence=0.8,
                evidence={"requests": suspicious_ua[:20]},
                recommendation="识别异常 User-Agent 来源，结合请求序列判断是否为扫描或自动化攻击。",
            ).normalize())
        uploads = [row for row in http["requests"] if row["method"].upper() in {"POST", "PUT", "PATCH"} and (".php" in row["uri"] or ".jsp" in row["uri"] or ".asp" in row["uri"])]
        if uploads:
            findings.append(DetectionResult(
                engine=self.name,
                rule_id="PROTO_HTTP_UPLOAD_001",
                severity="High",
                confidence=0.85,
                evidence={"requests": uploads[:20]},
                recommendation="对动态脚本上传请求进行审计，结合文件内容判断是否存在 WebShell 上传。",
            ).normalize())
        return findings
