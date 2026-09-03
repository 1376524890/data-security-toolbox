import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult
from app.services.protocol_service import extract_app_fields, protocol_distribution, stream_tshark
from app.engine.data_engine.engine import shannon_entropy


def tcp_streams(path: Path, timeout: int = 300) -> list[dict[str, Any]]:
    fields = ["tcp.stream", "tcp.seq", "tcp.len", "tcp.payload", "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport"]
    field_args = [item for field in fields for item in ("-e", field)]
    streams: dict[str, dict[str, Any]] = defaultdict(lambda: {"stream": "", "packets": 0, "bytes": 0, "payload": bytearray(), "src_ip": "", "dst_ip": "", "src_port": 0, "dst_port": 0, "start": 0.0, "end": 0.0})
    for line in stream_tshark(["-r", str(path), "-T", "fields", *field_args], timeout):
        parts = line.split("\t")
        if len(parts) < 9:
            continue
        stream_id = parts[0] or "unknown"
        seq = int(parts[1] or 0)
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
            try:
                stream["payload"].extend(bytes.fromhex(payload_hex))
            except ValueError:
                pass
    return [{"stream": item["stream"], "packets": item["packets"], "bytes": item["bytes"], "payload_size": len(item["payload"]), "src_ip": item["src_ip"], "dst_ip": item["dst_ip"], "src_port": item["src_port"], "dst_port": item["dst_port"], "start": item["start"], "end": item["end"]} for item in streams.values()]


def tls_analysis(path: Path, timeout: int = 300) -> dict[str, Any]:
    fields = ["tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.ciphersuite", "tls.handshake.ja3", "tls.handshake.ja3_full"]
    field_args = [item for field in fields for item in ("-e", field)]
    rows = []
    for line in stream_tshark(["-r", str(path), "-T", "fields", *field_args], timeout):
        parts = line.split("\t")
        rows.append({"type": parts[0] if len(parts) > 0 else "", "sni": parts[1] if len(parts) > 1 else "", "cipher": parts[2] if len(parts) > 2 else "", "ja3": parts[3] if len(parts) > 3 else "", "ja3_full": parts[4] if len(parts) > 4 else ""})
    return {"handshakes": rows[:1000], "ja3": dict(Counter(row["ja3"] for row in rows if row["ja3"]).most_common(20)), "sni": dict(Counter(row["sni"] for row in rows if row["sni"]).most_common(50))}


def dns_analysis(path: Path, timeout: int = 300) -> dict[str, Any]:
    fields = ["dns.qry.name", "dns.qry.type", "dns.resp.len", "dns.txt"]
    field_args = [item for field in fields for item in ("-e", field)]
    rows = []
    for line in stream_tshark(["-r", str(path), "-T", "fields", *field_args], timeout):
        parts = line.split("\t")
        rows.append({"name": parts[0] if len(parts) > 0 else "", "type": parts[1] if len(parts) > 1 else "", "resp_len": int(parts[2] or 0), "txt": parts[3] if len(parts) > 3 else ""})
    high = [row for row in rows if shannon_entropy(row["name"]) >= 3.5 or len(row["name"]) >= 40]
    long_txt = [row for row in rows if len(row["txt"]) > 200]
    return {"queries": rows[:1000], "high_entropy": high[:100], "long_queries": [row for row in rows if len(row["name"]) >= 40][:100], "txt_large": long_txt[:100]}


def http_analysis(path: Path, timeout: int = 300) -> dict[str, Any]:
    fields = ["http.user_agent", "http.request.method", "http.request.uri", "http.response.code", "http.file_data"]
    field_args = [item for field in fields for item in ("-e", field)]
    rows = []
    for line in stream_tshark(["-r", str(path), "-T", "fields", *field_args], timeout):
        parts = line.split("\t")
        rows.append({"user_agent": parts[0] if len(parts) > 0 else "", "method": parts[1] if len(parts) > 1 else "", "uri": parts[2] if len(parts) > 2 else "", "status": parts[3] if len(parts) > 3 else "", "file_data": parts[4] if len(parts) > 4 else ""})
    return {"requests": rows[:1000]}


class ProtocolEngine(DetectionEngine):
    name = "protocol_engine"
    version = "2.0.0"

    def analyze(self, context: DetectionContext) -> list[DetectionResult]:
        findings: list[DetectionResult] = []
        path = context.path
        if not path or not path.exists():
            return findings
        streams = tcp_streams(path)
        dns = dns_analysis(path)
        tls = tls_analysis(path)
        http = http_analysis(path)
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
