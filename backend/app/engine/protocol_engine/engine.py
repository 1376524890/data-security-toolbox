import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

from app.engine.core.base import DetectionEngine
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult
from app.services.protocol_service import NO_TCP_DESEGMENT, stream_tshark
from app.engine.data_engine.engine import shannon_entropy
from app.rules.library import rule_params

# Detection parameters come from the platform rule library (app/rules/protocol),
# so an operator can retune a rule without rebuilding the image. These literals
# are the values the engine has always used and apply when the rule file is
# missing, disabled or malformed.
DNS_TUNNEL_DEFAULTS = {"min_name_entropy": 3.5, "min_name_length": 40,
                       "min_queries": 20, "min_encoded_labels": 3}
DNS_TXT_DEFAULTS = {"min_txt_length": 200}
HTTP_UA_DEFAULTS = {"user_agent_pattern": r"(sqlmap|nikto|nmap|python-requests|curl/|wget/)"}
HTTP_UPLOAD_DEFAULTS = {"methods": ["POST", "PUT", "PATCH"], "extensions": [".php", ".jsp", ".asp"]}


def _first_num(value: object, cast: type = int, default: int = 0):
    """Parse a numeric tshark field that may be a comma-separated list (e.g.
    ``dns.resp.len`` returns '16,16,16'). Take the first numeric token."""
    text = str(value or "").strip()
    if not text:
        return default
    token = text.split(",")[0].strip()
    try:
        return cast(token)
    except (ValueError, TypeError):
        return default


def _registered_domain(name: str) -> str:
    """Last two labels of a name, so queries can be grouped by operator domain."""
    labels = [label for label in name.rstrip(".").lower().split(".") if label]
    if len(labels) <= 2:
        return ".".join(labels)
    return ".".join(labels[-2:])


def _observe_dns(groups: dict[tuple[str, str], dict[str, Any]], name: str, src_ip: str,
                 timestamp: float, min_entropy: float, min_length: int) -> None:
    """Accumulate one DNS query into its (source, registered-domain) group.

    A single long or high-entropy name is a clue, not a tunnel. The group keeps
    the per-label evidence a tunnel actually leaves: many encoded labels for one
    domain from one host inside a time window.
    """
    labels = [label for label in name.rstrip(".").split(".") if label]
    if not labels:
        return
    key = (src_ip, _registered_domain(name))
    group = groups.setdefault(key, {
        "queried_at": [], "subdomains": set(), "encoded_labels": 0,
        "max_label_entropy": 0.0, "max_label_length": 0, "samples": [],
    })
    label = labels[0]
    entropy = shannon_entropy(label)
    encoded = entropy >= min_entropy or len(label) >= min_length
    group["queried_at"].append(timestamp)
    group["subdomains"].add(label)
    if encoded:
        group["encoded_labels"] += 1
    if entropy > group["max_label_entropy"] or len(label) > group["max_label_length"]:
        group["max_label_entropy"] = round(max(entropy, group["max_label_entropy"]), 3)
        group["max_label_length"] = max(len(label), group["max_label_length"])
    if encoded and len(group["samples"]) < 10:
        group["samples"].append({"name": name, "src_ip": src_ip, "timestamp": timestamp})




# Bounded detail rows kept for the UI / evidence; detection still runs over the
# full stream via streaming aggregation so a large PCAP never grows memory.
MAX_PROTOCOL_DETAIL_ROWS = 10000
MAX_EVIDENCE_ROWS = 100
MAX_PAYLOAD_SIZE = 128 * 1024  # per stream, bytes


def tcp_streams(path: Path, timeout: int = 300) -> list[dict[str, Any]]:
    fields = ["tcp.stream", "tcp.seq", "tcp.len", "tcp.payload", "frame.time_epoch", "ip.src", "ip.dst", "tcp.srcport", "tcp.dstport"]
    field_args = [item for field in fields for item in ("-e", field)]
    streams: dict[str, dict[str, Any]] = defaultdict(lambda: {"stream": "", "packets": 0, "bytes": 0, "payload_size": 0, "src_ip": "", "dst_ip": "", "src_port": 0, "dst_port": 0, "start": 0.0, "end": 0.0})
    args = [*NO_TCP_DESEGMENT, "-r", str(path), "-T", "fields", *field_args]
    for line in stream_tshark(args, timeout):
        parts = line.split("\t")
        if len(parts) < 9:
            continue
        stream_id = parts[0] or "unknown"
        length = _first_num(parts[2], int, 0)
        payload_hex = parts[3] or ""
        timestamp = _first_num(parts[4], float, 0.0)
        stream = streams[stream_id]
        stream["stream"] = stream_id
        stream["packets"] += 1
        stream["bytes"] += length
        stream["src_ip"] = parts[5]
        stream["dst_ip"] = parts[6]
        stream["src_port"] = _first_num(parts[7], int, 0)
        stream["dst_port"] = _first_num(parts[8], int, 0)
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
        # Appended, never inserted: the loop reads these by index.
        "ip.src",
        "ip.dst",
        "frame.time_epoch",
        "http.content_type",
    ]
    field_args = [item for field in fields for item in ("-e", field)]
    dns_rows: list[dict[str, Any]] = []
    http_rows: list[dict[str, Any]] = []
    tls_rows: list[dict[str, Any]] = []
    high_entropy: list[dict[str, Any]] = []
    txt_large: list[dict[str, Any]] = []
    dns_tunnel_rule = rule_params("protocol_engine", "PROTO_DNS_TUNNEL_001", DNS_TUNNEL_DEFAULTS)
    dns_txt_rule = rule_params("protocol_engine", "PROTO_DNS_TXT_001", DNS_TXT_DEFAULTS)
    min_name_entropy = float(dns_tunnel_rule.get("min_name_entropy", 3.5))
    min_name_length = int(dns_tunnel_rule.get("min_name_length", 40))
    min_txt_length = int(dns_txt_rule.get("min_txt_length", 200))
    dns_names: Counter[str] = Counter()
    dns_types: Counter[str] = Counter()
    http_ua: Counter[str] = Counter()
    http_methods: Counter[str] = Counter()
    http_status: Counter[str] = Counter()
    tls_sni: Counter[str] = Counter()
    tls_ja3: Counter[str] = Counter()
    dns_groups: dict[tuple[str, str], dict[str, Any]] = {}

    for line in stream_tshark(["-r", str(path), "-T", "fields", *field_args], timeout):
        parts = line.split("\t")
        dns_name = parts[0] if len(parts) > 0 else ""
        dns_type = parts[1] if len(parts) > 1 else ""
        dns_resp = parts[2] if len(parts) > 2 else ""
        dns_txt = parts[3] if len(parts) > 3 else ""
        if dns_name or dns_resp:
            src_ip = parts[13] if len(parts) > 13 else ""
            timestamp = _first_num(parts[15], float, 0.0) if len(parts) > 15 else 0.0
            row = {"name": dns_name, "type": dns_type, "resp_len": _first_num(dns_resp, int, 0),
                   "txt": dns_txt, "src_ip": src_ip, "timestamp": timestamp}
            if len(dns_rows) < max_rows:
                dns_rows.append(row)
            if dns_name:
                dns_names[dns_name] += 1
                _observe_dns(dns_groups, dns_name, src_ip, timestamp, min_name_entropy, min_name_length)
            if dns_type:
                dns_types[dns_type] += 1
            encoded_name = bool(dns_name) and (
                shannon_entropy(dns_name) >= min_name_entropy or len(dns_name) >= min_name_length
            )
            if encoded_name and len(high_entropy) < MAX_EVIDENCE_ROWS:
                high_entropy.append(row)
            if len(dns_txt) > min_txt_length and len(txt_large) < MAX_EVIDENCE_ROWS:
                txt_large.append(row)
        ua = parts[4] if len(parts) > 4 else ""
        method = parts[5] if len(parts) > 5 else ""
        uri = parts[6] if len(parts) > 6 else ""
        status = parts[7] if len(parts) > 7 else ""
        file_data = parts[8] if len(parts) > 8 else ""
        content_type = parts[16] if len(parts) > 16 else ""
        if ua or method or uri:
            row = {"user_agent": ua, "method": method, "uri": uri, "status": status,
                   "file_data": file_data, "content_type": content_type}
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

    tunnel_candidates: list[dict[str, Any]] = []
    for (src_ip, domain), group in dns_groups.items():
        times = [item for item in group["queried_at"] if item]
        tunnel_candidates.append({
            "src_ip": src_ip,
            # Missing source attribution is reported as unknown, never guessed.
            "attribution": "source" if src_ip else "unknown",
            "registered_domain": domain,
            "query_count": len(group["queried_at"]),
            "distinct_subdomains": len(group["subdomains"]),
            "encoded_labels": group["encoded_labels"],
            "max_label_entropy": group["max_label_entropy"],
            "max_label_length": group["max_label_length"],
            "window_start": min(times) if times else 0.0,
            "window_end": max(times) if times else 0.0,
            "samples": group["samples"],
        })
    tunnel_candidates.sort(
        key=lambda item: (item["encoded_labels"], item["query_count"]), reverse=True)
    return {
        "dns": {"queries": dns_rows, "high_entropy": high_entropy, "txt_large": txt_large,
                "tunnel_candidates": tunnel_candidates,
                "stats": {"names": dns_names.most_common(50), "types": dns_types.most_common(20)}},
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
        # A lone long/high-entropy name stays a clue. A tunnel is a host asking
        # the same registered domain many encoded-label questions in a window.
        dns_rule = rule_params("protocol_engine", "PROTO_DNS_TUNNEL_001", DNS_TUNNEL_DEFAULTS)
        min_queries = int(dns_rule.get("min_queries") or DNS_TUNNEL_DEFAULTS["min_queries"])
        min_encoded = int(
            dns_rule.get("min_encoded_labels") or DNS_TUNNEL_DEFAULTS["min_encoded_labels"])
        tunnel_groups = [
            group for group in dns.get("tunnel_candidates", [])
            if group["encoded_labels"] >= min_encoded and group["query_count"] >= min_queries
        ]
        if tunnel_groups:
            findings.append(DetectionResult(
                engine=self.name,
                rule_id="PROTO_DNS_TUNNEL_001",
                severity="High",
                confidence=0.8,
                evidence={
                    "groups": tunnel_groups[:20],
                    "candidates": dns.get("tunnel_candidates", [])[:20],
                    "isolated_high_entropy": dns["high_entropy"][:20],
                    "criteria": {"min_queries": min_queries, "min_encoded_labels": min_encoded},
                },
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
        ua_rule = rule_params("protocol_engine", "PROTO_HTTP_UA_001", HTTP_UA_DEFAULTS)
        upload_rule = rule_params("protocol_engine", "PROTO_HTTP_UPLOAD_001", HTTP_UPLOAD_DEFAULTS)
        try:
            ua_pattern = re.compile(str(ua_rule.get("user_agent_pattern") or HTTP_UA_DEFAULTS["user_agent_pattern"]), re.I)
        except re.error:
            ua_pattern = re.compile(HTTP_UA_DEFAULTS["user_agent_pattern"], re.I)
        upload_methods = {str(item).upper() for item in (upload_rule.get("methods") or HTTP_UPLOAD_DEFAULTS["methods"])}
        upload_extensions = tuple(
            str(item).lower() for item in (upload_rule.get("extensions") or HTTP_UPLOAD_DEFAULTS["extensions"])
        )
        suspicious_ua = [row for row in http["requests"] if ua_pattern.search(row["user_agent"])]
        if suspicious_ua:
            findings.append(DetectionResult(
                engine=self.name,
                rule_id="PROTO_HTTP_UA_001",
                severity="Medium",
                confidence=0.8,
                evidence={"requests": suspicious_ua[:20]},
                recommendation="识别异常 User-Agent 来源，结合请求序列判断是否为扫描或自动化攻击。",
            ).normalize())
        # A POST to a .php URI is routine. An upload needs an actual file body:
        # a multipart/octet-stream request carrying a dynamic script name. The
        # response is kept as evidence but is not required to be successful.
        uploads = []
        for row in http["requests"]:
            if str(row.get("method")).upper() not in upload_methods:
                continue
            content_type = str(row.get("content_type") or "").lower()
            if "multipart/form-data" not in content_type and "octet-stream" not in content_type:
                continue
            blob = f"{row.get('uri', '')}\n{row.get('file_data', '')}".lower()
            if any(ext in blob for ext in upload_extensions):
                uploads.append(row)
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
