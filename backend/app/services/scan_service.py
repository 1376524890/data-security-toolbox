"""Active network scanning for information-security assessment.

The toolbox historically only observed traffic/files passively. This module
adds active discovery + host scanning so a registered probe/backend can assess
the whole network segment: find live hosts, enumerate open services, and feed
the results into the asset / compliance / threat-intel (CVE) pipeline.

Two engines are used:

* ``nmap`` when the binary is present. It is always invoked with ``-Pn`` and
  ``-sT`` because inside containers/hardened hosts ICMP+ARP host discovery is
  routinely blocked, which made nmap report ``0 hosts up`` and skip the port
  scan entirely - the reason scans produced no assets at all.
* A dependency-free TCP-connect engine (``python-tcp``) as automatic fallback:
  it needs no root, no ``NET_RAW`` capability and no nmap install, so a scan
  always produces evidence even in restricted container setups.
"""

from __future__ import annotations

import ipaddress
import re
import shutil
import socket
import ssl
import subprocess
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any


# Ports probed to decide whether a host is alive. Kept small so a /24 sweep
# stays within the timeout budget, and covers Windows/Linux/database/network
# gear defaults where ICMP is filtered.
LIVENESS_PORTS: tuple[int, ...] = (
    22, 80, 135, 139, 443, 445, 3389, 8080, 8000, 8443, 21, 23, 25, 110, 143,
    3306, 5432, 6379, 1433, 1521, 27017, 5672, 9200, 5900, 111, 2049, 161, 53,
)

# Curated "top ports" used by the TCP-connect engine, ordered by how often they
# are found exposed. Mirrors nmap's top-ports spirit without shipping the list.
COMMON_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 69, 80, 81, 88, 110, 111, 119, 123, 135, 137, 138, 139,
    143, 161, 162, 179, 194, 389, 443, 445, 465, 514, 515, 548, 554, 587, 623,
    631, 636, 646, 873, 902, 989, 990, 993, 995, 1025, 1080, 1099, 1194, 1241,
    1352, 1433, 1434, 1521, 1701, 1723, 1883, 1900, 2049, 2082, 2083, 2181,
    2222, 2375, 2376, 2379, 2480, 3000, 3128, 3260, 3306, 3389, 3478, 3690,
    4000, 4369, 4443, 4505, 4506, 5000, 5001, 5060, 5222, 5357, 5432, 5433,
    5555, 5601, 5672, 5683, 5900, 5901, 5984, 6000, 6379, 6443, 7001, 7002,
    7077, 8000, 8008, 8009, 8010, 8042, 8069, 8080, 8081, 8082, 8086, 8088,
    8090, 8123, 8161, 8181, 8200, 8300, 8443, 8500, 8529, 8834, 8888, 8983,
    9000, 9001, 9042, 9060, 9080, 9090, 9092, 9100, 9160, 9200, 9300, 9443,
    9600, 9999, 10000, 10250, 11211, 15672, 16379, 25565, 27017, 27018, 50000,
    50070, 50090, 61616,
)

PORT_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 69: "tftp",
    80: "http", 88: "kerberos", 110: "pop3", 111: "rpcbind", 123: "ntp",
    135: "msrpc", 137: "netbios-ns", 139: "netbios-ssn", 143: "imap",
    161: "snmp", 179: "bgp", 389: "ldap", 443: "https", 445: "microsoft-ds",
    465: "smtps", 514: "syslog", 548: "afp", 554: "rtsp", 587: "submission",
    623: "ipmi", 631: "ipp", 636: "ldaps", 873: "rsync", 993: "imaps",
    995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "mssql", 1521: "oracle",
    1883: "mqtt", 2049: "nfs", 2181: "zookeeper", 2375: "docker", 2379: "etcd",
    3000: "http", 3128: "squid", 3260: "iscsi", 3306: "mysql", 3389: "ms-wbt-server",
    3690: "svn", 4369: "erlang-epmd", 4443: "https", 5000: "http", 5060: "sip",
    5222: "xmpp", 5357: "wsdapi", 5432: "postgresql", 5433: "postgresql",
    5601: "kibana", 5672: "amqp", 5900: "vnc", 5901: "vnc", 5984: "couchdb",
    6379: "redis", 6443: "kubernetes", 7001: "weblogic", 7077: "spark",
    8000: "http", 8008: "http", 8009: "ajp", 8080: "http", 8081: "http",
    8086: "influxdb", 8088: "http", 8090: "http", 8123: "http", 8161: "activemq",
    8181: "http", 8200: "vault", 8300: "consul", 8443: "https", 8500: "consul",
    8529: "arangodb", 8888: "http", 8983: "solr", 9000: "http", 9042: "cassandra",
    9090: "http", 9092: "kafka", 9100: "jetdirect", 9200: "elasticsearch",
    9300: "elasticsearch", 9443: "https", 10000: "webmin", 10250: "kubelet",
    11211: "memcached", 15672: "rabbitmq-management", 27017: "mongodb",
    50000: "sap", 50070: "hdfs", 61616: "activemq",
}

# Ports that speak TLS on their own (handshake first, no plaintext banner).
TLS_PORTS = {443, 465, 636, 993, 995, 4443, 6443, 8443, 9443}
# Ports that answer an HTTP request even before version detection.
HTTP_PORTS = {80, 81, 88, 3000, 5000, 5357, 5601, 8000, 8008, 8080, 8081, 8086, 8088, 8090, 8123, 8161, 8181, 8200, 8300, 8500, 8529, 8888, 8983, 9000, 9090, 9200, 10000, 15672, 2375, 2379, 10250}
# Ports that greet the client with a banner on connect.
BANNER_PORTS = {21, 22, 23, 25, 110, 143, 220, 587, 993, 995, 1433, 1521, 3306, 5432, 5900, 6379, 11211, 27017}

SERVICE_KEYWORDS: dict[str, tuple[str, ...]] = {
    "mysql": ("mysql", "mariadb"),
    "postgresql": ("postgresql", "postgres"),
    "mongodb": ("mongodb", "mongo"),
    "redis": ("redis",),
    "oracle": ("oracle",),
    "mssql": ("microsoft sql", "mssql"),
    "nginx": ("nginx",),
    "apache": ("apache", "httpd"),
    "iis": ("iis", "microsoft-iis"),
    "tomcat": ("tomcat", "coyote"),
    "elasticsearch": ("elasticsearch", "opensearch"),
    "kafka": ("kafka",),
    "rabbitmq": ("rabbitmq",),
    "docker": ("docker",),
    "kubernetes": ("kubernetes", "kubelet"),
    "memcached": ("memcached",),
    "openssh": ("openssh",),
    "vsftpd": ("vsftpd",),
    "proftpd": ("proftpd",),
}

MAX_SWEEP_HOSTS = 4096
BANNER_BYTES = 1024


def _nmap(args: list[str], timeout: int = 300) -> str:
    if not shutil.which("nmap"):
        return ""
    try:
        proc = subprocess.run(["nmap", *args], capture_output=True, text=True, timeout=timeout, check=False)
        return proc.stdout or ""
    except Exception:
        return ""


def nmap_available() -> bool:
    return bool(shutil.which("nmap"))


# Only a real IP range counts: "web-server-01" is a hostname, not a range.
IP_RANGE_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}\s*-\s*(?:\d{1,3}(?:\.\d{1,3}){3}|\d{1,3})$")


def is_subnet(target: str) -> bool:
    """True for CIDR or IP-range targets that need host discovery."""
    text = str(target or "").strip()
    if "/" in text:
        try:
            ipaddress.ip_network(text, strict=False)
        except ValueError:
            return False
        return True
    return bool(IP_RANGE_RE.match(text))


def select_ports(limit: int = 1000, ports: list[int] | None = None, liveness: bool = False) -> list[int]:
    """Return the TCP ports to probe for one scan."""
    if ports:
        cleaned = sorted({int(item) for item in ports if 1 <= int(item) <= 65535})
        if cleaned:
            return cleaned[:4096]
    source = LIVENESS_PORTS if liveness else COMMON_PORTS
    limit = max(1, min(int(limit), len(source)))
    return list(source)[:limit]


def expand_targets(target: str, max_hosts: int = MAX_SWEEP_HOSTS) -> list[str]:
    """Expand an IP / CIDR / ``a-b`` range target into individual host addresses."""
    text = str(target or "").strip()
    if not text:
        return []
    if "/" in text:
        try:
            network = ipaddress.ip_network(text, strict=False)
        except ValueError:
            return []
        if network.num_addresses <= 2:
            return [str(network.network_address)]
        hosts = [str(item) for item in network.hosts()]
        return hosts[:max_hosts]
    if IP_RANGE_RE.match(text):
        start_text, _, end_text = text.partition("-")
        start_text, end_text = start_text.strip(), end_text.strip()
        start = ipaddress.ip_address(start_text)
        if "." in end_text:  # 192.168.1.10-192.168.1.20
            end = ipaddress.ip_address(end_text)
        else:  # 192.168.1.10-20
            end = ipaddress.ip_address(f"{start_text.rsplit('.', 1)[0]}.{end_text}")
        if int(end) < int(start):
            start, end = end, start
        span = int(end) - int(start) + 1
        return [str(ipaddress.ip_address(int(start) + offset)) for offset in range(min(span, max_hosts))]
    try:
        return [str(ipaddress.ip_address(text))]
    except ValueError:
        return [text]


def _grab_banner(sock: socket.socket, port: int, host: str) -> dict[str, Any]:
    """Read a service banner/TLS metadata over an established connection."""
    info: dict[str, Any] = {"banner": "", "tls": {}}
    if port in TLS_PORTS:
        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            with context.wrap_socket(sock, server_hostname=host) as tls:
                info["tls"] = {"version": tls.version() or "", "cipher": (tls.cipher() or ("",))[0]}
        except (OSError, ssl.SSLError, ValueError):
            pass
        return info
    try:
        if port in HTTP_PORTS:
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\nUser-Agent: dst-scanner\r\n\r\n".encode())
            info["banner"] = sock.recv(BANNER_BYTES).decode("utf-8", "replace")
        elif port in BANNER_PORTS:
            info["banner"] = sock.recv(BANNER_BYTES).decode("utf-8", "replace")
        else:
            # Unknown/非标准端口：连接已建立，做一次有界被动读取（SSH/MySQL/
            # SMTP 等在非标准端口也能识别），失败即视为无 banner。
            sock.settimeout(min(0.6, max(0.2, sock.gettimeout() or 0.6)))
            info["banner"] = sock.recv(BANNER_BYTES).decode("utf-8", "replace")
    except OSError:
        pass
    info["banner"] = str(info["banner"])[:BANNER_BYTES]
    return info


def _refine_service(port: int, banner: str, tls: dict[str, Any]) -> tuple[str, str, str]:
    """Derive (service, product, version) from a banner. Best effort only."""
    text = (banner or "").lower()
    service = PORT_SERVICES.get(port, "unknown")
    product = ""
    version = ""
    for name, keywords in SERVICE_KEYWORDS.items():
        if any(keyword in text for keyword in keywords):
            product = name
            break
    if not product and banner.startswith("HTTP/"):
        product = "http"
    server_line = ""
    for line in (banner or "").splitlines():
        if line.lower().startswith("server:"):
            server_line = line.split(":", 1)[1].strip()
            break
    if server_line:
        product = product or "http"
        version = server_line
    if port in {443, 8443, 4443, 9443} and service in {"https", "unknown"}:
        service = "https"
    if not product and tls.get("version"):
        product = service if service != "unknown" else "tls"
    return service, product, version


def tcp_open(host: str, port: int, timeout: float = 0.6) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def scan_host_python(host: str, ports: list[int], timeout: float = 0.7, concurrency: int = 64) -> list[dict[str, Any]]:
    """TCP-connect port/service scan; requires no privileges and no nmap."""
    timeout = min(max(float(timeout), 0.1), 3.0)
    workers = min(max(int(concurrency), 1), 128)
    results: list[dict[str, Any]] = []

    def probe(port: int) -> dict[str, Any] | None:
        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                sock.settimeout(timeout)
                banner = _grab_banner(sock, port, host)
        except OSError:
            return None
        service, product, version = _refine_service(port, banner.get("banner", ""), banner.get("tls", {}))
        return {
            "port": port,
            "protocol": "tcp",
            "service": service,
            "product": product,
            "version": version,
            "extra": "",
            "banner": banner.get("banner", ""),
            "tls": banner.get("tls", {}),
        }

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for future in as_completed([pool.submit(probe, port) for port in ports]):
            try:
                item = future.result()
            except Exception:
                item = None
            if item:
                results.append(item)
    return sorted(results, key=lambda item: item["port"])


def scan_host(host: str, top_ports: int = 1000, timeout: int = 300, ports: list[int] | None = None) -> list[dict[str, Any]]:
    """Service/version scan a single host; return open services with product/version.

    Prefers nmap (``-Pn -sT`` so blocked ICMP cannot suppress the port scan) and
    transparently falls back to the built-in TCP-connect engine.
    """
    explicit = select_ports(top_ports, ports)
    # ``--host-timeout`` keeps one filtered/slow host from stalling the whole
    # sweep: without it a single unresponsive host can block a multi-host scan
    # for minutes, which is why segment scans appeared to "hang".
    host_timeout = max(10, min(int(timeout), 60))
    args = ["-Pn", "-sT", "-sV", "--version-light", "--max-retries", "1", "-T4",
            "--host-timeout", f"{host_timeout}s", "-oX", "-"]
    if ports:
        args += ["-p", ",".join(str(port) for port in explicit)]
    else:
        args += ["--top-ports", str(max(1, min(int(top_ports), 65535)))]
    args.append(host)
    out = _nmap(args, timeout)
    services: list[dict[str, Any]] = []
    if out:
        try:
            root = ET.fromstring(out)
        except ET.ParseError:
            root = None
        if root is not None:
            for port in root.findall(".//port"):
                state = port.find("state")
                if state is None or state.get("state") != "open":
                    continue
                svc = port.find("service")
                services.append({
                    "port": int(port.get("portid") or 0),
                    "protocol": port.get("protocol") or "tcp",
                    "service": (svc.get("name") if svc is not None else "") or "",
                    "product": (svc.get("product") if svc is not None else "") or "",
                    "version": (svc.get("version") if svc is not None else "") or "",
                    "extra": (svc.get("extrainfo") if svc is not None else "") or "",
                    "banner": "",
                    "tls": {},
                })
    if services:
        return services
    # nmap missing, rejected, timing out, or seeing nothing: always fall back so
    # the scan still returns evidence instead of an empty asset list.
    return scan_host_python(host, explicit)


# RFC 5737 documentation ranges: never routed, so anything that "answers" is
# evidence of a transparent proxy/NAT intercepting the scan path.
UNROUTABLE_PROBES: tuple[str, ...] = ("192.0.2.1", "198.51.100.1", "203.0.113.1")


def detect_interception(timeout: float = 0.6, ports: list[int] | None = None) -> str:
    """Return a warning string when the scan path answers for unroutable IPs.

    Container runtimes and corporate proxies that transparently accept outbound
    TCP connections make every host look alive and every port look open. The
    scan itself cannot be trusted in that case, so the caller reports it instead
    of emitting fabricated assets (use a probe on the target segment instead).
    """
    probes = list(ports or LIVENESS_PORTS)[:16]
    for host in UNROUTABLE_PROBES:
        for port in probes:
            if tcp_open(host, port, timeout):
                return (f"扫描路径存在透明代理/NAT 拦截（{host}:{port} 被应答），"
                        "平台侧扫描结果不可信；请改用目标网段内的探针扫描")
    return ""


def discover_hosts_python(target: str, timeout: float = 0.5, concurrency: int = 128, ports: list[int] | None = None) -> list[str]:
    """TCP-connect liveness sweep. Works without root, ICMP or ARP."""
    hosts = expand_targets(target)
    probes = list(ports or LIVENESS_PORTS)
    timeout = min(max(float(timeout), 0.1), 2.0)
    workers = min(max(int(concurrency), 1), 256)
    alive: list[str] = []

    def sweep(host: str) -> str | None:
        for port in probes:
            if tcp_open(host, port, timeout):
                return host
        return None

    with ThreadPoolExecutor(max_workers=workers) as pool:
        for future in as_completed([pool.submit(sweep, host) for host in hosts]):
            try:
                item = future.result()
            except Exception:
                item = None
            if item:
                alive.append(item)
    return sorted(alive, key=lambda value: tuple(int(part) for part in value.split(".")) if value.count(".") == 3 else (0, 0, 0, 0))


def discover_hosts_nmap(target: str, timeout: int = 120) -> list[str]:
    """nmap-assisted sweep (ICMP + TCP ping). Best effort, may legitimately find nothing."""
    ping_ports = ",".join(str(port) for port in LIVENESS_PORTS[:16])
    out = _nmap(["-sn", "-PE", "-PS" + ping_ports, "-oX", "-", target], timeout)
    if not out:
        return []
    try:
        root = ET.fromstring(out)
    except ET.ParseError:
        return []
    hosts: list[str] = []
    for host in root.findall(".//host"):
        addr = host.find("address")
        status = host.find("status")
        if addr is not None and (status is None or status.get("state") == "up"):
            hosts.append(str(addr.get("addr")))
    return hosts


def discover_hosts(target: str, timeout: int = 120, ports: list[int] | None = None) -> list[str]:
    """Return live host IPs for a single host, IP range or CIDR.

    TCP-connect probing runs first because ICMP/ARP discovery is unreliable in
    containers and segmented networks; nmap is only consulted when the TCP sweep
    finds nothing (e.g. hosts that answer ping but expose no scanned TCP port).
    """
    alive = discover_hosts_python(target, ports=ports)
    if alive:
        return alive
    return discover_hosts_nmap(target, timeout=timeout)
