#!/usr/bin/env python3
"""Data Security Toolbox Probe daemon (V3.1).

Implements persistent probe identity, a strict upload state machine, atomic
spool manifests, sequence restoration, capture-format metadata and real (or
explicitly unavailable) packet-drop metrics.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import platform
import re
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
import uuid
import urllib.error
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import tomllib

try:
    import psutil
except ImportError:
    psutil = None


try:
    from .scanner import scan_network
except ImportError:
    from scanner import scan_network

try:
    from .data_assets import discover_data_assets, guard_report, use_engine
except ImportError:
    from data_assets import discover_data_assets, guard_report, use_engine

try:
    from .ruleset_client import RuleSetClient
except ImportError:
    from ruleset_client import RuleSetClient

# The documented scan budgets live in the shared package so the probe, the
# platform and the docs cannot drift apart. `data_assets.discover_data_assets`
# reads exactly these names out of the `[data]` config block.
try:
    from shared.scanning.budget import DEFAULT_LIMITS as _SCAN_LIMITS
except ImportError:  # pragma: no cover - the probe package always ships shared/
    _SCAN_LIMITS = {}

SCAN_BUDGET_KEYS = (
    "max_files", "max_depth", "max_dirs", "max_bytes_read", "max_single_file_size",
    "max_full_hash_size", "sample_block_size", "max_sample_rows", "max_cpu_seconds",
    "max_rss_mb", "xlsx_max_entries", "xlsx_max_uncompressed_bytes",
    "xlsx_max_compression_ratio", "xlsx_max_shared_strings", "xlsx_max_sheets",
    "xlsx_max_columns", "xlsx_max_rows",
)


def _scan_budget_defaults() -> dict[str, Any]:
    return {key: _SCAN_LIMITS[key] for key in SCAN_BUDGET_KEYS if key in _SCAN_LIMITS}


AGENT_VERSION = "3.7.0"
DEFAULT_CONFIG = {
    "server": {"url": "http://localhost:8000", "verify_tls": True, "ca_file": ""},
    "capture": {"interface": "any", "segment_seconds": 30, "segment_max_mb": 64, "enabled": True},
    "spool": {"path": "/var/lib/data-security-toolbox/spool", "max_mb": 2048, "retention_seconds": 86400},
    "agent": {
        "heartbeat_seconds": 30,
        "asset_interval_seconds": 900,
        "file_interval_seconds": 0,
        "upload_interval_seconds": 2,
        "upload_max_interval_seconds": 60,
        "bootstrap_token": "",
        "deployment_id": 0,
        "identity_path": "/etc/data-security-toolbox/probe.identity.json",
        "token_path": "/etc/data-security-toolbox/probe.token",
        "allow_auto_reenroll": False,
        "ports": [22, 80, 443, 445, 3306, 5432, 6379, 8080],
        "paths": [],
        "max_files": 10000,
        "demo": False,
    },
    "scan": {
        "enabled": False,
        "interval_seconds": 3600,
        "targets": [],
        "discovery": True,
        "top_ports": 200,
        "nuclei": False,
        "nuclei_tags": "",
        "ports": [22, 80, 443, 445, 3306, 5432, 6379, 8080],
        "max_hosts": 256,
        "concurrency": 32,
        "connect_timeout": 0.5,
        "timeout_seconds": 120,
        "allow_remote": False,
        "poll_seconds": 30,
    },
    "ruleset": {
        # Hot update is on by default: the server is the only place rules are
        # managed, and the probe keeps working with its in-package pack offline.
        "enabled": True,
        "dir": "/var/lib/data-security-toolbox/rules",
        "max_pack_bytes": 2097152,
        "self_test_timeout_seconds": 2.0,
        "poll_seconds": 900,
    },
    "data": {
        "enabled": False,
        "interval_seconds": 3600,
        "paths": [],
        # Excludes are scope, not budget: a bare name filters that directory
        # anywhere, an absolute path excludes exactly that subtree. ``file_types``
        # is an allow-list of extensions; empty means every type is in scope.
        "exclude_paths": [],
        "file_types": [],
        "include_databases": True,
        # Wall-clock ceiling for one inventory run; separate from the network
        # scan timeout so the two jobs can be tuned independently.
        "timeout_seconds": 120,
        # Unchanged files are reused without re-reading their content, as long as
        # size/mtime/inode and the engine/rules/profile versions all match.
        "cache_enabled": True,
        "cache_path": "/var/lib/data-security-toolbox/cache/analysis.sqlite",
        "allow_remote": False,
        "poll_seconds": 30,
        **_scan_budget_defaults(),
    },
}

# Upload state machine states.
STATE_PENDING = "pending"
STATE_UPLOADING = "uploading"
STATE_UPLOADED = "uploaded"
STATE_RETRY_WAIT = "retry_wait"
STATE_AUTH_ERROR = "auth_error"
STATE_QUARANTINED = "quarantined"

# Transient HTTP statuses that trigger exponential-backoff retry.
TRANSIENT_HTTP = {429, 500, 502, 503, 504}
# Permanent data errors the server rejects outright -> quarantine.
PERMANENT_HTTP = {400, 413, 422}


def now_iso() -> str:
    return datetime.now(UTC).isoformat()


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(base.get(key), dict):
            base[key] = _merge(base[key], value)
        else:
            base[key] = value
    return base


class Config:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = _merge(json.loads(json.dumps(DEFAULT_CONFIG)), self._load(path))
        if self.agent.get("demo"):
            self.capture["segment_seconds"] = 15
            self.agent["heartbeat_seconds"] = 5
            self.agent["upload_interval_seconds"] = 1

    @staticmethod
    def _load(path: Path) -> dict[str, Any]:
        if not path.exists():
            return {}
        with path.open("rb") as handle:
            return tomllib.load(handle)

    @property
    def server(self) -> dict[str, Any]:
        return self.data["server"]

    @property
    def capture(self) -> dict[str, Any]:
        return self.data["capture"]

    @property
    def spool(self) -> dict[str, Any]:
        return self.data["spool"]

    @property
    def agent(self) -> dict[str, Any]:
        return self.data["agent"]

    @property
    def scan(self) -> dict[str, Any]:
        return self.data["scan"]

    @property
    def data_assets(self) -> dict[str, Any]:
        return self.data["data"]

    @property
    def ruleset(self) -> dict[str, Any]:
        return self.data["ruleset"]

    def base_url(self) -> str:
        return str(self.server["url"]).rstrip("/")

    def identity_path(self) -> Path:
        return Path(self.agent["identity_path"]).expanduser()

    def spool_path(self) -> Path:
        return Path(self.spool["path"]).expanduser()

    def ensure(self) -> None:
        self.spool_path().mkdir(parents=True, exist_ok=True)
        identity_path = self.identity_path()
        identity_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(identity_path.parent, 0o700)
        except OSError:
            pass

    def clear_bootstrap(self) -> None:
        """Remove the one-time enrollment/bootstrap token from the config file."""
        if not self.path.exists():
            return
        text = self.path.read_text(encoding="utf-8")
        text = re.sub(r"^(bootstrap_token\s*=\s*).*$", r'\1""', text, flags=re.MULTILINE)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        tmp.write_text(text, encoding="utf-8")
        tmp.replace(self.path)
        self.data = _merge(json.loads(json.dumps(DEFAULT_CONFIG)), self._load(self.path))


class ProbeIdentity:
    """Persistent probe identity stored atomically with 0600 permissions."""

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.data: dict[str, Any] = {}
        self.load()

    def load(self) -> None:
        if self.path.exists():
            try:
                self.data = json.loads(self.path.read_text(encoding="utf-8"))
            except Exception:
                self.data = {}
        else:
            self.data = {}

    @property
    def probe_id(self) -> int | None:
        value = self.data.get("probe_id")
        try:
            return int(value) if value is not None else None
        except (TypeError, ValueError):
            return None

    @property
    def token(self) -> str:
        return str(self.data.get("token") or "")

    @property
    def registered_at(self) -> str:
        return str(self.data.get("registered_at") or "")

    def exists(self) -> bool:
        return self.probe_id is not None and bool(self.token)

    def save(self, probe_id: int, token: str, registered_at: str, server: str) -> None:
        payload = {"probe_id": int(probe_id), "token": token, "registered_at": registered_at, "server": server}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.path.parent, 0o700)
        tmp = self.path.with_suffix(self.path.suffix + ".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        tmp.replace(self.path)
        os.chmod(self.path, stat.S_IRUSR | stat.S_IWUSR)
        self.data = payload

    def clear(self) -> None:
        self.path.unlink(missing_ok=True)
        self.data = {}


def network_interfaces() -> list[dict[str, Any]]:
    """Report every NIC and all IPv4/IPv6 addresses, including down interfaces."""
    if not psutil:
        return []
    try:
        stats = psutil.net_if_stats()
        return [{'name': name, 'is_up': bool(stats.get(name) and stats[name].isup),
                 'addresses': [{'address': addr.address, 'family': 'IPv4' if addr.family == socket.AF_INET else 'IPv6',
                                'netmask': addr.netmask} for addr in values if addr.family in (socket.AF_INET, socket.AF_INET6)]}
                for name, values in psutil.net_if_addrs().items()]
    except Exception:
        return []


def capture_interfaces(value) -> list[str]:
    """Accept any/all/*, a single NIC, comma-separated names, or a TOML array."""
    names = value if isinstance(value, list) else str(value).split(',')
    names = list(dict.fromkeys(str(name).strip() for name in names if str(name).strip()))
    if not names or any(name.lower() in {'any', 'all', '*'} for name in names):
        if platform.system() == 'Linux':
            return ['any']  # Linux cooked capture follows newly added interfaces too.
        names = [item['name'] for item in network_interfaces() if item['is_up']]
        if not names:
            raise ValueError('No active capture interfaces found')
    return names


def local_ip(interface: str = "") -> str:
    if psutil:
        try:
            addresses = psutil.net_if_addrs()
            if interface:
                selected = interface if isinstance(interface, list) else str(interface).split(',')
                for addr in [addr for name in selected for addr in addresses.get(name.strip(), [])]:
                    if addr.family == socket.AF_INET:
                        return addr.address
            for values in addresses.values():
                for addr in values:
                    if addr.family == socket.AF_INET and not addr.address.startswith("127."):
                        return addr.address
        except Exception:
            pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


def system_metrics() -> dict[str, Any]:
    info: dict[str, Any] = {"hostname": socket.gethostname(), "os": platform.platform(), "python": platform.python_version(), "agent_version": AGENT_VERSION}
    if psutil:
        info.update({
            "cpu_percent": psutil.cpu_percent(interval=0.2),
            "memory_percent": psutil.virtual_memory().percent,
            "memory_available_mb": round(psutil.virtual_memory().available / 1024 / 1024, 1),
            "memory_rss_mb": round(psutil.Process().memory_info().rss / 1024 / 1024, 1),
        })
    return info


def detect_configured_services(ports: list[int], host: str = "") -> list[dict[str, Any]]:
    target = host or local_ip()
    services: list[dict[str, Any]] = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        try:
            result = sock.connect_ex((target, port))
            if result == 0:
                try:
                    service = socket.getservbyport(port, "tcp")
                except OSError:
                    service = ""
                banner = ""
                try:
                    sock.settimeout(0.5)
                    banner = sock.recv(1024).decode("utf-8", "replace").strip()[:512]
                except Exception:
                    banner = ""
                services.append({"port": port, "service": service, "protocol": "tcp", "ip": target, "banner": banner})
        finally:
            sock.close()
    return services


def file_records(paths: list[Path], max_files: int = 50) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for root in paths:
        if not root.exists():
            continue
        candidates = root.rglob("*") if root.is_dir() else [root]
        for item in candidates:
            if not item.is_file() or item.stat().st_size > 500 * 1024 * 1024:
                continue
            digest_sha = hashlib.sha256()
            digest_md5 = hashlib.md5()
            with item.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest_sha.update(chunk)
                    digest_md5.update(chunk)
            records.append({
                "name": item.name,
                "path": str(item),
                "size": item.stat().st_size,
                "sha256": digest_sha.hexdigest(),
                "md5": digest_md5.hexdigest(),
                "file_type": item.suffix.lstrip("."),
            })
            if len(records) >= max_files:
                return records
    return records


def spool_size_mb(spool: Path) -> float:
    return sum(item.stat().st_size for item in spool.rglob("*") if item.is_file()) / 1024 / 1024


def spool_pending(spool: Path) -> list[Path]:
    return sorted(spool.glob("*.json"))


def spool_metadata(path: Path) -> dict[str, Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}


def write_spool_metadata_atomic(path: Path, metadata: dict[str, Any]) -> None:
    """Atomically write a spool manifest via tmp + fsync + rename."""
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as handle:
        json.dump(metadata, handle, ensure_ascii=False, indent=2)
        handle.flush()
        os.fsync(handle.fileno())
    tmp.replace(path)


def resolve_pcap(meta_path: Path) -> Path | None:
    for suffix in (".pcapng", ".pcap"):
        candidate = meta_path.with_suffix(suffix)
        if candidate.exists():
            return candidate
    return None


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def ssl_context(config: Config):
    import ssl
    if not config.server.get("verify_tls", True):
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        return context
    if config.server.get("ca_file"):
        return ssl.create_default_context(cafile=str(config.server["ca_file"]))
    return None


def tool_version(binary: str) -> str:
    try:
        proc = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10, check=False)
        text = (proc.stdout or proc.stderr).strip().splitlines()
        return text[0].strip() if text else ""
    except Exception:
        return ""


def detect_capture_tool(config: Config) -> tuple[str, str]:
    if shutil.which("dumpcap"):
        return "dumpcap", ".pcapng"
    if shutil.which("tcpdump"):
        return "tcpdump", ".pcap"
    return "", ""


def capture_command(config: Config, partial: Path) -> tuple[str, str, list[str]]:
    """Return (tool, extension, command). dumpcap -> pcapng, tcpdump -> pcap."""
    interfaces = capture_interfaces(config.capture['interface'])
    duration = int(config.capture["segment_seconds"])
    max_mb = int(config.capture["segment_max_mb"])
    dumpcap = shutil.which("dumpcap")
    if dumpcap:
        args = [arg for interface in interfaces for arg in ('-i', interface)]
        return "dumpcap", ".pcapng", [dumpcap, *args, "-a", f"duration:{duration}", "-a", f"filesize:{max_mb * 1024}", "-w", str(partial), "-q"]
    tcpdump = shutil.which("tcpdump")
    if tcpdump:
        if len(interfaces) > 1:
            raise ValueError('Multiple selected interfaces require dumpcap; use any on Linux for tcpdump')
        return "tcpdump", ".pcap", [tcpdump, "-i", interfaces[0], "-w", str(partial), "-U"]
    return "", "", []


def parse_capture_drop_metrics(stderr: str, tool: str) -> dict[str, Any]:
    """Best-effort packet-drop extraction from capture stderr.

    If the tool does not expose reliable drop counters we return
    ``drop_metric_available=False`` rather than pretending zero drops.
    """
    text = stderr or ""
    received = None
    dropped = None
    # dumpcap prints "N packets captured, M packets dropped by interface".
    if tool == "dumpcap":
        for line in text.splitlines():
            match = re.search(r"(\d+)\s+packets? captured,.*?(\d+)\s+packets? dropped", line)
            if match:
                received = int(match.group(1))
                dropped = int(match.group(2))
                break
    # tcpdump prints "N packets captured / M packets received by filter".
    elif tool == "tcpdump":
        for line in text.splitlines():
            match = re.search(r"(\d+)\s+packets? captured", line)
            if match:
                received = int(match.group(1))
            drop_match = re.search(r"(\d+)\s+packets? dropped", line)
            if drop_match:
                dropped = int(drop_match.group(1))
    if received is None and dropped is None:
        return {"packets_received": None, "packets_dropped": None, "drop_rate": None, "drop_metric_available": False}
    received = received or 0
    dropped = dropped or 0
    rate = round(dropped / received, 4) if received else None
    return {"packets_received": received, "packets_dropped": dropped, "drop_rate": rate, "drop_metric_available": True}


def capture_once(config: Config, sequence: int) -> dict[str, Any] | None:
    spool = config.spool_path()
    started = datetime.now(UTC)
    stamp = started.strftime("%Y%m%dT%H%M%S%fZ")
    tool, ext = detect_capture_tool(config)
    if not tool:
        return None
    final = spool / f"{stamp}-{sequence:06d}{ext}"
    partial = final.with_suffix(final.suffix + ".partial")
    tool, ext, command = capture_command(config, partial)
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
    deadline = time.time() + int(config.capture["segment_seconds"]) + 5
    max_bytes = int(config.capture["segment_max_mb"]) * 1024 * 1024
    try:
        while process.poll() is None and time.time() < deadline:
            if max_bytes and partial.exists() and partial.stat().st_size >= max_bytes:
                process.terminate()
                break
            time.sleep(0.5)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
        stderr_text = ""
        if process.stderr:
            try:
                stderr_text = process.stderr.read() or ""
            except Exception:
                pass
        if not partial.exists() or partial.stat().st_size == 0:
            return None
        partial.replace(final)
        finished = datetime.now(UTC)
        drop = parse_capture_drop_metrics(stderr_text, tool)
        metadata = {
            "segment_id": final.name,
            "segment_uuid": uuid.uuid4().hex,
            "sequence": sequence,
            "interface": config.capture["interface"],
            "capture_format": ext.lstrip("."),
            "capture_tool": tool,
            "capture_tool_version": tool_version(tool),
            "capture_started_at": started.isoformat(),
            "capture_finished_at": finished.isoformat(),
            "size": final.stat().st_size,
            "sha256": sha256_file(final),
            "packet_drop": drop["packets_dropped"],
            "packets_received": drop["packets_received"],
            "drop_rate": drop["drop_rate"],
            "drop_metric_available": drop["drop_metric_available"],
            "state": STATE_PENDING,
            "attempts": 0,
            "last_attempt_at": "",
            "next_attempt_at": "",
        }
        write_spool_metadata_atomic(final.with_suffix(".json"), metadata)
        return metadata
    finally:
        if partial.exists():
            partial.unlink(missing_ok=True)
        if process.stderr:
            try:
                process.stderr.close()
            except Exception:
                pass


def http_json(url: str, payload: dict[str, Any], headers: dict[str, str], config: Config, timeout: int = 30) -> dict[str, Any]:
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", **headers}, method="POST")
    context = ssl_context(config)
    with urllib.request.urlopen(request, timeout=timeout, context=context) as response:
        return json.loads(response.read().decode())


def http_get_json(url: str, headers: dict[str, str], config: Config, timeout: int = 30) -> dict[str, Any]:
    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=timeout, context=ssl_context(config)) as response:
        return json.loads(response.read().decode())


def http_get_bounded(url: str, headers: dict[str, str], config: Config, limit: int, timeout: int = 60) -> bytes:
    """Read at most ``limit`` bytes so a wrong or hostile response cannot fill memory."""
    request = urllib.request.Request(url, headers=headers, method="GET")
    chunks: list[bytes] = []
    total = 0
    with urllib.request.urlopen(request, timeout=timeout, context=ssl_context(config)) as response:
        declared = response.headers.get("Content-Length")
        if declared and declared.isdigit() and int(declared) > limit:
            raise ValueError(f"规则包声明大小 {declared} 超过上限 {limit}")
        while True:
            chunk = response.read(min(65536, limit - total + 1))
            if not chunk:
                break
            total += len(chunk)
            if total > limit:
                raise ValueError(f"规则包超过上限 {limit} 字节")
            chunks.append(chunk)
    return b"".join(chunks)


def http_upload(path: Path, metadata: dict[str, Any], probe_id: int, token: str, config: Config, timeout: int = 120, url_path: str = "/api/v1/pcaps/upload") -> dict[str, Any]:
    boundary = f"----dst{os.getpid()}{int(time.time() * 1000)}"
    fields = [("probe_id", str(probe_id)), ("metadata_json", json.dumps(metadata, ensure_ascii=False))]
    chunks = []
    for name, value in fields:
        chunks.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n".encode())
    chunks.append(f"--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"{path.name}\"\r\nContent-Type: application/octet-stream\r\n\r\n".encode())
    trailing = f"\r\n--{boundary}--\r\n".encode()

    def body_iter():
        for chunk in chunks:
            yield chunk
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                yield chunk
        yield trailing

    parsed = urllib.parse.urlsplit(config.base_url())
    host = parsed.hostname or "localhost"
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if parsed.scheme == "https":
        connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=ssl_context(config))
    else:
        connection = http.client.HTTPConnection(host, port, timeout=timeout)
    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "X-Probe-ID": str(probe_id),
        "X-Probe-Token": token,
    }
    connection.request("POST", url_path, body=body_iter(), headers=headers, encode_chunked=True)
    response = connection.getresponse()
    payload = response.read().decode("utf-8", errors="replace")
    connection.close()
    if response.status < 200 or response.status >= 300:
        raise urllib.error.HTTPError(config.base_url(), response.status, response.reason, response.headers, None)
    return json.loads(payload)


def http_upload_file(path: Path, metadata: dict[str, Any], probe_id: int, token: str, config: Config, timeout: int = 120) -> dict[str, Any]:
    """Upload a target file's content to ``/api/v1/files/upload`` so the backend
    can run metadata + sensitive-data analysis on the real bytes."""
    return http_upload(path, metadata, probe_id, token, config, timeout=timeout, url_path="/api/v1/files/upload")


def backoff_seconds(attempts: int, maximum: int) -> float:
    sequence = [2, 5, 10, 30, 60, 120]
    if attempts <= 0:
        return min(sequence[0], maximum)
    if attempts <= len(sequence):
        return min(sequence[max(0, attempts - 1)], maximum)
    return min(sequence[-1] * 2 ** (attempts - len(sequence)), maximum)


class ProbeAgent:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.stop_event = threading.Event()
        self.identity = ProbeIdentity(config.identity_path())
        self.probe_id = self.identity.probe_id
        self.token = self.identity.token
        self.sequence = self._restore_sequence()
        self.last_capture = ""
        self.last_upload = ""
        self.capture_status = "online"
        self.upload_status = "online"
        self.auth_error = False
        self.upload_failures = 0
        self.uploaded_files: list[str] = []
        self.lock = threading.Lock()
        ruleset_config = config.ruleset
        self.ruleset = RuleSetClient(
            directory=Path(str(ruleset_config["dir"])).expanduser(),
            fetch_json=lambda url: self._ruleset_json(url),
            fetch_bytes=lambda url, limit: self._ruleset_bytes(url, limit),
            manifest_url=lambda current: f"{config.base_url()}/api/v1/probes/{self.probe_id}/ruleset/manifest?current={current}",
            download_url=lambda version: f"{config.base_url()}/api/v1/probes/{self.probe_id}/ruleset?version={version}",
            agent_version=AGENT_VERSION,
            max_pack_bytes=int(ruleset_config["max_pack_bytes"]),
            self_test_timeout=float(ruleset_config["self_test_timeout_seconds"]),
            enabled=bool(ruleset_config.get("enabled", True)),
        )
        self.ruleset.load_usable()

    def _ruleset_json(self, url: str) -> dict[str, Any]:
        return http_get_json(url, {**self.headers(), "X-Agent-Version": AGENT_VERSION}, self.config)

    def _ruleset_bytes(self, url: str, limit: int) -> bytes:
        return http_get_bounded(url, {**self.headers(), "X-Agent-Version": AGENT_VERSION}, self.config, limit)

    def _restore_sequence(self) -> int:
        """Best-effort monotonic sequence restored from existing spool manifests."""
        maximum = 0
        for meta_path in spool_pending(self.config.spool_path()):
            meta = spool_metadata(meta_path)
            try:
                maximum = max(maximum, int(meta.get("sequence") or 0))
            except (TypeError, ValueError):
                continue
        return maximum

    def headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.probe_id:
            headers["X-Probe-ID"] = str(self.probe_id)
        if self.token:
            headers["X-Probe-Token"] = self.token
        return headers

    def register(self) -> None:
        bootstrap = str(self.config.agent.get("bootstrap_token") or "")
        deployment_id = int(self.config.agent.get("deployment_id") or 0)
        # A platform-managed deployment always pushes a fresh one-time enrollment
        # token together with its deployment id, and a successful enrollment
        # clears that token again. A token that is still here therefore means the
        # platform is waiting for this host to enroll now, which outranks a
        # leftover identity (`install.sh` keeps probe.identity.json on purpose):
        # deleting the probe and deploying again, or reinstalling on a host that
        # once ran a probe, must register instead of silently reusing a probe_id
        # the platform already revoked.
        if self.identity.exists() and not (bootstrap and deployment_id):
            # Existing identity wins; never re-enroll/rotate on restart.
            self.probe_id = self.identity.probe_id
            self.token = self.identity.token
            return
        if not bootstrap:
            self.auth_error = True
            raise RuntimeError("probe has no identity and no bootstrap token")
        headers = {"X-Probe-Bootstrap-Token": bootstrap}
        info = {
            "name": socket.gethostname(),
            "hostname": socket.gethostname(),
            "ip_address": local_ip(self.config.capture["interface"]),
            "metadata": {"system": system_metrics(), "agent_version": AGENT_VERSION, "interface": self.config.capture["interface"], "interfaces": network_interfaces()},
        }
        if deployment_id:
            info["deployment_id"] = deployment_id
        try:
            result = http_json(f"{self.config.base_url()}/api/v1/probes/register", info, headers, self.config)
        except urllib.error.HTTPError as exc:
            # The pushed token is one-time. If the enrollment already succeeded but
            # the process died before the token was cleared (or the platform
            # revoked it), the identity on disk is still the credential the
            # platform last issued, so prefer it over a restart loop.
            if exc.code in (401, 403) and self.identity.exists():
                print(
                    f"probe enrollment rejected (HTTP {exc.code}); keeping the stored identity",
                    file=sys.stderr,
                )
                self.probe_id = self.identity.probe_id
                self.token = self.identity.token
                return
            raise
        probe_id = int(result["id"])
        token = result.get("token") or self.token
        if not token:
            raise RuntimeError("registration did not return a probe token")
        self.identity.save(probe_id, token, now_iso(), self.config.base_url())
        self.probe_id = probe_id
        self.token = token
        self.auth_error = False
        if deployment_id:
            self.config.clear_bootstrap()

    def heartbeat_once(self) -> None:
        if not self.probe_id:
            return
        spool = self.config.spool_path()
        quarantined = sum(1 for meta_path in spool_pending(spool) if spool_metadata(meta_path).get("state") == STATE_QUARANTINED)
        metrics = system_metrics()
        metadata = {
            "system": metrics,
            "interfaces": network_interfaces(),
            "agent_version": AGENT_VERSION,
            "interface": self.config.capture["interface"],
            "spool_size_mb": round(spool_size_mb(spool), 2),
            "pending_segments": len([m for m in (spool_metadata(p) for p in spool_pending(spool)) if m.get("state") in (STATE_PENDING, STATE_UPLOADING, STATE_RETRY_WAIT)]),
            "quarantined_segments": quarantined,
            "last_capture": self.last_capture,
            "last_upload": self.last_upload,
            "capture_status": self.capture_status,
            "upload_status": self.upload_status,
            "memory_rss_mb": metrics.get("memory_rss_mb"),
            "cpu_percent": metrics.get("cpu_percent"),
            "drop_rate": None,
            "capture_tool": "dumpcap" if shutil.which("dumpcap") else ("tcpdump" if shutil.which("tcpdump") else ""),
            # Rule version and capability negotiation. Older platforms ignore the
            # extra keys; older probes simply do not send them.
            **self.ruleset.status.to_dict(),
            "capabilities": {**self.ruleset.capabilities(), "data_asset_scan": True, "ruleset_download": True},
        }
        try:
            http_json(f"{self.config.base_url()}/api/v1/probes/{self.probe_id}/heartbeat", {"status": "online", "metadata": metadata}, self.headers(), self.config)
            self.auth_error = False
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                self.auth_error = True
                self.upload_status = STATE_AUTH_ERROR
        except Exception:
            pass

    def capture_loop(self) -> None:
        if not self.config.capture.get('enabled', True):
            self.capture_status = 'disabled'
            return
        while not self.stop_event.is_set():
            if spool_size_mb(self.config.spool_path()) >= int(self.config.spool["max_mb"]):
                self.capture_status = "degraded"
                self.heartbeat_once()
                self.stop_event.wait(5)
                continue
            self.capture_status = "online"
            with self.lock:
                self.sequence += 1
                seq = self.sequence
            metadata = capture_once(self.config, seq)
            if metadata:
                self.last_capture = metadata["capture_finished_at"]
            else:
                self.capture_status = "degraded"
            self.stop_event.wait(1)

    def _retry(self, meta_path: Path, metadata: dict[str, Any], error: str) -> None:
        attempts = int(metadata.get("attempts") or 0)
        delay = backoff_seconds(attempts, int(self.config.agent["upload_max_interval_seconds"]))
        metadata["state"] = STATE_RETRY_WAIT
        metadata["next_attempt_at"] = (datetime.now(UTC).timestamp() + delay)
        metadata["error"] = error[:500]
        write_spool_metadata_atomic(meta_path, metadata)
        self.upload_failures += 1
        self.upload_status = STATE_RETRY_WAIT

    def _process_upload(self, meta_path: Path, metadata: dict[str, Any]) -> bool:
        """Run the upload FSM for a single spool manifest. Returns True if the
        segment reached ``uploaded``."""
        pcap_path = resolve_pcap(meta_path)
        if metadata.get("state") == STATE_UPLOADED or not pcap_path:
            return False
        if metadata.get("state") in (STATE_AUTH_ERROR, STATE_QUARANTINED):
            return False
        if metadata.get("state") == STATE_RETRY_WAIT:
            try:
                next_at = float(metadata.get("next_attempt_at") or 0)
            except (TypeError, ValueError):
                next_at = 0
            if datetime.now(UTC).timestamp() < next_at:
                return False
        metadata["state"] = STATE_UPLOADING
        metadata["attempts"] = int(metadata.get("attempts") or 0) + 1
        metadata["last_attempt_at"] = now_iso()
        write_spool_metadata_atomic(meta_path, metadata)
        try:
            result = http_upload(pcap_path, metadata, int(self.probe_id), self.token, self.config)
            metadata["state"] = STATE_UPLOADED
            metadata["backend_id"] = result.get("id")
            metadata["task_id"] = result.get("task_id")
            metadata["uploaded_at"] = now_iso()
            metadata["error"] = ""
            write_spool_metadata_atomic(meta_path, metadata)
            self.last_upload = now_iso()
            self.upload_failures = 0
            self.upload_status = STATE_UPLOADED
            self.auth_error = False
            return True
        except urllib.error.HTTPError as exc:
            if exc.code in (401, 403):
                metadata["state"] = STATE_AUTH_ERROR
                metadata["error"] = f"auth_error: HTTP {exc.code}"
                write_spool_metadata_atomic(meta_path, metadata)
                self.auth_error = True
                self.upload_status = STATE_AUTH_ERROR
            elif exc.code in PERMANENT_HTTP:
                metadata["state"] = STATE_QUARANTINED
                metadata["error"] = f"permanent: HTTP {exc.code}"
                write_spool_metadata_atomic(meta_path, metadata)
                self.upload_status = STATE_QUARANTINED
            elif exc.code in TRANSIENT_HTTP:
                self._retry(meta_path, metadata, f"HTTP {exc.code}")
            else:
                self._retry(meta_path, metadata, f"HTTP {exc.code}")
        except (ConnectionResetError, TimeoutError, urllib.error.URLError, socket.timeout) as exc:
            self._retry(meta_path, metadata, f"{type(exc).__name__}: {exc}")
        except Exception as exc:
            self._retry(meta_path, metadata, f"{type(exc).__name__}: {exc}")
        return False

    def upload_loop(self) -> None:
        while not self.stop_event.is_set():
            if not self.probe_id:
                self.stop_event.wait(2)
                continue
            if self.auth_error:
                self.upload_status = STATE_AUTH_ERROR
                self.stop_event.wait(10)
                continue
            uploaded_any = False
            for meta_path in spool_pending(self.config.spool_path()):
                metadata = spool_metadata(meta_path)
                if self._process_upload(meta_path, metadata):
                    uploaded_any = True
            if uploaded_any:
                self.cleanup_uploaded()
                self.stop_event.wait(1)
            else:
                self.stop_event.wait(backoff_seconds(self.upload_failures, int(self.config.agent["upload_max_interval_seconds"])))

    def cleanup_uploaded(self) -> None:
        retention = int(self.config.spool["retention_seconds"])
        for meta_path in spool_pending(self.config.spool_path()):
            metadata = spool_metadata(meta_path)
            if metadata.get("state") != STATE_UPLOADED:
                continue
            uploaded = metadata.get("uploaded_at", "")
            try:
                age = (datetime.now(UTC) - datetime.fromisoformat(uploaded)).total_seconds()
            except Exception:
                age = 0
            if age >= retention:
                resolve_pcap(meta_path) and resolve_pcap(meta_path).unlink(missing_ok=True)
                meta_path.unlink(missing_ok=True)

    def asset_loop(self) -> None:
        interval = int(self.config.agent["asset_interval_seconds"])
        if interval <= 0:
            return
        while not self.stop_event.is_set():
            try:
                services = detect_configured_services([int(item) for item in self.config.agent["ports"]], local_ip(self.config.capture["interface"]))
                metadata = {"services": services, "hostname": socket.gethostname(), "ip": local_ip(self.config.capture["interface"]), "agent_version": AGENT_VERSION, "capture_status": self.capture_status, "upload_status": self.upload_status}
                if self.probe_id:
                    http_json(f"{self.config.base_url()}/api/v1/probes/{self.probe_id}/heartbeat", {"status": "online", "metadata": metadata}, self.headers(), self.config)
            except Exception:
                pass
            self.stop_event.wait(interval)

    def file_loop(self) -> None:
        interval = int(self.config.agent["file_interval_seconds"])
        if interval <= 0 or not self.config.agent["paths"]:
            return
        state_dir = self.config.spool_path() / 'agent-state'
        state_dir.mkdir(parents=True, exist_ok=True)
        manifest = state_dir / 'uploaded-files.json'
        try:
            uploaded: set[str] = set(json.loads(manifest.read_text(encoding='utf-8')))
        except (OSError, ValueError):
            uploaded = set()
        while not self.stop_event.is_set():
            try:
                files = file_records([Path(item) for item in self.config.agent["paths"]], int(self.config.agent["max_files"]))
                for record in files:
                    if record["sha256"] in uploaded or not self.probe_id:
                        continue
                    try:
                        meta = {
                            "name": record["name"],
                            "path": record["path"],
                            "size": record["size"],
                            "sha256": record["sha256"],
                            "md5": record["md5"],
                            "file_type": record["file_type"],
                            "agent_version": AGENT_VERSION,
                        }
                        result = http_upload_file(Path(record["path"]), meta, int(self.probe_id), self.token, self.config)
                        uploaded.add(record["sha256"])
                        tmp = manifest.with_suffix('.tmp')
                        tmp.write_text(json.dumps(sorted(uploaded)[-10000:]), encoding='utf-8')
                        os.replace(tmp, manifest)
                        if result.get("id"):
                            self.uploaded_files.append(record["sha256"])
                    except Exception:
                        pass
                if self.probe_id:
                    http_json(f"{self.config.base_url()}/api/v1/probes/{self.probe_id}/heartbeat", {"status": "online", "metadata": {"file_inventory": files, "capture_status": self.capture_status, "upload_status": self.upload_status}}, self.headers(), self.config)
            except Exception:
                pass
            self.stop_event.wait(interval)

    def heartbeat_loop(self) -> None:
        interval = max(1, int(self.config.agent["heartbeat_seconds"]))
        while not self.stop_event.is_set():
            self.heartbeat_once()
            self.stop_event.wait(interval)

    def _default_targets(self) -> list[str]:
        return [str(t) for t in (self.config.scan.get('targets') or []) if str(t).strip()]

    def _spool_report(self, state_dir: Path, name: str, report: dict[str, Any]) -> None:
        """Write a report atomically so a crash cannot upload half a JSON file."""
        target = state_dir / name
        tmp = target.with_suffix('.tmp')
        tmp.write_text(json.dumps(report), encoding='utf-8')
        os.replace(tmp, target)

    def _upload_pending(self, pending: Path, endpoint: str) -> None:
        if not pending.exists():
            return
        report = json.loads(pending.read_text(encoding='utf-8'))
        http_json(f'{self.config.base_url()}/api/v1/probes/{self.probe_id}/{endpoint}', report, self.headers(), self.config)
        pending.unlink()

    def _next_command(self) -> dict[str, Any] | None:
        req = urllib.request.Request(f'{self.config.base_url()}/api/v1/probes/{self.probe_id}/commands', headers=self.headers())
        with urllib.request.urlopen(req, context=ssl_context(self.config), timeout=30) as response:
            commands = json.load(response).get('commands', [])
        return commands[0] if commands else None

    def _job_stop_event(self, task_id):
        agent = self

        class JobStop:
            stopped = False
            checked = 0.0

            def is_set(self):
                if agent.stop_event.is_set() or self.stopped:
                    return True
                if task_id and time.monotonic() - self.checked >= 3:
                    self.checked = time.monotonic()
                    try:
                        req = urllib.request.Request(
                            f'{agent.config.base_url()}/api/v1/probes/{agent.probe_id}/command-status?task_id={task_id}',
                            headers=agent.headers())
                        with urllib.request.urlopen(req, context=ssl_context(agent.config), timeout=2) as response:
                            self.stopped = bool(json.load(response).get('stop'))
                    except urllib.error.HTTPError as exc:
                        self.stopped = exc.code in (401, 403, 404)
                    except (OSError, ValueError):
                        pass  # Local deadline still bounds a job during a network outage.
                return self.stopped

        return JobStop()

    def _run_scan_job(self, state_dir: Path, config: dict[str, Any], task_id: int | None) -> None:
        try:
            report = scan_network(config, self._job_stop_event(task_id))
        except Exception as exc:
            report = {'assets': [], 'complete': False, 'error': str(exc)[:500]}
        report.update(report_id=uuid.uuid4().hex, task_id=task_id)
        self._spool_report(state_dir, 'inventory.pending.json', report)

    def _run_data_asset_job(self, state_dir: Path, config: dict[str, Any], task_id: int | None) -> None:
        merged = {**self.config.data_assets, **(config or {})}
        if not merged.get('paths'):
            merged['paths'] = self.config.data_assets.get('paths') or []
        # Pin the rule/engine snapshot for this whole task: a hot update published
        # while the scan runs applies to the next task, so one report never mixes
        # two rule versions.
        use_engine(self.ruleset.engine_snapshot())
        # The cache key includes the rule version, so pinning it here is what makes
        # an unchanged file a hit until the rules actually change.
        merged['ruleset_version'] = self.ruleset.snapshot_version()
        # One scan_id per job, carried into the spooled report so a retry after an
        # ACK loss re-sends the same identity instead of inventing a second scan.
        merged['scan_id'] = uuid.uuid4().hex
        if task_id:
            merged['profile_version'] = str(merged.get('profile_version') or '')
        try:
            report = discover_data_assets(
                merged, self._job_stop_event(task_id),
                on_progress=lambda coverage, path: self._report_progress(
                    task_id, merged['scan_id'], coverage, path))
        except Exception as exc:
            report = {'assets': [], 'databases': [], 'scanned_paths': [], 'complete': False,
                      'error': str(exc)[:500], 'observed_at': now_iso(), 'scanner': 'probe-file-inventory'}
        report.update(report_id=uuid.uuid4().hex, task_id=task_id,
                      scan_id=merged['scan_id'],
                      ruleset_version=self.ruleset.snapshot_version(),
                      engine_version=self.ruleset.status.engine_version)
        self._spool_report(state_dir, 'data-assets.pending.json', guard_report(report))

    def _report_progress(self, task_id: int | None, scan_id: str, coverage: dict[str, Any] | None,
                         current_path: str = '') -> None:
        """Push aggregated progress for one running job; failure is never fatal.

        Progress is a convenience for the operator: it can never fail the scan and
        it can never move a task into a terminal state. The platform applies the
        same rule on its side.
        """
        if not task_id:
            return
        payload: dict[str, Any] = {'task_id': task_id, 'scan_id': scan_id,
                                   'current_path': str(current_path or '')[:1024]}
        if coverage:
            payload['coverage'] = coverage
        try:
            http_json(f'{self.config.base_url()}/api/v1/probes/{self.probe_id}/data-assets/progress',
                      payload, self.headers(), self.config, timeout=5)
        except Exception:
            pass

    def inventory_loop(self) -> None:
        """Run scheduled and platform-queued network scans / data asset collection."""
        scan_cfg = self.config.scan
        data_cfg = self.config.data_assets
        remote_allowed = bool(scan_cfg.get('allow_remote')) or bool(data_cfg.get('allow_remote'))
        scheduled_scan = bool(scan_cfg.get('enabled'))
        scheduled_data = bool(data_cfg.get('enabled'))
        if not (remote_allowed or scheduled_scan or scheduled_data):
            return
        state_dir = self.config.spool_path() / 'agent-state'
        state_dir.mkdir(parents=True, exist_ok=True)
        pending_scan = state_dir / 'inventory.pending.json'
        pending_data = state_dir / 'data-assets.pending.json'
        next_scan = 0.0
        next_data = 0.0
        next_ruleset = 0.0
        ruleset_config = self.config.ruleset
        while not self.stop_event.is_set():
            try:
                self._upload_pending(pending_scan, 'inventory')
                self._upload_pending(pending_data, 'data-assets')
                if time.monotonic() >= next_ruleset:
                    self.ruleset.sync()
                    next_ruleset = time.monotonic() + max(60, int(ruleset_config.get('poll_seconds', 900)))
                if remote_allowed:
                    job = self._next_command()
                    if job:
                        kind = job.get('kind')
                        if kind == 'data_asset_scan':
                            self._run_data_asset_job(state_dir, job.get('config') or {}, job.get('id'))
                            self._upload_pending(pending_data, 'data-assets')
                        elif kind == 'asset_scan':
                            self._run_scan_job(state_dir, job.get('config') or {}, job.get('id'))
                            self._upload_pending(pending_scan, 'inventory')
                if scheduled_scan and time.monotonic() >= next_scan:
                    self._run_scan_job(state_dir, scan_cfg, None)
                    self._upload_pending(pending_scan, 'inventory')
                    next_scan = time.monotonic() + max(60, int(scan_cfg.get('interval_seconds', 3600)))
                if scheduled_data and time.monotonic() >= next_data:
                    self._run_data_asset_job(state_dir, {}, None)
                    self._upload_pending(pending_data, 'data-assets')
                    next_data = time.monotonic() + max(60, int(data_cfg.get('interval_seconds', 3600)))
            except Exception as exc:
                print(f'probe inventory upload/scan retry: {type(exc).__name__}', file=sys.stderr)
            self.stop_event.wait(max(2, min(int(scan_cfg.get('poll_seconds', 30)), int(data_cfg.get('poll_seconds', 30)))))

    def run(self) -> int:
        self.config.ensure()
        try:
            self.register()
        except Exception as exc:
            print(f"probe registration failed: {exc}", file=sys.stderr)
            return 1
        if not self.probe_id:
            print("probe registration failed", file=sys.stderr)
            return 1
        threads = [
            threading.Thread(target=self.capture_loop, name="capture", daemon=True),
            threading.Thread(target=self.upload_loop, name="upload", daemon=True),
            threading.Thread(target=self.heartbeat_loop, name="heartbeat", daemon=True),
            threading.Thread(target=self.asset_loop, name="assets", daemon=True),
            threading.Thread(target=self.file_loop, name="files", daemon=True),
            threading.Thread(target=self.inventory_loop, name="inventory", daemon=True),
        ]
        for thread in threads:
            thread.start()
        try:
            while not self.stop_event.is_set():
                time.sleep(1)
        except KeyboardInterrupt:
            self.stop_event.set()
        return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Data Security Toolbox Probe daemon")
    parser.add_argument("--config", default="/etc/data-security-toolbox/probe.toml", help="TOML config path")
    args = parser.parse_args()
    return ProbeAgent(Config(Path(args.config))).run()


if __name__ == "__main__":
    raise SystemExit(main())
