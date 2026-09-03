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


AGENT_VERSION = "3.1.0"
DEFAULT_CONFIG = {
    "server": {"url": "http://localhost:8000", "verify_tls": True, "ca_file": ""},
    "capture": {"interface": "eth0", "segment_seconds": 30, "segment_max_mb": 64, "enabled": True},
    "spool": {"path": "/var/lib/data-security-toolbox/spool", "max_mb": 2048, "retention_seconds": 86400},
    "agent": {
        "heartbeat_seconds": 30,
        "asset_interval_seconds": 900,
        "file_interval_seconds": 0,
        "upload_interval_seconds": 2,
        "upload_max_interval_seconds": 60,
        "bootstrap_token": "",
        "identity_path": "/etc/data-security-toolbox/probe.identity.json",
        "token_path": "/etc/data-security-toolbox/probe.token",
        "allow_auto_reenroll": False,
        "ports": [22, 80, 443, 445, 3306, 5432, 6379, 8080],
        "paths": [],
        "max_files": 50,
        "demo": False,
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


def local_ip(interface: str = "") -> str:
    if psutil:
        try:
            addresses = psutil.net_if_addrs()
            if interface:
                for addr in addresses.get(interface, []):
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
                services.append({"port": port, "service": service, "protocol": "tcp", "ip": target})
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
            digest = hashlib.sha256()
            with item.open("rb") as handle:
                for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                    digest.update(chunk)
            records.append({"name": item.name, "path": str(item), "size": item.stat().st_size, "sha256": digest.hexdigest()})
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
    interface = config.capture["interface"]
    duration = int(config.capture["segment_seconds"])
    max_mb = int(config.capture["segment_max_mb"])
    dumpcap = shutil.which("dumpcap")
    if dumpcap:
        return "dumpcap", ".pcapng", [dumpcap, "-i", interface, "-a", f"duration:{duration}", "-a", f"filesize:{max_mb * 1024}", "-w", str(partial), "-q"]
    tcpdump = shutil.which("tcpdump")
    if tcpdump:
        return "tcpdump", ".pcap", [tcpdump, "-i", interface, "-w", str(partial), "-U"]
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
    command = capture_command(config, partial)
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


def http_upload(path: Path, metadata: dict[str, Any], probe_id: int, token: str, config: Config, timeout: int = 120) -> dict[str, Any]:
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
    connection.request("POST", "/api/v1/pcaps/upload", body=body_iter(), headers=headers, encode_chunked=True)
    response = connection.getresponse()
    payload = response.read().decode("utf-8", errors="replace")
    connection.close()
    if response.status < 200 or response.status >= 300:
        raise urllib.error.HTTPError(config.base_url(), response.status, response.reason, response.headers, None)
    return json.loads(payload)


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
        self.lock = threading.Lock()

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
        if self.identity.exists():
            # Existing identity wins; never re-enroll/rotate on restart.
            self.probe_id = self.identity.probe_id
            self.token = self.identity.token
            return
        bootstrap = str(self.config.agent.get("bootstrap_token") or "")
        if not bootstrap:
            self.auth_error = True
            raise RuntimeError("probe has no identity and no bootstrap token")
        headers = {"X-Probe-Bootstrap-Token": bootstrap} if bootstrap else {}
        info = {
            "name": socket.gethostname(),
            "hostname": socket.gethostname(),
            "ip_address": local_ip(self.config.capture["interface"]),
            "metadata": {"system": system_metrics(), "agent_version": AGENT_VERSION, "interface": self.config.capture["interface"]},
        }
        result = http_json(f"{self.config.base_url()}/api/v1/probes/register", info, headers, self.config)
        probe_id = int(result["id"])
        token = result.get("token") or self.token
        if not token:
            raise RuntimeError("registration did not return a probe token")
        self.identity.save(probe_id, token, now_iso(), self.config.base_url())
        self.probe_id = probe_id
        self.token = token
        self.auth_error = False

    def heartbeat_once(self) -> None:
        if not self.probe_id:
            return
        spool = self.config.spool_path()
        quarantined = sum(1 for meta_path in spool_pending(spool) if spool_metadata(meta_path).get("state") == STATE_QUARANTINED)
        metrics = system_metrics()
        metadata = {
            "system": metrics,
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
            "agent_version": AGENT_VERSION,
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
        while not self.stop_event.is_set():
            try:
                files = file_records([Path(item) for item in self.config.agent["paths"]], int(self.config.agent["max_files"]))
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
