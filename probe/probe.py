#!/usr/bin/env python3
"""Data Security Toolbox Probe daemon."""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import platform
import shutil
import socket
import stat
import subprocess
import sys
import threading
import time
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


AGENT_VERSION = "3.0.0"
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
        "token_path": "/etc/data-security-toolbox/probe.token",
        "ports": [22, 80, 443, 445, 3306, 5432, 6379, 8080],
        "paths": [],
        "max_files": 50,
        "demo": False,
    },
}


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

    def spool_path(self) -> Path:
        return Path(self.spool["path"]).expanduser()

    def ensure(self) -> None:
        self.spool_path().mkdir(parents=True, exist_ok=True)
        token_path = Path(self.agent["token_path"])
        token_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.chmod(token_path.parent, 0o700)
        except OSError:
            pass


def load_token(config: Config) -> str:
    token_path = Path(config.agent["token_path"])
    if token_path.exists():
        return token_path.read_text(encoding="utf-8").strip()
    return ""


def save_token(config: Config, token: str) -> None:
    token_path = Path(config.agent["token_path"])
    token_path.write_text(token, encoding="utf-8")
    os.chmod(token_path, stat.S_IRUSR | stat.S_IWUSR)


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


def write_spool_metadata(path: Path, metadata: dict[str, Any]) -> None:
    path.write_text(json.dumps(metadata, ensure_ascii=False, indent=2), encoding="utf-8")


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


def capture_command(config: Config, partial: Path) -> list[str]:
    interface = config.capture["interface"]
    duration = int(config.capture["segment_seconds"])
    max_mb = int(config.capture["segment_max_mb"])
    dumpcap = shutil.which("dumpcap")
    if dumpcap:
        return [dumpcap, "-i", interface, "-a", f"duration:{duration}", "-a", f"filesize:{max_mb * 1024}", "-w", str(partial), "-q"]
    tcpdump = shutil.which("tcpdump")
    if tcpdump:
        return [tcpdump, "-i", interface, "-w", str(partial), "-U"]
    return []


def capture_once(config: Config, sequence: int) -> dict[str, Any] | None:
    spool = config.spool_path()
    started = datetime.now(UTC)
    stamp = started.strftime("%Y%m%dT%H%M%S%fZ")
    final = spool / f"{stamp}-{sequence:06d}.pcapng"
    partial = final.with_suffix(final.suffix + ".partial")
    command = capture_command(config, partial)
    if not command:
        return None
    process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
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
        if not partial.exists() or partial.stat().st_size == 0:
            return None
        partial.replace(final)
        finished = datetime.now(UTC)
        metadata = {
            "segment_id": final.name,
            "sequence": sequence,
            "interface": config.capture["interface"],
            "capture_started_at": started.isoformat(),
            "capture_finished_at": finished.isoformat(),
            "size": final.stat().st_size,
            "sha256": sha256_file(final),
            "packet_drop": 0,
            "state": "pending",
            "attempts": 0,
        }
        write_spool_metadata(final.with_suffix(".json"), metadata)
        return metadata
    finally:
        if partial.exists():
            partial.unlink(missing_ok=True)


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
    if attempts <= len(sequence):
        return min(sequence[max(0, attempts - 1)], maximum)
    return min(sequence[-1] * 2 ** (attempts - len(sequence)), maximum)


class ProbeAgent:
    def __init__(self, config: Config) -> None:
        self.config = config
        self.stop_event = threading.Event()
        self.probe_id: int | None = None
        self.token = load_token(config)
        self.sequence = 0
        self.last_capture = ""
        self.last_upload = ""
        self.capture_status = "online"
        self.upload_failures = 0
        self.lock = threading.Lock()

    def headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.probe_id:
            headers["X-Probe-ID"] = str(self.probe_id)
        if self.token:
            headers["X-Probe-Token"] = self.token
        return headers

    def register(self) -> None:
        if self.token and self.probe_id:
            return
        bootstrap = str(self.config.agent.get("bootstrap_token") or "")
        headers = {"X-Probe-Bootstrap-Token": bootstrap} if bootstrap else {}
        info = {
            "name": socket.gethostname(),
            "hostname": socket.gethostname(),
            "ip_address": local_ip(self.config.capture["interface"]),
            "metadata": {"system": system_metrics(), "agent_version": AGENT_VERSION, "interface": self.config.capture["interface"]},
        }
        result = http_json(f"{self.config.base_url()}/api/v1/probes/register", info, headers, self.config)
        self.probe_id = int(result["id"])
        if result.get("token"):
            self.token = result["token"]
            save_token(self.config, self.token)

    def heartbeat_once(self) -> None:
        if not self.probe_id:
            return
        metadata = {
            "system": system_metrics(),
            "agent_version": AGENT_VERSION,
            "interface": self.config.capture["interface"],
            "spool_size_mb": round(spool_size_mb(self.config.spool_path()), 2),
            "pending_segments": len(spool_pending(self.config.spool_path())),
            "last_capture": self.last_capture,
            "last_upload": self.last_upload,
            "capture_status": self.capture_status,
        }
        try:
            http_json(f"{self.config.base_url()}/api/v1/probes/{self.probe_id}/heartbeat", {"status": "online", "metadata": metadata}, self.headers(), self.config)
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

    def upload_loop(self) -> None:
        while not self.stop_event.is_set():
            if not self.probe_id:
                self.stop_event.wait(2)
                continue
            uploaded_any = False
            for meta_path in spool_pending(self.config.spool_path()):
                metadata = spool_metadata(meta_path)
                pcap_path = meta_path.with_suffix(".pcapng")
                if metadata.get("state") == "uploaded" or not pcap_path.exists():
                    continue
                if metadata.get("state") == "uploading":
                    metadata["attempts"] = int(metadata.get("attempts") or 0) + 1
                    write_spool_metadata(meta_path, metadata)
                try:
                    result = http_upload(pcap_path, metadata, int(self.probe_id), self.token, self.config)
                    metadata["state"] = "uploaded"
                    metadata["backend_id"] = result.get("id")
                    metadata["task_id"] = result.get("task_id")
                    metadata["uploaded_at"] = now_iso()
                    write_spool_metadata(meta_path, metadata)
                    self.last_upload = now_iso()
                    self.upload_failures = 0
                    uploaded_any = True
                except urllib.error.HTTPError as exc:
                    if exc.code in {429, 500, 502, 503, 504}:
                        self.upload_failures += 1
                        break
                    metadata["state"] = "failed"
                    metadata["error"] = str(exc.code)
                    write_spool_metadata(meta_path, metadata)
                except Exception as exc:
                    self.upload_failures += 1
                    metadata["state"] = "pending"
                    metadata["error"] = str(exc)[:500]
                    write_spool_metadata(meta_path, metadata)
                    break
            if uploaded_any:
                self.cleanup_uploaded()
                self.stop_event.wait(1)
            else:
                self.stop_event.wait(backoff_seconds(self.upload_failures, int(self.config.agent["upload_max_interval_seconds"])))

    def cleanup_uploaded(self) -> None:
        retention = int(self.config.spool["retention_seconds"])
        for meta_path in spool_pending(self.config.spool_path()):
            metadata = spool_metadata(meta_path)
            if metadata.get("state") != "uploaded":
                continue
            uploaded = metadata.get("uploaded_at", "")
            try:
                age = (datetime.now(UTC) - datetime.fromisoformat(uploaded)).total_seconds()
            except Exception:
                age = 0
            if age >= retention:
                meta_path.with_suffix(".pcapng").unlink(missing_ok=True)
                meta_path.unlink(missing_ok=True)

    def asset_loop(self) -> None:
        interval = int(self.config.agent["asset_interval_seconds"])
        if interval <= 0:
            return
        while not self.stop_event.is_set():
            try:
                services = detect_configured_services([int(item) for item in self.config.agent["ports"]], local_ip(self.config.capture["interface"]))
                metadata = {"services": services, "hostname": socket.gethostname(), "ip": local_ip(self.config.capture["interface"]), "agent_version": AGENT_VERSION, "capture_status": self.capture_status}
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
                    http_json(f"{self.config.base_url()}/api/v1/probes/{self.probe_id}/heartbeat", {"status": "online", "metadata": {"file_inventory": files, "capture_status": self.capture_status}}, self.headers(), self.config)
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
        self.register()
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
