#!/usr/bin/env python3
"""Low-resource single-process collection agent for Data Security Toolbox."""

import argparse
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests
except ImportError:
    requests = None


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            return sock.getsockname()[0]
    except Exception:
        return socket.gethostbyname(socket.gethostname())


def system_info() -> dict[str, Any]:
    info: dict[str, Any] = {
        "hostname": socket.gethostname(),
        "os": platform.platform(),
        "python": platform.python_version(),
        "collected_at": now_iso(),
    }
    if psutil:
        info.update({
            "cpu_percent": psutil.cpu_percent(interval=0.5),
            "memory_percent": psutil.virtual_memory().percent,
            "memory_available_mb": round(psutil.virtual_memory().available / 1024 / 1024, 1),
        })
    return info


def detect_services(ports: list[int], host: str = "") -> list[dict[str, Any]]:
    target = host or local_ip()
    services = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        try:
            sock.connect_ex((target, port))
            services.append({"port": port, "service": socket.getservbyport(port, "tcp") if port > 0 else "", "protocol": "tcp"})
        finally:
            sock.close()
    return services


def file_records(paths: list[Path]) -> list[dict[str, Any]]:
    records = []
    for root in paths:
        if not root.exists():
            continue
        candidates = root.rglob("*") if root.is_dir() else [root]
        for item in candidates:
            if not item.is_file() or item.stat().st_size > 500 * 1024 * 1024:
                continue
            digest = hashlib.sha256()
            try:
                with item.open("rb") as handle:
                    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                        digest.update(chunk)
                records.append({"name": item.name, "path": str(item), "size": item.stat().st_size, "sha256": digest.hexdigest()})
            except OSError:
                continue
    return records


def capture_pcap(output: Path, interface: str, count: int = 1000, timeout: int = 10) -> Path | None:
    if shutil.which("tcpdump"):
        cmd = ["tcpdump", "-i", interface, "-c", str(count), "-w", str(output), "-Z", "nobody"]
        try:
            subprocess.run(cmd, timeout=timeout, check=False)
            return output if output.exists() and output.stat().st_size > 0 else None
        except Exception:
            return None
    return None


def post_json(url: str, payload: dict[str, Any], token: str, timeout: int = 30) -> dict[str, Any]:
    headers = {"Content-Type": "application/json", "X-Probe-Token": token}
    if requests:
        response = requests.post(url, json=payload, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.json()
    import urllib.request
    request = urllib.request.Request(url, data=json.dumps(payload).encode(), headers=headers)
    with urllib.request.urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode())


def post_file(url: str, path: Path, probe_id: int, token: str, timeout: int = 120) -> dict[str, Any]:
    headers = {"X-Probe-Token": token}
    if requests:
        with path.open("rb") as handle:
            response = requests.post(url, files={"file": (path.name, handle)}, data={"probe_id": str(probe_id)}, headers=headers, timeout=timeout)
        response.raise_for_status()
        return response.json()
    raise RuntimeError("requests is required for file upload")


def run(args: argparse.Namespace) -> int:
    base = args.base.rstrip("/")
    probe_info = {
        "name": args.name,
        "hostname": socket.gethostname(),
        "ip_address": local_ip(),
        "metadata": {
            "system": system_info(),
            "services": detect_services(args.ports),
            "files": file_records([Path(path) for path in args.paths]),
            "public_exposed": args.public_exposed,
        },
    }
    try:
        registered = post_json(f"{base}/api/v1/probes/register", probe_info, args.token)
        probe_id = registered["id"]
    except Exception as exc:
        print(f"register failed: {exc}", file=sys.stderr)
        return 1
    if args.upload_files:
        uploaded = 0
        for item in probe_info["metadata"].get("files", [])[: args.max_files]:
            try:
                post_file(f"{base}/api/v1/files/upload", Path(item["path"]), probe_id, args.token)
                uploaded += 1
            except Exception as exc:
                print(f"file upload failed: {exc}", file=sys.stderr)
        print(f"uploaded files: {uploaded}")
    if args.capture:
        output = Path(args.capture_output)
        captured = capture_pcap(output, args.interface, args.packet_count, args.capture_timeout)
        if captured:
            payload = {"probe_id": probe_id, "filename": captured.name, "path": str(captured), "size": captured.stat().st_size, "sha256": hashlib.sha256(captured.read_bytes()).hexdigest()}
            try:
                post_file(f"{base}/api/v1/pcaps/upload", captured, probe_id, args.token)
                post_json(f"{base}/api/v1/probes/{probe_id}/heartbeat", {"status": "online", "metadata": {"last_pcap": payload}}, args.token)
            except Exception as exc:
                print(f"heartbeat failed: {exc}", file=sys.stderr)
    print(json.dumps({"probe_id": probe_id, "collected_at": now_iso()}, ensure_ascii=False))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Data Security Toolbox Probe")
    parser.add_argument("--base", default="http://localhost:8000", help="backend base URL")
    parser.add_argument("--name", default=socket.gethostname(), help="probe name")
    parser.add_argument("--token", default=os.getenv("PROBE_TOKEN", ""), help="probe token")
    parser.add_argument("--paths", nargs="*", default=[], help="file directories to collect")
    parser.add_argument("--upload-files", action="store_true", help="upload collected files to backend")
    parser.add_argument("--max-files", type=int, default=50, help="maximum files to upload")
    parser.add_argument("--ports", nargs="*", type=int, default=[22, 80, 443, 445, 3306, 5432, 6379, 8080], help="ports to probe")
    parser.add_argument("--capture", action="store_true", help="capture pcap before upload")
    parser.add_argument("--capture-output", default="/tmp/probe-capture.pcap")
    parser.add_argument("--interface", default="eth0")
    parser.add_argument("--packet-count", type=int, default=1000)
    parser.add_argument("--capture-timeout", type=int, default=10)
    parser.add_argument("--public-exposed", action="store_true", help="mark assets as externally exposed")
    return run(parser.parse_args())


if __name__ == "__main__":
    time.sleep(0)
    raise SystemExit(main())
