"""Host preflight checks executed over SSH before a Probe deployment."""

from __future__ import annotations

import re
import json
from typing import Any

from app.core.config import settings
from app.deployment.ssh_client import SshClient, SshError


def _run(ssh: SshClient, command: str) -> tuple[int, str]:
    rc, out, err = ssh.exec(command)
    return rc, (out or err).strip()


def _os_name(os_release: str) -> str:
    match = re.search(r"^ID=(.+)$", os_release, re.MULTILINE)
    if not match:
        return "unknown"
    return match.group(1).strip().strip("\"'").lower()


def _python_ok(python_version: str) -> tuple[bool, str]:
    match = re.match(r"Python (\d+)\.(\d+)", python_version)
    if not match:
        return False, python_version
    major, minor = int(match.group(1)), int(match.group(2))
    ok = (major, minor) >= (3, 11)
    return ok, python_version


def run_preflight(ssh: SshClient, profile: str | None = None, backend_url: str | None = None) -> dict[str, Any]:
    """Collect host facts and return a preflight report (no secrets)."""
    checks: list[dict[str, Any]] = []

    def add(name: str, required: str, actual: str, ok: bool, reason: str = "") -> None:
        checks.append({"name": name, "actual": actual, "required": required, "pass": ok, "reason": reason})

    _, os_release = _run(ssh, "cat /etc/os-release 2>/dev/null")
    _, arch_raw = _run(ssh, "uname -m 2>/dev/null")
    arch = arch_raw.lower()
    arch_norm = "amd64" if arch in {"x86_64", "amd64"} else ("arm64" if arch in {"aarch64", "arm64"} else arch)
    os_name = _os_name(os_release)

    _, python_raw = _run(ssh, "python3 --version 2>&1 || true")
    python_ok, python_version = _python_ok(python_raw)
    add("python", ">=3.11", python_version, python_ok)

    _, pid1 = _run(ssh, "ps -p 1 -o comm= 2>/dev/null || echo none")
    systemd_ok = pid1 == "systemd"
    add("systemd", "systemd as PID 1", pid1, systemd_ok)

    _, mem_raw = _run(ssh, "free -m 2>/dev/null | awk 'NR==2{print $2}' || echo 0")
    try:
        mem_mb = int(mem_raw.split()[0])
    except (ValueError, IndexError):
        mem_mb = 0
    mem_ok = mem_mb >= 2048
    add("memory", ">=2048 MB", f"{mem_mb} MB", mem_ok)

    _, disk_raw = _run(ssh, "df -P /var 2>/dev/null | awk 'NR==2{print $4}' || echo 0")
    try:
        disk_kb = int(disk_raw.split()[0])
    except (ValueError, IndexError):
        disk_kb = 0
    disk_mb = disk_kb // 1024
    disk_ok = disk_mb >= 1024
    add("disk", ">=1024 MB free", f"{disk_mb} MB", disk_ok)

    _, capture_tools = _run(ssh, "command -v dumpcap 2>/dev/null; command -v tcpdump 2>/dev/null")
    capture_tool = "dumpcap" if "dumpcap" in capture_tools else ("tcpdump" if "tcpdump" in capture_tools else "")
    add("capture_tool", "dumpcap|tcpdump", capture_tool or "none", bool(capture_tool))

    _, interfaces = _run(ssh, "ls /sys/class/net 2>/dev/null")
    iface_list = [line for line in interfaces.splitlines() if line and line not in {"lo"}]
    add("interface", "non-loopback NIC", ", ".join(iface_list[:5]) or "none", bool(iface_list))

    _, sudo = _run(ssh, "sudo -n true 2>&1 && echo sudo-ok || echo no-sudo")
    sudo_ok = "sudo-ok" in sudo or (ssh.username == "root")
    add("sudo", "root or passwordless sudo", "ok" if sudo_ok else "unavailable", sudo_ok)

    backend_url = backend_url or settings.deployment_backend_url
    connectivity_ok = False
    connectivity_detail = ""
    if backend_url:
        rc, out = _run(
            ssh,
            "python3 - <<'PY'\n"
            "import socket, urllib.request\n"
            "try:\n"
            f"    host = {json.dumps(backend_url.rstrip('/') + '/api/v1/health')}\n"
            "    socket.setdefaulttimeout(10)\n"
            "    urllib.request.urlopen(host, timeout=10)\n"
            "    print('ok')\n"
            "except Exception as e:\n"
            "    print('fail:', type(e).__name__)\n"
            "PY",
        )
        connectivity_ok = "ok" in out
        connectivity_detail = out
    else:
        connectivity_detail = "backend_url not configured"
    add("backend_connectivity", "HTTP(S) reachable", connectivity_detail[:200], connectivity_ok)

    compatible = all(item["pass"] for item in checks if item["name"] != "backend_connectivity") and connectivity_ok
    capability_score = 100 if compatible else max(0, sum(10 for item in checks if item["pass"]))
    recommended_profile = "sensor" if compatible and capture_tool else ("standard" if compatible else "lite")
    if profile:
        recommended_profile = profile
    return {
        "compatible": compatible,
        "checks": checks,
        "os": os_name,
        "arch": arch_norm,
        "python": python_version,
        "cpu": "",
        "memory_mb": mem_mb,
        "disk_mb": disk_mb,
        "capture_tool": capture_tool,
        "interfaces": iface_list,
        "backend_connectivity": connectivity_ok,
        "backend_url": backend_url,
        "sudo": sudo_ok,
        "capability_score": capability_score,
        "recommended_profile": recommended_profile,
        "estimated_spool_time": None,
    }
