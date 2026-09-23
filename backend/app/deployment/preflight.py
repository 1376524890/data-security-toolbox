"""Host preflight checks executed over SSH before a Probe deployment."""

from __future__ import annotations

import re
from typing import Any

from app.core.config import settings
from app.deployment.package import PackageError
from app.deployment.runtime import check_runtime
from app.deployment.ssh_client import SshClient, SshError


def _run(ssh: SshClient, command: str) -> tuple[int, str]:
    rc, out, err = ssh.exec(command)
    return rc, (out or err).strip()


def _os_name(os_release: str) -> str:
    match = re.search(r"^ID=(.+)$", os_release, re.MULTILINE)
    if not match:
        return "unknown"
    return match.group(1).strip().strip("\"'").lower()


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

    _, interfaces = _run(ssh, "ls /sys/class/net 2>/dev/null")
    all_ifaces = [
        line.strip() for line in interfaces.splitlines() if line.strip() and line.strip() != "lo"
    ]
    # ``ls /sys/class/net`` lists dead ports too. A host with wifi plus an
    # unplugged ethernet port used to hand the ethernet port to the capture
    # picker (alphabetically first), so the probe watched a NIC that carries no
    # traffic and recorded nothing. Only offer NICs the kernel reports as up.
    _, states = _run(
        ssh,
        "for n in $(ls /sys/class/net 2>/dev/null); do "
        "[ \"$n\" = lo ] && continue; "
        "echo \"$n $(cat /sys/class/net/$n/operstate 2>/dev/null)\"; done",
    )
    up_ifaces: list[str] = []
    for line in states.splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1] == "up" and parts[0] != "lo":
            up_ifaces.append(parts[0])
    # Prefer up NICs, but never fail a host whose driver reports operstate as
    # "unknown" (some virtual/wifi stacks do): fall back to every non-loopback.
    iface_list = [name for name in all_ifaces if name in set(up_ifaces)] or all_ifaces
    add(
        "interface",
        "non-loopback NIC that is up",
        ", ".join(iface_list[:5]) or "none",
        bool(iface_list),
    )

    _, sudo = _run(ssh, "sudo -n true 2>&1 && echo sudo-ok || echo no-sudo")
    sudo_ok = "sudo-ok" in sudo or (ssh.username == "root")
    add("sudo", "root or passwordless sudo", "ok" if sudo_ok else "unavailable", sudo_ok)

    backend_url = backend_url or settings.deployment_backend_url
    runtime = {}
    runtime_error = ""
    try:
        runtime = check_runtime(ssh, arch_norm, backend_url)
    except (PackageError, SshError) as exc:
        runtime_error = str(exc)
    python_version = str(runtime.get("python", "unavailable"))
    capture_tool = str(runtime.get("capture_tool", ""))
    runtime_ok = bool(runtime.get("ok"))
    connectivity_ok = bool(runtime.get("connectivity"))
    add("python", "bundled Python 3.11 (host Python not required)", python_version, runtime_ok,
        runtime_error or str(runtime.get("error", "")))
    add("capture_tool", "bundled dumpcap + tcpdump", capture_tool or "unavailable", runtime_ok)
    add("backend_connectivity", "HTTP(S) reachable using bundled Python",
        "ok" if connectivity_ok else "unreachable", connectivity_ok,
        runtime_error or str(runtime.get("error", "")))

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
        "all_interfaces": all_ifaces,
        "backend_connectivity": connectivity_ok,
        "backend_url": backend_url,
        "sudo": sudo_ok,
        "capability_score": capability_score,
        "recommended_profile": recommended_profile,
        "estimated_spool_time": None,
    }
