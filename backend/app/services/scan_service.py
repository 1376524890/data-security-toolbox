"""Active network scanning (nmap) for information-security assessment.

The toolbox historically only observed traffic/files passively. This module
adds active discovery + host scanning so a registered probe/backend can assess
the whole network segment: find live hosts, enumerate open services, and feed
the results into the asset / compliance / threat-intel (CVE) pipeline.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from typing import Any


def _nmap(args: list[str], timeout: int = 300) -> str:
    if not shutil.which("nmap"):
        return ""
    try:
        proc = subprocess.run(["nmap", *args], capture_output=True, text=True, timeout=timeout)
        return proc.stdout or ""
    except Exception:
        return ""


def discover_hosts(target: str, timeout: int = 120) -> list[str]:
    """Ping-sweep a target (single host, IP, or CIDR) and return live host IPs."""
    out = _nmap(["-sn", "-oX", "-", target], timeout)
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
            hosts.append(addr.get("addr"))
    return hosts


def scan_host(host: str, top_ports: int = 1000, timeout: int = 300) -> list[dict[str, Any]]:
    """Service/version scan a single host; return open services with product/version."""
    out = _nmap(["-sV", "--top-ports", str(top_ports), "-oX", "-", host], timeout)
    if not out:
        return []
    try:
        root = ET.fromstring(out)
    except ET.ParseError:
        return []
    services: list[dict[str, Any]] = []
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
        })
    return services


def is_subnet(target: str) -> bool:
    """Heuristic: a target that contains '/' or a dash range is a discovery target."""
    return "/" in target or "-" in target
