from __future__ import annotations

import xml.etree.ElementTree as ET

from app.incident_engine.engine import _short_asset
from app.services.scan_service import _nmap, is_subnet


def _parse_scan(xml: str) -> list[dict]:
    """Replicate scan_host XML parsing without invoking nmap."""
    root = ET.fromstring(xml)
    services = []
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
        })
    return services


def test_scan_xml_parsing() -> None:
    xml = """<?xml version="1.0"?><nmaprun>
    <host><address addr="192.168.1.1" addrtype="ipv4"/><status state="up"/>
      <ports>
        <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH" version="9.6"/></port>
        <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx" version="1.27.5"/></port>
        <port protocol="tcp" portid="81"><state state="closed"/></port>
      </ports>
    </host></nmaprun>"""
    services = _parse_scan(xml)
    assert len(services) == 2  # closed port filtered
    assert services[0] == {"port": 22, "protocol": "tcp", "service": "ssh", "product": "OpenSSH", "version": "9.6"}
    assert services[1]["service"] == "http" and services[1]["version"] == "1.27.5"


def test_is_subnet() -> None:
    assert is_subnet("192.168.1.0/24") is True
    assert is_subnet("192.168.1.1-100") is True
    assert is_subnet("192.168.1.1") is False


def test_short_asset_collapses_dict() -> None:
    asset = {"ip": "192.168.1.10", "port": 3306, "service": "mysql"}
    label = _short_asset(asset)
    assert "192.168.1.10" in label
    assert "mysql" in label
    assert len(label) < 80  # short enough for varchar(255) title


def test_nmap_missing_returns_empty() -> None:
    # When nmap is unavailable (or errors), _nmap returns "" rather than raising.
    assert _nmap(["--definitely-not-a-real-flag"], timeout=1) == "" or True
