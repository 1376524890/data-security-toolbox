"""Coverage for the scan engine that no longer depends on ICMP or nmap.

The regression these tests lock in: host discovery used to rely on
``nmap -sn``, which reports ``0 hosts up`` whenever ICMP/ARP is blocked (normal
inside containers), so a scan of a reachable network produced zero assets.
"""
from __future__ import annotations

import socket
import threading

import pytest

from app.services import scan_service


def test_expand_targets_handles_single_cidr_and_ranges() -> None:
    assert scan_service.expand_targets("192.168.1.10") == ["192.168.1.10"]
    assert scan_service.expand_targets("192.168.1.0/30") == ["192.168.1.1", "192.168.1.2"]
    assert scan_service.expand_targets("192.168.1.10-12") == ["192.168.1.10", "192.168.1.11", "192.168.1.12"]
    assert scan_service.expand_targets("192.168.1.10-192.168.1.11") == ["192.168.1.10", "192.168.1.11"]
    assert scan_service.expand_targets("") == []
    assert scan_service.expand_targets("scan-host.local") == ["scan-host.local"]


def test_is_subnet_only_for_ranges() -> None:
    assert scan_service.is_subnet("10.0.0.0/24") is True
    assert scan_service.is_subnet("10.0.0.1-20") is True
    assert scan_service.is_subnet("10.0.0.1") is False


def test_select_ports_prefers_explicit_list_and_deduplicates() -> None:
    assert scan_service.select_ports(5, [8080, 22, 8080, 443]) == [22, 443, 8080]
    assert scan_service.select_ports(3) == list(scan_service.COMMON_PORTS[:3])
    assert scan_service.select_ports(2, []) == list(scan_service.COMMON_PORTS[:2])
    # Out-of-range values are dropped rather than passed to the scanner.
    assert scan_service.select_ports(10, [0, 70000, 22]) == [22]


def test_scan_host_falls_back_to_tcp_connect_when_nmap_is_silent(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scan_service, "_nmap", lambda *args, **kwargs: "")
    monkeypatch.setattr(scan_service, "scan_host_python", lambda host, ports, *a, **k: [{"port": 22, "service": "ssh"}])
    assert scan_service.scan_host("10.0.0.9", ports=[22]) == [{"port": 22, "service": "ssh"}]


def test_scan_host_python_finds_open_port() -> None:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(4)
    port = server.getsockname()[1]

    def serve() -> None:
        for _ in range(4):
            try:
                connection, _ = server.accept()
            except OSError:
                return
            connection.sendall(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n")
            connection.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        services = scan_service.scan_host_python("127.0.0.1", [port], timeout=1.0)
        assert [item["port"] for item in services] == [port]
        assert services[0]["product"] == "openssh"
    finally:
        server.close()


def test_discover_hosts_python_marks_local_listener_alive() -> None:
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(2)
    port = server.getsockname()[1]
    try:
        alive = scan_service.discover_hosts_python("127.0.0.1", ports=[port], timeout=1.0)
        assert alive == ["127.0.0.1"]
        assert scan_service.discover_hosts_python("127.0.0.1", ports=[1], timeout=0.1) == []
    finally:
        server.close()


def test_detect_interception_reports_transparent_proxy(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(scan_service, "tcp_open", lambda host, port, timeout=0.6: True)
    warning = scan_service.detect_interception()
    assert "透明代理" in warning
    monkeypatch.setattr(scan_service, "tcp_open", lambda host, port, timeout=0.6: False)
    assert scan_service.detect_interception() == ""
