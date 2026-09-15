from __future__ import annotations

import json
from threading import Event

import pytest

from app.services.dlp_service import DEFAULT_POLICY, inspect_content
from app.services.intelligence_service import normalize, parse_indicators


def test_intelligence_import_normalizes_and_rejects_invalid_rows() -> None:
    rows, rejected = parse_indicators(json.dumps([
        {"type": "domain", "value": "Example.COM."},
        {"type": "ip", "value": "192.0.2.1"},
        {"type": "hash", "value": "A" * 64},
        {"type": "domain", "value": "not a domain"},
    ]))
    assert rejected == 1
    assert rows[0]["value"] == "example.com"
    assert rows[2]["value"] == "a" * 64
    with pytest.raises(ValueError):
        normalize("url", "file:///etc/passwd")


def test_dlp_masks_sensitive_samples_and_matches_complete_fingerprint() -> None:
    body = b"customer=13800138000&email=alice@example.com"
    policy = {**DEFAULT_POLICY, "fingerprints": []}
    hits = inspect_content(body, policy)
    assert {item["kind"] for item in hits} >= {"phone", "email"}
    assert all("13800138000" not in sample for item in hits for sample in item["samples"])


def test_probe_scanner_requires_explicit_bounded_targets(monkeypatch) -> None:
    from probe.scanner import expand_targets, scan_network

    assert expand_targets(["192.0.2.0/30"], 2) == ["192.0.2.1", "192.0.2.2"]
    with pytest.raises(ValueError):
        expand_targets([], 2)
    with pytest.raises(ValueError):
        expand_targets(["10.0.0.0/8"], 256)

    monkeypatch.setattr("probe.scanner.inspect_port", lambda host, port, timeout: {
        "ip": host, "port": port, "protocol": "tcp", "service": "http", "banner": ""
    })
    report = scan_network({"targets": ["192.0.2.1/32"], "ports": [80], "max_hosts": 1}, Event())
    assert report["complete"] is True
    assert report["assets"][0]["port"] == 80
