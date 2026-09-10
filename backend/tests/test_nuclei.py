from __future__ import annotations

import json

from app.services.nuclei_service import _SEVERITY_MAP


def _parse(line: str) -> dict:
    """Replicate run_nuclei_scan JSONL parsing without invoking nuclei."""
    item = json.loads(line)
    info = item.get("info") or {}
    return {
        "template_id": str(item.get("template-id") or ""),
        "name": str(info.get("name") or ""),
        "severity": _SEVERITY_MAP.get(str(info.get("severity") or "").lower(), "Low"),
        "url": str(item.get("url") or item.get("matched-at") or ""),
        "extracted": item.get("extracted-results") or [],
        "matcher_status": bool(item.get("matcher-status")),
    }


def test_nuclei_jsonl_parsing() -> None:
    line = json.dumps({
        "template-id": "test-nginx-detect",
        "info": {"name": "Test Nginx Detect", "severity": "info"},
        "type": "http",
        "host": "localhost",
        "port": "8080",
        "url": "http://localhost:8080",
        "matched-at": "http://localhost:8080",
        "extracted-results": ["nginx/1.27.5"],
        "matcher-status": True,
    })
    finding = _parse(line)
    assert finding["template_id"] == "test-nginx-detect"
    assert finding["name"] == "Test Nginx Detect"
    assert finding["severity"] == "Low"  # info maps to Low for the alert pipeline
    assert finding["url"] == "http://localhost:8080"
    assert finding["extracted"] == ["nginx/1.27.5"]
    assert finding["matcher_status"] is True


def test_severity_map() -> None:
    assert _SEVERITY_MAP["critical"] == "Critical"
    assert _SEVERITY_MAP["high"] == "High"
    assert _SEVERITY_MAP["info"] == "Low"
