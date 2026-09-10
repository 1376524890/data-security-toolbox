"""Nuclei active vulnerability scanning integration.

Runs the ``nuclei`` binary against a target (or list of hosts), parses its
JSONL output, and returns normalized findings ready for the detection pipeline.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from app.core.config import settings

_SEVERITY_MAP = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": "Low",
}


def nuclei_bin() -> str:
    """Resolve the nuclei binary path (settings override, then PATH)."""
    configured = str(settings.nuclei_bin or "")
    if configured and Path(configured).exists():
        return configured
    found = shutil.which("nuclei")
    return found or configured


def templates_dir() -> str:
    """Resolve the nuclei templates directory (settings override, then default)."""
    configured = str(settings.nuclei_templates_dir or "")
    if configured and Path(configured).exists():
        return configured
    default = Path.home() / "nuclei-templates"
    return str(default) if default.exists() else ""


def run_nuclei_scan(target: str, templates_dir: str = "", tags: str = "", timeout: int = 600) -> list[dict[str, Any]]:
    """Run nuclei against a target and return normalized findings.

    Uses ``-jsonl -silent -no-color`` for parseable output. ``templates_dir`` may
    be a template file, a directory, or empty (uses the default template set).
    """
    binary = nuclei_bin()
    if not binary:
        return []
    cmd = [binary, "-u", target, "-jsonl", "-silent", "-no-color"]
    if templates_dir:
        cmd += ["-t", templates_dir]
    if tags:
        cmd += ["-tags", tags]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except Exception:
        return []
    findings: list[dict[str, Any]] = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = item.get("info") or {}
        findings.append({
            "template_id": str(item.get("template-id") or item.get("template_id") or ""),
            "name": str(info.get("name") or ""),
            "severity": _SEVERITY_MAP.get(str(info.get("severity") or "").lower(), "Low"),
            "type": str(item.get("type") or ""),
            "host": str(item.get("host") or ""),
            "port": str(item.get("port") or ""),
            "scheme": str(item.get("scheme") or ""),
            "url": str(item.get("url") or item.get("matched-at") or ""),
            "matched_at": str(item.get("matched-at") or ""),
            "description": str(info.get("description") or "").replace("\n", " "),
            "reference": info.get("reference") or [],
            "extracted": item.get("extracted-results") or [],
            "matcher_name": str(item.get("matcher-name") or ""),
            "matcher_status": bool(item.get("matcher-status")),
        })
    return findings
