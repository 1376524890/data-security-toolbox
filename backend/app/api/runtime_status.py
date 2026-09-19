"""Runtime status shared by the console endpoints.

Two read-only views of the running platform are used by more than one route:
the capability heartbeats the analysis workers publish to Redis
(``worker:capability:*``, written by ``workers/maintenance_tasks.py``) and the
per-engine rule file inventory on disk.  ``/health`` and the integration
catalogue both report them, so they live here instead of in either route
module.  This module does not register routes.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.config import settings


def read_worker_capabilities() -> list[dict[str, Any]]:
    try:
        import redis as redis_lib

        client = redis_lib.Redis.from_url(
            settings.redis_url, decode_responses=True, socket_connect_timeout=1, socket_timeout=1
        )
        keys = list(client.scan_iter("worker:capability:*"))
        items = []
        for key in keys:
            try:
                value = client.get(key)
                if value:
                    items.append(json.loads(value))
            except Exception:
                continue
        return items
    except Exception:
        return []


def merge_capability(capabilities: list[dict[str, Any]]) -> dict[str, Any]:
    merged: dict[str, Any] = {}
    for item in capabilities:
        for tool in ("tshark", "zeek", "suricata"):
            info = item.get(tool) or {}
            if not merged.get(tool):
                merged[tool] = {"available": False, "version": "", "rule_count": 0}
            merged[tool]["available"] = bool(merged[tool]["available"] or info.get("available"))
            merged[tool]["version"] = merged[tool]["version"] or info.get("version", "")
            merged[tool]["rule_count"] = max(
                merged[tool].get("rule_count", 0), int(info.get("rule_count") or 0)
            )
    return merged


def engine_rule_counts() -> dict[str, int]:
    base = Path(__file__).resolve().parents[1] / "rules"
    counts: dict[str, int] = {}
    for sub, engine in (
        ("network", "traffic_engine"),
        ("data", "data_engine"),
        ("logs", "sigma_log_engine"),
        ("compliance", "compliance_engine"),
    ):
        directory = base / sub
        count = 0
        if directory.exists():
            for path in directory.rglob("*"):
                if path.is_file() and path.suffix in {".yaml", ".yml", ".yar"}:
                    count += 1
        counts[engine] = count
    counts["yara"] = (
        sum(1 for _ in (base / "data").glob("*.yar")) if (base / "data").exists() else 0
    )
    return counts
