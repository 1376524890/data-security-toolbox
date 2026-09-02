from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from xml.etree import ElementTree


def parse_xccdf_xml(path: Path) -> list[dict[str, Any]]:
    tree = ElementTree.parse(str(path))
    root = tree.getroot()
    records: list[dict[str, Any]] = []
    benchmark = next((item for item in root.iter() if item.tag.endswith("Benchmark")), None)
    benchmark_title = _local_text(benchmark, "title") if benchmark is not None else ""
    profiles = [item for item in root.iter() if item.tag.endswith("Profile")]
    profile = _local_text(profiles[0], "title") if profiles else ""
    for item in root.iter():
        if not item.tag.endswith("rule-result"):
            continue
        result = _local_text(item, "result")
        if result and str(result).lower() in {"pass", "notchecked", "notapplicable", "unknown"}:
            continue
        ident = _local_text(item, "ident")
        records.append({
            "idref": item.attrib.get("idref", ""),
            "result": result,
            "title": _local_text(item, "title"),
            "benchmark": benchmark_title,
            "profile": profile,
            "ident": ident,
            "cve": ident if ident and ident.upper().startswith("CVE-") else "",
        })
    return records


def _local_text(node: Any, tag: str) -> str:
    if node is None:
        return ""
    for child in node:
        if child.tag.endswith(tag):
            return (child.text or "").strip()
    return ""


def parse_openscap_payload(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        if payload.get("results"):
            return payload["results"]
        if payload.get("path") or payload.get("xccdf") or payload.get("arf"):
            path = Path(payload.get("path") or payload.get("xccdf") or payload.get("arf"))
            if path.exists():
                return parse_xccdf_xml(path)
        if payload.get("json"):
            value = json.loads(str(payload["json"])) if isinstance(payload["json"], str) else payload["json"]
            return value if isinstance(value, list) else value.get("results", [])
        return []
    if isinstance(payload, (str, Path)):
        path = Path(payload)
        return parse_xccdf_xml(path) if path.exists() and path.suffix.lower() in {".xml", ".arf"} else []
    return []
