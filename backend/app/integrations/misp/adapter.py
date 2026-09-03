from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.config import settings
from app.engine.core.context import DetectionContext
from app.integrations.base import AdapterResult, IntegrationAdapter, finding
from app.integrations.misp.client import MISPClient, extract_iocs
from app.integrations.misp.store import MISPStore


def _collect_observations(context: DetectionContext | None) -> dict[str, set[str]]:
    observations: dict[str, set[str]] = {"ip": set(), "domain": set(), "hash": set(), "url": set()}
    if context is None:
        return observations
    for flow in context.flows:
        for key, value in (("ip", flow.get("src_ip")), ("ip", flow.get("dst_ip")), ("domain", flow.get("dns_query")), ("url", flow.get("url"))):
            if value:
                observations[key].add(str(value).lower())
    for packet in context.packets:
        for key, value in (("ip", packet.get("src_ip")), ("ip", packet.get("dst_ip"))):
            if value:
                observations[key].add(str(value).lower())
    for line in context.log_lines:
        observations["url"].add(line.strip())
    data = context.data
    for key, target in (("iocs", None), ("ip", "ip"), ("domain", "domain"), ("url", "url"), ("hashes", "hash")):
        if target and key in data:
            values = data[key] if isinstance(data[key], list) else [data[key]]
            observations[target].update(str(item).lower() for item in values)
    for asset in context.assets:
        for key, value in (("ip", asset.get("ip")), ("domain", asset.get("hostname"))):
            if value:
                observations[key].add(str(value).lower())
    return observations


class MISPAdapter(IntegrationAdapter):
    name = "misp"
    version = "2.1.0"
    supported_types = ("ip", "domain", "hash", "url")
    capabilities = ("offline-store", "api-sync", "ioc-match")

    def supports(self, context: DetectionContext | None = None) -> bool:
        if not context:
            return False
        return bool(context.data.get("ioc_library") or context.data.get("iocs"))

    def health(self) -> dict[str, Any]:
        configured = bool(settings.misp_url and settings.misp_api_key)
        return {
            "name": self.name,
            "adapter_version": self.version,
            "installed": True,
            "enabled": True,
            "healthy": True,
            "runtime_version": "offline-store" if not configured else "MISP API",
            "supported_types": list(self.supported_types),
            "capabilities": list(self.capabilities),
            "last_check": datetime.now(UTC).isoformat(),
            "status": "ready",
            "message": "" if configured else "Offline IOC store available; MISP API not configured",
        }

    def parse(self, payload: Any) -> list[dict[str, Any]]:
        if isinstance(payload, list):
            return payload
        if isinstance(payload, dict):
            if payload.get("iocs"):
                return payload["iocs"]
            if payload.get("path") or payload.get("file"):
                path = Path(payload.get("path") or payload.get("file"))
                if path.suffix not in {".pcap", ".pcapng", ".pcap.gz", ".pcapng.gz"}:
                    return MISPStore(path).load()
            if payload.get("events"):
                return extract_iocs(payload["events"])
            if payload.get("ioc"):
                return [payload["ioc"]]
        return []

    def adapt(self, payload: Any, context: DetectionContext | None = None) -> AdapterResult:
        iocs = self.parse(payload)
        if not iocs and context and context.data.get("ioc_library"):
            iocs = context.data["ioc_library"]
        if isinstance(payload, dict) and payload.get("sync"):
            client = MISPClient(payload["url"], payload["api_key"], bool(payload.get("verify_ssl", True)))
            iocs = client.sync(payload.get("last", ""), int(payload.get("limit", 1000)))
            if payload.get("store", True):
                MISPStore().append(iocs)
        observations = _collect_observations(context)
        findings: list[Any] = []
        matched: dict[str, list[dict[str, Any]]] = {"ip": [], "domain": [], "hash": [], "url": []}
        for ioc in iocs:
            ioc_type = str(ioc.get("type", "ip")).lower()
            value = str(ioc.get("value", "")).lower()
            if ioc_type not in observations or value not in observations[ioc_type]:
                continue
            matched.setdefault(ioc_type, []).append(ioc)
            findings.append(finding(
                self.name,
                "MISP_IOC_MATCH_001",
                "High",
                0.9,
                {"ioc": ioc, "type": ioc_type, "value": value, "source": ioc.get("source", "MISP")},
                "命中 MISP 威胁情报，应阻断、隔离并开展取证。",
            ))
        summary = {key: len(value) for key, value in matched.items()}
        return AdapterResult(self.name, iocs, findings, {"ioc_count": len(iocs), "matched": summary})
