from __future__ import annotations

from typing import Any

import requests


class MISPClient:
    def __init__(self, url: str, api_key: str, verify_ssl: bool = True, timeout: int = 30) -> None:
        self.url = url.rstrip("/")
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.timeout = timeout

    def sync(self, last: str = "", limit: int = 1000) -> list[dict[str, Any]]:
        headers = {"Authorization": self.api_key, "Accept": "application/json"}
        payload = {"returnFormat": "json", "limit": limit}
        if last:
            payload["last"] = last
        response = requests.post(f"{self.url}/events/restSearch", json=payload, headers=headers, verify=self.verify_ssl, timeout=self.timeout)
        response.raise_for_status()
        events = response.json().get("response", [])
        return extract_iocs(events)


def extract_iocs(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    iocs: list[dict[str, Any]] = []
    type_map = {
        "ip-src": "ip",
        "ip-dst": "ip",
        "hostname": "domain",
        "domain": "domain",
        "md5": "hash",
        "sha1": "hash",
        "sha256": "hash",
        "url": "url",
    }
    for event in events:
        attributes = event.get("Attribute") or event.get("attributes") or []
        if isinstance(attributes, dict):
            attributes = [attributes]
        for attr in attributes:
            ioc_type = type_map.get(str(attr.get("type", "")).lower())
            if not ioc_type:
                continue
            iocs.append({
                "value": str(attr.get("value", "")),
                "type": ioc_type,
                "source": "MISP",
                "event_id": event.get("id", ""),
                "info": event.get("info", ""),
                "tags": [tag.get("name", "") for tag in (attr.get("Tag") or []) if isinstance(tag, dict)],
            })
    return iocs
