"""Identity resolved from a finding's ``evidence`` payload.

This is *platform asset identity* - which host or indicator a detection is
about - and it is deliberately separate from the data-object identity in
``services/data_objects/identity.py``, which answers whether two reported files
are the same file. Asset, alert, incident and de-duplication code all consume
this module so an address is never parsed two different ways.
"""

from __future__ import annotations

from typing import Any


def short_asset(value: object) -> str:
    """Collapse a dict (e.g. an asset or CVE payload) to a short label."""
    if isinstance(value, dict):
        parts = []
        for key in ("ip", "hostname", "host", "service", "port", "cve_id", "name"):
            if value.get(key):
                parts.append(str(value[key]))
        return ":".join(parts) if parts else "asset"
    return str(value)


def asset_identity(value: object) -> str:
    """The address a nested asset payload is known by.

    ``short_asset`` output is a *display* label ("10.0.0.7:mysql:3306"); using
    it as the identity matched no asset row and split one host into one incident
    per open port, so correlation resolves the address first and only falls back
    to the composite label when the payload carries no address at all.
    """
    if isinstance(value, dict):
        address = value.get("ip") or value.get("host") or value.get("hostname")
        if address:
            return str(address)
    return short_asset(value)


def evidence_asset_keys(evidence: dict[str, Any]) -> list[str]:
    """Every host address a single finding's evidence points at."""
    keys = []
    # ``src``/``dst`` are the traffic engine's spelling of the same pair, so
    # they must be read too or every port-scan finding looks assetless.
    for field_name in (
        "src_ip",
        "dest_ip",
        "dst_ip",
        "src",
        "dst",
        "ip",
        "asset",
        "host",
        "hostname",
        "agent_name",
    ):
        value = evidence.get(field_name)
        if value:
            keys.append(asset_identity(value).lower())
    for flow in evidence.get("flow", []):
        if isinstance(flow, dict):
            for field_name in ("src_ip", "dst_ip", "dest_ip"):
                if flow.get(field_name):
                    keys.append(str(flow[field_name]).lower())
    # The rules engine names the host only inside its metric keys
    # (``src:<ip>:ports``), so the address is parsed back out of them.
    metrics = evidence.get("metrics")
    for name in metrics if isinstance(metrics, dict) else {}:
        parts = str(name).split(":")
        if len(parts) >= 3 and parts[0] in ("src", "dst") and parts[1]:
            keys.append(parts[1].lower())
    if isinstance(evidence.get("record"), dict):
        record = evidence["record"]
        for field_name in ("src_ip", "dest_ip", "ip", "hostname", "agent.name"):
            value = record.get(field_name)
            if value:
                keys.append(str(value).lower())
    return sorted({key for key in keys if key})


#: Evidence fields naming the observing side of an event, most specific first.
ASSET_SOURCE_FIELDS = ("src_ip", "src", "ip", "asset", "host", "hostname", "agent_name")


def evidence_primary_asset(evidence: dict[str, Any]) -> str:
    """The one host a finding is filed under, resolved identically everywhere.

    ``evidence_asset_keys`` returns every address for correlation, but an alert
    fingerprint needs a single stable identity. The source side wins over the
    destination, so a scan is filed under the scanning host and two different
    scanners never collapse into one alert. Unresolvable evidence returns "".
    """
    for field_name in ASSET_SOURCE_FIELDS:
        value = evidence.get(field_name)
        if isinstance(value, str) and value.strip():
            return value.strip().lower()
    record = evidence.get("record")
    if isinstance(record, dict):
        for field_name in ASSET_SOURCE_FIELDS:
            value = record.get(field_name)
            if isinstance(value, str) and value.strip():
                return value.strip().lower()
    metrics = evidence.get("metrics")
    for name in metrics if isinstance(metrics, dict) else {}:
        parts = str(name).split(":")
        if len(parts) >= 3 and parts[0] == "src" and parts[1]:
            return parts[1].lower()
    keys = evidence_asset_keys(evidence)
    return keys[0] if keys else ""


def evidence_ioc_keys(evidence: dict[str, Any]) -> list[str]:
    """Every indicator a single finding's evidence named."""
    ioc = evidence.get("ioc")
    if isinstance(ioc, dict) and ioc.get("value"):
        return [str(ioc["value"]).lower()]
    keys = []
    for field_name in (
        "value",
        "query",
        "qname",
        "rrname",
        "domain",
        "host",
        "hostname",
        "url",
        "uri",
    ):
        value = evidence.get(field_name)
        if value:
            keys.append(str(value).lower())
    record = evidence.get("record")
    if isinstance(record, dict):
        for field_name in ("query", "qname", "rrname", "domain", "host", "hostname", "url", "uri"):
            if record.get(field_name):
                keys.append(str(record[field_name]).lower())
    return sorted(set(keys))
