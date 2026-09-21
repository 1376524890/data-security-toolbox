"""Offline IP → region classification for the data-egress view.

Three inputs decide where a destination address sits, in this order:

1. an operator whitelist (always allowed, never counted as egress),
2. a special-use/internal set (loopback, RFC1918, CGNAT, link-local …),
3. a static CIDR → country table loaded from disk.

The country table is *not* shipped filled: a wrong country table would produce a
false "no egress" verdict, which is exactly what this module must never do. When
no country table is loaded, every non-internal destination falls into the
``unknown`` bucket and the page degrades to “无法判定”, not “无出境”. Operators
drop a real table at ``EGRESS_TABLE_PATH`` (JSON, see the example next to it) and
reload; nothing here reaches the network.
"""
from __future__ import annotations

import ipaddress
import json
from bisect import bisect_right
from functools import lru_cache
from pathlib import Path
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

#: Special-purpose ranges that can never leave the host/enterprise network. These
#: are factual (RFC 1918/3927/6598/etc.), unlike country data, so they are safe to
#: ship; everything outside them still needs the country table.
SPECIAL_USE: tuple[tuple[str, str], ...] = (
    ("0.0.0.0/8", "unspecified"),
    ("10.0.0.0/8", "internal"),
    ("100.64.0.0/10", "cgnat"),
    ("127.0.0.0/8", "loopback"),
    ("169.254.0.0/16", "link_local"),
    ("172.16.0.0/12", "internal"),
    ("192.0.0.0/24", "special"),
    ("192.0.2.0/24", "documentation"),
    ("192.168.0.0/16", "internal"),
    ("198.18.0.0/15", "benchmark"),
    ("198.51.100.0/24", "documentation"),
    ("203.0.113.0/24", "documentation"),
    ("224.0.0.0/4", "multicast"),
    ("240.0.0.0/4", "reserved"),
    ("::1/128", "loopback"),
    ("fc00::/7", "internal"),
    ("fe80::/10", "link_local"),
)

EGRESS_POLICY_KEY = "egress_policy"

#: Where a real CIDR → country table can be dropped for offline import.
EGRESS_TABLE_PATH = Path(__file__).resolve().parent / "data" / "egress_regions.json"

#: Destinations for which we can positively say "this left the country".
COUNTRY_TABLE_PRESENT_KEY = "country_table_present"


def _networks(entries: Any) -> list[tuple[ipaddress._BaseNetwork, str]]:
    out: list[tuple[ipaddress._BaseNetwork, str]] = []
    for item in entries or []:
        if isinstance(item, dict):
            cidr, region = item.get("cidr"), item.get("region", "")
        else:
            cidr, region = item, ""
        try:
            network = ipaddress.ip_network(str(cidr), strict=False)
        except ValueError:
            continue
        out.append((network, str(region)))
    return out


@lru_cache(maxsize=1)
def _special_networks() -> tuple[tuple[ipaddress._BaseNetwork, str], ...]:
    return tuple(_networks([{"cidr": cidr, "region": label} for cidr, label in SPECIAL_USE]))


def country_table(path: Path | None = None) -> dict[str, Any]:
    """The static table: ``{"version", "source", "count", "regions": {CC: [CIDR]}}``.

    Empty ``regions`` means no country table is loaded, which is what drives the
    degrade-to-"无法判定" path instead of a false "无出境".
    """
    target = path or EGRESS_TABLE_PATH
    try:
        payload = json.loads(target.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {"regions": {}}
    regions = payload.get("regions") if isinstance(payload, dict) else payload
    if not isinstance(regions, dict):
        return {"regions": {}}
    return {"version": str(payload.get("version", "")), "source": str(payload.get("source", "")),
            "count": int(payload.get("count", 0) or 0), "regions": regions}


@lru_cache(maxsize=1)
def _country_ranges() -> tuple[tuple[int, ...], tuple[tuple[int, int, str], ...]]:
    """Flattened, sorted ``(starts, (start, end, country))`` for a bisect lookup.

    A linear scan of ~260k registry blocks per address would be unusable, so the
    table is resolved once into sorted integer ranges and each lookup is O(log n).
    """
    table = country_table().get("regions") or {}
    flat: list[tuple[int, int, str]] = []
    for country, cidrs in table.items():
        code = str(country).upper()
        for cidr in cidrs or []:
            try:
                network = ipaddress.ip_network(str(cidr), strict=False)
            except ValueError:
                continue
            if network.version != 4:
                continue
            flat.append((int(network.network_address), int(network.broadcast_address), code))
    flat.sort()
    return tuple(item[0] for item in flat), tuple(flat)


def _country_of(value: str) -> str:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return ""
    if address.version != 4:
        return ""
    number = int(address)
    starts, ranges = _country_ranges()
    index = bisect_right(starts, number) - 1
    if index >= 0:
        start, end, country = ranges[index]
        if start <= number <= end:
            return country
    return ""


def table_present() -> bool:
    """True only when a *country* table is loaded; drives the degrade-to-unknown path."""
    return bool(country_table().get("regions") or {})


def _entry(ip: str | None, networks) -> str:
    try:
        address = ipaddress.ip_address(str(ip or ""))
    except ValueError:
        return ""
    for network, region in networks:
        if address.version == network.version and address in network:
            return region
    return ""


def _in(ip: str | None, entries: Any) -> bool:
    """True when ``ip`` falls inside any of the given ranges.

    Separate from :func:`_entry` on purpose: a black/white-list range carries no
    region label, so membership must not be decided by whether the label is
    empty (that bug made every list entry silently miss).
    """
    try:
        address = ipaddress.ip_address(str(ip or ""))
    except ValueError:
        return False
    for network, _region in _networks(entries):
        if address.version == network.version and address in network:
            return True
    return False


def policy(db: Session | None) -> dict[str, Any]:
    """Operator black/white lists and extra internal ranges, from a settings row."""
    default: dict[str, Any] = {"whitelist": [], "blacklist": [], "internal_cidrs": []}
    if db is None:
        return default
    from app.models import SystemSetting

    row = db.scalar(select(SystemSetting).where(SystemSetting.key == EGRESS_POLICY_KEY))
    value = (row.value if row else None) or {}
    if not isinstance(value, dict):
        return default
    for key in default:
        items = value.get(key)
        default[key] = [str(item).strip() for item in items if str(item).strip()] \
            if isinstance(items, list) else []
    return default


def normalize_policy(value: dict[str, Any] | None) -> dict[str, Any]:
    """Validate a submitted policy; invalid CIDRs/IPs are rejected, not stored."""
    cleaned: dict[str, Any] = {"whitelist": [], "blacklist": [], "internal_cidrs": []}
    for key in cleaned:
        items = (value or {}).get(key) or []
        if not isinstance(items, list):
            raise ValueError(f"{key} 必须是数组")
        seen = []
        for item in items:
            text = str(item).strip()
            if not text:
                continue
            try:
                ipaddress.ip_network(text, strict=False)
            except ValueError as exc:
                raise ValueError(f"无效的地址或网段（{key}）：{text}") from exc
            if text not in seen:
                seen.append(text)
        cleaned[key] = seen
    return cleaned


def classify(ip: str | None, *, blacklist: list[str], whitelist: list[str],
             internal: list[str]) -> dict[str, str]:
    """Bucket one destination address: whitelist / blacklist / internal / country|unknown."""
    if _in(ip, blacklist):
        return {"bucket": "blacklist", "region": "", "reason": "命中黑名单"}
    if _in(ip, whitelist):
        return {"bucket": "whitelist", "region": "", "reason": "命中白名单"}
    special = _entry(ip, _special_networks())
    if special:
        return {"bucket": "internal", "region": "", "reason": f"特殊/私网地址（{special}）"}
    if _in(ip, internal):
        return {"bucket": "internal", "region": "", "reason": "命中自定义内网段"}
    region = _country_of(str(ip or ""))
    if region:
        return {"bucket": "country", "region": region, "reason": f"地区表命中 {region}"}
    return {"bucket": "unknown", "region": "", "reason": "地区表未命中"}
