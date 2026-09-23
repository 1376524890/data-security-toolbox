"""Which traffic an anomaly rule may be reported for, and on which port.

Traffic rules are the single largest source of false positives this platform
produced in practice - 179 ``NETWORK_PORT_SCAN`` and 485 ``NET_BROAD_001``
findings against one monitored host, essentially all of them noise. Two
independent mistakes caused that, and both are fixed by describing the metric
the way the rule reads it:

**Scope.** Loopback, link-local, multicast and broadcast traffic is not a data
security event, and the platform's own management channel is not the customer's
data - the DLP stage already refuses to alert on its own upload, and the traffic
rules must agree. Every flow whose source or destination is one of those
addresses is dropped before any metric is computed.

**Direction.** Capture flows are *directional*: a DNS server's answers appear as
``114.114.114.114:53 -> client:33209``, one flow per client, each with a
different destination port. Counting "distinct destination ports per source
address" therefore described every busy server on the network as a port scanner,
which is exactly what it reported. A port scan is many ports on **one target**,
so the count is taken per ``(source, destination)`` pair and, within a pair, on
the side of the conversation that is actually the service.
"""
from __future__ import annotations

import ipaddress
from collections.abc import Iterable
from typing import Any

#: Ranges that can never describe a customer's own service being attacked, and
#: which the network stack itself generates: loopback, link-local, multicast,
#: broadcast, the unspecified address and the documentation ranges.
SPECIAL_USE_NETWORKS: tuple[str, ...] = (
    "0.0.0.0/32",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "224.0.0.0/4",
    "255.255.255.255/32",
    "::1/128",
    "ff00::/8",
    "fe80::/10",
)

#: Ports at or below this are treated as service ports when the two ends of a
#: flow disagree. 32767 is the top of the registered range; above it a port is
#: almost always an ephemeral client port.
SERVICE_PORT_CEILING = 32767


def _networks() -> list[ipaddress._BaseNetwork]:
    parsed = []
    for entry in SPECIAL_USE_NETWORKS:
        try:
            parsed.append(ipaddress.ip_network(entry, strict=False))
        except ValueError:  # pragma: no cover - the table above is a constant
            continue
    return parsed


SPECIAL_USE = _networks()


def ignored_matcher():
    """One ``(ip, port) -> bool`` test, with the config parsed exactly once.

    A segment holds tens of thousands of packets, so the self-endpoint list is
    resolved and parsed here rather than per packet.
    """
    from app.services.dlp.self_traffic import (
        endpoint_is_self,
        parse_self_endpoints,
        self_endpoint_entries,
    )

    entries = parse_self_endpoints(
        self_endpoint_entries({"ignore_own_traffic": True, "self_endpoints": []})
    )

    def ignored(ip: Any, port: Any = None) -> bool:
        try:
            address = ipaddress.ip_address(str(ip))
        except ValueError:
            return False
        if any(address in network for network in SPECIAL_USE):
            return True
        return bool(entries) and endpoint_is_self(str(ip), port, entries)

    return ignored


def address_ignored(ip: Any, port: Any = None) -> bool:
    """True for an address the anomaly rules must never describe."""
    return ignored_matcher()(ip, port)


def service_port(src_port: Any, dst_port: Any) -> int:
    """Which end of a flow is the service, for "how many ports" questions.

    A client request and its reply are two flows with the ports swapped. The
    port that repeats across a scan is the target's, and the target's port is the
    one in the well-known/registered range while the other end is ephemeral.
    """
    src, dst = int(src_port or 0), int(dst_port or 0)
    if not src or not dst:
        return dst or src
    src_service = src <= SERVICE_PORT_CEILING
    dst_service = dst <= SERVICE_PORT_CEILING
    if src_service and not dst_service:
        return src
    if dst_service and not src_service:
        return dst
    return min(src, dst)


def is_ignored(flow: dict[str, Any], ignored=None) -> bool:
    test = ignored or ignored_matcher()
    return test(flow.get("src_ip"), flow.get("src_port")) or test(
        flow.get("dst_ip"), flow.get("dst_port")
    )


#: A packet rate needs a duration to be a rate. A single-packet conversation has
#: zero span, and dividing by an epsilon turned "one packet" into 1000 pps -
#: which tripped ``NET_RATE_001`` (``packet_rate > 500``) on every segment that
#: happened to contain one, i.e. on essentially every segment. Measuring over at
#: least this long keeps a genuine burst high (1000 packets in 10 ms still reads
#: 20000 pps) while one packet reads 20.
MIN_RATE_SPAN_SECONDS = 0.05


def conversation_rate(flow: dict[str, Any]) -> float:
    """Packets per second inside one conversation, measured over a real span."""
    span = float(flow.get("end_time") or 0) - float(flow.get("start_time") or 0)
    return int(flow.get("packets") or 0) / max(span, MIN_RATE_SPAN_SECONDS)


def filter_flows(flows: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    """Split flows into the ones a rule may describe and the ones it may not."""
    test = ignored_matcher()
    kept: list[dict[str, Any]] = []
    ignored = 0
    for flow in flows:
        if is_ignored(flow, test):
            ignored += 1
            continue
        kept.append(flow)
    return kept, ignored


def filter_packets(packets: Iterable[dict[str, Any]]) -> tuple[list[dict[str, Any]], int]:
    test = ignored_matcher()
    kept: list[dict[str, Any]] = []
    ignored = 0
    for packet in packets:
        if test(packet.get("src_ip"), packet.get("src_port")) or test(
            packet.get("dst_ip"), packet.get("dst_port")
        ):
            ignored += 1
            continue
        kept.append(packet)
    return kept, ignored
