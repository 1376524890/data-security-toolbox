"""Recognising the toolbox's own management traffic inside a capture.

Our probes and console are the most talkative hosts on a checked network, and a
token in our own upload must never be reported as data loss. Identity comes from
two independent hints: the addresses this deployment is reachable at, and the
fixed header/cookie names our management channel authenticates with.
"""
import ipaddress
import re
from urllib.parse import urlsplit

from app.services.dlp.constants import OWN_TRAFFIC_MARKERS


def own_traffic_markers():
    from app.core.config import settings
    return (*OWN_TRAFFIC_MARKERS, str(settings.cookie_name).lower().encode())


def self_endpoint_entries(policy):
    """Addresses that belong to the toolbox itself.

    ``DEPLOYMENT_BACKEND_URL`` is the URL our own probes upload to, so it is the
    authoritative "this address is us" hint. ``DLP_SELF_ENDPOINTS`` adds extra
    ``host[:port]`` / CIDR entries (for example sibling tooling on the same
    host), and a stored policy may carry its own list.
    """
    entries = list(policy.get('self_endpoints') or [])
    if policy.get('ignore_own_traffic', True):
        from app.core.config import settings
        backend_url = str(getattr(settings, 'deployment_backend_url', '') or '').strip()
        if backend_url:
            parts = urlsplit(backend_url if '//' in backend_url else f'//{backend_url}')
            if parts.hostname:
                entries.append(f'{parts.hostname}:{parts.port}' if parts.port else parts.hostname)
        entries.extend(item for item in re.split(r'[,;\s]+', str(getattr(settings, 'dlp_self_endpoints', '') or '')) if item)
    return [str(item).strip() for item in entries if str(item).strip()]


def _split_endpoint(value):
    host, port = str(value or '').strip(), None
    if ':' in host:
        head, _, tail = host.rpartition(':')
        if tail.isdigit() and head:
            host, port = head, int(tail)
    return host.strip(), port


def parse_self_endpoints(entries):
    """Parse ``host``, ``host:port``, ``cidr`` and ``cidr:port`` entries once per capture."""
    parsed = []
    for item in entries:
        host, port = _split_endpoint(item)
        if not host:
            continue
        try:
            network = ipaddress.ip_network(host, strict=False)
        except ValueError:
            network = None
        parsed.append((network, host.lower(), port))
    return parsed


def endpoint_is_self(ip, port, parsed):
    try:
        address = ipaddress.ip_address(str(ip))
    except ValueError:
        return False
    for network, host, entry_port in parsed:
        if entry_port is not None and int(port) != entry_port:
            continue
        if network is not None:
            if address in network:
                return True
        elif str(ip) == host:
            return True
    return False


def host_header_is_self(host_header, parsed):
    """Match the HTTP ``Host`` header so hostname-addressed tooling is excluded too."""
    host, port = _split_endpoint(host_header)
    host = host.lower()
    if not host:
        return False
    for network, name, entry_port in parsed:
        if network is not None or name != host:
            continue
        if entry_port is None or port is None or port == entry_port:
            return True
    return False


def is_own_traffic(key, data, parsed, markers):
    """True when a stream belongs to the toolbox's own management traffic."""
    if parsed and (endpoint_is_self(key[0], key[1], parsed) or endpoint_is_self(key[2], key[3], parsed)):
        return True
    if not markers:
        return False
    sample = data[:65536].lower()
    return any(marker in sample for marker in markers)
