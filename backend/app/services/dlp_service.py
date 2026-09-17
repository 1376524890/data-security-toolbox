"""Bounded TCP reassembly and passive cleartext HTTP data-loss detection.

No TLS decryption or inline blocking. Missing packets and resource limits are
reported as incomplete coverage, never treated as proof that a capture is safe.
"""
import hashlib
import io
import ipaddress
import re
import zlib
from email import policy
from email.parser import BytesParser
from pathlib import Path
from urllib.parse import unquote_plus, urlsplit

import dpkt

from app.core.config import settings

from app.services.rule_library import DEFAULT_CONFIDENCE, MIN_ALERT_CONFIDENCE

MAX_STREAM = 2 * 1024 * 1024
MAX_TOTAL = 32 * 1024 * 1024
MAX_STREAMS = 256
MAX_PACKETS = 200000
MAX_OBJECTS = 500
DEFAULT_POLICY = {'enabled': True, 'categories': ['phone', 'id_card', 'email', 'api_key'],
                  'keywords': [], 'fingerprints': [], 'min_matches': 1,
                  'min_confidence': MIN_ALERT_CONFIDENCE,
                  'exclude_cidrs': ['127.0.0.0/8', '::1/128'],
                  # The toolbox talking to itself is not data loss.
                  'self_endpoints': [], 'ignore_own_traffic': True}
# Our own management channel authenticates with fixed header/cookie names, so a
# captured stream carrying them is the toolbox talking to itself no matter which
# address it uses (platform URL, DHCP change, hostname vs IP, ...).
OWN_TRAFFIC_MARKERS = (b'x-probe-token', b'x-probe-id', b'x-probe-bootstrap-token')
# Precision of the built-in patterns. ``token`` matches any long random run, so
# hashes, base64 blobs and container ids keep it below the alert threshold.
BUILTIN_CONFIDENCE = {'phone': .7, 'id_card': .9, 'bank_card': .85, 'email': .85, 'api_key': .95, 'token': .3}


def normalize_policy(config):
    """Fill policy defaults so stored policies written before a key existed stay usable."""
    policy = {**DEFAULT_POLICY, **(config or {})}
    try:
        policy['min_matches'] = max(1, int(policy['min_matches']))
    except (TypeError, ValueError):
        policy['min_matches'] = DEFAULT_POLICY['min_matches']
    try:
        policy['min_confidence'] = min(1.0, max(0.0, float(policy['min_confidence'])))
    except (TypeError, ValueError):
        policy['min_confidence'] = MIN_ALERT_CONFIDENCE
    if not isinstance(policy.get('exclude_cidrs'), list):
        policy['exclude_cidrs'] = list(DEFAULT_POLICY['exclude_cidrs'])
    if not isinstance(policy.get('self_endpoints'), list):
        policy['self_endpoints'] = list(DEFAULT_POLICY['self_endpoints'])
    policy['ignore_own_traffic'] = bool(policy.get('ignore_own_traffic', True))
    return policy


def alertable(hit, min_confidence):
    """A hit raises an alert only when it is protected data of sufficient precision."""
    return bool(hit.get('sensitive', True)) and float(hit.get('confidence', DEFAULT_CONFIDENCE)) >= min_confidence


def host_internal(value, networks):
    """True for addresses that never leave the host: loopback, link-local, unspecified, multicast."""
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return (address.is_loopback or address.is_link_local or address.is_unspecified or address.is_multicast
            or any(address in network for network in networks))


def excluded_networks(policy):
    networks = []
    for item in policy['exclude_cidrs']:
        try:
            networks.append(ipaddress.ip_network(str(item), strict=False))
        except ValueError:
            continue
    return networks


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


def looks_like_text(data):
    """Cheap guard so binary protocols are not decoded as cleartext payload."""
    sample = data[:8192]
    if not sample or b'\x00' in sample:
        return False
    printable = sum(1 for byte in sample if byte in (9, 10, 13) or 32 <= byte < 127 or byte >= 128)
    return printable / len(sample) >= .9


def reassemble(path):
    streams, total = {}, 0
    coverage = {'packet_limit': False, 'byte_limit': False, 'stream_limit': False, 'gaps': 0, 'malformed_packets': 0, 'encrypted_streams': 0}
    with Path(path).open('rb') as handle:
        try:
            reader = dpkt.pcap.Reader(handle)
        except (ValueError, dpkt.NeedData):
            handle.seek(0)
            reader = dpkt.pcapng.Reader(handle)
        linktype = reader.datalink()
        for number, (_, raw) in enumerate(reader):
            if number >= MAX_PACKETS:
                coverage['packet_limit'] = True
                break
            try:
                if linktype == 1:
                    network = dpkt.ethernet.Ethernet(raw).data
                elif linktype == 113:
                    network = dpkt.sll.SLL(raw).data
                elif linktype == 276:
                    # Linux any-interface captures can use cooked capture v2.
                    protocol = int.from_bytes(raw[:2], 'big')
                    if protocol not in (0x0800, 0x86dd):
                        continue
                    network = dpkt.ip6.IP6(raw[20:]) if protocol == 0x86dd else dpkt.ip.IP(raw[20:])
                elif linktype in (101, 228, 229):
                    network = dpkt.ip6.IP6(raw) if raw[0] >> 4 == 6 else dpkt.ip.IP(raw)
                else:
                    coverage['unsupported_linktype'] = linktype
                    break
                tcp = network.data
                if not isinstance(tcp, dpkt.tcp.TCP):
                    continue
                key = (str(ipaddress.ip_address(network.src)), tcp.sport, str(ipaddress.ip_address(network.dst)), tcp.dport)
                if not tcp.data:
                    continue
                if key not in streams and len(streams) >= MAX_STREAMS:
                    coverage['stream_limit'] = True
                    continue
                stream = streams.setdefault(key, {'segments': {}, 'size': 0, 'truncated': False})
                seq = tcp.seq + int(bool(tcp.flags & dpkt.tcp.TH_SYN))
                if seq in stream['segments']:
                    continue  # retransmission; overlaps are handled below
                if stream['size'] + len(tcp.data) > MAX_STREAM or total + len(tcp.data) > MAX_TOTAL:
                    stream['truncated'] = coverage['byte_limit'] = True
                    continue
                stream['segments'][seq] = bytes(tcp.data)
                stream['size'] += len(tcp.data)
                total += len(tcp.data)
            except (ValueError, AttributeError, dpkt.UnpackError, IndexError):
                coverage['malformed_packets'] += 1
    chunks = []
    for key, stream in streams.items():
        data, end = bytearray(), None
        gap = False
        for seq, payload in sorted(stream['segments'].items()):
            if end is not None and seq > end:
                gap = True
                coverage['gaps'] += 1
                # Do not concatenate across an unknown gap and invent a match.
                chunks.append((key, bytes(data), True))
                data = bytearray()
            overlap = max(0, (end or seq) - seq)
            data.extend(payload[overlap:])
            end = max(end or 0, seq + len(payload))
        if data[:2] in (b'\x16\x03', b'\x17\x03'):
            coverage['encrypted_streams'] += 1
            continue
        chunks.append((key, bytes(data), gap or stream['truncated']))
    return chunks, coverage


def dechunk(data):
    out, offset = bytearray(), 0
    while True:
        end = data.find(b'\r\n', offset)
        if end < 0:
            raise ValueError('Incomplete chunk header')
        size = int(data[offset:end].split(b';')[0], 16)
        offset = end + 2
        if size == 0:
            return bytes(out), offset + 2
        if size < 0 or len(out) + size > MAX_STREAM or offset + size + 2 > len(data):
            raise ValueError('Incomplete or oversized chunk')
        out.extend(data[offset:offset + size])
        if data[offset + size:offset + size + 2] != b'\r\n':
            raise ValueError('Invalid chunk terminator')
        offset += size + 2


def http_objects(data):
    offset, results = 0, []
    while offset < len(data) and len(results) < 50:
        head_end = data.find(b'\r\n\r\n', offset)
        if head_end < 0 or head_end - offset > 65536:
            break
        header = data[offset:head_end]
        first = header.split(b'\r\n', 1)[0].decode('latin1')
        if not re.match(r'^(?:GET |POST |PUT |PATCH |DELETE |HEAD |HTTP/1\.[01] )', first):
            break
        message = BytesParser(policy=policy.default).parsebytes(header.split(b'\r\n', 1)[-1] + b'\r\n\r\n')
        start = head_end + 4
        complete = True
        remaining = data[start:]
        try:
            if 'chunked' in message.get('Transfer-Encoding', '').lower():
                body, consumed = dechunk(remaining)
            elif message.get('Content-Length') is not None:
                size = int(message['Content-Length'])
                if size < 0 or size > MAX_STREAM:
                    raise ValueError('Invalid length')
                body, consumed = remaining[:size], min(size, len(remaining))
                complete = len(body) == size
            elif first.startswith('HTTP/'):
                body, consumed = remaining, len(remaining)
                complete = False  # capture may stop before connection-close
            else:
                body, consumed = b'', 0
            if 'gzip' in message.get('Content-Encoding', '').lower():
                decoder = zlib.decompressobj(16 + zlib.MAX_WBITS)
                body = decoder.decompress(body, MAX_STREAM)
                complete = complete and decoder.eof
        except (ValueError, zlib.error):
            body, consumed, complete = remaining[:MAX_STREAM], len(remaining), False
        host = message.get('Host', '')
        parts = first.split(' ')
        uri = parts[1] if not first.startswith('HTTP/') and len(parts) > 1 else ''
        filename = message.get_filename() or (uri.split('?', 1)[0].rsplit('/', 1)[-1] if uri else '') or 'http-body'
        base = {'filename': filename[:255], 'content_type': message.get_content_type(), 'complete': complete,
                'method': parts[0], 'host': host[:255], 'url': ('http://' + host + uri) if host and uri else '', 'body': body}
        if message.get_content_type().startswith('multipart/'):
            mime = BytesParser(policy=policy.default).parsebytes(b'Content-Type: ' + str(message['Content-Type']).encode() + b'\r\n\r\n' + body)
            for part in mime.walk():
                if part.is_multipart():
                    continue
                results.append({**base, 'filename': (part.get_filename() or part.get_param('name', header='content-disposition') or 'form-field')[:255],
                                'content_type': part.get_content_type(), 'body': (part.get_payload(decode=True) or b'')[:MAX_STREAM]})
                if len(results) >= 50:
                    break
        else:
            results.append(base)
        # Include query strings/headers for token and PII detection without persisting raw headers.
        results.append({**base, 'filename': 'http-headers', 'content_type': 'text/plain', 'body': header, 'is_header': True})
        offset = start + consumed
        if not complete:
            break
    return results


def masked(value):
    return value[:2] + '***' + value[-2:] if len(value) >= 6 else '***'


def inspect_content(body, config):
    """Text stage of the network DLP path, using the shared detection engine.

    The engine is the same one the probe runs, so a type cannot mean two things.
    Only the categories named by the stored policy are reported, and no matched
    value is carried out of this function.
    """
    from app.services import sensitive_engine

    policy = normalize_policy(config)
    minimum = policy['min_matches']
    text = unquote_plus(body.decode('utf-8', 'replace'))
    hits = []
    for hit in sensitive_engine.to_legacy_hits(
            sensitive_engine.scan_text(text, source_type='network', protocol='http'),
            policy['categories']):
        if hit['count'] >= minimum:
            hits.append({**hit, 'samples': []})
    for keyword in policy['keywords']:
        count = text.casefold().count(keyword.casefold())
        if count >= minimum:
            hits.append({'kind': 'keyword', 'count': count, 'samples': [masked(keyword)], 'confidence': 1.0, 'sensitive': True})
    digest = hashlib.sha256(body).hexdigest()
    if digest in policy['fingerprints']:
        hits.append({'kind': 'file_fingerprint', 'count': 1, 'samples': [digest], 'confidence': 1.0, 'sensitive': True})
    from app.services.rule_library import scan_managed
    hits.extend(scan_managed(text, policy.get('managed_rules', []), minimum, policy.get('rule_timeouts')))
    return hits


def analyze_capture(path, config):
    from app.services.rule_library import managed_rules
    policy = normalize_policy({**config, 'managed_rules': managed_rules(), 'rule_timeouts': []})
    networks = excluded_networks(policy)
    self_parsed = parse_self_endpoints(self_endpoint_entries(policy))
    markers = own_traffic_markers() if policy['ignore_own_traffic'] else ()
    streams, coverage = reassemble(path)
    coverage['excluded_streams'] = 0
    coverage['excluded_own_traffic'] = 0
    objects, observations, findings = [], {'domain': set(), 'url': set(), 'hash': set()}, []
    for key, data, incomplete in streams:
        if host_internal(key[0], networks) or host_internal(key[2], networks):
            # Host-internal traffic never leaves the machine, so it is not egress.
            coverage['excluded_streams'] += 1
            continue
        if is_own_traffic(key, data, self_parsed, markers):
            # The toolbox's own probe/console channel is not data loss.
            coverage['excluded_own_traffic'] += 1
            continue
        extracted = http_objects(data)
        if not extracted:
            # Cleartext protocols without an HTTP parser still get bounded text scanning.
            if looks_like_text(data):
                extracted = [{'filename': 'tcp-payload', 'body': data, 'complete': False, 'content_type': 'text/plain'}]
        if self_parsed and any(host_header_is_self(obj.get('host'), self_parsed) for obj in extracted):
            # Hostname-addressed tooling: the IP check above cannot see it.
            coverage['excluded_own_traffic'] += 1
            continue
        for obj in extracted:
            if len(objects) >= MAX_OBJECTS:
                coverage['object_limit'] = True
                break
            body = obj.pop('body')
            metadata = {**obj, 'id': len(objects) + 1, 'src_ip': key[0], 'src_port': key[1], 'dst_ip': key[2], 'dst_port': key[3],
                        'size': len(body), 'sha256': hashlib.sha256(body).hexdigest(), 'complete': obj.get('complete', False) and not incomplete}
            if obj.get('host'):
                observations['domain'].add(obj['host'].split(':')[0].lower())
            if obj.get('url'):
                observations['url'].add(obj['url'])
            if metadata['complete'] and not obj.get('is_header'):
                observations['hash'].update((hashlib.sha256(body).hexdigest(), hashlib.md5(body).hexdigest(), hashlib.sha1(body).hexdigest()))
            hits = inspect_content(body, policy)
            if not metadata['complete']:
                hits = [h for h in hits if h['kind'] != 'file_fingerprint']
            # Query/header values can themselves contain secrets; retain path only in evidence.
            metadata['url'] = metadata.get('url', '').split('?', 1)[0]
            metadata['matches'] = hits
            objects.append(metadata)
            triggered = [h for h in hits if alertable(h, policy['min_confidence'])]
            if triggered:
                if not obj.get('is_header'):
                    directory = settings.storage_dir / 'dlp_objects'
                    directory.mkdir(parents=True, exist_ok=True)
                    target = directory / metadata['sha256']
                    import os
                    import tempfile
                    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as handle:
                        handle.write(body)
                        temporary = Path(handle.name)
                    try:
                        os.replace(temporary, target)
                    finally:
                        temporary.unlink(missing_ok=True)
                    metadata['binary_available'] = True
                    metadata['hash_scope'] = 'complete_file' if metadata['complete'] else 'captured_bytes'
                findings.append({
                    'engine': 'dlp_engine', 'rule_id': 'DLP_TRANSFER_001', 'severity': 'High',
                    'confidence': max(hit['confidence'] for hit in triggered),
                    'evidence': {**metadata, 'action': 'alert', 'mode': 'passive',
                                 'triggered_by': [hit['kind'] for hit in triggered]},
                    'recommendation': '核查传输目的地和业务授权；对敏感内容脱敏、加密，必要时通过网关或终端策略阻断。',
                })
    coverage['rule_timeouts'] = sorted(set(policy['rule_timeouts']))
    return {'objects': objects, 'coverage': coverage, 'mode': 'passive', 'tls_decryption': False,
            'sensitive_objects': len(findings)}, observations, findings
