"""Detection stage: turn a capture into objects, coverage and DLP findings.

Passive only. Nothing here blocks a transfer, and every bound it applies is
reported through ``coverage`` instead of being presented as a clean capture.
"""
import hashlib
import os
import tempfile
from pathlib import Path
from urllib.parse import unquote_plus

from app.core.config import settings
from app.services.dlp import capture
from app.services.dlp.constants import MAX_OBJECTS
from app.services.dlp.policy import alertable, excluded_networks, host_internal, normalize_policy
from app.services.dlp.self_traffic import (
    host_header_is_self,
    is_own_traffic,
    own_traffic_markers,
    parse_self_endpoints,
    self_endpoint_entries,
)
from app.services.masking import masked


def inspect_content(body, config, *, timeouts: list[str] | None = None):
    """Text stage of the network DLP path, using the shared detection engine.

    The engine is the same one the probe, the file scan and the database scan
    run, and it now carries the console's own rules too, so one rule means one
    thing everywhere. Only the categories named by the stored policy are
    reported for the builtin pack; a rule an operator authored is reported
    because they asked for it, not because a policy checkbox lists its entity.

    Every hit carries the bounded matched原文 (``matches``: the value plus the
    line it sits on) so the console can show what was actually transmitted. The
    counts, categories and rule metadata stay value-free.
    """
    from app.services import sensitive_engine

    policy = normalize_policy(config)
    minimum = policy['min_matches']
    text = unquote_plus(body.decode('utf-8', 'replace'))
    scanned = sensitive_engine.scan_all(text, source_type='network', protocol='http')
    if timeouts is not None:
        timeouts.extend(sensitive_engine.scan_timeouts())
    authored = [hit for hit in scanned if sensitive_engine.has_analyst_rule(hit)]
    builtin = [hit for hit in scanned if not sensitive_engine.has_analyst_rule(hit)]
    hits = []
    for hit in (sensitive_engine.to_legacy_hits(builtin, policy['categories'], include_matches=True)
                + sensitive_engine.to_legacy_hits(authored, None, include_matches=True)):
        if hit['count'] >= minimum:
            hits.append({**hit, 'samples': []})
    for keyword in policy['keywords']:
        count = text.casefold().count(keyword.casefold())
        if count >= minimum:
            hits.append({'kind': 'keyword', 'count': count, 'samples': [masked(keyword)], 'confidence': 1.0,
                         'sensitive': True, 'rule_source': 'policy_keyword',
                         'matches': sensitive_engine.text_matches(text, keyword)})
    digest = hashlib.sha256(body).hexdigest()
    if digest in policy['fingerprints']:
        hits.append({'kind': 'file_fingerprint', 'count': 1, 'samples': [digest], 'confidence': 1.0,
                     'sensitive': True, 'rule_source': 'policy_fingerprint', 'matches': []})
    return hits


def stream_objects(data):
    """The objects one reassembled stream carries.

    Cleartext protocols without an HTTP parser still get bounded text scanning,
    so an unknown protocol is not an unexamined one.
    """
    extracted = capture.http_objects(data)
    if extracted:
        return extracted
    if capture.looks_like_text(data):
        return [{'filename': 'tcp-payload', 'body': data, 'complete': False, 'content_type': 'text/plain'}]
    return []


def object_metadata(entry, key, body, digest, *, index, incomplete):
    """The stored form of one object: identity, size, hash and completeness."""
    return {**entry, 'id': index, 'src_ip': key[0], 'src_port': key[1], 'dst_ip': key[2], 'dst_port': key[3],
            'size': len(body), 'sha256': digest,
            'complete': entry.get('complete', False) and not incomplete}


def store_object_bytes(body, digest):
    """Keep the bytes a finding points at, so the console can show what was sent.

    Written through a temporary file in the same directory: a reader must never
    see a half-written object under its final content address.
    """
    directory = settings.storage_dir / 'dlp_objects'
    directory.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(dir=directory, delete=False) as handle:
        handle.write(body)
        temporary = Path(handle.name)
    try:
        os.replace(temporary, directory / digest)
    finally:
        temporary.unlink(missing_ok=True)


def build_finding(metadata, triggered):
    """One DLP finding for one object, with the rule families that fired."""
    return {
        'engine': 'dlp_engine', 'rule_id': 'DLP_TRANSFER_001', 'severity': 'High',
        'confidence': max(hit['confidence'] for hit in triggered),
        'evidence': {**metadata, 'action': 'alert', 'mode': 'passive',
                     'triggered_by': [hit['kind'] for hit in triggered]},
        'recommendation': '核查传输目的地和业务授权；对敏感内容脱敏、加密，必要时通过网关或终端策略阻断。',
    }


def analyze_capture(path, config):
    policy = normalize_policy(config)
    networks = excluded_networks(policy)
    self_parsed = parse_self_endpoints(self_endpoint_entries(policy))
    markers = own_traffic_markers() if policy['ignore_own_traffic'] else ()
    streams, coverage = capture.reassemble(path)
    coverage['excluded_streams'] = 0
    coverage['excluded_own_traffic'] = 0
    rule_timeouts: list[str] = []
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
        extracted = stream_objects(data)
        if self_parsed and any(host_header_is_self(obj.get('host'), self_parsed) for obj in extracted):
            # Hostname-addressed tooling: the IP check above cannot see it.
            coverage['excluded_own_traffic'] += 1
            continue
        for obj in extracted:
            if len(objects) >= MAX_OBJECTS:
                coverage['object_limit'] = True
                break
            body = obj.pop('body')
            digest = hashlib.sha256(body).hexdigest()
            metadata = object_metadata(obj, key, body, digest, index=len(objects) + 1, incomplete=incomplete)
            if obj.get('host'):
                observations['domain'].add(obj['host'].split(':')[0].lower())
            if obj.get('url'):
                observations['url'].add(obj['url'])
            if metadata['complete'] and not obj.get('is_header'):
                observations['hash'].update((digest, hashlib.md5(body).hexdigest(), hashlib.sha1(body).hexdigest()))
            hits = inspect_content(body, policy, timeouts=rule_timeouts)
            if not metadata['complete']:
                hits = [h for h in hits if h['kind'] != 'file_fingerprint']
            # Query/header values can themselves contain secrets; retain path only in evidence.
            metadata['url'] = metadata.get('url', '').split('?', 1)[0]
            metadata['matches'] = hits
            objects.append(metadata)
            triggered = [h for h in hits if alertable(h, policy['min_confidence'])]
            if triggered:
                if not obj.get('is_header'):
                    store_object_bytes(body, digest)
                    metadata['binary_available'] = True
                    metadata['hash_scope'] = 'complete_file' if metadata['complete'] else 'captured_bytes'
                findings.append(build_finding(metadata, triggered))
    coverage['rule_timeouts'] = sorted(set(rule_timeouts))
    return {'objects': objects, 'coverage': coverage, 'mode': 'passive', 'tls_decryption': False,
            'sensitive_objects': len(findings)}, observations, findings
