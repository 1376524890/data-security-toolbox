"""DLP alerts on protected data and stays quiet on infrastructure chatter.

The worldwide Presidio pack contains locators (IP addresses, dates) and impostor
patterns (foreign licence plates, bare digit runs) that match ordinary container
traffic. Every hit stays visible as evidence, but only protected data of
sufficient precision may raise an alert.
"""
import io
import json
import socket
import zipfile

import dpkt
import pytest

from app.core.config import settings
from app.services.dlp import DEFAULT_POLICY, alertable, analyze_capture, inspect_content, normalize_policy
from app.services.rule_library import atomic_json, import_presidio_wheel, managed_rules, scan_managed

BASE_POLICY = {'categories': ['phone', 'id_card', 'email', 'api_key'], 'min_matches': 1}

PRESIDIO_SOURCE = '''
class IpRecognizer:
    PATTERNS = [Pattern("IPv4", r"(?<!\\d)(?:\\d{1,3}\\.){3}\\d{1,3}(?!\\d)", 0.6)]
    def __init__(self, supported_entity="IP_ADDRESS"): pass

class TrLicensePlateRecognizer:
    PATTERNS = [Pattern("TR License Plate (space)", r"(?<![\\w-])[A-Z]{1,3}\\s[A-Z]{1,2}\\s\\d{1,4}[EH]?(?!\\w)", 0.5)]
    def __init__(self, supported_entity="TR_LICENSE_PLATE"): pass

class AuAbnRecognizer:
    PATTERNS = [Pattern("ABN (Low)", r"\\b\\d{11}\\b", 0.1)]
    def __init__(self, supported_entity="AU_ABN"): pass

class DateRecognizer:
    PATTERNS = [Pattern("yyyy-mm-dd", r"\\b\\d{4}-\\d{2}-\\d{2}\\b", 0.6)]
    def __init__(self, supported_entity="DATE_TIME"): pass
'''

# Bare digit runs, licence plates, dates and IP addresses: metadata, never data.
CONTAINER_TRAFFIC = [
    ('172.18.0.9', 41234, '172.18.0.4', 8000,
     b'GET /api/v1/health HTTP/1.1\r\nHost: 172.18.0.4:8000\r\nUser-Agent: curl/8.5.0\r\n\r\n'),
    ('172.18.0.4', 8000, '172.18.0.9', 41234,
     b'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 118\r\n\r\n'
     b'{"status":"ok","container":"7c9f2a1b4e","collected_at":"2026-09-15","sequence":20260915133}'),
    ('172.17.0.1', 49001, '172.18.0.2', 2375,
     b'GET /v1.43/containers/json?all=1 HTTP/1.1\r\nHost: 172.18.0.2:2375\r\nDocker-Client: 24.0.7\r\n\r\n'),
]


def capture(path, streams):
    """Write raw-IP TCP segments, one packet per stream."""
    with path.open('wb') as handle:
        writer = dpkt.pcap.Writer(handle, linktype=101)
        timestamp = 1
        for src, sport, dst, dport, payload in streams:
            tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=1, flags=dpkt.tcp.TH_ACK, data=payload)
            packet = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=6, data=tcp)
            packet.len = len(packet)
            writer.writepkt(bytes(packet), ts=timestamp)
            timestamp += 1
    return path


@pytest.fixture
def presidio_rules(tmp_path, monkeypatch):
    """Import a synthetic upstream pack and force every rule on, as a legacy store does."""
    monkeypatch.setattr(settings, 'integration_dir', tmp_path / 'integrations')
    settings.integration_dir.mkdir(parents=True, exist_ok=True)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w') as wheel:
        wheel.writestr('presidio_analyzer/predefined_recognizers/generic/recognizers.py', PRESIDIO_SOURCE)
    import_presidio_wheel(buffer.getvalue(), 'test')
    document = json.loads((settings.integration_dir / 'dlp_rules' / 'presidio.json').read_text(encoding='utf-8'))
    for rule in document['rules']:
        rule['enabled'] = True
    atomic_json(settings.integration_dir / 'dlp_rules' / 'presidio.json', document)
    return managed_rules()


def matched_values(hits):
    """Every原文 the hits carry, in the one key allowed to hold it."""
    return [match["value"] for hit in hits for match in hit.get("matches") or []]


def test_container_traffic_is_evidence_without_alerts(presidio_rules, tmp_path):
    path = capture(tmp_path / 'container.pcap', CONTAINER_TRAFFIC)
    result, _, findings = analyze_capture(path, BASE_POLICY)
    # Locators and impostor patterns still surface in the transfer evidence.
    kinds = {hit['kind'] for obj in result['objects'] for hit in obj['matches']}
    assert {'IP_ADDRESS', 'DATE_TIME', 'AU_ABN'} <= kinds
    assert findings == [] and result['sensitive_objects'] == 0


def test_protected_data_transfer_still_alerts(presidio_rules, tmp_path):
    body = 'id_card=110101199003071234&phone=13800138000&key=sk-ABCDEFGHIJKLMNOPQRSTUVWX0123'
    streams = [('10.0.0.12', 51000, '10.0.0.33', 80,
                b'POST /api/customer/export HTTP/1.1\r\nHost: bi.example.com\r\nContent-Length: ' + str(len(body)).encode()
                + b'\r\n\r\n' + body.encode())]
    result, _, findings = analyze_capture(capture(tmp_path / 'export.pcap', streams), BASE_POLICY)
    assert result['sensitive_objects'] == 1 and len(findings) == 1
    finding = findings[0]
    assert finding['severity'] == 'High' and finding['rule_id'] == 'DLP_TRANSFER_001'
    assert {'id_card', 'phone', 'api_key'} <= set(finding['evidence']['triggered_by'])
    # The operator asked to see what was transmitted, so a hit now carries the
    # bounded matched原文 under ``matches``; this deliberately inverted the
    # earlier "no matched value leaves the network DLP stage" contract.
    assert '110101199003071234' in matched_values(finding['evidence']['matches'])
    # Bounded exactly like every other原文出口: 3 samples, 120/240 characters.
    for hit in finding['evidence']['matches']:
        assert len(hit.get('matches') or []) <= 3
        for match in hit.get('matches') or []:
            assert len(match['value']) <= 120 and len(match['context']) <= 240


def test_host_internal_traffic_is_not_egress(presidio_rules, tmp_path):
    streams = [('172.18.0.9', 40000, '127.0.0.11', 53, b'\x12\x34\x01\x00query\x00'),
               ('127.0.0.1', 50000, '127.0.0.1', 8080, b'GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n')]
    result, _, findings = analyze_capture(capture(tmp_path / 'internal.pcap', streams), BASE_POLICY)
    assert findings == [] and result['objects'] == [] and result['coverage']['excluded_streams'] == 2


def test_weak_and_metadata_hits_never_alert(presidio_rules):
    # The engine reads the rule store itself; nothing is injected through the
    # policy any more, because the platform and the console must run one set.
    hits = {hit['kind']: hit for hit in inspect_content(b'sequence 20260915133 host 172.18.0.4', BASE_POLICY)}
    assert not alertable(hits['AU_ABN'], DEFAULT_POLICY['min_confidence'])
    # Metadata locators are reported but can never make a stream sensitive.
    assert hits['IP_ADDRESS']['sensitive'] is False
    assert not alertable(hits['IP_ADDRESS'], DEFAULT_POLICY['min_confidence'])
    # The value behind a metadata hit is still原文 an operator can check.
    assert matched_values([hits['AU_ABN']]) == ['20260915133']


def test_loose_email_pattern_rejects_connection_strings(presidio_rules):
    rule = {'id': 'presidio-email', 'name': 'EmailRecognizer: Email (Medium)', 'entity': 'EMAIL_ADDRESS',
            'pattern': r"\b\w+@\w+(?:\.\w+)+\b", 'enabled': True, 'source': 'Presidio', 'confidence': .8}
    assert scan_managed('postgresql://security@172.18.0.2:5432/security_toolbox', [rule]) == []
    assert scan_managed('contact alice@example.com now', [rule])[0]['kind'] == 'EMAIL_ADDRESS'


def test_store_rules_get_the_same_email_shape_check(presidio_rules):
    """A loose email rule from the store rejects the same impostor, one engine."""
    from app.services import sensitive_engine
    from app.services.rule_library import save_manual_rule

    save_manual_rule({'name': 'EmailRecognizer: Email (Medium)', 'entity': 'EMAIL_ADDRESS',
                      'pattern': r"\b\w+@\w+(?:\.\w+)+\b", 'confidence': .8})
    entities = {hit.entity for hit in sensitive_engine.scan_all('postgresql://security@172.18.0.2:5432/security_toolbox')}
    assert 'EMAIL' not in entities
    entities = {hit.entity for hit in sensitive_engine.scan_all('contact alice@example.com now')}
    assert 'EMAIL' in entities


def test_policy_defaults_cover_stored_documents_without_new_keys():
    policy = normalize_policy({'categories': ['phone'], 'min_matches': 1})
    assert policy['min_confidence'] == DEFAULT_POLICY['min_confidence']
    assert policy['exclude_cidrs'] == DEFAULT_POLICY['exclude_cidrs']
    assert policy['self_endpoints'] == [] and policy['ignore_own_traffic'] is True


UPLOAD_BODY = 'phone=13800138000&id_card=110101199003071234'


def probe_upload(host, dst, dport=8088, headers=b'X-Probe-ID: 6\r\nX-Probe-Token: abc\r\n'):
    return ('192.168.191.128', 51000, dst, dport,
            b'POST /api/v1/pcaps/upload HTTP/1.1\r\nHost: ' + host.encode() + b'\r\n' + headers
            + b'Content-Length: ' + str(len(UPLOAD_BODY)).encode() + b'\r\n\r\n' + UPLOAD_BODY.encode())


def test_platform_endpoint_is_never_reported_as_data_loss(presidio_rules, tmp_path, monkeypatch):
    """The URL our own probes upload to is by definition us, whatever it carries."""
    monkeypatch.setattr(settings, 'deployment_backend_url', 'http://192.168.191.1:8088')
    streams = [probe_upload('192.168.191.1:8088', '192.168.191.1', headers=b'')]
    result, _, findings = analyze_capture(capture(tmp_path / 'platform.pcap', streams), BASE_POLICY)
    assert findings == [] and result['objects'] == []
    assert result['coverage']['excluded_own_traffic'] == 1


def test_own_auth_headers_exclude_traffic_regardless_of_address(presidio_rules, tmp_path, monkeypatch):
    """Address lists go stale (DHCP, containers); our own credentials do not."""
    monkeypatch.setattr(settings, 'deployment_backend_url', '')
    streams = [probe_upload('10.9.9.9:8088', '10.9.9.9')]
    result, _, findings = analyze_capture(capture(tmp_path / 'agent.pcap', streams), BASE_POLICY)
    assert findings == [] and result['coverage']['excluded_own_traffic'] == 1


def test_own_hostname_endpoint_matches_by_host_header(presidio_rules, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'deployment_backend_url', 'http://security-platform.local:8088')
    streams = [probe_upload('security-platform.local:8088', '192.168.191.1', headers=b'')]
    result, _, findings = analyze_capture(capture(tmp_path / 'hostname.pcap', streams), BASE_POLICY)
    assert findings == [] and result['coverage']['excluded_own_traffic'] == 1


def test_own_traffic_exclusion_can_be_disabled(presidio_rules, tmp_path, monkeypatch):
    monkeypatch.setattr(settings, 'deployment_backend_url', 'http://192.168.191.1:8088')
    policy = {**BASE_POLICY, 'ignore_own_traffic': False, 'self_endpoints': []}
    streams = [probe_upload('192.168.191.1:8088', '192.168.191.1')]
    result, _, findings = analyze_capture(capture(tmp_path / 'audit.pcap', streams), policy)
    assert len(findings) == 1 and result['coverage']['excluded_own_traffic'] == 0
