"""网络资产: the standing inventory of scanned services and their CVE hits."""
from fastapi.testclient import TestClient

from app.core.database import SessionLocal
from app.main import app
from app.models import Asset, DetectionFinding

IP = '10.255.255.30'


def _seed(db) -> None:
    db.query(Asset).filter(Asset.ip == IP).delete()
    db.query(DetectionFinding).filter(DetectionFinding.target_id == '10').delete()
    db.add(Asset(ip=IP, hostname=IP, port=8080, protocol='tcp', service='http',
                 asset_type='web', risk_level='High',
                 extra={'source': 'platform_scan', 'product': 'Apache httpd',
                        'version': '2.4.68', 'banner': 'Apache/2.4.68'}))
    db.add(Asset(ip=IP, hostname=IP, port=22, protocol='tcp', service='ssh',
                 asset_type='server', risk_level='Medium',
                 extra={'source': 'platform_scan', 'product': 'OpenSSH', 'version': '8.2p1'}))
    db.add(DetectionFinding(
        task_id=None, target_type='scan', target_id='10', engine='threat_intel',
        rule_id='CVE_CVE-2099-0001', severity='Critical', confidence=0.95,
        evidence={'cve': {'cve_id': 'CVE-2099-0001', 'cvss_score': 9.8, 'source': 'nvd'},
                  'asset': {'ip': IP, 'port': 8080, 'product': 'Apache httpd', 'version': '2.4.68'},
                  'confirmed': True, 'match_reason': 'matched_declared_range'},
        recommendation='升级 httpd', risk_score=9.8, risk_level='Critical'))
    db.commit()


def test_the_inventory_joins_each_service_to_the_cves_its_fingerprint_matched():
    with SessionLocal() as db:
        _seed(db)
    with TestClient(app) as client:
        body = client.get('/api/v1/network/assets', params={'search': IP}).json()
    row = next(item for item in body['items'] if item['port'] == 8080)
    assert (row['product'], row['version'], row['banner']) == ('Apache httpd', '2.4.68', 'Apache/2.4.68')
    assert row['source'] == 'platform_scan'
    assert row['confirmed_cve_count'] == 1
    assert row['cves'][0]['cve_id'] == 'CVE-2099-0001'
    assert row['cves'][0]['match_reason'] == 'matched_declared_range'
    # A port with no CVE is still listed: absence of a hit is information too.
    ssh = next(item for item in body['items'] if item['port'] == 22)
    assert ssh['cve_count'] == 0

    filtered = client.get('/api/v1/network/assets',
                          params={'search': IP, 'only_vulnerable': True}).json()
    assert [item['port'] for item in filtered['items']] == [8080]

    summary = client.get('/api/v1/network/assets/summary').json()
    assert summary['hosts'] >= 1 and summary['cves'] >= 1
    assert summary['by_severity'][0]['severity'] == 'Critical'
