r"""Removing the false positives that are already stored.

Fixing a rule stops the *next* false positive; it does nothing about the 331
Swedish organisation numbers sitting in the database because ``\b\d{6}[-]?\d{4}\b``
matched shell-history timestamps. Everything here works from what a row itself
recorded, and nothing is deleted that the row does not prove: a rule an analyst
removed, a path that moved or a host that went away is *not* evidence.
"""
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.models import (
    Alert,
    AssetInstance,
    Base,
    Detection,
    DetectionEvidence,
    DetectionFinding,
)
from app.services import finding_hygiene
from app.services.file_scan import service as file_scan_service


def config(name):
    return dict(name=name, protocol='ftp', host='files.invalid', port=21, username='reader',
                password='never-return-this', root_path='/share', host_key_sha256='',
                enabled=True, limits={}, interval_minutes=15)


def _session(tmp_path):
    """A database of this test's own: the sweeps read every row in the table."""
    engine = create_engine(f"sqlite:///{tmp_path / 'hygiene.db'}")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)()


def _detection(db, path, value, rule_id='SD_CREDENTIAL_001'):
    instance = AssetInstance(object_id=1, owner_key='probe:1', source_kind='file',
                             path=path, name=path.rsplit('/', 1)[-1], size=10,
                             status='ACTIVE')
    db.add(instance)
    db.flush()
    detection = Detection(object_id=1, instance_id=instance.id, source_kind='file',
                          category='credential', sensitivity_level='L4', severity='Critical')
    db.add(detection)
    db.flush()
    db.add(DetectionEvidence(detection_id=detection.id, rule_id=rule_id, evidence_key='k',
                             extra={'matches': [{'value': value}]}))
    db.flush()
    return detection


def test_a_detection_from_an_excluded_dependency_path_is_reported(tmp_path) -> None:
    with _session(tmp_path) as db:
        file_scan_service.save(db, config('hygiene-source'))
        detection = _detection(db, '/srv/app/node_modules/left-pad/index.js', 'password: bytes,')

        verdict = finding_hygiene.stale_file_detections(db, revalidate=False)

        assert detection.id in verdict['reasons'][finding_hygiene.REASON_EXCLUDED_PATH]
        assert verdict['counts'][finding_hygiene.REASON_EXCLUDED_PATH] == 1


def test_the_programme_s_own_source_tree_is_not_blanket_excluded(tmp_path) -> None:
    """Only dependency and VCS stores are skipped: a credential in the customer's
    own project must stay visible."""
    with _session(tmp_path) as db:
        file_scan_service.save(db, config('hygiene-source'))
        detection = _detection(db, '/srv/app/src/settings.py', 'password: bytes,')

        verdict = finding_hygiene.stale_file_detections(db, revalidate=False)

        assert detection.id not in verdict['reasons'][finding_hygiene.REASON_EXCLUDED_PATH]


def test_traffic_findings_are_matched_on_the_addresses_their_evidence_names(tmp_path) -> None:
    with _session(tmp_path) as db:
        for target, evidence in (
            ('bridge', {'src': '172.23.0.7', 'dst': '172.23.0.2'}),
            ('dns', {'src': '114.114.114.114:53 -> 192.168.110.168'}),
        ):
            db.add(DetectionFinding(target_type='pcap', target_id=target, engine='traffic',
                                    rule_id='NET_SCAN_001', severity='High', evidence=evidence))
        db.flush()

        # An empty list matches nothing: a purge must never be the default.
        assert finding_hygiene.stale_traffic_findings(db, []) == []
        matched = finding_hygiene.stale_traffic_findings(db, ['172.23.0.0/16', '127.0.0.0/8'])
        assert [row.target_id for row in matched] == ['bridge']


def test_dry_run_reports_without_deleting(tmp_path) -> None:
    with _session(tmp_path) as db:
        file_scan_service.save(db, config('hygiene-source'))
        detection = _detection(db, '/srv/app/node_modules/left-pad/index.js', 'password: bytes,')
        finding = DetectionFinding(target_type='pcap', target_id='bridge', engine='traffic',
                                   rule_id='NET_SCAN_001', severity='High',
                                   evidence={'src': '172.23.0.7'})
        db.add(finding)
        db.flush()
        db.add(Alert(fingerprint='fp-bridge', finding_id=finding.id, severity='High',
                     title='bridge scan', status='new'))
        db.flush()

        preview = finding_hygiene.purge(db, addresses=['172.23.0.0/16'], dry_run=True)

        assert preview['dry_run'] is True
        assert preview['detections_total'] == 1
        assert preview['findings'] == 1
        assert db.get(Detection, detection.id) is not None
        assert db.get(DetectionFinding, finding.id) is not None

        applied = finding_hygiene.purge(db, addresses=['172.23.0.0/16'], dry_run=False)

        assert applied['detection_evidence_deleted'] == 1
        # An alert whose finding was proven stale is the alert the operator asked
        # to be rid of, and ``alerts.finding_id`` has no cascading delete.
        assert applied['alerts_deleted'] == 1
        assert db.get(Detection, detection.id) is None
        assert db.get(DetectionFinding, finding.id) is None
        assert db.query(Alert).filter(Alert.finding_id == finding.id).count() == 0
