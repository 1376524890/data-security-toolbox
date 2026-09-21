"""Persist remote files and bounded evidence with the shared data-object writer."""
import hashlib
from sqlalchemy import select
from app.models import AssetInstance, DataObject
from app.services import sensitive_engine, sensitivity_map
from app.services import fingerprint_candidates
from app.services.data_objects.evidence import _evidence_rows, _merge_detection
from app.services.data_objects.persistence import _get_or_create, recount_object
from shared.scanning import magic
from shared.scanning.budget import ScanBudget
from shared.scanning.parsers import parse_file


def analyze(path):
    size = path.stat().st_size
    kind = magic.detect(path.suffix.lower(), magic.probe_head(path), name=path.name)
    budget = ScanBudget({'max_bytes_read': 67108864, 'max_single_file_size': 8388608})
    parsed = parse_file(path, size, kind, budget=budget)
    blocks = [(parsed.text, '', '')] if parsed.text else []
    for sheet in parsed.sheets:
        blocks.extend((column.sample_text(), column.name, sheet.name) for column in sheet.columns)
    hits, counts = [], {}
    for text, field, sheet in blocks:
        for hit in sensitive_engine.scan_engine().scan(sensitive_engine.SensitiveDetectionContext(
                text=text, field_name=field, sheet_name=sheet, source_type='file')):
            if not (hit.sensitive and hit.confirmed and hit.count):
                continue
            category = sensitive_engine.legacy_name(hit.entity) or hit.entity.lower()
            counts[category] = counts.get(category, 0) + hit.count
            hits.append({'category': category, 'count': hit.count, 'confidence': hit.confidence,
                         'field_name': field, 'sheet_name': sheet,
                         'matches': [dict(item) for item in hit.matches],
                         'evidence': [item.to_dict() for item in hit.evidence][:32]})
    coverage = parsed.coverage if kind.kind != magic.KIND_BINARY else 'unsupported'
    return {'hits': hits, 'counts': counts, 'coverage': coverage,
            'reason': parsed.termination_reason if coverage != 'unsupported' else 'binary_metadata_only',
            'rows': parsed.rows_read}


def store(db, source, task, remote_path, size, scan, now):
    owner = f'file-source:{source.id}'
    key = 'remote:' + hashlib.sha256(f"{owner}:{remote_path}:{scan.get('hash', '')}".encode()).hexdigest()
    categories = list(scan['counts'])
    severity = sensitivity_map.worst_severity(categories)
    obj, _ = _get_or_create(db, DataObject, {'object_key': key},
        {'object_type': 'file', 'hash_type': 'scoped', 'size': size,
         'categories': categories, 'sensitivity': severity, 'first_seen_at': now, 'last_seen_at': now})
    instance, created = _get_or_create(db, AssetInstance, {'owner_key': owner, 'path': remote_path},
        {'object_id': obj.id, 'probe_id': None, 'source_kind': 'file_share',
         'name': remote_path.rsplit('/', 1)[-1], 'instance_type': 'file', 'size': size,
         'status': 'ACTIVE', 'hash_type': 'scoped', 'first_seen_at': now, 'last_seen_at': now})
    previous_object = instance.object_id
    instance.object_id = obj.id
    previous = instance.content_hash or ''
    digest = scan.get('hash', '')
    instance.size = size
    instance.content_hash = digest
    # A content hash is evidence of change here, not cross-source identity.
    instance.last_seen_at = instance.last_scan_at = now
    instance.last_scan_id = str(task.id)
    instance.status = 'ACTIVE'
    instance.coverage = scan['coverage']
    instance.termination_reason = scan['reason']
    instance.categories = categories if scan['coverage'] == 'complete' else sorted(set(instance.categories or []) | set(categories))
    instance.sensitivity = sensitivity_map.worst_severity(instance.categories)
    # A high-risk file is proposed as a fingerprint candidate; nothing is added to
    # a rule until an operator accepts it (see services/fingerprint_candidates).
    fingerprint_candidates.record(
        db, sha256=digest, path=remote_path, name=instance.name, source_name=source.name,
        level=sensitivity_map.worst_level(instance.categories), severity=instance.sensitivity,
        task_id=task.id)
    instance.extra = {**(instance.extra or {}), 'source_name': source.name, 'host': source.host,
                      'source_id': source.id, 'protocol': source.protocol,
                      'last_change': 'new' if created else 'changed' if previous and digest and previous != digest else 'unchanged'}
    db.flush()
    rows = _evidence_rows({'evidence': {'hits': scan['hits']}})
    for category in categories:
        _merge_detection(db, instance=instance, obj=obj, probe_id=None, source_kind='file_share',
            scan_id=str(task.id), category=category, counts=scan['counts'], evidence_rows=rows,
            engine_version=sensitive_engine.ENGINE_VERSION, ruleset_version='builtin', observed_at=now,
            sample_size=scan['rows'], sample_limit=25, confidence=max((h['confidence'] for h in scan['hits'] if h['category']==category), default=0),
            severity=sensitivity_map.severity_for(category), level=sensitivity_map.level_for(category))
    obj.last_seen_at = now
    recount_object(db, obj)
    if previous_object != obj.id:
        old = db.get(DataObject, previous_object)
        if old:
            recount_object(db, old)
    return instance, created, bool(previous and digest and previous != digest)
