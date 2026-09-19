"""Read APIs for the data-type-centric view: types, objects, instances, detections.

Everything here answers from the object model (``data_objects`` /
``asset_instances`` / ``detections`` / ``detection_evidence``), not from the
legacy ``data_assets`` projection, so the pages cannot drift from the scan
results. Lists are bounded, sortable only by a whitelist and paginated with the
platform's existing ``paginate``/``page_response`` helpers.

Nothing in this module returns a matched value: the evidence API exposes rule,
recogniser, field and count, which is all the model ever stores.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.pagination import page_response, paginate
from app.core.database import get_db
from app.models import AssetInstance, DataObject, Detection, DetectionEvidence, Probe
from app.services import data_object_service, sensitivity_map
from app.services.audit_service import record_audit

router = APIRouter(prefix='/api/v1')

#: Whitelisted sort keys. Anything else is rejected rather than silently ignored,
#: so a page cannot ask for an unindexed full scan.
OBJECT_SORTABLE = {'id': DataObject.id, 'size': DataObject.size,
                   'active_instance_count': DataObject.active_instance_count,
                   'instance_count': DataObject.instance_count,
                   'last_seen_at': DataObject.last_seen_at,
                   'identity_confidence': DataObject.identity_confidence}
INSTANCE_SORTABLE = {'id': AssetInstance.id, 'size': AssetInstance.size,
                     'path': AssetInstance.path, 'last_seen_at': AssetInstance.last_seen_at,
                     'status': AssetInstance.status}
DETECTION_SORTABLE = {'id': Detection.id, 'confidence': Detection.confidence,
                      'hit_count': Detection.hit_count, 'last_seen_at': Detection.last_seen_at,
                      'sensitivity_level': Detection.sensitivity_level}


def _sorted(query: Any, order_by: Any, sortable: dict[str, Any], default: Any) -> Any:
    if not order_by:
        return query.order_by(default)
    key = str(order_by).lstrip('-')
    column = sortable.get(key)
    if column is None:
        raise HTTPException(400, detail={'error': 'unsupported_sort',
                                         'allowed': sorted(sortable)})
    return query.order_by(column.desc() if str(order_by).startswith('-') else column.asc())


def _object_row(obj: DataObject, mapping: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        'id': obj.id, 'object_key': obj.object_key, 'object_type': obj.object_type,
        'content_hash': obj.content_hash, 'hash_type': obj.hash_type,
        'identity_confidence': round(float(obj.identity_confidence or 0), 3),
        'identity_kind': ('confirmed' if obj.hash_type == data_object_service.HASH_FULL
                          else 'candidate' if obj.hash_type == data_object_service.HASH_PARTIAL
                          else 'scoped'),
        'partial_version': obj.partial_version,
        'size': obj.size, 'categories': list(obj.categories or []),
        'sensitivity': obj.sensitivity,
        'level': sensitivity_map.worst_level(obj.categories, mapping=mapping),
        'level_source': 'settings_override' if mapping else 'builtin_default',
        'instance_count': obj.instance_count,
        'active_instance_count': obj.active_instance_count,
        'first_seen_at': obj.first_seen_at.isoformat() if obj.first_seen_at else '',
        'last_seen_at': obj.last_seen_at.isoformat() if obj.last_seen_at else '',
    }


def _instance_row(instance: AssetInstance, probe: Probe | None = None,
                  mapping: dict[str, str] | None = None) -> dict[str, Any]:
    return {
        'id': instance.id, 'object_id': instance.object_id, 'probe_id': instance.probe_id,
        'probe_name': probe.name if probe else '',
        'host': (probe.ip_address or probe.hostname) if probe else '',
        'path': instance.path, 'name': instance.name, 'instance_type': instance.instance_type,
        'size': instance.size, 'content_hash': instance.content_hash,
        'hash_type': instance.hash_type, 'status': instance.status,
        'owner': instance.owner, 'group': instance.group, 'permission': instance.permission,
        'sensitivity': instance.sensitivity,
        'level': sensitivity_map.worst_level(instance.categories, mapping=mapping),
        'level_source': 'settings_override' if mapping else 'builtin_default',
        'categories': list(instance.categories or []),
        'coverage': instance.coverage, 'termination_reason': instance.termination_reason,
        'ruleset_version': instance.ruleset_version, 'engine_version': instance.engine_version,
        'profile_version': instance.profile_version,
        'last_scan_id': instance.last_scan_id,
        'first_seen_at': instance.first_seen_at.isoformat() if instance.first_seen_at else '',
        'last_seen_at': instance.last_seen_at.isoformat() if instance.last_seen_at else '',
    }


def _detection_row(detection: Detection) -> dict[str, Any]:
    return {
        'id': detection.id, 'object_id': detection.object_id,
        'instance_id': detection.instance_id, 'probe_id': detection.probe_id,
        'scan_id': detection.scan_id, 'category': detection.category,
        'subcategory': detection.subcategory,
        'sensitivity_level': detection.sensitivity_level, 'severity': detection.severity,
        'confidence': round(float(detection.confidence or 0), 3),
        'sample_size': detection.sample_size, 'sample_limit': detection.sample_limit,
        'sample_hit_count': detection.sample_hit_count,
        'hit_count': detection.hit_count,
        'engine_version': detection.engine_version, 'ruleset_version': detection.ruleset_version,
        'first_seen_at': detection.first_seen_at.isoformat() if detection.first_seen_at else '',
        'last_seen_at': detection.last_seen_at.isoformat() if detection.last_seen_at else '',
    }


@router.get('/data-types')
def list_data_types(probe_id: int | None = Query(default=None),
                    db: Session = Depends(get_db)) -> dict[str, Any]:
    """The data-type centre: one row per sensitive type with its real metrics."""
    mapping = sensitivity_map.overrides(db)
    rows = data_object_service.data_type_rows(db, mapping=mapping, probe_id=probe_id)
    return {
        'items': rows,
        'count': len(rows),
        # Cross-type totals over de-duplicated object/instance sets. The per-row
        # ``object_count``/``active_instance_count`` are type relations and may
        # count the same object twice, so a page must read these instead of
        # summing the table.
        'totals': data_object_service.data_type_summary(db, probe_id=probe_id),
        'totals_scope': 'all_probes' if not probe_id else f'probe:{probe_id}',
        'dedup_rules': {
            'totals.objects': '存在 ACTIVE 实例的敏感对象数，跨类型去重',
            'totals.instances': '上述对象在当前范围内的活跃实例数',
            'totals.confirmed_duplicates': '对每个完整 Hash 对象计数 max(范围内实例数 - 1, 0)',
            'totals.candidate_duplicates': '部分指纹对象中至少存在 2 个实例的疑似副本数',
            'totals.identity_pending': '仅 1 个实例的部分指纹对象，身份待确认，不称副本',
            'object_count': '该类型的关联对象数（不跨类型去重，仅供类型内查看）',
            'active_instance_count': '该类型的关联活跃实例数（不跨类型去重）',
            'candidate_count': '该类型的部分指纹对象数，单独统计，不计入确认副本',
        },
        'levels': sensitivity_map.LEVEL_META,
        'mapping_source': 'settings_override' if mapping else 'builtin_default',
    }


@router.get('/data-types/{category}')
def data_type_detail(category: str, probe_id: int | None = Query(default=None),
                     page: int = Query(1, ge=1),
                     page_size: int = Query(50, ge=1, le=200),
                     db: Session = Depends(get_db)) -> dict[str, Any]:
    mapping = sensitivity_map.overrides(db)
    rows = {row['category']: row for row in
            data_object_service.data_type_rows(db, mapping=mapping, probe_id=probe_id)}
    key = str(category or '').strip().lower()
    row = rows.get(key)
    if row is None:
        raise HTTPException(404, 'data type not found')
    # Only the object a detection was produced for counts; an instance that has
    # since moved to new content must not drag its history into this type.
    object_query = (select(Detection.object_id)
                    .join(AssetInstance, AssetInstance.id == Detection.instance_id)
                    .where(Detection.category == key,
                           AssetInstance.status == data_object_service.INSTANCE_ACTIVE,
                           Detection.object_id == AssetInstance.object_id))
    if probe_id:
        object_query = object_query.where(AssetInstance.probe_id == probe_id)
    object_ids = db.scalars(object_query.distinct()).all()
    query = select(DataObject).where(DataObject.id.in_(list(object_ids)))
    result = paginate(db, query.order_by(DataObject.active_instance_count.desc(), DataObject.id),
                      page, page_size)
    return {**row,
            'objects': page_response([_object_row(item, mapping) for item in result['items']],
                                     page, page_size, result['total'])}


@router.get('/data-objects')
def list_data_objects(category: str | None = None, hash_type: str | None = None,
                      identity_kind: str | None = None, probe_id: int | None = None,
                      search: str | None = None, order_by: str | None = None,
                      page: int = Query(1, ge=1), page_size: int = Query(50, ge=1, le=200),
                      db: Session = Depends(get_db)) -> dict[str, Any]:
    query = select(DataObject)
    if category:
        query = query.where(DataObject.categories.contains([str(category).lower()]))
    if hash_type:
        query = query.where(DataObject.hash_type == hash_type)
    if identity_kind == 'confirmed':
        query = query.where(DataObject.hash_type == data_object_service.HASH_FULL)
    elif identity_kind == 'candidate':
        query = query.where(DataObject.hash_type == data_object_service.HASH_PARTIAL)
    elif identity_kind == 'scoped':
        query = query.where(DataObject.hash_type == data_object_service.HASH_SCOPED)
    if probe_id:
        query = query.where(DataObject.id.in_(
            select(AssetInstance.object_id).where(AssetInstance.probe_id == probe_id)))
    if search:
        query = query.where(DataObject.object_key.ilike(f'%{search}%'))
    query = _sorted(query, order_by, OBJECT_SORTABLE, DataObject.id.desc())
    result = paginate(db, query, page, page_size)
    mapping = sensitivity_map.overrides(db)
    return page_response([_object_row(item, mapping) for item in result['items']],
                         page, page_size, result['total'])


@router.get('/data-objects/{object_id}')
def data_object_detail(object_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    payload = data_object_service.object_detail(db, object_id)
    if payload is None:
        raise HTTPException(404, 'data object not found')
    probe_ids = db.scalars(select(AssetInstance.probe_id).where(
        AssetInstance.object_id == object_id).distinct()).all()
    probes = {item.id: item for item in db.scalars(select(Probe).where(
        Probe.id.in_(list(probe_ids)))).all()} if probe_ids else {}
    instances = db.scalars(select(AssetInstance).where(
        AssetInstance.object_id == object_id).order_by(AssetInstance.id)).all()
    mapping = sensitivity_map.overrides(db)
    payload['instances'] = [_instance_row(item, probes.get(item.probe_id), mapping)
                            for item in instances]
    payload['host_count'] = len({item.probe_id for item in instances})
    payload['ruleset_versions'] = sorted({item.ruleset_version for item in instances if item.ruleset_version})
    return payload


@router.get('/data-objects/{object_id}/detections')
def data_object_detections(object_id: int, page: int = Query(1, ge=1),
                           page_size: int = Query(50, ge=1, le=200),
                           db: Session = Depends(get_db)) -> dict[str, Any]:
    if db.get(DataObject, object_id) is None:
        raise HTTPException(404, 'data object not found')
    query = select(Detection).where(Detection.object_id == object_id)
    result = paginate(db, query.order_by(Detection.id), page, page_size)
    return page_response([_detection_row(item) for item in result['items']],
                         page, page_size, result['total'])


@router.get('/asset-instances')
def list_asset_instances(probe_id: int | None = None, object_id: int | None = None,
                         status: str | None = None, category: str | None = None,
                         instance_type: str | None = None, search: str | None = None,
                         order_by: str | None = None, page: int = Query(1, ge=1),
                         page_size: int = Query(50, ge=1, le=200),
                         db: Session = Depends(get_db)) -> dict[str, Any]:
    query = select(AssetInstance)
    if probe_id:
        query = query.where(AssetInstance.probe_id == probe_id)
    if object_id:
        query = query.where(AssetInstance.object_id == object_id)
    if status:
        query = query.where(AssetInstance.status == str(status).upper())
    if instance_type:
        query = query.where(AssetInstance.instance_type == instance_type)
    if category:
        query = query.where(AssetInstance.categories.contains([str(category).lower()]))
    if search:
        query = query.where(AssetInstance.path.ilike(f'%{search}%'))
    query = _sorted(query, order_by, INSTANCE_SORTABLE, AssetInstance.id.desc())
    result = paginate(db, query, page, page_size)
    probes = {item.id: item for item in db.scalars(select(Probe)).all()}
    mapping = sensitivity_map.overrides(db)
    return page_response([_instance_row(item, probes.get(item.probe_id), mapping)
                          for item in result['items']],
                         page, page_size, result['total'])


@router.get('/asset-instances/{instance_id}')
def asset_instance_detail(instance_id: int, include_history: bool = False,
                          db: Session = Depends(get_db)) -> dict[str, Any]:
    """Instance detail plus its detections.

    ``include_history`` also returns detections belonging to *previous* objects at
    this path, which is how a content change stays explainable instead of looking
    like the old findings were deleted.
    """
    payload = data_object_service.instance_detail(db, instance_id)
    if payload is None:
        raise HTTPException(404, 'asset instance not found')
    query = select(Detection).where(Detection.instance_id == instance_id)
    if not include_history:
        query = query.where(Detection.object_id == payload['object_id'])
    detections = db.scalars(query.order_by(Detection.id)).all()
    payload['detections'] = [_detection_row(item) for item in detections]
    payload['history_included'] = bool(include_history)
    return payload


@router.get('/detections/{detection_id}/evidence')
def detection_evidence(detection_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    detection = db.get(Detection, detection_id)
    if detection is None:
        raise HTTPException(404, 'detection not found')
    rows = db.scalars(select(DetectionEvidence).where(
        DetectionEvidence.detection_id == detection_id).order_by(DetectionEvidence.id)).all()
    return {
        'detection': _detection_row(detection),
        'items': [{
            'id': row.id, 'rule_id': row.rule_id, 'rule_name': row.rule_name,
            'rule_source': row.rule_source, 'recognizer': row.recognizer,
            'evidence_type': row.evidence_type, 'field_name': row.field_name,
            'sheet_name': row.sheet_name, 'column_index': row.column_index,
            'confidence': round(float(row.confidence or 0), 3), 'hit_count': row.hit_count,
            'engine_version': row.engine_version, 'ruleset_version': row.ruleset_version,
        } for row in rows],
        'count': len(rows),
        'note': '证据只包含规则、识别器、字段与计数，从不包含匹配到的原始值',
    }


@router.get('/sensitivity-levels')
def sensitivity_levels(db: Session = Depends(get_db)) -> dict[str, Any]:
    """The L1..L4 mapping and where each entry's value came from."""
    mapping = sensitivity_map.overrides(db)
    return {'levels': sensitivity_map.LEVEL_META,
            'items': sensitivity_map.catalog(mapping=mapping),
            'non_protected': sensitivity_map.non_protected_catalog(),
            'note': 'L1～L4 是数据分级，Critical/High/Medium/Low 是旧页面的风险严重度，两者是不同维度',
            'source': 'settings_override' if mapping else 'builtin_default'}


class ProjectionRebuild(BaseModel):
    probe_id: int | None = Field(default=None, ge=1)


@router.post('/admin/data-assets/rebuild-projection')
def rebuild_projection(payload: ProjectionRebuild, request: Request,
                       db: Session = Depends(get_db)) -> dict[str, Any]:
    """Recover the derived legacy projection from the object model."""
    result = data_object_service.rebuild_projection(db, payload.probe_id)
    record_audit(db, request, action='data_assets.rebuild_projection',
                 target=f'probe:{payload.probe_id}' if payload.probe_id else 'all',
                 details=result)
    db.commit()
    return result


@router.post('/admin/data-assets/backfill')
def backfill(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Project pre-existing ``data_assets`` rows once, without inventing metadata."""
    result = data_object_service.backfill_legacy(db)
    record_audit(db, request, action='data_assets.backfill', target='data_assets',
                 details=result)
    db.commit()
    return result


__all__ = ['router']
