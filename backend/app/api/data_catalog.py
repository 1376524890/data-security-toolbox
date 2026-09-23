# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Read APIs for the data-type-centric view: types, objects, instances, detections.

Everything here answers from the object model (``data_objects`` /
``asset_instances`` / ``detections`` / ``detection_evidence``), not from the
legacy ``data_assets`` projection, so the pages cannot drift from the scan
results. Lists are bounded, sortable only by a whitelist and paginated with the
platform's existing ``paginate``/``page_response`` helpers.

The evidence API exposes rule, recogniser, field, count and - by explicit
operator requirement - the bounded matched原文 the probe returned for that hit
(``extra['matches']``).

File *bodies* are never stored: ``/asset-instances/{id}/content`` re-reads a
bounded window from the collection source and masks the returned values by
default, and ``/asset-instances/{id}/download`` streams the whole file back from
that source. Only sources the platform can reach itself are retrievable, and an
instance collected by a probe says so instead of pretending to be empty.
"""
from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session
from starlette.background import BackgroundTask

from app.api.pagination import page_response, paginate
from app.core.database import get_db
from app.models import (
    AssetInstance,
    DataObject,
    Detection,
    DetectionEvidence,
    FileSource,
    Probe,
    Task,
)
from app.services import sensitivity_map
from app.services.audit_service import record_audit
from app.services.data_objects import definitions, projection, queries
from app.services.masking import masked

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
        'identity_kind': ('confirmed' if obj.hash_type == definitions.HASH_FULL
                          else 'candidate' if obj.hash_type == definitions.HASH_PARTIAL
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
        'owner_key': instance.owner_key or '',
        # file | database: which source observed this copy.
        'source_kind': instance.source_kind or 'file',
        'probe_name': probe.name if probe else (instance.extra or {}).get('probe_name', ''),
        'host': (probe.ip_address or probe.hostname) if probe else (instance.extra or {}).get('host', ''),
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
        'source_name': (instance.extra or {}).get('source_name') or (instance.extra or {}).get('connection_name') or (instance.extra or {}).get('probe_name', ''),
        'last_change': (instance.extra or {}).get('last_change', ''),
        'first_seen_at': instance.first_seen_at.isoformat() if instance.first_seen_at else '',
        'last_seen_at': instance.last_seen_at.isoformat() if instance.last_seen_at else '',
    }


def _detection_row(detection: Detection) -> dict[str, Any]:
    return {
        'id': detection.id, 'object_id': detection.object_id,
        'instance_id': detection.instance_id, 'probe_id': detection.probe_id,
        'source_kind': detection.source_kind or 'file',
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
    rows = queries.data_type_rows(db, mapping=mapping, probe_id=probe_id)
    return {
        'items': rows,
        'count': len(rows),
        # Cross-type totals over de-duplicated object/instance sets. The per-row
        # ``object_count``/``active_instance_count`` are type relations and may
        # count the same object twice, so a page must read these instead of
        # summing the table.
        'totals': queries.data_type_summary(db, probe_id=probe_id),
        'totals_scope': 'all_probes' if not probe_id else f'probe:{probe_id}',
        'dedup_rules': {
            'totals.objects': '存在 ACTIVE 实例的敏感对象数，跨类型去重',
            'totals.instances': '上述对象在当前范围内的活跃实例数',
            'totals.confirmed_duplicates': '对每个完整 Hash 对象计数 max(范围内实例数 - 1, 0)',
            'totals.candidate_duplicates': '部分指纹对象中至少存在 2 个实例的疑似副本数',
            'totals.identity_pending': '仅 1 个实例的部分指纹对象，身份待确认，不称副本',
            'object_count': '该类型的关联对象数（不跨类型去重，仅供类型内查看）',
            'active_instance_count': '该类型的关联活跃实例数（不跨类型去重）',
            'host_count': '观测来源数：一台探针算一个，一个数据库连接也算一个',
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
            queries.data_type_rows(db, mapping=mapping, probe_id=probe_id)}
    key = str(category or '').strip().lower()
    row = rows.get(key)
    if row is None:
        raise HTTPException(404, 'data type not found')
    # Only the object a detection was produced for counts; an instance that has
    # since moved to new content must not drag its history into this type.
    object_query = (select(Detection.object_id)
                    .join(AssetInstance, AssetInstance.id == Detection.instance_id)
                    .where(Detection.category == key,
                           AssetInstance.status == definitions.INSTANCE_ACTIVE,
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
        query = query.where(DataObject.hash_type == definitions.HASH_FULL)
    elif identity_kind == 'candidate':
        query = query.where(DataObject.hash_type == definitions.HASH_PARTIAL)
    elif identity_kind == 'scoped':
        query = query.where(DataObject.hash_type == definitions.HASH_SCOPED)
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
    payload = queries.object_detail(db, object_id)
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
    # Distinct observers, not distinct probes: a database-sourced instance has
    # no probe_id at all, and counting that column put every configured target
    # database into one nameless bucket.
    payload['host_count'] = len({key for key in (
        queries.owner_key_of(item.probe_id, item.owner_key) for item in instances) if key})
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
                         source_kind: str | None = None,
                         task_id: int | None = None,
                         owner_key: str | None = None, sensitive_only: bool = False,
                         order_by: str | None = None, page: int = Query(1, ge=1),
                         page_size: int = Query(50, ge=1, le=200),
                         db: Session = Depends(get_db)) -> dict[str, Any]:
    query = select(AssetInstance)
    association = None
    if task_id is not None:
        task = db.get(Task, task_id)
        if task is None or task.kind not in {'data_asset_scan', 'database_scan', 'file_source_scan'}:
            raise HTTPException(404, 'data asset task not found')
        result = task.result or {}
        # Persist membership for new reports: last_scan_id changes on the next scan.
        payload = task.payload or {}
        if task.kind == 'data_asset_scan':
            key = f"probe:{payload.get('probe_id')}"
            query = query.where(or_(AssetInstance.owner_key == key,
                                    AssetInstance.probe_id == payload.get('probe_id')))
        elif task.kind == 'file_source_scan':
            query = query.where(AssetInstance.owner_key == f"file-source:{payload.get('source_id')}")
        else:
            query = query.where(AssetInstance.owner_key == f"db:{payload.get('connection_id')}")
        if 'asset_instance_ids' in result:
            query = query.where(AssetInstance.id.in_(result['asset_instance_ids']))
            association = 'recorded_membership'
        else:
            scan_id = result.get('scan_id')
            query = query.where(AssetInstance.last_scan_id == scan_id) if scan_id else query.where(False)
            association = 'latest_scan_only'
    if probe_id:
        query = query.where(AssetInstance.probe_id == probe_id)
    if owner_key:
        query = query.where(AssetInstance.owner_key == owner_key)
    if sensitive_only:
        query = query.where(AssetInstance.id.in_(select(Detection.instance_id).where(
            Detection.object_id == AssetInstance.object_id,
            Detection.hit_count > 0)))
    if object_id:
        query = query.where(AssetInstance.object_id == object_id)
    if status:
        query = query.where(AssetInstance.status == str(status).upper())
    if instance_type:
        query = query.where(AssetInstance.instance_type == instance_type)
    if source_kind:
        query = query.where(AssetInstance.source_kind == str(source_kind).lower())
    if category:
        query = query.where(AssetInstance.categories.contains([str(category).lower()]))
    if search:
        query = query.where(AssetInstance.path.ilike(f'%{search}%'))
    query = _sorted(query, order_by, INSTANCE_SORTABLE, AssetInstance.id.desc())
    result = paginate(db, query, page, page_size)
    probes = {item.id: item for item in db.scalars(select(Probe)).all()}
    mapping = sensitivity_map.overrides(db)
    rows = [_instance_row(item, probes.get(item.probe_id), mapping) for item in result['items']]
    # One extra grouped query for the whole page rather than one per row: the
    # 风险文件 list has to answer "how much fired here" before a row is opened.
    # Counted against the instance's *current* object only, so the number agrees
    # with the risk-point drawer instead of adding up stale hits.
    identities = {item['id']: item['object_id'] for item in rows}
    if identities:
        counts = db.execute(
            select(Detection.instance_id, func.count(Detection.id),
                   func.coalesce(func.sum(Detection.hit_count), 0))
            .join(AssetInstance, AssetInstance.id == Detection.instance_id)
            .where(Detection.instance_id.in_(list(identities)),
                   Detection.object_id == AssetInstance.object_id)
            .group_by(Detection.instance_id)
        ).all()
        by_instance = {row[0]: row for row in counts}
        for item in rows:
            entry = by_instance.get(item['id'])
            item['risk_point_count'] = int(entry[1]) if entry else 0
            item['risk_hit_count'] = int(entry[2]) if entry else 0
    response = page_response(rows, page, page_size, result['total'])
    if association:
        response['association'] = association
    return response


@router.get('/asset-instances/{instance_id}')
def asset_instance_detail(instance_id: int, include_history: bool = False,
                          db: Session = Depends(get_db)) -> dict[str, Any]:
    """Instance detail plus its detections.

    ``include_history`` also returns detections belonging to *previous* objects at
    this path, which is how a content change stays explainable instead of looking
    like the old findings were deleted.
    """
    payload = queries.instance_detail(db, instance_id)
    if payload is None:
        raise HTTPException(404, 'asset instance not found')
    query = select(Detection).where(Detection.instance_id == instance_id)
    if not include_history:
        query = query.where(Detection.object_id == payload['object_id'])
    detections = db.scalars(query.order_by(Detection.id)).all()
    payload['detections'] = [_detection_row(item) for item in detections]
    payload['history_included'] = bool(include_history)
    return payload


def _evidence_rows(db: Session, detection: Detection) -> list[dict[str, Any]]:
    """One entry per stored evidence row, carrying the bounded matched原文.

    A single implementation on purpose: the per-detection endpoint and the
    风险文件 drawer answer the same question ("why did this fire"), and two
    copies would drift on what counts as the evidence.
    """
    rows = db.scalars(select(DetectionEvidence).where(
        DetectionEvidence.detection_id == detection.id).order_by(DetectionEvidence.id)).all()
    return [
        {
            'id': row.id, 'rule_id': row.rule_id, 'rule_name': row.rule_name,
            'rule_source': row.rule_source, 'recognizer': row.recognizer,
            'evidence_type': row.evidence_type, 'field_name': row.field_name,
            'sheet_name': row.sheet_name, 'column_index': row.column_index,
            'confidence': round(float(row.confidence or 0), 3), 'hit_count': row.hit_count,
            'engine_version': row.engine_version, 'ruleset_version': row.ruleset_version,
            # 原文 the probe returned with this hit; older evidence rows have none,
            # which is shown as "no returned text" rather than as an empty finding.
            'matches': list((row.extra or {}).get('matches') or []),
        }
        for row in rows
    ]


def _evidence_payload(db: Session, detection: Detection) -> dict[str, Any]:
    items = _evidence_rows(db, detection)
    return {
        'detection': _detection_row(detection),
        'items': items,
        'count': len(items),
        'matches_returned': sum(len(item['matches']) for item in items),
        'note': '证据含规则、识别器、字段与计数，并回传命中处原文（每命中最多 3 条，长度有上限）',
    }


@router.get('/detections/{detection_id}/evidence')
def detection_evidence(detection_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    detection = db.get(Detection, detection_id)
    if detection is None:
        raise HTTPException(404, 'detection not found')
    return _evidence_payload(db, detection)


@router.get('/asset-instances/{instance_id}/risk-points')
def asset_instance_risk_points(instance_id: int,
                               db: Session = Depends(get_db)) -> dict[str, Any]:
    """Every risk point on one file, for the moment its row is opened.

    The 风险文件 page has to show *what* matched without another click, so this
    answers the whole file in one request: each detection that fired, with its
    rules, counts and the bounded matched原文. Only the detections of the
    instance's *current* object are returned - a previous object at this path is
    history, and mixing the two would attribute stale hits to today's content.
    """
    instance = db.get(AssetInstance, instance_id)
    if instance is None:
        raise HTTPException(404, 'asset instance not found')
    rows = db.scalars(
        select(Detection)
        .where(Detection.instance_id == instance_id, Detection.object_id == instance.object_id)
        .order_by(Detection.sensitivity_level.desc(), Detection.hit_count.desc(), Detection.id)
    ).all()
    items = [{'detection': _detection_row(row), 'evidence': _evidence_rows(db, row)}
             for row in rows]
    return {
        'instance_id': instance.id, 'object_id': instance.object_id,
        'path': instance.path, 'name': instance.name,
        'level': sensitivity_map.worst_level(instance.categories),
        'items': items,
        'detection_count': len(items),
        'hit_count': sum(int(item['detection']['hit_count'] or 0) for item in items),
        'matches_returned': sum(len(row['matches'])
                                for item in items for row in item['evidence']),
        'note': '风险点＝命中类别 + 规则 + 命中处原文；原文由采集端回传，长度有上限',
    }


#: How much of a risky file is shown inline. Bounded on purpose: browsing is a
#: preview, not a download, and the platform stays a read-only observer.
PREVIEW_BYTES = 64 * 1024


def _retrievable_source(db: Session, instance: AssetInstance) -> FileSource:
    """The file source an instance's content can be re-read from, or an error.

    The platform keeps no file body, so reading a file again means going back to
    the source. A host file a probe collected cannot be re-read this way - the
    probe owns that path - and that is stated instead of being shown as an empty
    file. Both the browse and the download path resolve the source here, so the
    two can never disagree about which instances are retrievable.
    """
    if instance.instance_type != 'file':
        raise HTTPException(400, 'only file instances have content to preview')
    owner = str(instance.owner_key or '')
    if not owner.startswith('file-source:'):
        raise HTTPException(409, detail={
            'error': 'not_retrievable',
            'detail': '该文件由探针或上传采集，平台只保留元数据与命中原文；原文预览需要回到采集端重新读取'})
    source = db.get(FileSource, int(owner.split(':', 1)[1]))
    if source is None:
        raise HTTPException(404, 'source not found')
    return source


def _source_config(source: FileSource) -> dict[str, Any]:
    return {'protocol': source.protocol, 'host': source.host, 'port': source.port,
            'username': source.username, 'host_key_sha256': source.host_key_sha256,
            'root_path': source.root_path}


def _matched_values(db: Session, instance: AssetInstance) -> list[str]:
    """The原文 the rules returned for this instance's current object.

    Masking uses exactly the strings the evidence already carries, longest
    first: there is no second list of "sensitive values" that could drift from
    what actually fired, and a value no rule returned cannot be masked.
    """
    rows = db.scalars(
        select(DetectionEvidence)
        .join(Detection, DetectionEvidence.detection_id == Detection.id)
        .where(Detection.instance_id == instance.id,
               Detection.object_id == instance.object_id)
    ).all()
    values = {
        str(match['value'])
        for row in rows
        for match in ((row.extra or {}).get('matches') or [])
        if isinstance(match, dict) and match.get('value')
    }
    return sorted(values, key=len, reverse=True)


def _mask_values(text: str, values: list[str]) -> str:
    """Replace every returned value with its masked form.

    Longest first, so a value contained in a longer one is not half-replaced and
    left readable in the remainder.
    """
    for value in values:
        text = text.replace(value, masked(value))
    return text


@router.get('/asset-instances/{instance_id}/content')
def asset_instance_content(instance_id: int, mask: bool = True,
                           db: Session = Depends(get_db)) -> dict[str, Any]:
    """Browse the file an instance points at, re-read from its source on demand.

    The default is masked: a browse view should not spill identity numbers or
    credentials onto a screen just because someone clicked a row. The matched
    values are replaced by their masked form, and ``mask=false`` is the explicit
    "查看全部" that shows the file as it is on the host.
    """
    instance = db.get(AssetInstance, instance_id)
    if instance is None:
        raise HTTPException(404, 'asset instance not found')
    source = _retrievable_source(db, instance)
    try:
        from app.services.file_scan import adapters, service

        with adapters.connect(_source_config(source), service.password(source)) as remote:
            payload = remote.preview(instance.path, PREVIEW_BYTES)
    except Exception as exc:  # noqa: BLE001 - reported as a read failure
        raise HTTPException(502, detail={'error': 'read_failed',
                                         'detail': type(exc).__name__}) from exc
    text = None
    encoding = ''
    for candidate in ('utf-8', 'gb18030'):
        try:
            text = payload.decode(candidate)
            encoding = candidate
            break
        except UnicodeDecodeError:
            continue
    values = _matched_values(db, instance)
    if text is not None and mask and values:
        text = _mask_values(text, values)
    return {
        'instance_id': instance.id, 'path': instance.path, 'name': instance.name,
        'source_name': source.name, 'size': int(instance.size or 0),
        'preview_bytes': len(payload), 'truncated': int(instance.size or 0) > len(payload),
        'encoding': encoding or 'binary', 'text': text, 'masked': bool(mask and values),
        'masked_values': len(values),
        'hex': None if text is not None else payload[:4096].hex(),
    }


@router.get('/asset-instances/{instance_id}/download')
def asset_instance_download(instance_id: int,
                            db: Session = Depends(get_db)) -> FileResponse:
    """Send the whole file back from its source as an attachment.

    No file body is kept anywhere, so this is a fresh read of the entire file -
    the same copy the scan itself makes. It lands in a scratch file first because
    neither the SFTP nor the FTP client hands back a seekable stream; the scratch
    directory is removed once the response has been sent.
    """
    instance = db.get(AssetInstance, instance_id)
    if instance is None:
        raise HTTPException(404, 'asset instance not found')
    source = _retrievable_source(db, instance)
    scratch = Path(tempfile.mkdtemp(prefix='dst-file-download-'))
    name = instance.name or Path(instance.path).name or f'instance-{instance.id}'
    target = scratch / name
    try:
        from app.services.file_scan import adapters, service

        with adapters.connect(_source_config(source), service.password(source)) as remote:
            remote.download(instance.path, target, lambda _count: None)
    except Exception as exc:  # noqa: BLE001 - reported as a read failure
        shutil.rmtree(scratch, ignore_errors=True)
        raise HTTPException(502, detail={'error': 'read_failed',
                                         'detail': type(exc).__name__}) from exc
    return FileResponse(target, media_type='application/octet-stream', filename=name,
                        headers={'X-Content-Type-Options': 'nosniff',
                                 'Cache-Control': 'no-store'},
                        background=BackgroundTask(shutil.rmtree, scratch, True))


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
    result = projection.rebuild_projection(db, payload.probe_id)
    record_audit(db, request, action='data_assets.rebuild_projection',
                 target=f'probe:{payload.probe_id}' if payload.probe_id else 'all',
                 details=result)
    db.commit()
    return result


@router.post('/admin/data-assets/backfill')
def backfill(request: Request, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Project pre-existing ``data_assets`` rows once, without inventing metadata."""
    result = projection.backfill_legacy(db)
    record_audit(db, request, action='data_assets.backfill', target='data_assets',
                 details=result)
    db.commit()
    return result


__all__ = ['router']
