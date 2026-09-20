# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Platform-asset domain: inventory, summary, relations and host detail.

The HTTP boundary only: scoring, correlation and evidence parsing stay in
``services/asset_service.py`` and ``incident_engine``. The asset-row shape is
shared with the other read domains, so it is exported as ``serialize_asset``.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from app.api.data_assets import _serialize_data_asset as _serialize_data_asset
from app.api.finding_presenter import _serialize_detection as _serialize_detection
from app.api.incident_presenter import serialize_incident
from app.api.ioc_presenter import serialize_ioc
from app.api.pagination import page_response, paginate
from app.core.database import get_db
from app.core.datetimes import aware
from app.incident_engine.engine import evidence_asset_keys
from app.models import (
    IOC,
    Asset,
    DataAsset,
    DetectionFinding,
    GraphRelation,
    Incident,
    Vulnerability,
)
from app.services.asset_service import asset_relations

router = APIRouter()


def serialize_asset(item: Asset) -> dict[str, Any]:
    return {
        "id": item.id,
        "probe_id": item.probe_id,
        "ip": item.ip,
        "hostname": item.hostname,
        "os": item.os,
        "port": item.port,
        "protocol": item.protocol,
        "service": item.service,
        "asset_type": item.asset_type,
        "risk_level": item.risk_level,
        "sensitive_categories": item.sensitive_categories,
        "metadata": item.extra,
        "first_seen": item.first_seen,
        "last_seen": aware(item.last_seen),
    }


@router.get("/assets")
def list_assets(
    risk: str | None = None,
    asset_type: str | None = None,
    ip: str | None = None,
    hostname: str | None = None,
    probe_id: int | None = None,
    search: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(Asset)
    if risk:
        query = query.where(Asset.risk_level == risk)
    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    if ip:
        query = query.where(Asset.ip == ip)
    if hostname:
        query = query.where(Asset.hostname == hostname)
    if probe_id:
        query = query.where(Asset.probe_id == probe_id)
    if search:
        query = query.where(
            or_(
                Asset.ip.ilike(f"%{search}%"),
                Asset.hostname.ilike(f"%{search}%"),
                Asset.service.ilike(f"%{search}%"),
            )
        )
    result = paginate(db, query.order_by(Asset.id.desc()), page, page_size)
    return page_response(
        [serialize_asset(item) for item in result["items"]], page, page_size, result["total"]
    )


@router.get("/assets/summary")
def asset_summary(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(
        select(Asset.risk_level, func.count(Asset.id)).group_by(Asset.risk_level)
    ).all()
    return {
        "count": db.scalar(select(func.count(Asset.id))) or 0,
        "risk": {risk: count for risk, count in rows},
    }


@router.get("/assets/relations")
def asset_relation_list(db: Session = Depends(get_db)) -> list[dict[str, str]]:
    assets = db.scalars(select(Asset)).all()
    return asset_relations(
        [{"ip": item.ip, "service": item.service, "port": item.port} for item in assets]
    )


def _incident_touches_asset(row: Incident, item: Asset) -> bool:
    """Whether an incident's *entire* host list covers this asset."""
    evidence = row.evidence if isinstance(row.evidence, dict) else {}
    if evidence.get("asset") in {item.ip, item.hostname}:
        return True
    assets = evidence.get("assets")
    return isinstance(assets, list) and item.ip in assets


def _finding_touches_asset(row: DetectionFinding, item: Asset) -> bool:
    """Whether a finding's evidence names this asset, in any of its spellings."""
    evidence = row.evidence if isinstance(row.evidence, dict) else {}
    wanted = {value.lower() for value in (item.ip, item.hostname) if value}
    return bool(wanted & set(evidence_asset_keys(evidence)))


@router.get("/assets/{asset_id}")
def asset_detail(asset_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(Asset, asset_id)
    if not item:
        raise HTTPException(404, "asset not found")
    # Findings name their asset in several spellings: a nested ``asset.ip``
    # (scan / threat-intel), a flat ``ip``, or only ``src``/``dst`` and
    # ``metrics`` keys (traffic, rules, dlp). Matching the first two left
    # "关联检测" empty for hosts that only appear in network evidence. The LIKE
    # is a cheap candidate filter; ``_finding_touches_asset`` decides.
    finding_candidates = db.scalars(
        select(DetectionFinding)
        .where(
            or_(
                DetectionFinding.evidence["asset"]["ip"].as_string() == item.ip,
                DetectionFinding.evidence["ip"].as_string() == item.ip,
                cast(DetectionFinding.evidence, String).like(f"%{item.ip}%"),
            )
        )
        .order_by(DetectionFinding.risk_score.desc())
        .limit(500)
    ).all()
    findings = [row for row in finding_candidates if _finding_touches_asset(row, item)][:100]
    # An incident lists every host it touches in ``evidence.assets`` while
    # ``evidence.asset`` only holds the display label, so matching the single
    # label hid a multi-host incident from all but one of its hosts. The LIKE is
    # a cheap candidate filter; ``_incident_touches_asset`` decides.
    incident_candidates = db.scalars(
        select(Incident)
        .where(
            or_(
                Incident.evidence["asset"].as_string() == item.ip,
                Incident.evidence["assets"].as_string().like(f"%{item.ip}%"),
            )
        )
        .order_by(Incident.risk_score.desc())
        .limit(200)
    ).all()
    incidents = [row for row in incident_candidates if _incident_touches_asset(row, item)][:50]
    # Probe-collected data assets record the host they were found on in
    # ``extra.host`` (``source`` holds "probe:<name>"), so matching ``source``
    # against a hostname never linked anything.
    data_assets = db.scalars(
        select(DataAsset)
        .where(
            or_(
                DataAsset.extra["host"].as_string() == item.ip,
                DataAsset.source == item.hostname,
            )
        )
        .limit(100)
    ).all()
    # An indicator belongs to an asset either because the asset *is* the
    # indicator, or because a finding on this asset fired on that indicator.
    ioc_values = {item.ip, item.hostname}
    for finding in findings:
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        for key in ("value", "ioc", "indicator"):
            candidate = evidence.get(key)
            if isinstance(candidate, str) and candidate.strip():
                ioc_values.add(candidate.strip())
        # The threat-intel engine reports hits as ``matched_iocs``; without
        # them a real indicator match never reached the asset's IOC tab.
        matched = evidence.get("matched_iocs")
        if isinstance(matched, list):
            ioc_values.update(str(value).strip() for value in matched if str(value).strip())
    iocs = db.scalars(select(IOC).where(IOC.value.in_(sorted(ioc_values))).limit(100)).all()
    relations = db.scalars(
        select(GraphRelation).where(
            or_(GraphRelation.source_node == item.ip, GraphRelation.target_node == item.ip)
        )
    ).all()
    vulnerabilities = db.scalars(
        select(Vulnerability)
        .where(Vulnerability.asset_id == asset_id)
        .order_by(Vulnerability.cvss_score.desc())
        .limit(100)
    ).all()
    return {
        "asset": serialize_asset(item),
        "findings": [_serialize_detection(item) for item in findings],
        "incidents": [serialize_incident(item) for item in incidents],
        "data_assets": [_serialize_data_asset(item) for item in data_assets],
        "iocs": [serialize_ioc(item) for item in iocs],
        "vulnerabilities": [
            {
                "id": item.id,
                "cve_id": item.cve_id,
                "cwe_id": item.cwe_id,
                "severity": item.severity,
                "cvss_score": item.cvss_score,
                "description": item.description,
                "status": item.status,
            }
            for item in vulnerabilities
        ],
        "relations": [
            {
                "source_node": item.source_node,
                "source_type": item.source_type,
                "target_node": item.target_node,
                "target_type": item.target_type,
                "relation": item.relation,
                "risk": item.risk,
            }
            for item in relations
        ],
    }
