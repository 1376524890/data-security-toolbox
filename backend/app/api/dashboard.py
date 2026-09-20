# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Dashboard, risk overview, graph and live-traffic domain.

The HTTP boundary only: every aggregate is derived from the stored findings,
assets, flows and incidents; this module owns the query shapes the console
charts and the node/edge projection the graph view renders.
"""

from __future__ import annotations

from collections import Counter
from datetime import UTC, datetime, timedelta
from typing import Any

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.api.assets import serialize_asset
from app.api.incident_presenter import serialize_incident
from app.api.pagination import page_response, paginate
from app.api.pcaps import serialize_flow
from app.api.probe_presenter import serialize_probe
from app.core.database import get_db
from app.integrations import integration_registry
from app.models import (
    IOC,
    Alert,
    Anomaly,
    Asset,
    DataAsset,
    DetectionFinding,
    FileRecord,
    Flow,
    GraphRelation,
    Incident,
    PacketRecord,
    PcapRecord,
    Probe,
    Report,
    Task,
)
from app.services.protocol_service import protocol_layer

router = APIRouter()


@router.get("/risk/summary")
def risk_summary(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(
        select(DetectionFinding.risk_level, func.count(DetectionFinding.id)).group_by(
            DetectionFinding.risk_level
        )
    ).all()
    engine_rows = db.execute(
        select(DetectionFinding.engine, func.count(DetectionFinding.id)).group_by(
            DetectionFinding.engine
        )
    ).all()
    asset_rows = db.execute(
        select(Asset.risk_level, func.count(Asset.id)).group_by(Asset.risk_level)
    ).all()
    data_rows = db.execute(
        select(DataAsset.sensitivity, func.count(DataAsset.id)).group_by(DataAsset.sensitivity)
    ).all()
    return {
        "count": db.scalar(select(func.count(DetectionFinding.id))) or 0,
        "risk_levels": {level: count for level, count in rows},
        "engines": {engine: count for engine, count in engine_rows},
        "asset_risk": {risk: count for risk, count in asset_rows},
        "data_sensitivity": {sensitivity: count for sensitivity, count in data_rows},
        "max_score": db.scalar(select(func.max(DetectionFinding.risk_score))) or 0,
        "avg_score": db.scalar(select(func.avg(DetectionFinding.risk_score))) or 0,
    }


@router.get("/graph")
def graph(db: Session = Depends(get_db)) -> dict[str, Any]:
    relations = [
        {
            "source_node": item.source_node,
            "source_type": item.source_type,
            "target_node": item.target_node,
            "target_type": item.target_type,
            "relation": item.relation,
            "risk": item.risk,
        }
        for item in db.scalars(select(GraphRelation).order_by(GraphRelation.id.desc())).all()
    ]
    assets = db.scalars(select(Asset)).all()
    data_assets = db.scalars(select(DataAsset)).all()
    incidents = db.scalars(select(Incident)).all()
    iocs = db.scalars(select(IOC)).all()
    probes = db.scalars(select(Probe)).all()
    nodes: list[dict[str, Any]] = []
    seen: set[str] = set()

    def add_node(
        node_id: str,
        label: str,
        node_type: str,
        risk: str = "Low",
        metadata: dict[str, Any] | None = None,
    ) -> None:
        if node_id in seen:
            return
        seen.add(node_id)
        nodes.append(
            {
                "id": node_id,
                "name": label,
                "type": node_type,
                "risk": risk,
                "metadata": metadata or {},
            }
        )

    for item in probes:
        add_node(f"probe:{item.id}", item.name, "probe", item.status, {"ip": item.ip_address})
    for item in assets:
        add_node(
            f"asset:{item.id}",
            item.ip or item.hostname,
            "host",
            item.risk_level,
            {"hostname": item.hostname, "service": item.service, "port": item.port},
        )
    for item in data_assets:
        add_node(
            f"data:{item.id}",
            item.name,
            "data_asset",
            item.sensitivity,
            {"asset_type": item.asset_type},
        )
    for item in iocs:
        add_node(f"ioc:{item.id}", item.value, "ioc", "High", {"ioc_type": item.ioc_type})
    for item in incidents:
        add_node(
            f"incident:{item.id}", item.title, "incident", item.risk_level, {"status": item.status}
        )
    return {"nodes": nodes, "relations": relations}


@router.get("/dashboard/summary")
def dashboard(db: Session = Depends(get_db)) -> dict[str, Any]:
    healthy_integrations = sum(1 for item in integration_registry.metadata() if item.get("healthy"))
    return {
        "assets": db.scalar(select(func.count(Asset.id))) or 0,
        "files": db.scalar(select(func.count(FileRecord.id))) or 0,
        "pcaps": db.scalar(select(func.count(PcapRecord.id))) or 0,
        "anomalies": db.scalar(select(func.count(Anomaly.id))) or 0,
        "tasks": db.scalar(select(func.count(Task.id))) or 0,
        "reports": db.scalar(select(func.count(Report.id))) or 0,
        "probes": db.scalar(select(func.count(Probe.id))) or 0,
        "incidents": db.scalar(select(func.count(Incident.id))) or 0,
        "iocs": db.scalar(select(func.count(IOC.id))) or 0,
        "alerts": db.scalar(select(func.count(Alert.id))) or 0,
        "open_alerts": db.scalar(select(func.count(Alert.id)).where(Alert.status == "new")) or 0,
        "high_risk_findings": db.scalar(
            select(func.count(DetectionFinding.id)).where(
                DetectionFinding.risk_level.in_(["Critical", "High"])
            )
        )
        or 0,
        "open_incidents": db.scalar(
            select(func.count(Incident.id)).where(Incident.status == "open")
        )
        or 0,
        "high_risk_assets": db.scalar(
            select(func.count(Asset.id)).where(Asset.risk_level.in_(["Critical", "High"]))
        )
        or 0,
        "sensitive_data_assets": db.scalar(
            select(func.count(DataAsset.id)).where(DataAsset.sensitivity.in_(["Critical", "High"]))
        )
        or 0,
        "online_probes": db.scalar(select(func.count(Probe.id)).where(Probe.status == "online"))
        or 0,
        "healthy_integrations": healthy_integrations,
    }


@router.get("/dashboard/risk-trend")
def risk_trend(range: str = Query("7d"), db: Session = Depends(get_db)) -> dict[str, Any]:
    days = 1 if range == "24h" else 7
    since = datetime.now(UTC) - timedelta(days=days)
    rows = db.scalars(
        select(DetectionFinding)
        .where(DetectionFinding.created_at >= since)
        .order_by(DetectionFinding.created_at)
    ).all()
    buckets: dict[str, dict[str, float | int]] = {}
    for item in rows:
        key = (
            item.created_at.strftime("%Y-%m-%d")
            if days > 1
            else item.created_at.strftime("%Y-%m-%d %H:00")
        )
        entry = buckets.setdefault(key, {"risk_score": 0, "count": 0, "critical": 0, "high": 0})
        entry["risk_score"] = max(float(entry["risk_score"]), item.risk_score)
        entry["count"] = int(entry["count"]) + 1
        if item.risk_level == "Critical":
            entry["critical"] = int(entry["critical"]) + 1
        elif item.risk_level == "High":
            entry["high"] = int(entry["high"]) + 1
    return {
        "range": range,
        "items": [{"time": key, **value} for key, value in sorted(buckets.items())],
    }


@router.get("/dashboard/severity")
def dashboard_severity(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(
        select(DetectionFinding.severity, func.count(DetectionFinding.id)).group_by(
            DetectionFinding.severity
        )
    ).all()
    return {"items": [{"severity": severity, "count": count} for severity, count in rows]}


@router.get("/dashboard/engines")
def dashboard_engines(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(
        select(DetectionFinding.engine, func.count(DetectionFinding.id)).group_by(
            DetectionFinding.engine
        )
    ).all()
    return {"items": [{"engine": engine, "count": count} for engine, count in rows]}


@router.get("/dashboard/incidents")
def dashboard_incidents(
    limit: int = Query(10, le=100), db: Session = Depends(get_db)
) -> dict[str, Any]:
    rows = db.scalars(select(Incident).order_by(Incident.risk_score.desc()).limit(limit)).all()
    return {"items": [serialize_incident(item) for item in rows]}


@router.get("/dashboard/high-risk-assets")
def dashboard_high_risk_assets(
    limit: int = Query(10, le=100), db: Session = Depends(get_db)
) -> dict[str, Any]:
    rows = db.scalars(
        select(Asset).order_by(Asset.risk_level.desc(), Asset.id.desc()).limit(limit)
    ).all()
    return {"items": [serialize_asset(item) for item in rows]}


@router.get("/dashboard/sensitive-data")
def dashboard_sensitive_data(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(
        select(DataAsset.sensitivity, func.count(DataAsset.id)).group_by(DataAsset.sensitivity)
    ).all()
    return {"items": [{"category": category, "count": count} for category, count in rows]}


# ---------------------------------------------------------------------------
# Frontend-alignment additions
# ---------------------------------------------------------------------------


@router.get("/flows")
def global_flows(
    search: str | None = None,
    ip: str | None = None,
    protocol: str | None = None,
    port: int | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Global flow explorer across all captured PCAPs."""
    query = select(Flow)
    if ip:
        query = query.where(or_(Flow.src_ip == ip, Flow.dst_ip == ip))
    if protocol:
        query = query.where(Flow.protocol == protocol)
    if port:
        query = query.where(or_(Flow.src_port == port, Flow.dst_port == port))
    if search:
        query = query.where(or_(Flow.src_ip.ilike(f"%{search}%"), Flow.dst_ip.ilike(f"%{search}%")))
    result = paginate(db, query.order_by(Flow.bytes.desc()), page, page_size)
    return page_response(
        [serialize_flow(item) for item in result["items"]], page, page_size, result["total"]
    )


@router.get("/protocols")
def global_protocols(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    """Global protocol distribution across all captured PCAPs.

    Every row carries the layer the protocol name belongs to, so the console
    can chart application protocols instead of transport and capture plumbing.
    """
    rows = db.execute(
        select(Flow.protocol, func.count(Flow.id), func.sum(Flow.bytes)).group_by(Flow.protocol)
    ).all()
    items = [
        {"name": name, "count": count, "bytes": int(bytes or 0), "layer": protocol_layer(name)}
        for name, count, bytes in rows
    ]
    items.sort(key=lambda item: item["count"], reverse=True)
    return items


@router.get("/network/live")
def network_live(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Live traffic overview derived from recent PCAP flows + probe heartbeat."""
    now = datetime.now(UTC)
    window_seconds = 300
    since = now - timedelta(seconds=window_seconds)
    recent_pcaps = db.scalars(select(PcapRecord.id).where(PcapRecord.created_at >= since)).all()
    pcap_ids = [item for item in recent_pcaps]
    probes = db.scalars(select(Probe)).all()
    online = 0
    degraded = 0
    cpu: list[float] = []
    mem: list[float] = []
    for probe in probes:
        status = serialize_probe(probe)["status"]
        if status == "online":
            online += 1
        elif status == "degraded":
            degraded += 1
        extra = probe.extra or {}
        system = extra.get("system") or {}
        if isinstance(system.get("cpu_percent"), (int, float)):
            cpu.append(float(system["cpu_percent"]))
        if isinstance(system.get("memory_percent"), (int, float)):
            mem.append(float(system["memory_percent"]))
    flows: list[Flow] = []
    packets: list[PacketRecord] = []
    if pcap_ids:
        flows = list(db.scalars(select(Flow).where(Flow.pcap_id.in_(pcap_ids))).all())
        packets = list(  # noqa: F841 - pre-existing dead local, moved verbatim from v1
            db.scalars(select(PacketRecord).where(PacketRecord.pcap_id.in_(pcap_ids))).all()
        )
    total_bytes = sum(item.bytes for item in flows)
    total_packets = sum(item.packets for item in flows)
    src_counter: Counter[str] = Counter()
    dst_counter: Counter[str] = Counter()
    port_counter: Counter[int] = Counter()
    for flow in flows:
        src_counter[flow.src_ip] += flow.bytes
        dst_counter[flow.dst_ip] += flow.bytes
        port_counter[flow.dst_port] += flow.bytes
    top_src = [{"ip": ip, "bytes": bytes} for ip, bytes in src_counter.most_common(10)]
    top_dst = [{"ip": ip, "bytes": bytes} for ip, bytes in dst_counter.most_common(10)]
    top_port = [{"port": port, "bytes": bytes} for port, bytes in port_counter.most_common(10)]
    recent_alerts = db.scalar(select(func.count(Alert.id)).where(Alert.created_at >= since)) or 0
    return {
        "window_seconds": window_seconds,
        "probes": {"online": online, "degraded": degraded, "total": len(probes)},
        "connections": len(flows),
        "packets": total_packets,
        "bytes": total_bytes,
        "pps": round(total_packets / window_seconds, 2),
        "bps": round(total_bytes / window_seconds, 2),
        "avg_cpu_percent": round(sum(cpu) / len(cpu), 2) if cpu else 0,
        "avg_memory_percent": round(sum(mem) / len(mem), 2) if mem else 0,
        "top_src": top_src,
        "top_dst": top_dst,
        "top_port": top_port,
        "alerts_30m": recent_alerts,
    }


#: Coarse buckets for the two engines that can emit sensitive findings; the
#: per-entity breakdown lives in the object-model ``Detection`` rows instead.


@router.get("/dashboard/incident-trend")
def incident_trend(range: str = Query("7d"), db: Session = Depends(get_db)) -> dict[str, Any]:
    days = 1 if range == "24h" else 7
    since = datetime.now(UTC) - timedelta(days=days)
    rows = db.scalars(
        select(Incident).where(Incident.created_at >= since).order_by(Incident.created_at)
    ).all()
    buckets: dict[str, dict[str, float | int]] = {}
    for item in rows:
        key = (
            item.created_at.strftime("%Y-%m-%d")
            if days > 1
            else item.created_at.strftime("%Y-%m-%d %H:00")
        )
        entry = buckets.setdefault(
            key, {"count": 0, "critical": 0, "high": 0, "medium": 0, "risk_score": 0}
        )
        entry["count"] = int(entry["count"]) + 1
        entry["risk_score"] = max(float(entry["risk_score"]), item.risk_score)
        if item.severity == "Critical":
            entry["critical"] = int(entry["critical"]) + 1
        elif item.severity == "High":
            entry["high"] = int(entry["high"]) + 1
        elif item.severity == "Medium":
            entry["medium"] = int(entry["medium"]) + 1
    return {
        "range": range,
        "items": [{"time": key, **value} for key, value in sorted(buckets.items())],
    }
