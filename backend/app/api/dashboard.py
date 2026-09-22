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
from sqlalchemy import String, cast, func, or_, select
from sqlalchemy.orm import Session

from app.api.assets import serialize_asset
from app.api.incident_presenter import serialize_incident
from app.api.integrations import integration_catalogue
from app.api.network_assets import SCAN_SOURCES
from app.api.pagination import page_response, paginate
from app.api.pcaps import serialize_flow
from app.api.probe_presenter import serialize_probe
from app.api.task_presenter import serialize_task
from app.core.database import get_db
from app.core.datetimes import aware
from app.domain.evidence_identity import evidence_asset_keys
from app.integrations import integration_registry
from app.models import (
    IOC,
    Alert,
    Anomaly,
    Asset,
    DataAsset,
    DataObject,
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
from app.services import cockpit_service, egress_regions
from app.services.probe_task_service import (
    default_task_filter,
    expire_probe_tasks,
    visible_tasks,
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


def severity_rows(db: Session) -> list[dict[str, Any]]:
    """Findings per severity; the one enumeration shared by both donut routes."""
    rows = db.execute(
        select(DetectionFinding.severity, func.count(DetectionFinding.id)).group_by(
            DetectionFinding.severity
        )
    ).all()
    return [{"severity": severity, "count": count} for severity, count in rows]


@router.get("/dashboard/severity")
def dashboard_severity(db: Session = Depends(get_db)) -> dict[str, Any]:
    return {"items": severity_rows(db)}


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


# ---------------------------------------------------------------------------
# 数据安全态势大屏 (big-screen aggregates)
#
# Every number below is derived on the fly from the stored rows; nothing is
# cached, and nothing is invented. Where the data model has no factual basis
# for a category (there is no zone table, so there is no honest "跨域" bucket),
# the endpoint reports the class the egress classifier can actually prove.
# ---------------------------------------------------------------------------

#: How many findings/incidents the per-node scan may read before giving up.
#: A node panel is a summary, not a report; the cap keeps the screen's refresh
#: interval from turning every 30 s into a full-table JSON scan.
NODE_FINDING_SCAN = 2000
NODE_INCIDENT_SCAN = 500

#: The three classes a flow can fall into on the screen, in display order.
FLOW_DIRECTIONS = ("internal", "external", "unknown")


def _direction_of(bucket: str) -> str:
    """The screen's flow class for a classifier bucket.

    The mapping lives with the classifier (``egress_regions.direction_of``) so
    the topology, the cockpit's egress count and the compliance board cannot
    drift into three vocabularies for the same verdict.
    """
    return egress_regions.direction_of(bucket)


def _utc(value: Any) -> datetime | None:
    """A row timestamp as an aware UTC datetime, or ``None`` when unusable.

    SQLite hands back naive datetimes while transcripts carry ISO strings; the
    trend buckets have to compare both against one window, so they are
    normalised here instead of in each route.
    """
    moment = aware(value)
    if isinstance(moment, datetime):
        return moment if moment.tzinfo else moment.replace(tzinfo=UTC)
    return None


def _count_rows(db: Session, model: Any, *conditions: Any) -> int:
    return int(db.scalar(select(func.count(model.id)).where(*conditions)) or 0)


def _window_counts(db: Session, model: Any, now: datetime) -> dict[str, Any]:
    """Total plus today/yesterday counts and the day-over-day change.

    ``delta_pct`` is ``None`` when yesterday has no rows: a percentage against
    zero would read as either "+∞%" or "+100%", both misleading, so the console
    renders the raw "今日新增" instead.
    """
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    yesterday_start = today_start - timedelta(days=1)
    today = _count_rows(db, model, model.created_at >= today_start)
    yesterday = _count_rows(
        db, model, model.created_at >= yesterday_start, model.created_at < today_start
    )
    return {
        "total": _count_rows(db, model),
        "today": today,
        "yesterday": yesterday,
        "delta_pct": None if not yesterday else round((today - yesterday) * 100 / yesterday),
    }


def _group_counts(
    db: Session, column: Any, model: Any, *conditions: Any
) -> list[dict[str, Any]]:
    """One ``{name, count}`` row per distinct value of ``column``."""
    rows = db.execute(
        select(column, func.count(model.id)).where(*conditions).group_by(column)
    ).all()
    return [{"name": str(name or "Unknown"), "count": int(count or 0)}
            for name, count in rows]


def _cockpit_blocks(
    db: Session,
    now: datetime,
    integrations: list[dict[str, Any]],
    alerts: dict[str, Any],
    incidents: dict[str, Any],
    findings: dict[str, Any],
    assets: dict[str, Any],
) -> dict[str, Any]:
    """The 数据安全综合驾驶舱 half of the overview.

    Everything the daily-use homepage shows is assembled here: the flat KPI
    counts, the posture ring, the two distribution cards, the compliance board,
    the week's focus list and the probe/engine status rows. The wall screen's
    blocks are computed beside these in the same request, so one page can never
    say 166 alerts while the other says 165.
    """
    flows = cockpit_service.flow_summary(db, now)
    board = cockpit_service.compliance(db, flows)
    posture = cockpit_service.health(db, board["checks"])
    catalogue = {
        "total": len(integrations),
        "healthy": sum(1 for item in integrations if item.get("healthy")),
    }
    scanned = Asset.extra["source"].as_string().in_(SCAN_SOURCES)
    high_risk = DetectionFinding.risk_level.in_(list(cockpit_service.HIGH_SEVERITIES))
    network_total = _count_rows(db, Asset, scanned)
    # One week window per KPI card, computed once and reused by the card and by
    # the 本周重点关注 row that reports the same number.
    windows = {
        "asset_count": cockpit_service.week_pair(db, Asset, now),
        "data_asset_count": cockpit_service.week_pair(db, DataObject, now),
        "network_asset_count": cockpit_service.week_pair(db, Asset, now, scanned),
        "finding_count": cockpit_service.week_pair(db, DetectionFinding, now),
        "incident_count": cockpit_service.week_pair(db, Incident, now),
        "alert_count": cockpit_service.week_pair(db, Alert, now),
        "high_risk_count": cockpit_service.week_pair(db, DetectionFinding, now, high_risk),
        "egress_event_count": flows["weekly"]["external"],
    }
    return {
        "asset_count": assets["total"],
        "data_asset_count": _count_rows(db, DataObject),
        "network_asset_count": network_total,
        "finding_count": findings["total"],
        "incident_count": incidents["total"],
        "alert_count": alerts["total"],
        "high_risk_count": findings["high_risk"],
        "egress_event_count": flows["totals"]["external"]["sessions"],
        "health_score": posture,
        "risk_distribution": {
            "risk_levels": _group_counts(db, DetectionFinding.risk_level, DetectionFinding),
            "severity": severity_rows(db),
            "data_sensitivity": _group_counts(db, DataObject.sensitivity, DataObject),
            "total_findings": findings["total"],
        },
        "asset_distribution": {
            "asset_types": _group_counts(db, Asset.asset_type, Asset),
            "network_types": _group_counts(db, Asset.asset_type, Asset, scanned),
            "total_assets": assets["total"],
            "total_network_assets": network_total,
        },
        "compliance_progress": board,
        "flow": {"totals": flows["totals"], "weekly": flows["weekly"]},
        "focus": cockpit_service.focus(
            high_risk_total=findings["high_risk"],
            high_risk=windows["high_risk_count"],
            incidents=windows["incident_count"],
            egress=windows["egress_event_count"],
            unhandled=alerts["open"],
            board=board,
        ),
        "status": cockpit_service.status(db, now, catalogue),
        "trends": windows,
    }


@router.get("/dashboard/overview")
def dashboard_overview(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Both homepages' KPI band, counted live in one pass.

    The 数据安全态势大屏 reads the ``alerts`` / ``incidents`` / ``findings`` /
    ``assets`` / ``loop`` / ``probes`` / ``integrations`` blocks; the 数据安全综合
    驾驶舱 reads the flat ``*_count`` keys, the posture score, the two
    distributions, the compliance board, the focus list and the status rows (see
    ``_cockpit_blocks``). Nothing here is cached or written.

    ``data_asset_count`` counts the de-duplicated data objects - the subject of
    the 数据资产 page; ``assets.data_assets`` stays the legacy projection row
    count the wall screen's card was built on, so the two are deliberately not
    the same number.
    """
    now = datetime.now(UTC)
    probes = [serialize_probe(item) for item in db.scalars(select(Probe)).all()]
    # The catalogue the console's header and engine card read, so every
    # "集成组件 x/y" on the screen is the same number.
    integrations = integration_catalogue()

    alerts = _window_counts(db, Alert, now)
    alerts["open"] = _count_rows(db, Alert, Alert.status == "new")
    alerts["critical_high"] = _count_rows(db, Alert, Alert.severity.in_(["Critical", "High"]))

    incidents = _window_counts(db, Incident, now)
    incidents["open"] = _count_rows(db, Incident, Incident.status == "open")

    findings = _window_counts(db, DetectionFinding, now)
    findings["high_risk"] = _count_rows(
        db, DetectionFinding, DetectionFinding.risk_level.in_(["Critical", "High"])
    )

    assets = {
        "total": _count_rows(db, Asset),
        "high_risk": _count_rows(db, Asset, Asset.risk_level.in_(["Critical", "High"])),
        "sensitive": _count_rows(db, DataAsset, DataAsset.sensitivity.in_(["Critical", "High"])),
        "data_assets": _count_rows(db, DataAsset),
    }

    # The closed loop the screen draws: what was found → what it became.
    loop = {
        "assets": assets["total"],
        "findings": findings["total"],
        "incidents": incidents["total"],
        "alerts": alerts["total"],
        "reports": _count_rows(db, Report),
    }

    return {
        "generated_at": now.isoformat(),
        "alerts": alerts,
        "incidents": incidents,
        "findings": findings,
        "assets": assets,
        "loop": loop,
        "probes": {
            "total": len(probes),
            "online": sum(1 for item in probes if item["status"] == "online"),
            "degraded": sum(1 for item in probes if item["status"] == "degraded"),
            "offline": sum(1 for item in probes if item["status"] not in ("online", "degraded")),
        },
        "integrations": {
            "total": len(integrations),
            "healthy": sum(1 for item in integrations if item.get("healthy")),
        },
        **_cockpit_blocks(db, now, integrations, alerts, incidents, findings, assets),
    }


def _node_risk_counts(db: Session, ips: list[str]) -> dict[str, dict[str, int]]:
    """Findings/incidents per host address, via the shared evidence identity.

    The LIKE is a cheap candidate filter; ``evidence_asset_keys`` decides, so a
    node count means the same thing as the count on the asset page.
    """
    counts = {ip: {"findings": 0, "high_risk_findings": 0, "incidents": 0} for ip in ips}
    if not ips:
        return counts
    wanted = set(ips)
    # Only the two columns the count reads: the findings table carries large
    # payloads, and hydrating 2 000 full rows to look at their evidence made
    # this the slowest part of the screen's refresh.
    finding_filter = or_(*[cast(DetectionFinding.evidence, String).like(f"%{ip}%") for ip in ips])
    findings = db.execute(
        select(DetectionFinding.evidence, DetectionFinding.risk_level)
        .where(finding_filter)
        .limit(NODE_FINDING_SCAN)
    ).all()
    for evidence, risk_level in findings:
        evidence = evidence if isinstance(evidence, dict) else {}
        for key in wanted.intersection(evidence_asset_keys(evidence)):
            counts[key]["findings"] += 1
            if risk_level in ("Critical", "High"):
                counts[key]["high_risk_findings"] += 1
    incident_filter = or_(*[cast(Incident.evidence, String).like(f"%{ip}%") for ip in ips])
    incidents = db.execute(
        select(Incident.evidence).where(incident_filter).limit(NODE_INCIDENT_SCAN)
    ).all()
    for (evidence,) in incidents:
        evidence = evidence if isinstance(evidence, dict) else {}
        for key in wanted.intersection(evidence_asset_keys(evidence)):
            counts[key]["incidents"] += 1
    return counts


@router.get("/dashboard/traffic-flow")
def dashboard_traffic_flow(
    limit: int = Query(18, ge=2, le=60),
    days: int = Query(7, ge=1, le=30),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """The data-flow topology: nodes, links, totals and the daily trend.

    Nodes are the real addresses seen in the flow table (top ``limit`` links by
    bytes), enriched from the asset inventory when an address is a managed
    asset. Links carry the classifier's verdict, so a line is red only when the
    destination was actually proven to be outside.
    """
    policy = egress_regions.policy(db)
    memo: dict[str, str] = {}

    def bucket_of(ip: str) -> str:
        if ip not in memo:
            memo[ip] = egress_regions.classify(
                ip,
                blacklist=policy["blacklist"],
                whitelist=policy["whitelist"],
                internal=policy["internal_cidrs"],
            )["bucket"]
        return memo[ip]

    rows = db.execute(
        select(Flow.pcap_id, Flow.src_ip, Flow.dst_ip, Flow.bytes, Flow.packets)
    ).all()

    links: dict[tuple[str, str], list[int]] = {}
    nodes: dict[str, list[int]] = {}
    direction_sessions: Counter[str] = Counter()
    direction_bytes: Counter[str] = Counter()
    total_bytes = 0
    total_packets = 0
    for _pcap_id, src, dst, size, packets in rows:
        byte_count, packet_count = int(size or 0), int(packets or 0)
        direction = _direction_of(bucket_of(dst))
        direction_sessions[direction] += 1
        direction_bytes[direction] += byte_count
        total_bytes += byte_count
        total_packets += packet_count
        link = links.setdefault((src, dst), [0, 0, 0])
        link[0] += 1
        link[1] += byte_count
        link[2] += packet_count
        for ip in (src, dst):
            node = nodes.setdefault(ip, [0, 0, 0, 0])
            node[0] += 1
            node[1] += byte_count
            node[2] += packet_count
            if ip == dst and direction == "external":
                node[3] += 1

    # Daily trend. Days with no capture stay in the series as a real zero, so
    # the axis is the requested window, not just the days that happen to have
    # rows; a gap is information, an omitted day is a lie.
    now = datetime.now(UTC)
    pcap_dates = {
        pcap_id: moment
        for pcap_id, created_at in db.execute(select(PcapRecord.id, PcapRecord.created_at)).all()
        if (moment := _utc(created_at)) is not None
    }
    window_start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days - 1)
    trend: dict[str, dict[str, int]] = {}
    for offset in range(days):
        key = (window_start + timedelta(days=offset)).strftime("%m-%d")
        trend[key] = {direction: 0 for direction in FLOW_DIRECTIONS}
    for pcap_id, _src, dst, _size, _packets in rows:
        captured = pcap_dates.get(pcap_id)
        if captured is None or captured < window_start:
            continue
        key = captured.strftime("%m-%d")
        if key in trend:
            trend[key][_direction_of(bucket_of(dst))] += 1

    ranked = sorted(links.items(), key=lambda item: item[1][1], reverse=True)[:limit]
    node_ips = list(dict.fromkeys([ip for (_src, _dst), _ in ranked for ip in (_src, _dst)]))
    assets_by_ip = (
        {item.ip: item for item in db.scalars(select(Asset).where(Asset.ip.in_(node_ips))).all()}
        if node_ips
        else {}
    )
    risk_counts = _node_risk_counts(db, node_ips)
    data_asset_counts: Counter[str] = Counter()
    if node_ips:
        # A probe-collected data asset names its host in ``extra.host`` and its
        # probe in ``source``; the asset page matches it the same way, so the
        # count a node shows is the count the asset page shows.
        host_conditions = [DataAsset.extra["host"].as_string() == ip for ip in node_ips]
        hostnames = [item.hostname for item in assets_by_ip.values() if item.hostname]
        if hostnames:
            host_conditions.append(DataAsset.source.in_(hostnames))
        for host in db.scalars(
            select(DataAsset.extra["host"].as_string()).where(or_(*host_conditions))
        ):
            data_asset_counts[str(host or "")] += 1

    node_payload = []
    for ip in node_ips:
        asset = assets_by_ip.get(ip)
        bucket = bucket_of(ip)
        if _direction_of(bucket) == "external":
            kind = "external"
        elif asset:
            kind = "asset"
        else:
            kind = "host"
        node_payload.append(
            {
                "id": f"ip:{ip}",
                "ip": ip,
                "name": (asset.hostname or asset.ip) if asset else ip,
                "kind": kind,
                "bucket": bucket,
                "asset_id": asset.id if asset else None,
                "hostname": asset.hostname if asset else "",
                "os": asset.os if asset else "",
                "port": asset.port if asset else 0,
                "service": asset.service if asset else "",
                "asset_type": asset.asset_type if asset else "",
                "risk_level": asset.risk_level if asset else "",
                "sensitive_categories": list(asset.sensitive_categories or []) if asset else [],
                "sessions": nodes[ip][0],
                "bytes": nodes[ip][1],
                "packets": nodes[ip][2],
                "external_sessions": nodes[ip][3],
                "data_assets": data_asset_counts.get(ip, 0),
                **risk_counts.get(ip, {"findings": 0, "high_risk_findings": 0, "incidents": 0}),
            }
        )

    return {
        "generated_at": now.isoformat(),
        "days": days,
        "totals": {
            "sessions": len(rows),
            "bytes": total_bytes,
            "packets": total_packets,
            **{direction: direction_sessions[direction] for direction in FLOW_DIRECTIONS},
            "bytes_by_direction": {d: direction_bytes[d] for d in FLOW_DIRECTIONS},
        },
        "nodes": node_payload,
        "links": [
            {
                "source": f"ip:{src}",
                "target": f"ip:{dst}",
                "src_ip": src,
                "dst_ip": dst,
                "sessions": value[0],
                "bytes": value[1],
                "packets": value[2],
                "direction": _direction_of(bucket_of(dst)),
                "bucket": bucket_of(dst),
            }
            for (src, dst), value in ranked
        ],
        "trend": [{"time": key, **value} for key, value in trend.items()],
    }


@router.get("/dashboard/risk-distribution")
def dashboard_risk_distribution(db: Session = Depends(get_db)) -> dict[str, Any]:
    """Risk-level, asset-type and sensitivity breakdown for the two donuts."""
    risk_levels = db.execute(
        select(DetectionFinding.risk_level, func.count(DetectionFinding.id)).group_by(
            DetectionFinding.risk_level
        )
    ).all()
    asset_types = db.execute(
        select(Asset.asset_type, func.count(Asset.id)).group_by(Asset.asset_type)
    ).all()
    sensitivity = db.execute(
        select(DataAsset.sensitivity, func.count(DataAsset.id)).group_by(DataAsset.sensitivity)
    ).all()
    return {
        "risk_levels": [{"level": level, "count": count} for level, count in risk_levels],
        "severity": severity_rows(db),
        "asset_types": [{"type": name, "count": count} for name, count in asset_types],
        "sensitivity": [{"sensitivity": value, "count": count} for value, count in sensitivity],
        "total_findings": _count_rows(db, DetectionFinding),
        "total_assets": _count_rows(db, Asset),
    }


def _trend_axis(
    days: int, now: datetime
) -> tuple[list[str], datetime, str]:
    """The zero-filled time axis: ``days`` daily buckets, or 24 hourly ones.

    Days with no rows stay in the series as real zeros - the axis is the
    requested window, not just the buckets that happen to have data.
    """
    if days > 1:
        start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=days - 1)
        fmt, count, step = "%Y-%m-%d", days, timedelta(days=1)
    else:
        start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=23)
        fmt, count, step = "%Y-%m-%d %H:00", 24, timedelta(hours=1)
    # ``range`` is the query parameter's name in the routes below, so the axis
    # is walked with a cursor instead of the builtin.
    keys: list[str] = []
    moment = start
    while len(keys) < count:
        keys.append(moment.strftime(fmt))
        moment += step
    return keys, start, fmt


@router.get("/dashboard/detection-trend")
def dashboard_detection_trend(
    range: str = Query("7d"), db: Session = Depends(get_db)
) -> dict[str, Any]:
    """Findings, incidents and alerts per bucket, for the switchable trend card.

    One request feeds all three series so switching the card never changes the
    time axis, and every series is bucketed the same way over a zero-filled
    window.
    """
    days = 1 if range == "24h" else 7
    now = datetime.now(UTC)
    keys, start, fmt = _trend_axis(days, now)

    items = {key: {"findings": 0, "incidents": 0, "alerts": 0} for key in keys}
    for label, model in (
        ("findings", DetectionFinding),
        ("incidents", Incident),
        ("alerts", Alert),
    ):
        for created_at in db.scalars(
            select(model.created_at).where(model.created_at >= start)
        ).all():
            moment = _utc(created_at)
            if moment is None:
                continue
            key = moment.strftime(fmt)
            if key in items:
                items[key][label] += 1
    return {
        "range": range,
        "items": [{"time": key, **value} for key, value in items.items()],
    }


@router.get("/dashboard/trend")
def dashboard_trend(
    range: str = Query("7d"), db: Session = Depends(get_db)
) -> dict[str, Any]:
    """The cockpit's daily series: findings, incidents, alerts and data movement.

    One request carries every series the 驾驶舱 draws over the same zero-filled
    axis, so the KPI sparklines and the 数据流动审计 bars can never disagree about
    which day "09-18" is. Flow buckets come from the real capture start of each
    session (``flows.start_time``); a session with no timestamp is left out
    rather than attributed to the day it was ingested.
    """
    days = 1 if range == "24h" else 7
    now = datetime.now(UTC)
    keys, start, fmt = _trend_axis(days, now)
    items = {key: {"findings": 0, "incidents": 0, "alerts": 0} for key in keys}
    for label, model in (
        ("findings", DetectionFinding),
        ("incidents", Incident),
        ("alerts", Alert),
    ):
        for created_at in db.scalars(
            select(model.created_at).where(model.created_at >= start)
        ).all():
            moment = _utc(created_at)
            if moment is None:
                continue
            key = moment.strftime(fmt)
            if key in items:
                items[key][label] += 1
    flows = {item["time"]: item for item in cockpit_service.flow_daily(db, days, now)}
    return {
        "range": range,
        "items": [
            {
                "time": key,
                **values,
                **{direction: flows.get(key, {}).get(direction, 0)
                   for direction in FLOW_DIRECTIONS},
            }
            for key, values in items.items()
        ],
    }


@router.get("/dashboard/tasks")
def dashboard_tasks(
    limit: int = Query(8, ge=1, le=50), db: Session = Depends(get_db)
) -> dict[str, Any]:
    """最近任务: the newest visible task rows for the cockpit's task card.

    The same filter and serializer as ``GET /tasks`` (``visible_tasks`` plus the
    default "hide capture segments" rule), ordered the same way, so a task the
    任务中心 cannot show never appears here either. Unlike that route this one
    does not run the monitoring roll-up: a homepage must not write.
    """
    expire_probe_tasks(db)
    db.commit()
    rows = db.scalars(
        select(Task)
        .where(visible_tasks(), default_task_filter())
        .order_by(Task.id.desc())
        .limit(limit)
    ).all()
    return {"items": [serialize_task(row) for row in rows]}
