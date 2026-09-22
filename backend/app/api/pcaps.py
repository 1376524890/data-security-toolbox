# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""PCAP capture domain: upload, listing, flow/packet views and extracted files.

The heavy lifting stays in services (``pcap_files``, ``protocol_service``); this
module owns the HTTP boundary only - probe ownership of an upload, pagination,
and the response shapes the workbench depends on.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Request, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.api.dependencies import enforce_queue_backpressure, upload_probe_id
from app.api.finding_presenter import _serialize_detection as _serialize_detection
from app.api.pagination import page_response, paginate
from app.api.task_presenter import serialize_task
from app.core.config import settings
from app.core.database import get_db
from app.core.storage import stream_to_storage
from app.models import (
    Alert,
    AnalysisResult,
    Anomaly,
    DetectionFinding,
    Flow,
    PacketRecord,
    PcapRecord,
    Task,
)
from app.services.alert_service import serialize_alert
from app.services.protocol_service import packet_detail, protocol_tree, tcp_stream_follow
from app.services.task_dispatch import ANALYZE_PCAP, dispatch_task_row
from app.services.task_service import create_task
from app.services.traffic_service import (
    detect_anomalies,
    host_behavior,
    protocol_distribution,
    top_n_communication,
    traffic_trend,
)

router = APIRouter()


def serialize_pcap(item: PcapRecord) -> dict[str, Any]:
    return {
        "id": item.id,
        "probe_id": item.probe_id,
        "segment_id": item.segment_id,
        "sequence": item.sequence,
        "capture_interface": item.capture_interface,
        "capture_started_at": item.capture_started_at,
        "capture_finished_at": item.capture_finished_at,
        "ingest_status": item.ingest_status,
        "analysis_status": item.analysis_status,
        "probe_metadata": item.probe_metadata,
        "filename": item.filename,
        "size": item.size,
        "sha256": item.sha256,
        "packet_count": item.packet_count,
        "total_packet_count": item.total_packet_count,
        "indexed_packet_count": item.indexed_packet_count,
        "duration": item.duration,
        "capture_start": item.capture_start,
        "capture_end": item.capture_end,
        "file_type": item.file_type,
        "protocol_summary": item.protocol_summary,
        "status": item.status,
        "retention_status": item.retention_status,
        "created_at": item.created_at,
    }


def serialize_flow(item: Flow) -> dict[str, Any]:
    return {
        "id": item.id,
        "src_ip": item.src_ip,
        "src_port": item.src_port,
        "dst_ip": item.dst_ip,
        "dst_port": item.dst_port,
        "protocol": item.protocol,
        "app_protocol": item.app_protocol,
        "packets": item.packets,
        "bytes": item.bytes,
        "start_time": item.start_time,
        "end_time": item.end_time,
    }


def serialize_packet(item: PacketRecord) -> dict[str, Any]:
    return {
        "id": item.id,
        "number": item.number,
        "timestamp": item.timestamp,
        "src_ip": item.src_ip,
        "dst_ip": item.dst_ip,
        "src_port": item.src_port,
        "dst_port": item.dst_port,
        "protocol": item.protocol,
        "length": item.length,
        "info": item.info,
    }


def serialize_anomaly(item: Anomaly) -> dict[str, Any]:
    return {
        "id": item.id,
        "rule": item.rule,
        "severity": item.severity,
        "description": item.description,
        "evidence": item.evidence,
    }


@router.post("/pcaps/upload")
async def upload_pcap(
    request: Request,
    file: UploadFile = File(...),
    probe_id: int | None = Form(None),
    metadata_json: str | None = Form(None),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    probe_id = upload_probe_id(request, db, probe_id)
    try:
        meta: dict[str, Any] = json.loads(metadata_json) if metadata_json else {}
    except (TypeError, json.JSONDecodeError) as exc:
        raise HTTPException(422, "metadata_json must be valid JSON") from exc
    if not isinstance(meta, dict):
        raise HTTPException(422, "metadata_json must be a JSON object")
    try:
        stored = await stream_to_storage(
            file,
            file.filename or "capture.pcap",
            subdir="pcaps",
            max_bytes=settings.max_upload_mb * 1024 * 1024,
        )
    except ValueError as exc:
        if "too_large" in str(exc):
            raise HTTPException(413, "pcap too large") from exc
        raise
    path = Path(stored["path"])
    with path.open("rb") as capture:
        header = capture.read(24)
    if len(header) < 24 or header[:4] not in {
        b"\xd4\xc3\xb2\xa1",
        b"\xa1\xb2\xc3\xd4",
        b"\x4d\x3c\xb2\xa1",
        b"\xa1\xb2\x3c\x4d",
        b"\x0a\x0d\x0d\x0a",
    }:
        path.unlink(missing_ok=True)
        raise HTTPException(422, "文件不是有效的 PCAP/PCAPNG 抓包文件")
    digest = str(stored["sha256"])
    segment_id = str(meta.get("segment_id") or digest)
    existing = db.scalar(
        select(PcapRecord).where(
            PcapRecord.probe_id == probe_id, PcapRecord.segment_id == segment_id
        )
    )
    if not existing and not meta.get("segment_id"):
        existing = db.scalar(
            select(PcapRecord).where(PcapRecord.probe_id == probe_id, PcapRecord.sha256 == digest)
        )
    if existing:
        path.unlink(missing_ok=True)
        return {
            "id": existing.id,
            "task_id": None,
            "filename": existing.filename,
            "size": existing.size,
            "duplicate": True,
            "status": existing.status,
        }
    try:
        enforce_queue_backpressure(db)
    except HTTPException:
        path.unlink(missing_ok=True)
        raise
    record = PcapRecord(
        probe_id=probe_id,
        segment_id=segment_id,
        sequence=int(meta.get("sequence") or 0),
        capture_interface=str(meta.get("interface") or ""),
        capture_started_at=str(meta.get("capture_started_at") or ""),
        capture_finished_at=str(meta.get("capture_finished_at") or ""),
        probe_metadata=meta,
        filename=path.name,
        storage_path=str(path),
        size=int(stored["size"]),
        sha256=digest,
        ingest_status="ingested",
        analysis_status="pending",
    )
    db.add(record)
    db.commit()
    db.refresh(record)
    task = create_task(db, "pcap", {"pcap_id": record.id})
    # A captured segment is child work of the probe's monitoring task; the task
    # list shows the monitor, not thousands of 30 s segments.
    from app.services import monitoring

    monitor = monitoring.ensure_monitor_task(db, probe_id)
    if monitor is not None:
        monitoring.attach_segment(db, monitor, task)
        db.commit()
    dispatch_task_row(ANALYZE_PCAP, task.id, record.id)
    return {
        "id": record.id,
        "task_id": task.id,
        "filename": record.filename,
        "size": record.size,
        "duplicate": False,
    }


@router.get("/pcaps")
def list_pcaps(
    search: str | None = None,
    status: str | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(PcapRecord)
    if search:
        query = query.where(PcapRecord.filename.ilike(f"%{search}%"))
    if status:
        query = query.where(PcapRecord.status == status)
    result = paginate(db, query.order_by(PcapRecord.id.desc()), page, page_size)
    return page_response(
        [serialize_pcap(item) for item in result["items"]], page, page_size, result["total"]
    )


@router.get("/pcaps/{pcap_id}")
def pcap_detail(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(PcapRecord, pcap_id)
    if not item:
        raise HTTPException(404, "pcap not found")
    return serialize_pcap(item)


@router.post("/pcaps/{pcap_id}/analyze")
def analyze_pcap(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = create_task(db, "pcap", {"pcap_id": pcap_id})
    dispatch_task_row(ANALYZE_PCAP, task.id, pcap_id)
    return serialize_task(task)


@router.get("/pcaps/{pcap_id}/flows")
def pcap_flows(
    pcap_id: int,
    protocol: str | None = None,
    ip: str | None = None,
    port: int | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=5000),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(Flow).where(Flow.pcap_id == pcap_id)
    if protocol:
        query = query.where(Flow.protocol == protocol)
    if ip:
        query = query.where(or_(Flow.src_ip == ip, Flow.dst_ip == ip))
    if port:
        query = query.where(or_(Flow.src_port == port, Flow.dst_port == port))
    result = paginate(db, query.order_by(Flow.bytes.desc()), page, page_size)
    return page_response(
        [serialize_flow(item) for item in result["items"]], page, page_size, result["total"]
    )


@router.get("/pcaps/{pcap_id}/packets")
def pcap_packets(
    pcap_id: int,
    protocol: str | None = None,
    ip: str | None = None,
    port: int | None = None,
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=5000),
    search: str | None = None,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    query = select(PacketRecord).where(PacketRecord.pcap_id == pcap_id)
    if protocol:
        query = query.where(PacketRecord.protocol == protocol)
    if ip:
        query = query.where(or_(PacketRecord.src_ip == ip, PacketRecord.dst_ip == ip))
    if port:
        query = query.where(or_(PacketRecord.src_port == port, PacketRecord.dst_port == port))
    if search:
        pattern = f"%{search}%"
        query = query.where(
            or_(
                PacketRecord.info.ilike(pattern),
                PacketRecord.protocol.ilike(pattern),
                PacketRecord.src_ip.ilike(pattern),
                PacketRecord.dst_ip.ilike(pattern),
            )
        )
    result = paginate(db, query.order_by(PacketRecord.number), page, page_size)
    return page_response(
        [serialize_packet(item) for item in result["items"]], page, page_size, result["total"]
    )


@router.get("/pcaps/{pcap_id}/anomalies")
def pcap_anomalies(pcap_id: int, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [
        serialize_anomaly(item)
        for item in db.scalars(
            select(Anomaly).where(Anomaly.pcap_id == pcap_id).order_by(Anomaly.id.desc())
        ).all()
    ]


@router.get("/pcaps/{pcap_id}/protocols")
def pcap_protocols(pcap_id: int, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    item = db.get(PcapRecord, pcap_id)
    if not item:
        raise HTTPException(404, "pcap not found")
    return protocol_tree(item.protocol_summary or {})


@router.get("/pcaps/{pcap_id}/traffic")
def pcap_traffic(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    flows = [
        serialize_flow(item)
        for item in db.scalars(select(Flow).where(Flow.pcap_id == pcap_id)).all()
    ]
    packets = [
        serialize_packet(item)
        for item in db.scalars(
            select(PacketRecord)
            .where(PacketRecord.pcap_id == pcap_id)
            .order_by(PacketRecord.number)
        ).all()
    ]
    return {
        "trend": traffic_trend(packets),
        "top_n": top_n_communication(flows),
        "protocols": protocol_distribution(flows),
        "hosts": host_behavior(flows, packets),
        "anomalies": detect_anomalies(flows, packets),
    }


def _external_details(pcap_id: int, db: Session) -> dict[str, Any]:
    result = {"dns": [], "http": [], "tls": [], "files": [], "alerts": []}
    rows = db.scalars(
        select(AnalysisResult).where(
            AnalysisResult.module == "protocol_details",
            AnalysisResult.task_id.in_(
                select(Task.id).where(Task.payload["pcap_id"].as_integer() == pcap_id)
            ),
        )
    ).all()
    for row in rows:
        content = row.content or {}
        result["dns"].extend(content.get("dns", {}).get("queries", []))
        result["http"].extend(content.get("http", {}).get("requests", []))
        result["tls"].extend(content.get("tls", {}).get("handshakes", []))
    external = db.scalars(
        select(AnalysisResult).where(
            AnalysisResult.module == "external_engine",
            AnalysisResult.task_id.in_(
                select(Task.id).where(Task.payload["pcap_id"].as_integer() == pcap_id)
            ),
        )
    ).all()
    for row in external:
        for engine in (row.content or {}).get("engines", []):
            name = engine.get("name", "")
            events = engine.get("events", {})
            if name == "zeek":
                for key in ("dns", "http", "ssl", "files"):
                    for item in events.get(key, []):
                        target = (
                            "dns"
                            if key == "dns"
                            else "http"
                            if key == "http"
                            else "tls"
                            if key == "ssl"
                            else "files"
                        )
                        result[target].append({**item, "source": "zeek"})
            elif name == "suricata":
                for item in events:
                    event_type = item.get("event_type", "")
                    if event_type in {"dns", "http"}:
                        result[event_type].append({**item, "source": "suricata"})
                    elif event_type == "fileinfo":
                        result["files"].append({**item, "source": "suricata"})
                    elif event_type == "alert":
                        result["alerts"].append({**item, "source": "suricata"})
    integration_rows = db.scalars(
        select(AnalysisResult).where(
            AnalysisResult.module == "integrations",
            AnalysisResult.task_id.in_(
                select(Task.id).where(Task.payload["pcap_id"].as_integer() == pcap_id)
            ),
        )
    ).all()
    for row in integration_rows:
        for name, events in (row.content or {}).items():
            if not isinstance(events, list):
                continue
            for item in events:
                event_type = str(item.get("event_type") or item.get("_path") or "").lower()
                if name == "zeek":
                    if event_type == "dns":
                        result["dns"].append({**item, "source": "zeek"})
                    elif event_type == "http":
                        result["http"].append({**item, "source": "zeek"})
                    elif event_type in {"ssl", "tls"}:
                        result["tls"].append({**item, "source": "zeek"})
                    elif event_type == "files":
                        result["files"].append({**item, "source": "zeek"})
                elif name == "suricata":
                    if event_type in {"dns", "http"}:
                        result[event_type].append({**item, "source": "suricata"})
                    elif event_type == "fileinfo":
                        result["files"].append({**item, "source": "suricata"})
                    elif event_type == "alert":
                        result["alerts"].append({**item, "source": "suricata"})
    return result


@router.get("/pcaps/{pcap_id}/dns")
def pcap_dns(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    return {"items": _external_details(pcap_id, db)["dns"]}


@router.get("/pcaps/{pcap_id}/http")
def pcap_http(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    return {"items": _external_details(pcap_id, db)["http"]}


@router.get("/pcaps/{pcap_id}/tls")
def pcap_tls(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    return {"items": _external_details(pcap_id, db)["tls"]}


@router.get("/pcaps/{pcap_id}/files")
def pcap_files(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    if not db.get(PcapRecord, pcap_id):
        raise HTTPException(404, "pcap not found")
    result = _captured_files(pcap_id, db)
    if result is not None:
        from app.services.pcap_files import object_path

        items = [
            {**item, "binary_available": object_path(pcap_id, item["id"]).is_file()}
            for item in result.get("items", [])
        ]
        return {**result, "items": items, "needs_analysis": False}
    return {
        "items": [
            {**item, "binary_available": False} for item in _external_details(pcap_id, db)["files"]
        ],
        "coverage": {},
        "needs_analysis": True,
    }


def _captured_files(pcap_id: int, db: Session) -> dict[str, Any] | None:
    row = db.scalar(
        select(AnalysisResult)
        .where(
            AnalysisResult.module == "pcap_files",
            AnalysisResult.task_id.in_(
                select(Task.id).where(Task.payload["pcap_id"].as_integer() == pcap_id)
            ),
        )
        .order_by(AnalysisResult.id.desc())
    )
    return row.content if row else None


def _captured_file(pcap_id: int, file_id: str, db: Session) -> tuple[dict, Path]:
    from app.services.pcap_files import object_path

    result = _captured_files(pcap_id, db) or {}
    item = next((item for item in result.get("items", []) if str(item.get("id")) == file_id), None)
    if item is None:
        raise HTTPException(404, "该文件未提取，请重新分析抓包")
    path = object_path(pcap_id, file_id)
    if not path.is_file():
        raise HTTPException(410, "提取文件已不存在，请重新分析抓包")
    return item, path


@router.get("/pcaps/{pcap_id}/files/{file_id}")
def pcap_file_preview(
    pcap_id: int,
    file_id: str,
    offset: int = Query(0, ge=0),
    limit: int = Query(16384, ge=1, le=65536),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    from app.services.pcap_files import preview

    item, path = _captured_file(pcap_id, file_id, db)
    return {**item, **preview(path, offset, limit)}


@router.get("/pcaps/{pcap_id}/alerts")
def pcap_alerts(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    anomalies = [
        serialize_anomaly(item)
        for item in db.scalars(select(Anomaly).where(Anomaly.pcap_id == pcap_id)).all()
    ]
    findings = [
        _serialize_detection(item)
        for item in db.scalars(
            select(DetectionFinding)
            .where(
                DetectionFinding.target_type == "pcap", DetectionFinding.target_id == str(pcap_id)
            )
            .order_by(DetectionFinding.risk_score.desc())
        ).all()
    ]
    alerts = (
        db.scalars(
            select(Alert)
            .where(Alert.finding_id.in_([item["id"] for item in findings]))
            .order_by(Alert.risk_score.desc())
        ).all()
        if findings
        else []
    )
    external = _external_details(pcap_id, db)["alerts"]
    # An alert is the correlated form of a finding, so the same hit used to be
    # listed twice (once as "alert", once as "finding") and the alert's
    # "evidence" was the alert row itself - id, severity, timestamps - rather
    # than the rule, condition and metrics that were actually matched. The
    # alert now carries the finding's evidence, and the finding is not listed
    # a second time.
    findings_by_id = {item["id"]: item for item in findings}
    covered = {alert.finding_id for alert in alerts if alert.finding_id}
    merged: dict[str, Any] = {}
    for item in alerts:
        key = f"alert:{item.fingerprint}"
        source_finding = findings_by_id.get(item.finding_id or -1)
        evidence = source_finding["evidence"] if source_finding else serialize_alert(item)
        merged.setdefault(
            key,
            {
                "kind": "alert",
                "severity": item.severity,
                "title": item.title,
                "description": item.summary,
                "evidence": evidence,
                "source": item.source,
                "id": item.id,
            },
        )
    for item in anomalies:
        key = f"anomaly:{item['rule']}:{item['severity']}:{item['description']}"
        merged.setdefault(
            key,
            {
                "kind": "anomaly",
                "severity": item["severity"],
                "title": item["rule"],
                "description": item["description"],
                "evidence": item["evidence"],
                "source": "builtin",
            },
        )
    for item in findings:
        if item["id"] in covered:
            continue
        key = f"finding:{item['engine']}:{item['rule_id']}:{item['timestamp']}"
        merged.setdefault(
            key,
            {
                "kind": "finding",
                "severity": item["severity"],
                "title": item["rule_id"],
                "description": item["recommendation"],
                "evidence": item["evidence"],
                "source": item["engine"],
                "id": item["id"],
            },
        )
    for item in external:
        alert = item.get("alert", {}) or {}
        signature = alert.get("signature_id", item.get("signature_id", ""))
        key = f"external:{item.get('source')}:{signature}:{item.get('timestamp', '')}"
        merged.setdefault(
            key,
            {
                "kind": "external",
                "severity": item.get("severity", "Medium"),
                "title": alert.get("signature", item.get("signature", "")),
                "description": alert.get("signature", ""),
                "evidence": item,
                "source": item.get("source", "external"),
            },
        )
    items = list(merged.values())
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    return {
        "items": sorted(items, key=lambda item: severity_order.get(item.get("severity", "Low"), 9))
    }


@router.get("/pcaps/{pcap_id}/packets/{packet_id}")
def pcap_packet_detail(
    pcap_id: int, packet_id: int, db: Session = Depends(get_db)
) -> dict[str, Any]:
    record = db.get(PacketRecord, packet_id)
    if not record or record.pcap_id != pcap_id:
        raise HTTPException(404, "packet not found")
    pcap = db.get(PcapRecord, pcap_id)
    if not pcap:
        raise HTTPException(404, "pcap not found")
    detail = packet_detail(Path(pcap.storage_path), record.number)
    if detail is None:
        detail = {"raw": "", "layers": []}
    return {
        "packet": serialize_packet(record),
        "raw": detail.get("raw", ""),
        "layers": detail.get("layers", []),
    }


@router.get("/pcaps/{pcap_id}/streams/{stream_id}")
def pcap_tcp_stream(pcap_id: int, stream_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    pcap = db.get(PcapRecord, pcap_id)
    if not pcap:
        raise HTTPException(404, "pcap not found")
    stream = tcp_stream_follow(Path(pcap.storage_path), stream_id)
    if stream is None:
        raise HTTPException(404, "stream not found")
    return stream


@router.get("/pcaps/{pcap_id}/files/{file_id}/download")
def pcap_file_download(pcap_id: int, file_id: str, db: Session = Depends(get_db)) -> FileResponse:
    item, path = _captured_file(pcap_id, file_id, db)
    return FileResponse(
        path,
        filename=item["filename"],
        media_type="application/octet-stream",
        headers={"X-Content-Type-Options": "nosniff"},
    )
