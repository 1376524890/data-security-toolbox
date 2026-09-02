from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.storage import save_bytes
from app.engine import registry
from app.engine.core.context import DetectionContext
from app.engine.core.pipeline import DetectionPipeline
from app.engine.risk_engine.engine import RiskEngine
from app.incident_engine.engine import IncidentEngine
from app.integrations import integration_registry
from app.integrations.offline import import_offline_bundle
from app.integrations.runner import run_adapter
from app.models import (
    IOC,
    AnalysisResult,
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
from app.schemas import (
    AlgorithmRandomnessRequest,
    EvaluateRequest,
    GenerateReportRequest,
    Heartbeat,
    LogAnalysisRequest,
    ProbeRegister,
    TaskCreate,
)
from app.services.algorithm_service import evaluate_model, performance_test, randomness_report
from app.services.asset_service import asset_relations
from app.services.audit_service import audit_summary, log_analysis
from app.services.protocol_service import protocol_tree
from app.services.report_service import build_summary, render_html, render_pdf
from app.services.traffic_service import (
    detect_anomalies,
    host_behavior,
    protocol_distribution,
    top_n_communication,
    traffic_trend,
)
from app.workers.tasks import analyze_pcap_task, asset_task, create_task, metadata_task

router = APIRouter(prefix="/api/v1")
incident_engine = IncidentEngine()


def _serialize_task(task: Task) -> dict[str, Any]:
    return {"id": task.id, "kind": task.kind, "status": task.status, "progress": task.progress, "current_stage": task.current_stage, "log": task.log, "payload": task.payload, "result": task.result, "error": task.error, "created_at": task.created_at, "started_at": task.started_at, "finished_at": task.finished_at}


def _dispatch(task_id: int, kind: str, func, *args: Any) -> None:
    if settings.app_env == "development":
        func(*args, task_id)
        return
    try:
        func.delay(*args, task_id)
    except Exception:
        func(*args, task_id)


@router.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}


@router.post("/probes/register")
def register_probe(payload: ProbeRegister, db: Session = Depends(get_db)) -> dict[str, Any]:
    probe = db.scalar(select(Probe).where(Probe.name == payload.name))
    if not probe:
        probe = Probe(name=payload.name, hostname=payload.hostname, ip_address=payload.ip_address, extra=payload.metadata, status="online")
        db.add(probe)
        db.commit()
        db.refresh(probe)
    else:
        probe.hostname = payload.hostname
        probe.ip_address = payload.ip_address
        probe.extra = payload.metadata
        probe.status = "online"
        db.commit()
    return {"id": probe.id, "name": probe.name}


@router.post("/probes/{probe_id}/heartbeat")
def heartbeat(probe_id: int, payload: Heartbeat, db: Session = Depends(get_db)) -> dict[str, str]:
    probe = db.get(Probe, probe_id)
    if not probe:
        raise HTTPException(404, "probe not found")
    probe.status = payload.status
    probe.extra = payload.metadata or probe.extra
    db.commit()
    return {"status": "ok"}


@router.get("/probes")
def list_probes(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": item.id, "name": item.name, "hostname": item.hostname, "ip_address": item.ip_address, "status": item.status, "last_seen": item.last_seen} for item in db.scalars(select(Probe).order_by(Probe.id.desc())).all()]


@router.post("/probes/{probe_id}/analyze")
def analyze_probe_assets(probe_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = create_task(db, "assets", {"probe_id": probe_id})
    _dispatch(task.id, "assets", asset_task, probe_id)
    return _serialize_task(task)


@router.get("/assets")
def list_assets(risk: str | None = None, asset_type: str | None = None, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    query = select(Asset)
    if risk:
        query = query.where(Asset.risk_level == risk)
    if asset_type:
        query = query.where(Asset.asset_type == asset_type)
    return [{"id": item.id, "probe_id": item.probe_id, "ip": item.ip, "hostname": item.hostname, "os": item.os, "port": item.port, "protocol": item.protocol, "service": item.service, "asset_type": item.asset_type, "risk_level": item.risk_level, "sensitive_categories": item.sensitive_categories, "metadata": item.extra} for item in db.scalars(query.order_by(Asset.id.desc())).all()]


@router.get("/assets/summary")
def asset_summary(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(select(Asset.risk_level, func.count(Asset.id)).group_by(Asset.risk_level)).all()
    return {"count": db.scalar(select(func.count(Asset.id))) or 0, "risk": {risk: count for risk, count in rows}}


@router.get("/assets/relations")
def asset_relation_list(db: Session = Depends(get_db)) -> list[dict[str, str]]:
    assets = db.scalars(select(Asset)).all()
    return asset_relations([{"ip": item.ip, "service": item.service, "port": item.port} for item in assets])


@router.post("/files/upload")
async def upload_file(file: UploadFile = File(...), probe_id: int | None = Form(None), db: Session = Depends(get_db)) -> dict[str, Any]:
    data = await file.read()
    if len(data) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(413, "file too large")
    path = save_bytes(data, file.filename or "upload.bin")
    record = FileRecord(probe_id=probe_id, name=path.name, path=str(path), size=len(data), sha256=sha256(data).hexdigest(), file_type="")
    db.add(record)
    db.commit()
    db.refresh(record)
    task = create_task(db, "metadata", {"file_id": record.id})
    _dispatch(task.id, "metadata", metadata_task, record.id)
    return {"id": record.id, "task_id": task.id, "name": record.name, "size": record.size}


@router.get("/files")
def list_files(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": item.id, "probe_id": item.probe_id, "name": item.name, "path": item.path, "size": item.size, "sha256": item.sha256, "file_type": item.file_type, "metadata_json": item.metadata_json, "risk_level": item.risk_level} for item in db.scalars(select(FileRecord).order_by(FileRecord.id.desc())).all()]


@router.get("/files/{file_id}")
def file_detail(file_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(FileRecord, file_id)
    if not item:
        raise HTTPException(404, "file not found")
    return {"id": item.id, "probe_id": item.probe_id, "name": item.name, "path": item.path, "size": item.size, "sha256": item.sha256, "file_type": item.file_type, "metadata_json": item.metadata_json, "risk_level": item.risk_level}


@router.post("/files/{file_id}/analyze")
def analyze_file(file_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = create_task(db, "metadata", {"file_id": file_id})
    _dispatch(task.id, "metadata", metadata_task, file_id)
    return _serialize_task(task)


@router.post("/pcaps/upload")
async def upload_pcap(file: UploadFile = File(...), probe_id: int | None = Form(None), db: Session = Depends(get_db)) -> dict[str, Any]:
    data = await file.read()
    if len(data) > settings.max_upload_mb * 1024 * 1024:
        raise HTTPException(413, "pcap too large")
    path = save_bytes(data, file.filename or "capture.pcap", subdir="pcaps")
    record = PcapRecord(probe_id=probe_id, filename=path.name, storage_path=str(path), size=len(data), sha256=sha256(data).hexdigest())
    db.add(record)
    db.commit()
    db.refresh(record)
    task = create_task(db, "pcap", {"pcap_id": record.id})
    _dispatch(task.id, "pcap", analyze_pcap_task, record.id)
    return {"id": record.id, "task_id": task.id, "filename": record.filename, "size": record.size}


@router.get("/pcaps")
def list_pcaps(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": item.id, "probe_id": item.probe_id, "filename": item.filename, "size": item.size, "sha256": item.sha256, "packet_count": item.packet_count, "duration": item.duration, "capture_start": item.capture_start, "capture_end": item.capture_end, "protocol_summary": item.protocol_summary, "status": item.status} for item in db.scalars(select(PcapRecord).order_by(PcapRecord.id.desc())).all()]


@router.get("/pcaps/{pcap_id}")
def pcap_detail(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(PcapRecord, pcap_id)
    if not item:
        raise HTTPException(404, "pcap not found")
    return {"id": item.id, "probe_id": item.probe_id, "filename": item.filename, "size": item.size, "sha256": item.sha256, "packet_count": item.packet_count, "duration": item.duration, "capture_start": item.capture_start, "capture_end": item.capture_end, "protocol_summary": item.protocol_summary, "status": item.status}


@router.post("/pcaps/{pcap_id}/analyze")
def analyze_pcap(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = create_task(db, "pcap", {"pcap_id": pcap_id})
    _dispatch(task.id, "pcap", analyze_pcap_task, pcap_id)
    return _serialize_task(task)


@router.get("/pcaps/{pcap_id}/flows")
def pcap_flows(pcap_id: int, limit: int = Query(200, le=5000), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": item.id, "src_ip": item.src_ip, "src_port": item.src_port, "dst_ip": item.dst_ip, "dst_port": item.dst_port, "protocol": item.protocol, "packets": item.packets, "bytes": item.bytes, "start_time": item.start_time, "end_time": item.end_time} for item in db.scalars(select(Flow).where(Flow.pcap_id == pcap_id).order_by(Flow.bytes.desc()).limit(limit)).all()]


@router.get("/pcaps/{pcap_id}/packets")
def pcap_packets(pcap_id: int, limit: int = Query(500, le=5000), db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"number": item.number, "timestamp": item.timestamp, "src_ip": item.src_ip, "dst_ip": item.dst_ip, "src_port": item.src_port, "dst_port": item.dst_port, "protocol": item.protocol, "length": item.length, "info": item.info} for item in db.scalars(select(PacketRecord).where(PacketRecord.pcap_id == pcap_id).order_by(PacketRecord.number).limit(limit)).all()]


@router.get("/pcaps/{pcap_id}/anomalies")
def pcap_anomalies(pcap_id: int, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": item.id, "rule": item.rule, "severity": item.severity, "description": item.description, "evidence": item.evidence} for item in db.scalars(select(Anomaly).where(Anomaly.pcap_id == pcap_id).order_by(Anomaly.id.desc())).all()]


@router.get("/pcaps/{pcap_id}/protocols")
def pcap_protocols(pcap_id: int, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    item = db.get(PcapRecord, pcap_id)
    if not item:
        raise HTTPException(404, "pcap not found")
    return protocol_tree(item.protocol_summary or {})


@router.get("/pcaps/{pcap_id}/traffic")
def pcap_traffic(pcap_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    flows = [{"src_ip": item.src_ip, "src_port": item.src_port, "dst_ip": item.dst_ip, "dst_port": item.dst_port, "protocol": item.protocol, "packets": item.packets, "bytes": item.bytes, "start_time": item.start_time, "end_time": item.end_time} for item in db.scalars(select(Flow).where(Flow.pcap_id == pcap_id)).all()]
    packets = [{"timestamp": item.timestamp, "length": item.length, "src_ip": item.src_ip, "dst_ip": item.dst_ip, "protocol": item.protocol} for item in db.scalars(select(PacketRecord).where(PacketRecord.pcap_id == pcap_id).order_by(PacketRecord.number)).all()]
    return {"trend": traffic_trend(packets), "top_n": top_n_communication(flows), "protocols": protocol_distribution(flows), "hosts": host_behavior(flows, packets), "anomalies": detect_anomalies(flows, packets)}


@router.post("/algorithms/randomness")
def randomness(payload: AlgorithmRandomnessRequest) -> dict[str, Any]:
    return randomness_report(payload.data.encode("utf-8"))


@router.post("/algorithms/evaluate")
def evaluate(payload: EvaluateRequest) -> dict[str, Any]:
    try:
        return evaluate_model(payload.X, payload.y)
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.post("/algorithms/performance")
def performance(payload: AlgorithmRandomnessRequest) -> dict[str, Any]:
    return performance_test(payload.data.encode("utf-8"))


@router.get("/tasks")
def list_tasks(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [_serialize_task(item) for item in db.scalars(select(Task).order_by(Task.id.desc())).all()]


@router.post("/tasks")
def create_generic_task(payload: TaskCreate, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = create_task(db, payload.kind, payload.payload)
    return _serialize_task(task)


@router.get("/tasks/{task_id}")
def task_detail(task_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "task not found")
    return _serialize_task(task)


@router.post("/audit/logs")
def analyze_log(payload: LogAnalysisRequest) -> dict[str, Any]:
    lines = payload.content.splitlines()
    context = DetectionContext(target_type="log", data={}, log_lines=lines)
    pipeline = DetectionPipeline(registry, RiskEngine())
    result = pipeline.run(context)
    return {"legacy": log_analysis(lines), "findings": [item.to_dict() for item in result.findings], "risk": {"score": result.risk_score, "level": result.risk_level}}


@router.get("/audit/summary")
def audit(db: Session = Depends(get_db)) -> dict[str, Any]:
    assets = [{"ip": item.ip, "service": item.service, "port": item.port, "asset_type": item.asset_type, "risk_level": item.risk_level, "sensitive_categories": item.sensitive_categories} for item in db.scalars(select(Asset)).all()]
    files = [{"name": item.name, "file_type": item.file_type, "risk_level": item.risk_level} for item in db.scalars(select(FileRecord)).all()]
    pcaps = [{"filename": item.filename, "protocol_summary": item.protocol_summary} for item in db.scalars(select(PcapRecord)).all()]
    anomalies = [{"severity": item.severity, "rule": item.rule, "description": item.description} for item in db.scalars(select(Anomaly)).all()]
    return audit_summary(assets, files, pcaps, anomalies)


@router.post("/reports/generate")
def generate_report(payload: GenerateReportRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    assets = [{"ip": item.ip, "service": item.service, "port": item.port, "asset_type": item.asset_type, "risk_level": item.risk_level, "sensitive_categories": item.sensitive_categories} for item in db.scalars(select(Asset)).all()]
    files = [{"name": item.name, "file_type": item.file_type, "risk_level": item.risk_level} for item in db.scalars(select(FileRecord)).all()]
    pcaps = [{"filename": item.filename, "packet_count": item.packet_count, "protocol_summary": item.protocol_summary} for item in db.scalars(select(PcapRecord)).all()]
    anomalies = [{"rule": item.rule, "severity": item.severity, "description": item.description} for item in db.scalars(select(Anomaly)).all()]
    findings = [{"engine": item.engine, "rule_id": item.rule_id, "severity": item.severity, "confidence": item.confidence, "evidence": item.evidence, "recommendation": item.recommendation, "risk_score": item.risk_score, "risk_level": item.risk_level} for item in db.scalars(select(DetectionFinding).order_by(DetectionFinding.risk_score.desc())).all()]
    data_assets = [{"name": item.name, "asset_type": item.asset_type, "sensitivity": item.sensitivity, "source": item.source, "columns": item.columns} for item in db.scalars(select(DataAsset).order_by(DataAsset.id.desc())).all()]
    incidents = [{"id": item.id, "title": item.title, "severity": item.severity, "confidence": item.confidence, "status": item.status, "evidence": item.evidence, "risk_score": item.risk_score, "risk_level": item.risk_level} for item in db.scalars(select(Incident).order_by(Incident.risk_score.desc())).all()]
    summary = build_summary(assets, files, pcaps, anomalies, audit_summary(assets, files, pcaps, anomalies), findings, data_assets, incidents)
    html = render_html(summary, assets, files, pcaps, anomalies, findings, data_assets, incidents)
    report_format = payload.format
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    output = settings.report_dir / f"{payload.title.replace(' ', '_')}_{stamp}.{report_format}"
    if report_format == "pdf":
        try:
            render_pdf(html, output)
        except ImportError:
            report_format = "html"
            output = output.with_suffix(".html")
            output.write_text(html, encoding="utf-8")
    else:
        output.write_text(html, encoding="utf-8")
    record = Report(title=payload.title, report_type=payload.report_type, format=report_format, storage_path=str(output), summary=summary)
    db.add(record)
    db.commit()
    db.refresh(record)
    return {"id": record.id, "title": record.title, "format": record.format, "storage_path": record.storage_path}


@router.get("/reports")
def list_reports(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": item.id, "title": item.title, "report_type": item.report_type, "format": item.format, "summary": item.summary, "created_at": item.created_at} for item in db.scalars(select(Report).order_by(Report.id.desc())).all()]


@router.get("/reports/{report_id}/download")
def download_report(report_id: int, db: Session = Depends(get_db)) -> FileResponse:
    item = db.get(Report, report_id)
    if not item:
        raise HTTPException(404, "report not found")
    path = Path(item.storage_path)
    if not path.exists():
        raise HTTPException(404, "report file not found")
    return FileResponse(str(path), filename=path.name)


@router.get("/analysis/results")
def analysis_results(module: str | None = None, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    query = select(AnalysisResult)
    if module:
        query = query.where(AnalysisResult.module == module)
    return [{"id": item.id, "task_id": item.task_id, "module": item.module, "content": item.content, "score": item.score, "risk_level": item.risk_level, "created_at": item.created_at} for item in db.scalars(query.order_by(AnalysisResult.id.desc())).all()]


@router.get("/incidents")
def list_incidents(status: str | None = None, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    query = select(Incident)
    if status:
        query = query.where(Incident.status == status)
    return [{"id": item.id, "title": item.title, "severity": item.severity, "confidence": item.confidence, "status": item.status, "findings": item.findings, "evidence": item.evidence, "risk_score": item.risk_score, "risk_level": item.risk_level, "timestamp": item.timestamp, "created_at": item.created_at} for item in db.scalars(query.order_by(Incident.risk_score.desc())).all()]


@router.get("/incidents/{incident_id}")
def incident_detail(incident_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    item = db.get(Incident, incident_id)
    if not item:
        raise HTTPException(404, "incident not found")
    return {"id": item.id, "title": item.title, "severity": item.severity, "confidence": item.confidence, "status": item.status, "findings": item.findings, "evidence": item.evidence, "risk_score": item.risk_score, "risk_level": item.risk_level, "timestamp": item.timestamp, "created_at": item.created_at}


@router.post("/incidents/correlate")
def correlate_incidents(payload: dict[str, Any]) -> list[dict[str, Any]]:
    from app.engine.core.result import DetectionResult

    findings = [DetectionResult(**item) for item in payload.get("findings", [])]
    return [item.to_dict() for item in incident_engine.correlate(findings, int(payload.get("window_seconds", 3600)))]


@router.get("/iocs")
def list_iocs(ioc_type: str | None = None, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    query = select(IOC)
    if ioc_type:
        query = query.where(IOC.ioc_type == ioc_type)
    return [{"id": item.id, "type": item.ioc_type, "value": item.value, "source": item.source, "first_seen": item.first_seen, "last_seen": item.last_seen, "tags": item.tags, "metadata": item.extra} for item in db.scalars(query.order_by(IOC.id.desc())).all()]


@router.get("/engine/registry")
def engine_registry() -> list[dict[str, Any]]:
    return [engine.metadata() for engine in registry.all()]


@router.get("/integrations")
def list_integrations() -> list[dict[str, Any]]:
    return integration_registry.metadata()


@router.post("/integrations/{name}/analyze")
def run_integration(name: str, payload: dict[str, Any], db: Session = Depends(get_db)) -> dict[str, Any]:
    try:
        adapter = integration_registry.get(name)
    except KeyError:
        raise HTTPException(404, "integration not found")
    context = DetectionContext(target_type="integration", target_id=name, data=payload.get("context", {}))
    result = run_adapter(adapter, payload, context, RiskEngine())
    for item in result.findings:
        db.add(DetectionFinding(
            target_type="integration",
            target_id=name,
            engine=item.engine,
            rule_id=item.rule_id,
            severity=item.severity,
            confidence=item.confidence,
            evidence=item.evidence,
            recommendation=item.recommendation,
            risk_score=item.risk_score,
            risk_level=item.risk_level,
            timestamp=item.timestamp,
        ))
    for incident in incident_engine.correlate(result.findings):
        db.add(Incident(
            title=incident.title,
            severity=incident.severity,
            confidence=incident.confidence,
            status=incident.status,
            findings={"items": incident.findings},
            evidence=incident.evidence,
            risk_score=incident.risk_score,
            risk_level=incident.risk_level,
            timestamp=incident.timestamp,
        ))
    db.commit()
    return result.to_dict()


@router.post("/integrations/offline/import")
def import_offline(payload: dict[str, Any]) -> dict[str, Any]:
    path = payload.get("path", "")
    if not path:
        raise HTTPException(400, "path is required")
    return import_offline_bundle(path, payload.get("categories")).to_dict()


@router.post("/engine/pipeline")
def run_engine_pipeline(payload: dict[str, Any]) -> dict[str, Any]:
    context = DetectionContext(
        target_type=payload.get("target_type", "manual"),
        target_id=payload.get("target_id"),
        data=payload.get("data", {}),
        assets=payload.get("assets", []),
        flows=payload.get("flows", []),
        packets=payload.get("packets", []),
        metadata=payload.get("metadata", {}),
        log_lines=payload.get("log_lines", []),
    )
    pipeline = DetectionPipeline(registry, RiskEngine())
    return pipeline.run(context).to_dict()


@router.get("/detections")
def list_detections(severity: str | None = None, engine: str | None = None, db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    query = select(DetectionFinding)
    if severity:
        query = query.where(DetectionFinding.severity == severity)
    if engine:
        query = query.where(DetectionFinding.engine == engine)
    return [{"id": item.id, "task_id": item.task_id, "target_type": item.target_type, "target_id": item.target_id, "engine": item.engine, "rule_id": item.rule_id, "severity": item.severity, "confidence": item.confidence, "evidence": item.evidence, "recommendation": item.recommendation, "risk_score": item.risk_score, "risk_level": item.risk_level, "timestamp": item.timestamp, "created_at": item.created_at} for item in db.scalars(query.order_by(DetectionFinding.risk_score.desc())).all()]


@router.get("/risk/summary")
def risk_summary(db: Session = Depends(get_db)) -> dict[str, Any]:
    rows = db.execute(select(DetectionFinding.risk_level, func.count(DetectionFinding.id)).group_by(DetectionFinding.risk_level)).all()
    return {
        "count": db.scalar(select(func.count(DetectionFinding.id))) or 0,
        "risk_levels": {level: count for level, count in rows},
        "max_score": db.scalar(select(func.max(DetectionFinding.risk_score))) or 0,
        "avg_score": db.scalar(select(func.avg(DetectionFinding.risk_score))) or 0,
    }


@router.get("/data/assets")
def data_assets(db: Session = Depends(get_db)) -> list[dict[str, Any]]:
    return [{"id": item.id, "name": item.name, "asset_type": item.asset_type, "sensitivity": item.sensitivity, "source": item.source, "columns": item.columns, "extra": item.extra} for item in db.scalars(select(DataAsset).order_by(DataAsset.id.desc())).all()]


@router.get("/graph")
def graph(db: Session = Depends(get_db)) -> dict[str, Any]:
    relations = [{"source_node": item.source_node, "source_type": item.source_type, "target_node": item.target_node, "target_type": item.target_type, "relation": item.relation, "risk": item.risk} for item in db.scalars(select(GraphRelation).order_by(GraphRelation.id.desc())).all()]
    nodes = sorted({item["source_node"] for item in relations} | {item["target_node"] for item in relations})
    return {"nodes": nodes, "relations": relations}


@router.get("/dashboard/summary")
def dashboard(db: Session = Depends(get_db)) -> dict[str, Any]:
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
    }
