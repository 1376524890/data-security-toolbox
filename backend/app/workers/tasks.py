from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sqlalchemy import select

from app.core.database import SessionLocal
from app.models import AnalysisResult, Anomaly, Asset, DataAsset, DetectionFinding, FileRecord, Flow, GraphRelation, IOC, Incident, PacketRecord, PcapRecord, Task
from app.services.asset_service import classify_assets
from app.services.metadata_service import extract_metadata
from app.services.protocol_service import parse_pcap
from app.services.traffic_service import detect_anomalies
from app.services.traffic_service import external_engine_analysis
from app.core.config import settings
from app.workers.celery_app import celery_app
from app.engine import registry
from app.engine.core.context import DetectionContext
from app.engine.core.pipeline import DetectionPipeline
from app.engine.graph import build_graph
from app.engine.risk_engine.engine import RiskEngine
from app.incident_engine.engine import IncidentEngine


pipeline = DetectionPipeline(registry, RiskEngine())
incident_engine = IncidentEngine()


def run_pipeline(context: DetectionContext, task_id: int, db=None) -> None:
    result = pipeline.run(context)
    owned = db is None
    session = db or SessionLocal()
    try:
        for finding in result.findings:
            session.add(DetectionFinding(
                task_id=task_id,
                target_type=context.target_type,
                target_id=str(context.target_id or ""),
                engine=finding.engine,
                rule_id=finding.rule_id,
                severity=finding.severity,
                confidence=finding.confidence,
                evidence=finding.evidence,
                recommendation=finding.recommendation,
                risk_score=finding.risk_score,
                risk_level=finding.risk_level,
                timestamp=finding.timestamp,
            ))
        incidents = incident_engine.correlate(result.findings)
        for incident in incidents:
            session.add(Incident(
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
        for item in context.data.get("iocs", []):
            if not isinstance(item, dict):
                continue
            session.add(IOC(
                ioc_type=item.get("type", item.get("ioc_type", "unknown")),
                value=item.get("value", ""),
                source=item.get("source", "integration"),
                first_seen=item.get("first_seen", ""),
                last_seen=item.get("last_seen", ""),
                tags=item.get("tags", []),
                extra=item,
            ))
        for item in context.data.get("data_assets", []):
            session.add(DataAsset(
                name=item.get("name", ""),
                asset_type=item.get("asset_type", "file"),
                sensitivity=item.get("sensitivity", "Low"),
                source=item.get("source", "file"),
                columns=item.get("columns", []),
                extra=item.get("extra", {}),
            ))
        relations = build_graph(context.assets, context.data.get("data_assets", []), [item.to_dict() for item in result.findings])
        for relation in relations:
            session.add(GraphRelation(**relation))
        if owned:
            session.commit()
    finally:
        if owned:
            session.close()
    return None


def update_task(task_id: int, **kwargs: Any) -> None:
    with SessionLocal() as db:
        task = db.get(Task, task_id)
        if not task:
            return
        for key, value in kwargs.items():
            setattr(task, key, value)
        if "log" in kwargs and isinstance(kwargs["log"], str):
            task.log = (task.log or "") + kwargs["log"]
        db.commit()


def create_task(db, kind: str, payload: dict[str, Any]) -> Task:
    task = Task(kind=kind, payload=payload)
    db.add(task)
    db.commit()
    db.refresh(task)
    return task


def _finish(task_id: int, error: str = "", result: dict[str, Any] | None = None) -> None:
    update_task(task_id, status="Success" if not error else "Failed", progress=100, current_stage="done" if not error else "failed", error=error, finished_at=datetime.now(timezone.utc), result=result or {})


@celery_app.task(name="security_toolbox.analyze_metadata")
def metadata_task(file_id: int, task_id: int) -> None:
    update_task(task_id, status="Running", progress=10, current_stage="读取文件")
    with SessionLocal() as db:
        record = db.get(FileRecord, file_id)
        if not record:
            _finish(task_id, "文件不存在")
            return
        path = Path(record.path)
        if not path.exists():
            _finish(task_id, "文件路径不存在")
            return
        update_task(task_id, progress=40, current_stage="解析元数据")
        result = extract_metadata(path)
        record.metadata_json = result
        record.sha256 = result["sha256"]
        record.file_type = result["file_type"]
        record.risk_level = "Medium" if result["hidden_info"]["hidden"] else "Low"
        context = DetectionContext(target_type="file", target_id=str(file_id), path=path, metadata=result, data={"file_type": result["file_type"], "metadata": result["metadata"]})
        run_pipeline(context, task_id, db)
        db.add(AnalysisResult(task_id=task_id, module="metadata", content=result, risk_level=record.risk_level))
        db.commit()
    _finish(task_id, result={"file_id": file_id, "metadata": result})


@celery_app.task(name="security_toolbox.analyze_pcap")
def analyze_pcap_task(pcap_id: int, task_id: int) -> None:
    update_task(task_id, status="Running", progress=10, current_stage="读取 PCAP")
    with SessionLocal() as db:
        record = db.get(PcapRecord, pcap_id)
        if not record:
            _finish(task_id, "PCAP 不存在")
            return
        path = Path(record.storage_path)
        if not path.exists():
            _finish(task_id, "PCAP 路径不存在")
            return
        update_task(task_id, progress=30, current_stage="协议解析")
        parsed = parse_pcap(path)
        record.packet_count = parsed["packet_count"]
        record.protocol_summary = parsed["protocol_summary"]
        record.status = "analyzed"
        record.duration = (parsed["packets"][-1]["timestamp"] - parsed["packets"][0]["timestamp"]) if parsed["packets"] else 0.0
        if parsed["packets"]:
            record.capture_start = str(parsed["packets"][0]["timestamp"])
            record.capture_end = str(parsed["packets"][-1]["timestamp"])
        db.add_all([Flow(pcap_id=pcap_id, **{k: v for k, v in flow.items() if k != "app_protocol"}) for flow in parsed["flows"]])
        db.add_all([PacketRecord(pcap_id=pcap_id, **packet) for packet in parsed["packets"]])
        update_task(task_id, progress=70, current_stage="流量与异常分析")
        anomalies = detect_anomalies(parsed["flows"], parsed["packets"])
        db.add_all([Anomaly(pcap_id=pcap_id, **item) for item in anomalies])
        context = DetectionContext(target_type="pcap", target_id=str(pcap_id), path=path, flows=parsed["flows"], packets=parsed["packets"], data={"protocol_summary": parsed["protocol_summary"], "anomalies": anomalies})
        run_pipeline(context, task_id, db)
        external = external_engine_analysis(path, settings.external_engine_dir)
        if external["engines"]:
            db.add(AnalysisResult(task_id=task_id, module="external_engine", content=external, risk_level="Low"))
        db.add(AnalysisResult(task_id=task_id, module="protocol", content=parsed["protocol_summary"], risk_level="High" if anomalies else "Low"))
        db.add(AnalysisResult(task_id=task_id, module="traffic", content={"anomalies": len(anomalies)}, risk_level="High" if anomalies else "Low"))
        db.commit()
    _finish(task_id, result={"pcap_id": pcap_id, "packet_count": parsed["packet_count"], "anomalies": len(anomalies)})


@celery_app.task(name="security_toolbox.analyze_assets")
def asset_task(probe_id: int, task_id: int) -> None:
    update_task(task_id, status="Running", progress=20, current_stage="资产识别")
    with SessionLocal() as db:
        from sqlalchemy import delete
        from app.models import Probe
        probe = db.get(Probe, probe_id)
        if not probe:
            _finish(task_id, "探针不存在")
            return
        payload = dict(probe.extra or {})
        payload.update({"hostname": probe.hostname, "ip": probe.ip_address})
        assets = classify_assets(payload)
        db.execute(delete(Asset).where(Asset.probe_id == probe_id))
        for item in assets:
            db.add(Asset(probe_id=probe_id, ip=item["ip"], hostname=item["hostname"], os=item["os"], port=item["port"], protocol=item["protocol"], service=item["service"], asset_type=item["asset_type"], risk_level=item["risk_level"], sensitive_categories=item["sensitive_categories"], extra=item["metadata"]))
        context = DetectionContext(target_type="probe", target_id=str(probe_id), assets=assets, data={"public_exposed": payload.get("public_exposed", False), "services": payload.get("services", [])})
        run_pipeline(context, task_id, db)
        db.add(AnalysisResult(task_id=task_id, module="assets", content={"count": len(assets)}, risk_level="High" if any(a["risk_level"] == "High" for a in assets) else "Low"))
        db.commit()
    _finish(task_id, result={"probe_id": probe_id, "assets": len(assets)})
