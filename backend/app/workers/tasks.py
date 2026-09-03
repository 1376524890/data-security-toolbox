import json
import smtplib
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from sqlalchemy import or_, select

from app.core.config import settings
from app.core.database import SessionLocal
from app.engine import registry
from app.engine.core.context import DetectionContext
from app.engine.core.pipeline import DetectionPipeline
from app.engine.core.result import DetectionResult
from app.engine.graph import build_graph
from app.engine.risk_engine.engine import RiskEngine
from app.incident_engine.engine import IncidentEngine
from app.models import (
    IOC,
    Alert,
    AlertDelivery,
    AnalysisResult,
    Anomaly,
    Asset,
    DataAsset,
    DetectionFinding,
    FileRecord,
    Flow,
    GraphRelation,
    Incident,
    LocalCve,
    PacketRecord,
    PcapRecord,
    Task,
)
from app.services.alert_service import (
    EVENT_CREATED,
    EVENT_UPDATED,
    create_finding_alert,
    create_incident_alert,
    publish_alert,
    queue_deliveries,
)
from app.services.asset_service import classify_assets
from app.services.metadata_service import extract_metadata
from app.services.protocol_service import parse_pcap
from app.services.traffic_service import detect_anomalies
from app.workers.celery_app import celery_app

pipeline = DetectionPipeline(registry, RiskEngine())
incident_engine = IncidentEngine()


def _recent_findings(db, probe_id: int | None, window_seconds: int = 3600, exclude_task_id: int | None = None) -> list[DetectionResult]:
    since = datetime.now(UTC) - timedelta(seconds=window_seconds)
    query = select(DetectionFinding).where(DetectionFinding.created_at >= since)
    if exclude_task_id is not None:
        query = query.where(DetectionFinding.task_id != exclude_task_id)
    rows = db.scalars(query.order_by(DetectionFinding.timestamp).limit(10000)).all()
    if probe_id is not None:
        rows = [item for item in rows if int((item.evidence or {}).get("probe_id") or 0) == int(probe_id)]
    return [
        DetectionResult(
            engine=item.engine,
            rule_id=item.rule_id,
            severity=item.severity,
            confidence=item.confidence,
            evidence=item.evidence,
            recommendation=item.recommendation,
            timestamp=item.timestamp,
            risk_score=item.risk_score,
            risk_level=item.risk_level,
        )
        for item in rows
    ]


def _finding_signature(item: dict[str, Any]) -> str:
    evidence = item.get("evidence") or {}
    asset = evidence.get("src_ip") or evidence.get("dst_ip") or evidence.get("asset") or ""
    return f"{item.get('engine')}|{item.get('rule_id')}|{item.get('timestamp')}|{asset}"


def _merge_findings(existing: list[dict[str, Any]], incoming: list[dict[str, Any]]) -> list[dict[str, Any]]:
    merged: dict[str, dict[str, Any]] = {}
    for item in [*existing, *incoming]:
        if isinstance(item, dict):
            merged.setdefault(_finding_signature(item), item)
    return list(merged.values())


def _upsert_incident(db, incident: Incident, probe_id: int | None) -> Incident:
    existing = db.scalar(select(Incident).where(Incident.fingerprint == incident.fingerprint))
    now = datetime.now(UTC)
    if existing:
        merged = _merge_findings((existing.findings or {}).get("items", []), incident.findings)
        existing.findings = {"items": merged}
        existing.evidence = {**(existing.evidence or {}), **incident.evidence}
        existing.risk_score = max(existing.risk_score, incident.risk_score)
        existing.risk_level = incident.risk_level
        existing.severity = incident.severity if existing.severity != "Critical" else "Critical"
        existing.last_seen = now
        existing.occurrence_count += 1
        existing.probe_id = probe_id or existing.probe_id
        return existing
    row = Incident(
        fingerprint=incident.fingerprint,
        probe_id=probe_id,
        source=incident.source,
        title=incident.title,
        severity=incident.severity,
        confidence=incident.confidence,
        status=incident.status,
        findings={"items": incident.findings},
        evidence=incident.evidence,
        risk_score=incident.risk_score,
        risk_level=incident.risk_level,
        timestamp=incident.timestamp,
        last_seen=now,
        occurrence_count=1,
    )
    db.add(row)
    db.flush()
    return row


def _run_correlations_and_alerts(db, context: DetectionContext, task_id: int, result, probe_id: int | None) -> list[tuple[Alert, bool]]:
    persisted: list[DetectionFinding] = []
    for finding in result.findings:
        row = DetectionFinding(
            task_id=task_id,
            target_type=context.target_type,
            target_id=str(context.target_id or ""),
            engine=finding.engine,
            rule_id=finding.rule_id,
            severity=finding.severity,
            confidence=finding.confidence,
            evidence={**finding.evidence, "probe_id": probe_id},
            recommendation=finding.recommendation,
            risk_score=finding.risk_score,
            risk_level=finding.risk_level,
            timestamp=finding.timestamp,
        )
        db.add(row)
        persisted.append(row)
    db.flush()
    # Historical findings must NOT include the current task (avoids the current
    # finding being counted twice). Current findings are appended exactly once.
    historical = _recent_findings(db, probe_id, 3600, exclude_task_id=task_id)
    historical.extend(
        DetectionResult(
            engine=item.engine,
            rule_id=item.rule_id,
            severity=item.severity,
            confidence=item.confidence,
            evidence=item.evidence,
            recommendation=item.recommendation,
            timestamp=item.timestamp,
            risk_score=item.risk_score,
            risk_level=item.risk_level,
        )
        for item in persisted
    )
    incidents = incident_engine.correlate(historical, 3600)
    alerts: list[tuple[Alert, bool]] = []
    for incident in incidents:
        if context.target_type == "pcap":
            incident.evidence["pcap_id"] = str(context.target_id or "")
        row = _upsert_incident(db, incident, probe_id)
        alert, created = create_incident_alert(db, row)
        if alert:
            alerts.append((alert, created))
    for finding in persisted:
        alert, created = create_finding_alert(db, finding, probe_id)
        if alert:
            alerts.append((alert, created))
    # Deduplicate by alert id, preferring ``created=True`` when any path is new.
    deduped: dict[int, tuple[Alert, bool]] = {}
    for alert, created in alerts:
        prev = deduped.get(alert.id)
        if prev is None or created:
            deduped[alert.id] = (alert, created)
    return list(deduped.values())


def run_pipeline(context: DetectionContext, task_id: int, db=None) -> list[tuple[int, bool]]:
    if db is not None:
        context.data["ioc_library"] = [
            {"value": item.value, "type": item.ioc_type, "source": item.source}
            for item in db.scalars(select(IOC)).all()
        ]
        context.data["local_cves"] = [
            {"cve_id": item.cve_id, "severity": item.severity, "cvss_score": item.cvss_score, "description": item.description}
            for item in db.scalars(select(LocalCve)).all()
        ]
        if context.data.get("local_cves"):
            context.data["cve_lookup_enabled"] = True
    result = pipeline.run(context)
    owned = db is None
    session = db or SessionLocal()
    probe_id = context.data.get("probe_id")
    try:
        alerts = _run_correlations_and_alerts(session, context, task_id, result, probe_id)
        for alert, created in alerts:
            queue_deliveries(session, alert.id)
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
            for alert, created in alerts:
                publish_alert(alert.id, event_type=EVENT_CREATED if created else EVENT_UPDATED)
                try:
                    deliver_alert_task.delay(alert.id)
                except Exception:
                    deliver_alert_task(alert.id)
            return [(alert.id, created) for alert, created in alerts]
        return [(alert.id, created) for alert, created in alerts]
    finally:
        if owned:
            session.close()


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
    update_task(task_id, status="Success" if not error else "Failed", progress=100, current_stage="done" if not error else "failed", error=error, finished_at=datetime.now(UTC), result=result or {})


@celery_app.task(name="security_toolbox.deliver_alert")
def _delivery_backoff(attempts: int) -> int:
    sequence = [10, 60, 300, 900, 1800]
    if attempts <= 0:
        return sequence[0]
    return sequence[min(attempts - 1, len(sequence) - 1)]


def deliver_alert_task(alert_id: int) -> None:
    with SessionLocal() as db:
        alert = db.get(Alert, alert_id)
        if not alert:
            return
        now = datetime.now(UTC)
        rows = db.scalars(
            select(AlertDelivery).where(
                AlertDelivery.alert_id == alert_id,
                AlertDelivery.status.in_(["pending", "retrying"]),
                or_(AlertDelivery.next_attempt_at.is_(None), AlertDelivery.next_attempt_at <= now),
            )
        ).all()
        payload = {
            "alert_id": alert.id,
            "title": alert.title,
            "summary": alert.summary,
            "severity": alert.severity,
            "risk_score": alert.risk_score,
            "status": alert.status,
            "finding_id": alert.finding_id,
            "incident_id": alert.incident_id,
            "probe_id": alert.probe_id,
            "occurrence_count": alert.occurrence_count,
            "last_seen": alert.last_seen.isoformat() if alert.last_seen else "",
        }
        for row in rows:
            row.attempts += 1
            try:
                if row.channel == "webhook":
                    request = Request(
                        row.target,
                        data=json.dumps(payload).encode("utf-8"),
                        headers={"Content-Type": "application/json"},
                        method="POST",
                    )
                    if settings.webhook_secret:
                        request.add_header("X-Webhook-Secret", settings.webhook_secret)
                    with urlopen(request, timeout=10) as response:
                        response.read(1024)
                elif row.channel == "smtp":
                    import email.message

                    message = email.message.EmailMessage()
                    message["Subject"] = f"[Data Security Toolbox] {alert.severity} {alert.title}"
                    message["From"] = settings.smtp_from or settings.smtp_user
                    message["To"] = row.target
                    message.set_content(json.dumps(payload, ensure_ascii=False, indent=2))
                    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
                        smtp.starttls()
                        if settings.smtp_user:
                            smtp.login(settings.smtp_user, settings.smtp_password)
                        smtp.send_message(message)
                else:
                    raise ValueError(f"unknown channel: {row.channel}")
                row.status = "sent"
                row.last_error = ""
                row.sent_at = now
                row.next_attempt_at = None
            except Exception as exc:  # noqa: BLE001
                max_attempts = row.max_attempts or settings.alert_delivery_max_attempts
                row.last_error = str(exc)[:2000]
                if row.attempts >= max_attempts:
                    row.status = "failed_permanent"
                    row.next_attempt_at = None
                else:
                    row.status = "retrying"
                    row.next_attempt_at = now + timedelta(seconds=_delivery_backoff(row.attempts))
                    deliver_alert_task.apply_async(args=[alert_id], countdown=_delivery_backoff(row.attempts))
        db.commit()


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
        context = DetectionContext(target_type="file", target_id=str(file_id), path=path, metadata=result, data={"file_type": result["file_type"], "metadata": result["metadata"], "probe_id": record.probe_id})
        alerts = run_pipeline(context, task_id, db)
        db.add(AnalysisResult(task_id=task_id, module="metadata", content=result, risk_level=record.risk_level))
        db.commit()
        for alert_id, created in alerts:
            publish_alert(alert_id, event_type=EVENT_CREATED if created else EVENT_UPDATED)
            try:
                deliver_alert_task.delay(alert_id)
            except Exception:
                deliver_alert_task(alert_id)
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
        parsed = parse_pcap(path, max_index_packets=settings.pcap_index_limit)
        record.packet_count = parsed["packet_count"]
        record.total_packet_count = parsed.get("total_packet_count", parsed["packet_count"])
        record.indexed_packet_count = parsed.get("indexed_packet_count", len(parsed["packets"]))
        record.file_type = parsed.get("file_type", "")
        record.protocol_summary = parsed["protocol_summary"]
        record.status = "analyzed"
        record.ingest_status = "ingested"
        record.analysis_status = "analyzed"
        record.duration = float(parsed.get("duration") or 0)
        if parsed.get("capture_start"):
            record.capture_start = parsed["capture_start"]
            record.capture_started_at = record.capture_started_at or parsed["capture_start"]
        if parsed.get("capture_end"):
            record.capture_end = parsed["capture_end"]
            record.capture_finished_at = record.capture_finished_at or parsed["capture_end"]
        if not record.duration and parsed["packets"]:
            record.duration = parsed["packets"][-1]["timestamp"] - parsed["packets"][0]["timestamp"]
        db.add_all([Flow(pcap_id=pcap_id, **{k: v for k, v in flow.items() if k != "app_protocol"}) for flow in parsed["flows"]])
        db.add_all([PacketRecord(pcap_id=pcap_id, **packet) for packet in parsed["packets"]])
        update_task(task_id, progress=70, current_stage="流量与异常分析")
        anomalies = detect_anomalies(parsed["flows"], parsed["packets"])
        db.add_all([Anomaly(pcap_id=pcap_id, **item) for item in anomalies])
        context = DetectionContext(target_type="pcap", target_id=str(pcap_id), path=path, flows=parsed["flows"], packets=parsed["packets"], data={
            "protocol_summary": parsed["protocol_summary"],
            "anomalies": anomalies,
            "probe_id": record.probe_id,
            "pcap_id": pcap_id,
            "exposure_factor": 3,
            "port_scan_window_seconds": settings.port_scan_window_seconds,
            "port_scan_ports_threshold": settings.port_scan_ports_threshold,
        })
        alerts = run_pipeline(context, task_id, db)
        db.add(AnalysisResult(
            task_id=task_id,
            module="protocol_details",
            content={
                "tcp_streams": context.data.get("tcp_streams", []),
                "dns": context.data.get("dns", {"queries": [], "high_entropy": [], "txt_large": []}),
                "tls": context.data.get("tls", {"handshakes": [], "ja3": {}, "sni": {}}),
                "http": context.data.get("http", {"requests": []}),
            },
            risk_level="Low",
        ))
        if context.data.get("adapter_records"):
            db.add(AnalysisResult(task_id=task_id, module="integrations", content=context.data["adapter_records"], risk_level="Low"))
        db.add(AnalysisResult(task_id=task_id, module="protocol", content=parsed["protocol_summary"], risk_level="High" if anomalies else "Low"))
        db.add(AnalysisResult(task_id=task_id, module="traffic", content={"anomalies": len(anomalies)}, risk_level="High" if anomalies else "Low"))
        db.commit()
        for alert_id, created in alerts:
            publish_alert(alert_id, event_type=EVENT_CREATED if created else EVENT_UPDATED)
            try:
                deliver_alert_task.delay(alert_id)
            except Exception:
                deliver_alert_task(alert_id)
    _finish(task_id, result={"pcap_id": pcap_id, "packet_count": parsed["packet_count"], "indexed_packet_count": parsed.get("indexed_packet_count", 0), "anomalies": len(anomalies)})


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
        context = DetectionContext(target_type="probe", target_id=str(probe_id), assets=assets, data={"public_exposed": payload.get("public_exposed", False), "services": payload.get("services", []), "probe_id": probe_id})
        alerts = run_pipeline(context, task_id, db)
        db.add(AnalysisResult(task_id=task_id, module="assets", content={"count": len(assets)}, risk_level="High" if any(a["risk_level"] == "High" for a in assets) else "Low"))
        db.commit()
        for alert_id, created in alerts:
            publish_alert(alert_id, event_type=EVENT_CREATED if created else EVENT_UPDATED)
            try:
                deliver_alert_task.delay(alert_id)
            except Exception:
                deliver_alert_task(alert_id)
    _finish(task_id, result={"probe_id": probe_id, "assets": len(assets)})


@celery_app.task(name="security_toolbox.cleanup_pcap_retention")
def cleanup_pcap_retention_task() -> dict[str, int]:
    removed = 0
    with SessionLocal() as db:
        cutoff = datetime.now(UTC) - timedelta(days=settings.pcap_retention_days)
        rows = db.scalars(select(PcapRecord).where(PcapRecord.created_at < cutoff, PcapRecord.retention_status == "active")).all()
        for record in rows:
            open_alert = db.scalar(select(Alert.id).where(Alert.status.in_(["new", "acknowledged"]), Alert.finding_id.in_(select(DetectionFinding.id).where(DetectionFinding.target_type == "pcap", DetectionFinding.target_id == str(record.id)))).limit(1))
            open_incident = any(str((item.evidence or {}).get("pcap_id", "")) == str(record.id) for item in db.scalars(select(Incident).where(Incident.status == "open")).all())
            if open_alert or open_incident:
                record.retention_status = "extended"
                continue
            path = Path(record.storage_path)
            if path.exists():
                path.unlink()
            record.retention_status = "retained_analysis"
            record.status = "retained_analysis"
            removed += 1
        db.commit()
    return {"removed": removed}
