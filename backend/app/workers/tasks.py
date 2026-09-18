import functools
import json
import smtplib
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

from sqlalchemy import and_, or_, select

from app.core.config import settings
from app.core.database import SessionLocal
from app.engine import registry
from app.engine.core.context import DetectionContext
from app.engine.core.pipeline import DetectionPipeline
from app.engine.core.result import DetectionResult, PipelineResult
from app.engine.graph import build_graph
from app.engine.risk_engine.engine import RiskEngine
from app.incident_engine.engine import IncidentEngine, evidence_asset_keys
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
from app.services.scan_service import detect_interception, discover_hosts, is_subnet, nmap_available, scan_host
from app.services.metadata_service import extract_metadata
from app.services.nuclei_service import run_nuclei_scan, templates_dir
from app.services.protocol_service import parse_pcap
from app.services.traffic_service import detect_anomalies
from app.workers.celery_app import celery_app

pipeline = DetectionPipeline(registry, RiskEngine())
incident_engine = IncidentEngine()


@celery_app.task(name='security_toolbox.sync_intelligence')
def sync_intelligence_task(task_id: int):
    from app.services.intelligence_service import sync_provider
    with SessionLocal() as db:
        task = db.get(Task, task_id)
        if not task:
            return
        task.status, task.current_stage = 'Running', '同步威胁情报'
        db.commit()
        try:
            result = sync_provider(db, task.payload['provider'])
            task.result = result
            task.status = 'Success' if result['status'] == 'success' else 'Failed'
            task.error = result.get('error', '')
        except Exception:
            db.rollback()
            task.status, task.error = 'Failed', 'Intelligence synchronization failed'
        task.progress, task.finished_at = 100, datetime.now(UTC)
        db.commit()


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
    # Findings are plain dicts at this point, so the identity is rebuilt with
    # the same rules the incident engine uses. Reading only src_ip/dst_ip/asset
    # left every traffic finding (which spells them ``src``/``dst``) on an
    # empty asset and merged distinct hosts into one signature.
    assets = ",".join(evidence_asset_keys(evidence))
    return f"{item.get('engine')}|{item.get('rule_id')}|{item.get('timestamp')}|{assets}"


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
        title=(incident.title or "")[:255],
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
            if (item.extra or {}).get('enabled', True)
        ]
        from app.models import SystemSetting
        from app.services.dlp_service import DEFAULT_POLICY
        policy = db.scalar(select(SystemSetting).where(SystemSetting.key == 'dlp_policy'))
        context.data['dlp_policy'] = policy.value if policy else DEFAULT_POLICY
        # Grype contains hundreds of thousands of CVEs. Query per service in
        # ThreatIntelEngine rather than loading the whole catalog per packet task.
        if db.scalar(select(LocalCve.id).limit(1)) is not None:
            context.data["cve_lookup_enabled"] = True
        from app.integrations.offline_manager import resolve_active_suricata_rules_dir
        context.data["suricata_rules_dir"] = resolve_active_suricata_rules_dir(db)
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


def _finish(task_id: int, error: str = "", result: dict[str, Any] | None = None, status: str | None = None) -> None:
    import socket as _socket

    payload = dict(result or {})
    payload.setdefault("worker", _socket.gethostname())
    final = status or ("Success" if not error else "Failed")
    stage = {"Success": "done", "Partial": "partial", "Failed": "failed"}.get(final, final.lower())
    update_task(task_id, status=final, progress=100, current_stage=stage, error=error, finished_at=datetime.now(UTC), result=payload)


def _mark_failed(task_id: int, exc: Exception, stage: str = "failed") -> None:
    """A task must never remain Running; any exception lands in Failed."""
    import traceback

    update_task(
        task_id,
        status="Failed",
        progress=100,
        current_stage=stage,
        error=f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[:2000]}",
        finished_at=datetime.now(UTC),
    )


def _mark_running(task_id: int, progress: int, stage: str) -> None:
    update_task(task_id, status="Running", progress=progress, current_stage=stage)


def task_guard(func):
    """Wrap a Celery task so any exception lands the Task row in Failed.

    A task must never remain ``Running``. The guard extracts ``task_id`` from
    the final positional arg or the ``task_id`` kwarg, marks Failed with a full
    stack trace, then re-raises so Celery logs the real failure.
    """

    @functools.wraps(func)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        task_id = kwargs.get("task_id") or (args[-1] if args and isinstance(args[-1], int) else None)
        try:
            return func(*args, **kwargs)
        except Exception as exc:
            if task_id is not None:
                _mark_failed(int(task_id), exc)
            raise

    return wrapper


WORKER_CAPABILITY_TTL = 60


def _worker_capability() -> dict[str, Any]:
    import shutil as _shutil
    import socket as _socket

    def _ver(binary: str) -> dict[str, Any]:
        path = _shutil.which(binary)
        if not path:
            return {"available": False, "version": ""}
        try:
            proc = subprocess.run([binary, "--version"], capture_output=True, text=True, timeout=10, check=False)
            version = (proc.stdout or proc.stderr).splitlines()[0].strip() if (proc.stdout or proc.stderr) else ""
        except Exception:
            version = ""
        return {"available": True, "version": version}

    rule_count = 0
    if _shutil.which("suricata"):
        # Count the rule files Suricata is really started with. ``run_suricata``
        # loads the shipped rule set (``integrations/suricata/rules``) plus the
        # resolved offline set; reading only the offline directory reported
        # "0 rules" while Suricata ran with rules loaded.
        from app.rules.library import rule_files, _suricata_lines

        for rule_file in rule_files('suricata'):
            try:
                rule_count += len(_suricata_lines(str(rule_file), rule_file.stat().st_mtime_ns))
            except OSError:
                pass
    return {
        "worker_id": f"analysis-{_socket.gethostname()}",
        "heartbeat": datetime.now(UTC).isoformat(),
        "tshark": _ver("tshark"),
        "zeek": _ver("zeek"),
        "suricata": {**_ver("suricata"), "rule_count": rule_count},
    }


@celery_app.task(name="security_toolbox.worker_capability_heartbeat")
def worker_capability_heartbeat() -> dict[str, Any]:
    import redis as redis_lib

    capability = _worker_capability()
    try:
        client = redis_lib.Redis.from_url(settings.redis_url, decode_responses=True, socket_connect_timeout=1, socket_timeout=1)
        key = f"worker:capability:{capability['worker_id']}"
        client.set(key, json.dumps(capability), ex=WORKER_CAPABILITY_TTL)
    except Exception:
        pass
    return capability


def _delivery_backoff(attempts: int) -> int:
    sequence = [10, 60, 300, 900, 1800]
    if attempts <= 0:
        return sequence[0]
    return sequence[min(attempts - 1, len(sequence) - 1)]


@celery_app.task(name="security_toolbox.deliver_alert")
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
@task_guard
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
        record.md5 = result.get("md5", "")
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
@task_guard
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
        # Re-analysis must not re-append derived rows. Wipe previous derived
        # data (flows, packets, anomalies, findings and their alerts) so a
        # manual re-analyze is idempotent and never duplicates records.
        from sqlalchemy import delete

        db.execute(delete(Anomaly).where(Anomaly.pcap_id == pcap_id))
        db.execute(delete(Flow).where(Flow.pcap_id == pcap_id))
        db.execute(delete(PacketRecord).where(PacketRecord.pcap_id == pcap_id))
        old_findings = db.scalars(select(DetectionFinding.id).where(DetectionFinding.target_type == "pcap", DetectionFinding.target_id == str(pcap_id))).all()
        if old_findings:
            db.execute(delete(AlertDelivery).where(AlertDelivery.alert_id.in_(select(Alert.id).where(Alert.finding_id.in_(old_findings)))))
            db.execute(delete(Alert).where(Alert.finding_id.in_(old_findings)))
            db.execute(delete(DetectionFinding).where(DetectionFinding.id.in_(old_findings)))
        db.commit()
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
        from app.services.pcap_files import extract_capture_files

        update_task(task_id, progress=60, current_stage="传输文件提取")
        captured_files = extract_capture_files(path, pcap_id, parsed['protocol_summary'])
        db.add(AnalysisResult(task_id=task_id, module='pcap_files', content=captured_files,
                              risk_level='Low'))
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
        if context.data.get('dlp'):
            dlp = context.data['dlp']
            # Matches alone are evidence; only protected data of sufficient
            # precision makes a capture a high-risk transfer.
            db.add(AnalysisResult(task_id=task_id, module='dlp', content=dlp,
                                  risk_level='High' if dlp.get('sensitive_objects') else 'Low'))
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
@task_guard
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
        db.execute(delete(Asset).where(Asset.probe_id == probe_id, or_(Asset.extra['source'].as_string() != 'probe_scan', Asset.extra['source'].as_string().is_(None))))
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


def _nuclei_to_detection(item: dict[str, Any]) -> DetectionResult:
    """Convert a normalized nuclei finding into a DetectionResult."""
    return DetectionResult(
        engine="nuclei_engine",
        rule_id=f"NUCLEI_{item.get('template_id') or item.get('name') or 'unknown'}",
        severity=item.get("severity", "Low"),
        confidence=0.8,
        evidence={
            "template_id": item.get("template_id", ""),
            "name": item.get("name", ""),
            "type": item.get("type", ""),
            "host": item.get("host", ""),
            "port": item.get("port", ""),
            "url": item.get("url", ""),
            "matched_at": item.get("matched_at", ""),
            "extracted": item.get("extracted", []),
            "reference": item.get("reference", []),
            "matcher_name": item.get("matcher_name", ""),
        },
        recommendation=f"根据 Nuclei 模板「{item.get('name') or item.get('template_id')}」评估并修复受影响资产。",
    ).normalize()


@celery_app.task(name="security_toolbox.network_scan")
@task_guard
def network_scan_task(task_id: int) -> dict[str, Any]:
    """Active network scan: discover hosts, enumerate services, run detection.

    Host discovery and port scanning never depend on ICMP/ARP or raw sockets:
    ``nmap`` is invoked with ``-Pn -sT`` and a dependency-free TCP-connect engine
    takes over whenever nmap is missing, blocked or returns nothing - otherwise
    a containerised platform scans a reachable network and still reports zero
    assets.
    """
    from sqlalchemy import delete

    with SessionLocal() as db:
        task = db.get(Task, task_id)
        if not task:
            _finish(task_id, error="task not found")
            return {}
        payload = task.payload or {}
        target = str(payload.get("target") or "")
        if not target:
            _finish(task_id, error="scan target is required")
            return {}
        discovery = bool(payload.get("discovery", True))
        top_ports = int(payload.get("top_ports") or 200)
        ports = [int(item) for item in (payload.get("ports") or []) if str(item).strip().isdigit()]
        public_exposed = bool(payload.get("public_exposed", False))
        nuclei = bool(payload.get("nuclei", False))
        nuclei_tags = str(payload.get("nuclei_tags") or "")
        nuclei_tpl = str(payload.get("nuclei_templates") or "")
        port_scope = f"{len(ports)} 个指定端口" if ports else f"top {top_ports} 端口"
        update_task(task_id, status="Running", progress=5, current_stage=f"准备网段扫描（{port_scope}）")
        warning = ""
        if discovery:
            warning = detect_interception(ports=ports or None)
            if warning:
                update_task(task_id, log=f"[scan] {warning}\n")
        hosts = [target]
        if discovery and is_subnet(target):
            from app.services.scan_service import expand_targets
            hosts = expand_targets(target)
            update_task(task_id, progress=15, current_stage=f"待扫描 {len(hosts)} 个地址", log=f"[scan] discovery {target} -> {len(hosts)} host(s)\n")
        if not hosts:
            db.add(AnalysisResult(task_id=task_id, module="scan", content={"target": target, "hosts": [], "assets": 0, "findings": 0}, risk_level="Low"))
            db.commit()
            _finish(task_id, result={"target": target, "hosts": [], "alive_hosts": 0, "assets": 0, "findings": 0, "engine": "python-tcp", "reason": "no live host answered the TCP liveness ports"})
            return {"target": target, "hosts": [], "assets": 0}
        scanned_hosts: list[str] = []
        total_assets = 0
        total_findings = 0
        engines: set[str] = set()
        # Bounded parallelism: nmap is invoked per host, so scanning a segment
        # four hosts at a time keeps a /24 practical while staying gentle.
        scan_concurrency = max(1, min(int(payload.get("concurrency") or 4), 8))
        services_by_host: dict[str, list[dict[str, Any]]] = {}
        with ThreadPoolExecutor(max_workers=scan_concurrency) as pool:
            for host, services in pool.map(lambda item: (item, scan_host(item, top_ports, ports=ports or None)), hosts):
                services_by_host[host] = services or []
                update_task(task_id, progress=15 + int(65 * len(services_by_host) / max(1, len(hosts))),
                            current_stage=f"扫描 {host} ({len(services_by_host)}/{len(hosts)})")
        for idx, host in enumerate(hosts, 1):
            services = services_by_host.get(host) or []
            if not services:
                continue
            scanned_hosts.append(host)
            engines.add("nmap" if any(str(item.get("product", "")).strip() for item in services) else "python-tcp")
            # Keep re-scans current: drop stale platform assets for this host.
            try:
                db.execute(delete(Asset).where(Asset.probe_id.is_(None), Asset.ip == host, Asset.extra["source"].as_string().in_(["platform_scan", "nmap_scan"])))
            except Exception:
                db.rollback()
            assets = classify_assets({"hostname": host, "ip": host, "os": "", "services": services, "public_exposed": public_exposed, "metadata": {}})
            for a in assets:
                meta = a.get("metadata", {}) or {}
                a["version"] = meta.get("version", "")
                a["product"] = meta.get("product", "")
                db.add(Asset(probe_id=None, ip=host, hostname=host, os="", port=a["port"], protocol=a["protocol"], service=a["service"], asset_type=a["asset_type"], risk_level=a["risk_level"], sensitive_categories=a["sensitive_categories"], extra={"source": "platform_scan", **meta}))
            context = DetectionContext(target_type="scan", target_id=str(task_id), assets=assets, data={"public_exposed": public_exposed, "services": services, "cve_lookup_enabled": True, "nvd_api_key": ""})
            alerts = run_pipeline(context, task_id, db)
            total_assets += len(assets)
            total_findings += len(alerts)
            db.commit()
            for alert_id, created in alerts:
                publish_alert(alert_id, event_type=EVENT_CREATED if created else EVENT_UPDATED)
                try:
                    deliver_alert_task.delay(alert_id)
                except Exception:
                    deliver_alert_task(alert_id)
            if nuclei:
                # Run nuclei against each discovered HTTP/HTTPS service URL.
                nuclei_targets = []
                for svc in services:
                    name = str(svc.get("service", "")).lower()
                    port = int(svc.get("port", 0) or 0)
                    if "http" in name or "https" in name or port in (80, 443, 8080, 8443):
                        scheme = "https" if (port in (443, 8443) or "https" in name) else "http"
                        nuclei_targets.append(f"{scheme}://{host}:{port}")
                if not nuclei_targets:
                    nuclei_targets = [host]
                for target_url in nuclei_targets:
                    update_task(task_id, progress=90, current_stage=f"Nuclei 扫描 {target_url}")
                    nfindings = run_nuclei_scan(target_url, templates_dir=nuclei_tpl or templates_dir(), tags=nuclei_tags)
                    if nfindings:
                        nresult = PipelineResult(target_type="scan", target_id=str(task_id), findings=[_nuclei_to_detection(f) for f in nfindings])
                        n_alerts = _run_correlations_and_alerts(db, context, task_id, nresult, None)
                        total_findings += len(n_alerts)
                        db.commit()
                        for alert, created in n_alerts:
                            publish_alert(alert.id, event_type=EVENT_CREATED if created else EVENT_UPDATED)
                            try:
                                deliver_alert_task.delay(alert.id)
                            except Exception:
                                deliver_alert_task(alert.id)
        summary = {"target": target, "hosts": hosts, "alive_hosts": len(scanned_hosts), "assets": total_assets, "findings": total_findings, "ports": ports, "top_ports": top_ports, "engine": "+".join(sorted(engines)) or ("nmap" if nmap_available() else "python-tcp")}
        if warning:
            summary["warning"] = warning
        db.add(AnalysisResult(task_id=task_id, module="scan", content=summary, risk_level="High" if total_findings else "Low"))
        db.commit()
    if not scanned_hosts:
        _finish(task_id, result={**summary, "reason": "存活主机未开放任何被扫描端口"}, status="Partial")
        return summary
    _finish(task_id, result=summary)
    return summary

@celery_app.task(name="security_toolbox.cleanup_pcap_retention")
@task_guard
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


@celery_app.task(name="security_toolbox.sync_wazuh_alerts")
def wazuh_alerts_task() -> dict[str, Any]:
    """Periodically pull alerts from the configured Wazuh API and ingest findings.

    Degrades to a no-op when Wazuh is not configured, and reports an error
    object when the API is reachable but fails (so operators can see why).
    """
    from app.integrations.host_audit.wazuh_adapter import WazuhAdapter
    from app.integrations.runner import run_adapter

    adapter = WazuhAdapter()
    if not adapter.configured:
        return {"status": "skipped", "reason": "Wazuh API not configured"}
    try:
        records = adapter.fetch()
    except Exception as exc:  # noqa: BLE001 - surface any client/network error
        return {"status": "error", "error": str(exc)[:300]}
    if not records:
        return {"status": "ok", "records": 0, "findings": 0}
    context = DetectionContext(target_type="integration", target_id="wazuh", data={})
    result = run_adapter(adapter, records, context, RiskEngine())
    alerts: list[tuple[Alert, bool]] = []
    with SessionLocal() as db:
        # Skip findings already persisted for the same engine+rule+timestamp.
        sigs = [(item.engine, item.rule_id, str(item.timestamp)) for item in result.findings]
        existing = set()
        if sigs:
            sig_conditions = [
                and_(DetectionFinding.engine == e, DetectionFinding.rule_id == r, DetectionFinding.timestamp == ts)
                for e, r, ts in sigs
            ]
            rows = db.execute(select(DetectionFinding.engine, DetectionFinding.rule_id, DetectionFinding.timestamp).where(or_(*sig_conditions))).all()
            existing = {(row[0], row[1], str(row[2])) for row in rows}
        for item in result.findings:
            sig = (item.engine, item.rule_id, str(item.timestamp))
            if sig in existing:
                continue
            finding_row = DetectionFinding(
                target_type="integration",
                target_id="wazuh",
                engine=item.engine,
                rule_id=item.rule_id,
                severity=item.severity,
                confidence=item.confidence,
                evidence=item.evidence,
                recommendation=item.recommendation,
                risk_score=item.risk_score,
                risk_level=item.risk_level,
                timestamp=item.timestamp,
            )
            db.add(finding_row)
            db.flush()
            alert, created = create_finding_alert(db, finding_row)
            if alert:
                alerts.append((alert, created))
        for incident in incident_engine.correlate(result.findings):
            row = _upsert_incident(db, incident, None)
            alert, created = create_incident_alert(db, row)
            if alert:
                alerts.append((alert, created))
        db.commit()
    for alert, created in alerts:
        publish_alert(alert.id, event_type=EVENT_CREATED if created else EVENT_UPDATED)
    return {"status": "ok", "records": len(records), "findings": len(result.findings), "alerts": len(alerts)}


@celery_app.task(name="security_toolbox.expire_probe_tasks")
def expire_remote_probe_tasks():
    from app.services.probe_task_service import expire_probe_tasks
    with SessionLocal() as db:
        expire_probe_tasks(db)
        db.commit()
