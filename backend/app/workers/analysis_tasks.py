"""Celery entry points that analyse one target and persist its findings.

Each task owns its transaction: it opens a session, writes the rows the analysis
produced and commits before the alert fan-out, exactly as before the split.
"""

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import delete, or_, select

from app.application.analysis import (
    capture_exposure,
    run_correlations_and_alerts,
    run_pipeline,
)
from app.core.config import settings
from app.core.database import SessionLocal
from app.engine.core.context import DetectionContext
from app.engine.core.result import DetectionResult, PipelineResult
from app.models import (
    Alert,
    AlertDelivery,
    AlertHit,
    AnalysisResult,
    Anomaly,
    Asset,
    DataAsset,
    DetectionFinding,
    FileRecord,
    Flow,
    GraphRelation,
    PacketRecord,
    PcapRecord,
    Task,
)
from app.services.alert_service import (
    EVENT_CREATED,
    EVENT_UPDATED,
    publish_alert,
)
from app.services.asset_service import classify_assets
from app.services.database_scan.adapters import DatabaseError
from app.services.database_scan.scan import run_scan
from app.services.metadata_service import extract_metadata
from app.services.nuclei_service import run_nuclei_scan, templates_dir
from app.services.protocol_service import parse_pcap
from app.services.scan_service import detect_interception, is_subnet, nmap_available, scan_host
from app.services.task_dispatch import dispatch
from app.services.task_service import update_task
from app.services.traffic_service import detect_anomalies
from app.workers.celery_app import celery_app
from app.workers.task_names import (
    ANALYZE_ASSETS,
    ANALYZE_METADATA,
    ANALYZE_PCAP,
    DATABASE_SCAN,
    DELIVER_ALERT,
    NETWORK_SCAN,
)
from app.workers.task_runtime import _finish, _mark_running, task_guard


def _supersede_file_derivations(db, file_id: int, task_id: int, file_name: str) -> int:
    """Retire the previous analysis run's derived rows for one file.

    A file can be re-analysed at will. Keeping every run's findings as *current*
    made three runs look like three times the exposure, so the previous run is
    marked superseded: the rows stay queryable as history, while the file detail
    and the correlation window only see the latest run. The legacy per-file
    ``DataAsset`` projection and the graph relation it produced are derived and
    rebuildable, so the stale copies are removed instead of stacking up.
    """
    retired = 0
    findings = db.scalars(
        select(DetectionFinding).where(
            DetectionFinding.target_type == "file",
            DetectionFinding.target_id == str(file_id),
            DetectionFinding.task_id != task_id,
        )
    ).all()
    for row in findings:
        evidence = dict(row.evidence or {})
        if evidence.get("superseded"):
            continue
        evidence.update(
            {
                "superseded": True,
                "superseded_at": datetime.now(UTC).isoformat(),
                "superseded_by_task": task_id,
            }
        )
        row.evidence = evidence
        retired += 1
    if file_name:
        for row in db.scalars(
            select(DataAsset).where(DataAsset.asset_type == "file", DataAsset.source == file_name)
        ).all():
            db.delete(row)
        db.execute(
            delete(GraphRelation).where(
                GraphRelation.source_type == "data_asset", GraphRelation.source_node == file_name
            )
        )
    return retired


@celery_app.task(name=ANALYZE_METADATA)
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
        context = DetectionContext(
            target_type="file",
            target_id=str(file_id),
            path=path,
            metadata=result,
            data={
                "file_type": result["file_type"],
                "metadata": result["metadata"],
                "probe_id": record.probe_id,
            },
        )
        # Re-analysis is not a new incident: retire the previous run first.
        _supersede_file_derivations(db, file_id, task_id, record.name)
        alerts = run_pipeline(context, task_id, db)
        # The file's risk must summarise the detections that just ran, not only
        # the metadata/hidden-info hint: a Low-looking file carrying keys or PII
        # used to stay Low in the list while its detail page showed High.
        severity_rank = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
        metadata_risk = "Medium" if result["hidden_info"]["hidden"] else "Low"
        task_findings = db.scalars(
            select(DetectionFinding).where(DetectionFinding.task_id == task_id)
        ).all()
        data_risk = max(
            (item.severity for item in task_findings if item.engine == "data_engine"),
            key=lambda severity: severity_rank.get(severity, 0),
            default="",
        )
        if severity_rank.get(data_risk, 0) > severity_rank.get(metadata_risk, 0):
            risk_level = data_risk
        else:
            risk_level = metadata_risk
        result["risk"] = {
            "level": risk_level,
            "metadata_hint": metadata_risk,
            "data_engine": data_risk,
            # Unsupported/failed document reads are surfaced here instead of
            # letting an empty scan imply the file is clean.
            "scan_status": next(
                (
                    item.get("scan_status")
                    for item in context.data.get("data_assets", [])
                    if item.get("scan_status")
                ),
                "",
            ),
            "findings": [
                {"rule_id": item.rule_id, "severity": item.severity} for item in task_findings
            ][:50],
        }
        record.risk_level = risk_level
        record.metadata_json = result
        db.add(
            AnalysisResult(
                task_id=task_id, module="metadata", content=result, risk_level=risk_level
            )
        )
        db.commit()
        for alert_id, created in alerts:
            publish_alert(alert_id, event_type=EVENT_CREATED if created else EVENT_UPDATED)
            dispatch(DELIVER_ALERT, alert_id)
    _finish(task_id, result={"file_id": file_id, "metadata": result})


@celery_app.task(name=ANALYZE_PCAP)
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
        old_findings = db.scalars(
            select(DetectionFinding.id).where(
                DetectionFinding.target_type == "pcap", DetectionFinding.target_id == str(pcap_id)
            )
        ).all()
        if old_findings:
            db.execute(delete(AlertHit).where(AlertHit.finding_id.in_(old_findings)))
            db.execute(
                delete(AlertDelivery).where(
                    AlertDelivery.alert_id.in_(
                        select(Alert.id).where(Alert.finding_id.in_(old_findings))
                    )
                )
            )
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
        db.add_all(
            [
                Flow(pcap_id=pcap_id, **{k: v for k, v in flow.items() if k != "app_protocol"})
                for flow in parsed["flows"]
            ]
        )
        db.add_all([PacketRecord(pcap_id=pcap_id, **packet) for packet in parsed["packets"]])
        from app.services.pcap_files import extract_capture_files

        update_task(task_id, progress=60, current_stage="传输文件提取")
        captured_files = extract_capture_files(path, pcap_id, parsed["protocol_summary"])
        db.add(
            AnalysisResult(
                task_id=task_id, module="pcap_files", content=captured_files, risk_level="Low"
            )
        )
        update_task(task_id, progress=70, current_stage="流量与异常分析")
        anomalies = detect_anomalies(parsed["flows"], parsed["packets"])
        db.add_all([Anomaly(pcap_id=pcap_id, **item) for item in anomalies])
        exposure_factor, exposure_basis = capture_exposure(parsed["flows"])
        context = DetectionContext(
            target_type="pcap",
            target_id=str(pcap_id),
            path=path,
            flows=parsed["flows"],
            packets=parsed["packets"],
            data={
                "protocol_summary": parsed["protocol_summary"],
                "anomalies": anomalies,
                "probe_id": record.probe_id,
                "pcap_id": pcap_id,
                "exposure_factor": exposure_factor,
                "exposure_basis": exposure_basis,
                "port_scan_window_seconds": settings.port_scan_window_seconds,
                "port_scan_ports_threshold": settings.port_scan_ports_threshold,
            },
        )
        alerts = run_pipeline(context, task_id, db)
        if context.data.get("dlp"):
            dlp = context.data["dlp"]
            # Matches alone are evidence; only protected data of sufficient
            # precision makes a capture a high-risk transfer.
            db.add(
                AnalysisResult(
                    task_id=task_id,
                    module="dlp",
                    content=dlp,
                    risk_level="High" if dlp.get("sensitive_objects") else "Low",
                )
            )
        db.add(
            AnalysisResult(
                task_id=task_id,
                module="protocol_details",
                content={
                    "tcp_streams": context.data.get("tcp_streams", []),
                    "dns": context.data.get(
                        "dns", {"queries": [], "high_entropy": [], "txt_large": []}
                    ),
                    "tls": context.data.get("tls", {"handshakes": [], "ja3": {}, "sni": {}}),
                    "http": context.data.get("http", {"requests": []}),
                },
                risk_level="Low",
            )
        )
        if context.data.get("adapter_records"):
            db.add(
                AnalysisResult(
                    task_id=task_id,
                    module="integrations",
                    content=context.data["adapter_records"],
                    risk_level="Low",
                )
            )
        db.add(
            AnalysisResult(
                task_id=task_id,
                module="protocol",
                content=parsed["protocol_summary"],
                risk_level="High" if anomalies else "Low",
            )
        )
        db.add(
            AnalysisResult(
                task_id=task_id,
                module="traffic",
                content={"anomalies": len(anomalies)},
                risk_level="High" if anomalies else "Low",
            )
        )
        db.commit()
        for alert_id, created in alerts:
            publish_alert(alert_id, event_type=EVENT_CREATED if created else EVENT_UPDATED)
            dispatch(DELIVER_ALERT, alert_id)
    _finish(
        task_id,
        result={
            "pcap_id": pcap_id,
            "packet_count": parsed["packet_count"],
            "indexed_packet_count": parsed.get("indexed_packet_count", 0),
            "anomalies": len(anomalies),
        },
    )


@celery_app.task(name=ANALYZE_ASSETS)
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
        db.execute(
            delete(Asset).where(
                Asset.probe_id == probe_id,
                or_(
                    Asset.extra["source"].as_string() != "probe_scan",
                    Asset.extra["source"].as_string().is_(None),
                ),
            )
        )
        for item in assets:
            db.add(
                Asset(
                    probe_id=probe_id,
                    ip=item["ip"],
                    hostname=item["hostname"],
                    os=item["os"],
                    port=item["port"],
                    protocol=item["protocol"],
                    service=item["service"],
                    asset_type=item["asset_type"],
                    risk_level=item["risk_level"],
                    sensitive_categories=item["sensitive_categories"],
                    extra=item["metadata"],
                )
            )
        context = DetectionContext(
            target_type="probe",
            target_id=str(probe_id),
            assets=assets,
            data={
                "public_exposed": payload.get("public_exposed", False),
                "services": payload.get("services", []),
                "probe_id": probe_id,
            },
        )
        alerts = run_pipeline(context, task_id, db)
        db.add(
            AnalysisResult(
                task_id=task_id,
                module="assets",
                content={"count": len(assets)},
                risk_level="High" if any(a["risk_level"] == "High" for a in assets) else "Low",
            )
        )
        db.commit()
        for alert_id, created in alerts:
            publish_alert(alert_id, event_type=EVENT_CREATED if created else EVENT_UPDATED)
            dispatch(DELIVER_ALERT, alert_id)
    _finish(task_id, result={"probe_id": probe_id, "assets": len(assets)})


def _nuclei_to_detection(item: dict[str, Any]) -> DetectionResult:
    """Convert a normalized nuclei finding into a DetectionResult."""
    label = item.get("name") or item.get("template_id")
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
        recommendation=f"根据 Nuclei 模板「{label}」评估并修复受影响资产。",
    ).normalize()


@celery_app.task(name=NETWORK_SCAN)
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
        update_task(
            task_id, status="Running", progress=5, current_stage=f"准备网段扫描（{port_scope}）"
        )
        warning = ""
        if discovery:
            warning = detect_interception(ports=ports or None)
            if warning:
                update_task(task_id, log=f"[scan] {warning}\n")
        hosts = [target]
        if discovery and is_subnet(target):
            from app.services.scan_service import expand_targets

            hosts = expand_targets(target)
            update_task(
                task_id,
                progress=15,
                current_stage=f"待扫描 {len(hosts)} 个地址",
                log=f"[scan] discovery {target} -> {len(hosts)} host(s)\n",
            )
        if not hosts:
            db.add(
                AnalysisResult(
                    task_id=task_id,
                    module="scan",
                    content={"target": target, "hosts": [], "assets": 0, "findings": 0},
                    risk_level="Low",
                )
            )
            db.commit()
            _finish(
                task_id,
                result={
                    "target": target,
                    "hosts": [],
                    "alive_hosts": 0,
                    "assets": 0,
                    "findings": 0,
                    "engine": "python-tcp",
                    "reason": "no live host answered the TCP liveness ports",
                },
            )
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
            for host, services in pool.map(
                lambda item: (item, scan_host(item, top_ports, ports=ports or None)), hosts
            ):
                services_by_host[host] = services or []
                update_task(
                    task_id,
                    progress=15 + int(65 * len(services_by_host) / max(1, len(hosts))),
                    current_stage=f"扫描 {host} ({len(services_by_host)}/{len(hosts)})",
                )
        for _idx, host in enumerate(hosts, 1):
            services = services_by_host.get(host) or []
            if not services:
                continue
            scanned_hosts.append(host)
            engines.add(
                "nmap"
                if any(str(item.get("product", "")).strip() for item in services)
                else "python-tcp"
            )
            # Keep re-scans current: drop stale platform assets for this host.
            try:
                db.execute(
                    delete(Asset).where(
                        Asset.probe_id.is_(None),
                        Asset.ip == host,
                        Asset.extra["source"].as_string().in_(["platform_scan", "nmap_scan"]),
                    )
                )
            except Exception:
                db.rollback()
            assets = classify_assets(
                {
                    "hostname": host,
                    "ip": host,
                    "os": "",
                    "services": services,
                    "public_exposed": public_exposed,
                    "metadata": {},
                }
            )
            for a in assets:
                meta = a.get("metadata", {}) or {}
                a["version"] = meta.get("version", "")
                a["product"] = meta.get("product", "")
                db.add(
                    Asset(
                        probe_id=None,
                        ip=host,
                        hostname=host,
                        os="",
                        port=a["port"],
                        protocol=a["protocol"],
                        service=a["service"],
                        asset_type=a["asset_type"],
                        risk_level=a["risk_level"],
                        sensitive_categories=a["sensitive_categories"],
                        extra={"source": "platform_scan", **meta},
                    )
                )
            context = DetectionContext(
                target_type="scan",
                target_id=str(task_id),
                assets=assets,
                data={
                    "public_exposed": public_exposed,
                    "services": services,
                    "cve_lookup_enabled": True,
                    "nvd_api_key": "",
                },
            )
            alerts = run_pipeline(context, task_id, db)
            total_assets += len(assets)
            total_findings += len(alerts)
            db.commit()
            for alert_id, created in alerts:
                publish_alert(alert_id, event_type=EVENT_CREATED if created else EVENT_UPDATED)
                dispatch(DELIVER_ALERT, alert_id)
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
                    nfindings = run_nuclei_scan(
                        target_url, templates_dir=nuclei_tpl or templates_dir(), tags=nuclei_tags
                    )
                    if nfindings:
                        nresult = PipelineResult(
                            target_type="scan",
                            target_id=str(task_id),
                            findings=[_nuclei_to_detection(f) for f in nfindings],
                        )
                        n_alerts = run_correlations_and_alerts(db, context, task_id, nresult, None)
                        total_findings += len(n_alerts)
                        db.commit()
                        for alert, created in n_alerts:
                            publish_alert(
                                alert.id, event_type=EVENT_CREATED if created else EVENT_UPDATED
                            )
                            dispatch(DELIVER_ALERT, alert.id)
        summary = {
            "target": target,
            "hosts": hosts,
            "alive_hosts": len(scanned_hosts),
            "assets": total_assets,
            "findings": total_findings,
            "ports": ports,
            "top_ports": top_ports,
            "engine": "+".join(sorted(engines)) or ("nmap" if nmap_available() else "python-tcp"),
        }
        if warning:
            summary["warning"] = warning
        db.add(
            AnalysisResult(
                task_id=task_id,
                module="scan",
                content=summary,
                risk_level="High" if total_findings else "Low",
            )
        )
        db.commit()
    if not scanned_hosts:
        _finish(
            task_id, result={**summary, "reason": "存活主机未开放任何被扫描端口"}, status="Partial"
        )
        return summary
    _finish(task_id, result=summary)
    return summary


@celery_app.task(name=DATABASE_SCAN)
@task_guard
def database_scan_task(connection_id: int, task_id: int) -> dict[str, Any] | None:
    """Collect one configured target database and store its findings.

    The task owns its transaction: the objects, instances, detections and the
    analysis row land together. A stop request is honoured between tables, so a
    cancelled scan keeps everything it had already read and retires nothing.
    """
    _mark_running(task_id, 5, "准备连接目标数据库")
    with SessionLocal() as db:
        task = db.get(Task, task_id)
        if task is None:
            return None
        if str(task.status or "") == "Cancelled":
            return None
        snapshot_id = int((task.payload or {}).get("connection_id") or 0)
        if snapshot_id != int(connection_id):
            _finish(
                task_id,
                error="任务载荷与调度的连接不一致，已拒绝执行",
                result={"error": "connection_mismatch", "connection_id": connection_id},
            )
            return None
        _mark_running(task_id, 10, "连接目标数据库")
        try:
            summary = run_scan(db, task)
        except DatabaseError as exc:
            db.rollback()
            status = str(getattr(exc, "status", "error"))
            _finish(
                task_id, error=str(exc),
                result={"error": status, "message": str(exc),
                        "connection_id": connection_id,
                        "stage": "connect" if status in {"unreachable", "auth_error"} else "scan"},
            )
            return {"status": "failed", "error": status, "message": str(exc)}
        db.add(
            AnalysisResult(
                task_id=task_id,
                module="database_scan",
                content=summary,
                risk_level="High" if summary.get("detections") else "Low",
            )
        )
        db.commit()
    final = "Success"
    if summary.get("cancelled"):
        final = "Cancelled"
    elif not summary.get("complete_scope"):
        final = "Partial"
    _finish(task_id, result=summary, status=final)
    return summary


from app.workers.task_names import FILE_SOURCE_SCAN, FILE_SOURCE_SCHEDULE

@celery_app.task(name=FILE_SOURCE_SCAN)
@task_guard
def file_source_scan_task(source_id: int, task_id: int):
    from app.services.file_scan.scan import run
    with SessionLocal() as db:
        return run(db, task_id)

@celery_app.task(name=FILE_SOURCE_SCHEDULE)
def file_source_schedule_task():
    from datetime import UTC, datetime, timedelta
    from sqlalchemy import select
    from app.models import FileSource
    from app.services.file_scan import service
    from app.services.task_dispatch import enqueue
    with SessionLocal() as db:
        rows = db.scalars(select(FileSource).where(FileSource.enabled.is_(True),
            FileSource.interval_minutes > 0, FileSource.next_scan_at <= datetime.now(UTC))
            .with_for_update(skip_locked=True)).all()
        pending = []
        for row in rows:
            if service.active(db, row.id):
                row.next_scan_at = datetime.now(UTC) + timedelta(minutes=row.interval_minutes)
                continue
            task = service.queue(db, row)
            pending.append((row.id, task.id))
        db.commit()
    for source_id, task_id in pending:
        try:
            enqueue(FILE_SOURCE_SCAN, source_id, task_id)
        except Exception:
            _finish(task_id, error='queue_unavailable')
