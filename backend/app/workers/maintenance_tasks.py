"""Celery entry points for periodic and integration work.

Nothing here analyses a target on demand: these are the beats (retention,
heartbeats, probe-task expiry), the intelligence sync and the external alert
pulls. Splitting them out keeps a change to a scheduled job away from the
analysis queue registrations.
"""

import json
import subprocess
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, or_, select

from app.application.analysis import (
    incident_engine,
    upsert_incident,
)
from app.core.config import settings
from app.core.database import SessionLocal
from app.engine.core.context import DetectionContext
from app.engine.risk_engine.engine import RiskEngine
from app.models import (
    Alert,
    DetectionFinding,
    PcapRecord,
    Task,
)
from app.services import pcap_storage
from app.services.alert_service import (
    EVENT_CREATED,
    EVENT_UPDATED,
    create_finding_alert,
    create_incident_alert,
    publish_alert,
)
from app.workers.celery_app import celery_app
from app.workers.task_names import (
    CLEANUP_PCAP_RETENTION,
    ENFORCE_PCAP_STORAGE_CAP,
    EXPIRE_PROBE_TASKS,
    MARK_STALE_PROBES_OFFLINE,
    SWEEP_STALE_ANALYSES,
    SYNC_WAZUH_ALERTS,
    WORKER_CAPABILITY_HEARTBEAT,
)
from app.workers.task_runtime import task_guard


@celery_app.task(name="security_toolbox.sync_intelligence")
def sync_intelligence_task(task_id: int):
    from app.services.intelligence_service import sync_provider

    with SessionLocal() as db:
        task = db.get(Task, task_id)
        if not task:
            return
        task.status, task.current_stage = "Running", "同步威胁情报"
        db.commit()
        try:
            result = sync_provider(db, task.payload["provider"])
            task.result = result
            task.status = "Success" if result["status"] == "success" else "Failed"
            task.error = result.get("error", "")
        except Exception:
            db.rollback()
            task.status, task.error = "Failed", "Intelligence synchronization failed"
        task.progress, task.finished_at = 100, datetime.now(UTC)
        db.commit()


WORKER_CAPABILITY_TTL = 60


def _worker_capability() -> dict[str, Any]:
    import shutil as _shutil
    import socket as _socket

    def _ver(binary: str) -> dict[str, Any]:
        path = _shutil.which(binary)
        if not path:
            return {"available": False, "version": ""}
        try:
            proc = subprocess.run(
                [binary, "--version"], capture_output=True, text=True, timeout=10, check=False
            )
            version = (
                (proc.stdout or proc.stderr).splitlines()[0].strip()
                if (proc.stdout or proc.stderr)
                else ""
            )
        except Exception:
            version = ""
        return {"available": True, "version": version}

    rule_count = 0
    if _shutil.which("suricata"):
        # Count the rule files Suricata is really started with. ``run_suricata``
        # loads the shipped rule set (``integrations/suricata/rules``) plus the
        # resolved offline set; reading only the offline directory reported
        # "0 rules" while Suricata ran with rules loaded.
        from app.rules.library import _suricata_lines, rule_files

        for rule_file in rule_files("suricata"):
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


@celery_app.task(name=WORKER_CAPABILITY_HEARTBEAT)
def worker_capability_heartbeat() -> dict[str, Any]:
    import redis as redis_lib

    capability = _worker_capability()
    try:
        client = redis_lib.Redis.from_url(
            settings.redis_url, decode_responses=True, socket_connect_timeout=1, socket_timeout=1
        )
        key = f"worker:capability:{capability['worker_id']}"
        client.set(key, json.dumps(capability), ex=WORKER_CAPABILITY_TTL)
    except Exception:
        pass
    return capability


@celery_app.task(name=CLEANUP_PCAP_RETENTION)
@task_guard
def cleanup_pcap_retention_task() -> dict[str, int]:
    """Age sweep: retire segments older than the retention window.

    The eviction itself lives in :mod:`app.services.pcap_storage` so this sweep
    and the space sweep cannot disagree about which segment may be dropped.
    """
    with SessionLocal() as db:
        cutoff = datetime.now(UTC) - timedelta(days=settings.pcap_retention_days)
        return pcap_storage.cleanup_expired(db, cutoff)


@celery_app.task(name=ENFORCE_PCAP_STORAGE_CAP)
@task_guard
def enforce_pcap_storage_cap_task() -> dict[str, int | str]:
    """Space sweep: hold the data partition under its cap and above its floor.

    An hourly age sweep is far too slow to bound a probe that uploads a segment
    every few seconds - a full disk takes Postgres with it - so the cap gets its
    own short beat and acts on size rather than age.
    """
    with SessionLocal() as db:
        return pcap_storage.enforce_cap(db)


@celery_app.task(name=SYNC_WAZUH_ALERTS)
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
                and_(
                    DetectionFinding.engine == e,
                    DetectionFinding.rule_id == r,
                    DetectionFinding.timestamp == ts,
                )
                for e, r, ts in sigs
            ]
            rows = db.execute(
                select(
                    DetectionFinding.engine, DetectionFinding.rule_id, DetectionFinding.timestamp
                ).where(or_(*sig_conditions))
            ).all()
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
            row = upsert_incident(db, incident, None)
            alert, created = create_incident_alert(db, row)
            if alert:
                alerts.append((alert, created))
        db.commit()
    for alert, created in alerts:
        publish_alert(alert.id, event_type=EVENT_CREATED if created else EVENT_UPDATED)
    return {
        "status": "ok",
        "records": len(records),
        "findings": len(result.findings),
        "alerts": len(alerts),
    }


@celery_app.task(name=EXPIRE_PROBE_TASKS)
def expire_remote_probe_tasks():
    from app.services.probe_task_service import expire_probe_tasks

    with SessionLocal() as db:
        expire_probe_tasks(db)
        db.commit()


@celery_app.task(name=MARK_STALE_PROBES_OFFLINE)
def mark_stale_probes_offline() -> int:
    """Move probes that stopped heartbeating back to ``offline``.

    The console derives this on read, but the stored column is what
    ``/dashboard/summary`` and ``cockpit_service`` report, and nothing used to
    write it: a probe that died stayed ``online`` in the column forever. This is
    the one place that closes that gap.
    """
    from app.services.probe_status import mark_stale_offline

    with SessionLocal() as db:
        return mark_stale_offline(db)


#: An analysis task that has not finished in this long is wedged, not slow: the
#: longest legitimate single step is Suricata's 61 s startup budget, and a 30 s
#: segment is meant to be analysed well inside the window in which the next one
#: fills. 15 minutes is ~30 segments of backlog - already beyond the congestion
#: budget - so anything past it is a leak to be closed, not work to wait for.
STALE_ANALYSIS_SECONDS = 900


@celery_app.task(name=SWEEP_STALE_ANALYSES)
@task_guard
def sweep_stale_analyses_task() -> dict[str, int]:
    """Close analysis tasks that died without leaving a terminal status.

    A worker killed mid-run (restart, OOM, a third-party binary that never
    returns) leaves its task row ``Running`` and the segment record ``pending``
    forever, because nothing on the failure path survives to write them. The
    console then shows a busy queue that never drains, and the same segment can
    never be told apart from one still being worked on.
    """
    cutoff = datetime.now(UTC) - timedelta(seconds=STALE_ANALYSIS_SECONDS)
    closed = 0
    records = 0
    reclaimed = 0
    with SessionLocal() as db:
        # Rows whose payload a storage sweep already deleted can never be
        # analysed either. ``release`` now closes them as it frees the file, but
        # rows evicted before that existed still read as pending work.
        for orphan in db.scalars(
            select(PcapRecord).where(
                PcapRecord.analysis_status == "pending",
                PcapRecord.retention_status == pcap_storage.STATUS_RETAINED,
            )
        ).all():
            orphan.analysis_status = "evicted"
            reclaimed += 1
        stale = db.scalars(
            select(Task).where(Task.status == "Running", Task.updated_at < cutoff)
        ).all()
        for task in stale:
            task.status = "Failed"
            task.error = "分析未在预期时间内完成，已判定为中断（见 sweep_stale_analyses）"
            task.current_stage = "分析中断"
            task.finished_at = datetime.now(UTC)
            closed += 1
            pcap_id = (task.payload or {}).get("pcap_id")
            if not pcap_id:
                continue
            record = db.get(PcapRecord, int(pcap_id))
            # Only a record still waiting is repainted: one that reached
            # ``analyzed`` before the worker died is not a failure.
            if record is not None and record.analysis_status == "pending":
                record.analysis_status = "failed"
                records += 1
        if closed or reclaimed:
            db.commit()
    return {"tasks": closed, "records": records, "evicted": reclaimed}
