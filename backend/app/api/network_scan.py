# FastAPI dependency defaults are part of the existing HTTP contract.
# ruff: noqa: B008
"""Active network scan: start a scan and read its progress and result.

Without ``probe_id`` the platform itself discovers hosts and enumerates services
(nmap ``-Pn -sT`` with a built-in TCP-connect fallback); with ``probe_id`` the
bounded scan is queued for that probe through ``services/probe_task_service.py``,
which is the only way to reach a segment the platform container cannot route to.
Port selection stays in ``services/scan_service.py`` and the scan is dispatched
through ``api/dependencies.dispatch_task``; this module owns paths and response
shapes only.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import false, select
from sqlalchemy.orm import Session

from app.api.assets import serialize_asset
from app.api.dependencies import dispatch_task
from app.api.task_presenter import serialize_task
from app.core.database import get_db
from app.models import Asset, Probe, Task
from app.schemas import ScanRequest
from app.services.task_dispatch import NETWORK_SCAN
from app.services.task_service import create_task

router = APIRouter()


@router.post("/scan")
def start_scan(payload: ScanRequest, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Trigger an active network scan.

    Without ``probe_id`` the platform itself discovers hosts and enumerates
    services (nmap ``-Pn -sT`` with a built-in TCP-connect fallback). With
    ``probe_id`` the bounded scan is queued for that probe, which is the only
    way to reach a segment the platform container cannot route to.
    """
    if payload.probe_id:
        from app.services.probe_task_service import queue_probe_scan

        if not db.get(Probe, payload.probe_id):
            raise HTTPException(404, "probe not found")
        from app.services.scan_service import select_ports

        ports = payload.ports or select_ports(min(payload.top_ports, 256))
        task = queue_probe_scan(
            db,
            payload.probe_id,
            {
                "targets": [payload.target],
                "ports": ports,
                "max_hosts": 256,
                "concurrency": 32,
                "connect_timeout": 0.5,
                "timeout_seconds": 300,
            },
        )
        return {**serialize_task(task), "location": "probe", "probe_id": payload.probe_id}
    task = create_task(
        db,
        "scan",
        {
            "target": payload.target,
            "discovery": payload.discovery,
            "top_ports": payload.top_ports,
            "ports": payload.ports,
            "public_exposed": payload.public_exposed,
            "nuclei": payload.nuclei,
            "nuclei_tags": payload.nuclei_tags,
            "nuclei_templates": payload.nuclei_templates,
            "crypto_assess": payload.crypto_assess,
        },
    )
    dispatch_task(task.id, NETWORK_SCAN)
    return {**serialize_task(task), "location": "platform"}


@router.get("/scan/{task_id}")
def scan_result(task_id: int, db: Session = Depends(get_db)) -> dict[str, Any]:
    """Return a scan task's progress / result (assets + findings)."""
    task = db.get(Task, task_id)
    if not task:
        raise HTTPException(404, "scan task not found")
    result = serialize_task(task)
    hosts = list((task.result or {}).get("hosts") or [])
    if task.kind == "probe_scan":
        probe_id = (task.payload or {}).get("probe_id")
        query = select(Asset).where(
            Asset.probe_id == probe_id, Asset.extra["source"].as_string() == "probe_scan"
        )
    else:
        query = select(Asset).where(
            Asset.extra["source"].as_string().in_(["platform_scan", "nmap_scan"])
        )
    if hosts:
        query = query.where(Asset.ip.in_(hosts))
    else:
        query = query.where(false())
    result["scanned_assets"] = [
        serialize_asset(item) for item in db.scalars(query.order_by(Asset.ip, Asset.port)).all()
    ]
    return result
