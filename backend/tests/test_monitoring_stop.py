"""Stopping a monitoring session — and the segments hanging under it.

A probe in monitoring mode uploads one capture segment every few seconds, and
each segment is its own task row and its own queue entry. The console showed the
result as a task centre that never moved: the stop endpoint refused the kind
outright ("当前仅支持停止探针扫描、数据资产采集和数据库采集任务") and a stop
that only touched the monitor row would leave the whole backlog running. These
tests pin both halves: the row and its children end together, and a stopped
segment never reaches tshark.
"""

from fastapi.testclient import TestClient

from app.api.tasks import STOPPABLE_TASK_KINDS
from app.core.config import settings
from app.core.database import SessionLocal
from app.main import app
from app.models import Task
from app.services import monitoring
from app.workers.analysis_tasks import analyze_pcap_task
from app.workers.celery_app import celery_app


def monitor_with_segments(db, statuses=("Pending", "Running")):
    monitor = Task(kind=monitoring.MONITOR_KIND, status="Running", progress=100,
                   current_stage="持续监测中", payload={"probe_id": 4242})
    db.add(monitor)
    db.flush()
    segments = []
    for index, status in enumerate(statuses):
        segment = Task(kind=monitoring.SEGMENT_KIND, status=status,
                       payload={"pcap_id": 9000 + index})
        db.add(segment)
        db.flush()
        monitoring.attach_segment(db, monitor, segment)
        segments.append(segment)
    db.commit()
    return monitor, segments


def test_capture_segments_are_analysed_on_their_own_queue():
    """The isolation the console needs: a segment backlog cannot hold the pool."""
    assert celery_app.conf.task_routes["security_toolbox.analyze_pcap"]["queue"] == (
        settings.pcap_worker_queue)
    assert settings.pcap_worker_queue != celery_app.conf.task_default_queue


def test_the_stoppable_kinds_cover_what_the_console_offers():
    for kind in ("probe_scan", "data_asset_scan", "monitoring", "pcap",
                 "database_scan", "file_source_scan", "scan"):
        assert kind in STOPPABLE_TASK_KINDS


def test_stop_ends_the_monitor_and_every_segment_under_it():
    with TestClient(app) as client:
        with SessionLocal() as db:
            monitor, segments = monitor_with_segments(db)
            monitor_id = monitor.id
            segment_ids = [item.id for item in segments]
        body = client.post(f"/api/v1/tasks/{monitor_id}/stop").json()
        assert body["status"] == "Cancelled"
        assert "取消 2 段" in body["current_stage"]
        with SessionLocal() as db:
            assert all(db.get(Task, item).status == "Cancelled" for item in segment_ids)
            assert db.get(Task, monitor_id).finished_at is not None


def test_a_stopped_monitor_is_not_repainted_by_the_list_refresh():
    """`GET /tasks` refreshes every monitor row: it must leave a stopped one alone."""
    with TestClient(app) as client:
        with SessionLocal() as db:
            monitor, _ = monitor_with_segments(db)
            monitoring.stop_monitor(db, monitor)
            db.commit()
            monitor_id = monitor.id
        listing = client.get("/api/v1/tasks", params={"kind": "monitoring"}).json()
        assert monitor_id in [item["id"] for item in listing["items"]]
        with SessionLocal() as db:
            assert db.get(Task, monitor_id).current_stage == "已停止监测"


def test_a_stopped_segment_is_never_handed_to_tshark():
    """No pcap row stands behind this id: a task that went ahead would fail on
    "PCAP 不存在" instead of staying Cancelled."""
    with SessionLocal() as db:
        segment = Task(kind=monitoring.SEGMENT_KIND, status="Cancelled",
                       payload={"pcap_id": 424242})
        db.add(segment)
        db.commit()
        segment_id = segment.id
    assert analyze_pcap_task(424242, segment_id) is None
    with SessionLocal() as db:
        assert db.get(Task, segment_id).status == "Cancelled"


def test_stop_still_refuses_a_kind_whose_executor_cannot_notice():
    with TestClient(app) as client:
        with SessionLocal() as db:
            task = Task(kind="metadata", status="Running", payload={})
            db.add(task)
            db.commit()
            task_id = task.id
        response = client.post(f"/api/v1/tasks/{task_id}/stop")
        assert response.status_code == 409
        assert "监测任务" in response.json()["detail"]


def test_an_unlinked_segment_never_reaches_the_default_list():
    """A segment with no monitor link is still a segment, not a task row.

    The link is written at upload time, so a segment that arrived while no
    monitor was running (or was created before segments were linked at all)
    satisfied ``default_task_filter()`` and sat in 任务中心 as a bare ``pcap``
    row — the local database held 76 of them, which is exactly the "抓包刷屏"
    the operator saw. The kind is excluded from the default list outright;
    ``kind=pcap`` stays the way to reach the segments.
    """
    with TestClient(app) as client:
        with SessionLocal() as db:
            orphan = Task(kind=monitoring.SEGMENT_KIND, status="Success",
                          payload={"pcap_id": 4242})
            db.add(orphan)
            db.commit()
            orphan_id = orphan.id
        # The row is the newest one, so it would head the default list if the
        # filter still let it through.
        default_ids = [item["id"] for item in client.get("/api/v1/tasks").json()["items"]]
        assert orphan_id not in default_ids
        listed = client.get("/api/v1/tasks", params={"kind": "pcap"}).json()
        assert orphan_id in [item["id"] for item in listed["items"]]
