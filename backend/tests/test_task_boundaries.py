"""Keep analysis orchestration, HTTP and Celery entry points from re-coupling.

The split this guards: routes describe the request, ``app.application.analysis``
orchestrates, ``app.services.task_dispatch`` is the only place that knows a
queue exists, and ``app.workers.*`` registers tasks by their stable names.
"""

import ast
from pathlib import Path

import pytest

from app.core.config import settings
from app.services import task_dispatch
from app.workers.celery_app import celery_app

APP = Path(__file__).resolve().parents[1] / "app"

#: The single adapter allowed to know about Celery registration and task bodies.
QUEUE_PORT = "app/services/task_dispatch.py"


def module_imports(path):
    """Every imported module name, including imports inside functions."""
    return [
        node.module or ""
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
        if isinstance(node, ast.ImportFrom)
    ]


def python_files(*relative):
    for item in relative:
        target = APP / item
        if target.is_dir():
            yield from target.rglob("*.py")
        else:
            yield target


def test_only_the_queue_port_reaches_into_the_worker_package():
    offenders = []
    for path in python_files("api", "services", "application", "domain", "engine",
                             "incident_engine", "deployment", "integrations", "rules"):
        if path.as_posix().endswith(QUEUE_PORT):
            continue
        for module in module_imports(path):
            if module.startswith("app.workers"):
                offenders.append((path.relative_to(APP).as_posix(), module))
    assert offenders == []


def test_routes_do_not_import_task_objects_or_private_task_helpers():
    for path in (APP / "api").rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        for forbidden in ("analyze_pcap_task", "metadata_task", "asset_task",
                          "network_scan_task", "sync_intelligence_task", "celery_app"):
            assert forbidden not in source, (path.name, forbidden)


def test_application_layer_has_no_http_or_worker_dependency():
    for path in (APP / "application").rglob("*.py"):
        for module in module_imports(path):
            assert not module.startswith(("app.api", "app.workers", "fastapi")), (path.name, module)


def test_compatibility_facade_still_exposes_the_old_entry_points():
    from app.workers import tasks as facade

    for name in ("run_pipeline", "_upsert_incident", "_run_correlations_and_alerts",
                 "_recent_findings", "_merge_findings", "_capture_exposure",
                 "create_task", "update_task", "task_guard", "_finish", "_mark_failed",
                 "_mark_running", "metadata_task", "analyze_pcap_task", "asset_task",
                 "network_scan_task", "deliver_alert_task", "_delivery_backoff",
                 "sync_intelligence_task", "worker_capability_heartbeat", "_worker_capability",
                 "cleanup_pcap_retention_task", "wazuh_alerts_task", "expire_remote_probe_tasks"):
        assert hasattr(facade, name), name


def test_facade_registers_no_duplicate_tasks():
    facade = (APP / "workers/tasks.py").read_text(encoding="utf-8")
    assert "celery_app.task" not in facade


def test_every_scheduled_and_routed_task_name_is_registered():
    import app.workers.analysis_tasks  # noqa: F401
    import app.workers.deployment_tasks  # noqa: F401
    import app.workers.maintenance_tasks  # noqa: F401
    import app.workers.notification_tasks  # noqa: F401

    registered = set(celery_app.tasks)
    scheduled = {entry["task"] for entry in celery_app.conf.beat_schedule.values()}
    routed = set(celery_app.conf.task_routes)
    assert scheduled <= registered, sorted(scheduled - registered)
    assert routed <= registered, sorted(routed - registered)


def test_dispatch_reports_the_task_id_last_and_prefers_the_broker(monkeypatch):
    calls = []
    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(celery_app, "send_task", lambda name, args=None: calls.append((name, args)))

    task_dispatch.dispatch_task_row("security_toolbox.analyze_pcap", 7, 3)

    assert calls == [("security_toolbox.analyze_pcap", [3, 7])]


def test_enqueue_has_no_inline_fallback(monkeypatch):
    def broken(name, args=None):
        raise OSError("broker down")

    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(celery_app, "send_task", broken)

    with pytest.raises(OSError):
        task_dispatch.enqueue("security_toolbox.sync_intelligence", 1)


def test_dispatch_falls_back_to_this_process_when_the_broker_is_down(monkeypatch):
    @celery_app.task(name="test.boundary.echo")
    def echo(value: int, task_id: int) -> tuple[int, int]:
        return value, task_id

    monkeypatch.setattr(settings, "app_env", "production")
    monkeypatch.setattr(celery_app, "send_task", lambda *a, **k: (_ for _ in ()).throw(OSError()))

    assert task_dispatch.dispatch_task_row("test.boundary.echo", 5, 9) == (9, 5)
