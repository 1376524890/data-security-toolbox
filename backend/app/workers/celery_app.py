from celery import Celery
from celery.signals import worker_ready

from app.core.config import settings

celery_app = Celery(
    "security_toolbox",
    broker=settings.celery_broker_url,
    backend=settings.celery_result_backend,
    include=[
        "app.workers.analysis_tasks",
        "app.workers.notification_tasks",
        "app.workers.maintenance_tasks",
        "app.workers.deployment_tasks",
    ],
)


@worker_ready.connect
def _sweep_stale_scan_temp_dirs(**_kwargs) -> None:
    """Drop downloads a previously killed worker never got to unlink.

    A file-source scan copies each file into ``/tmp`` and deletes it right after
    the hash and detection run; a ``SIGKILL`` mid-copy skips both, so the copy
    outlives the worker. Clearing them at startup is the only moment that is
    guaranteed to happen before the next scan can run.
    """
    from app.services.file_scan.scan import sweep_stale_temp_dirs

    sweep_stale_temp_dirs()


celery_app.conf.update(
    task_track_started=True,
    task_time_limit=1800,
    worker_prefetch_multiplier=1,
    result_expires=3600,
    task_default_queue="default",
    task_routes={
        "security_toolbox.run_probe_deployment": {"queue": settings.deployment_worker_queue},
        # Segments are analysed by their own worker (see pcap_worker_queue): the
        # route is what keeps a monitoring backlog out of the analysis pool.
        "security_toolbox.analyze_pcap": {"queue": settings.pcap_worker_queue},
    },
    beat_schedule={
        "file-source-schedule": {"task": "security_toolbox.file_source_schedule", "schedule": 60.0},
        "expire-probe-tasks": {"task": "security_toolbox.expire_probe_tasks", "schedule": 60.0},
        "cleanup-pcap-retention": {
            "task": "security_toolbox.cleanup_pcap_retention",
            "schedule": 3600.0,
        },
        "worker-capability-heartbeat": {
            "task": "security_toolbox.worker_capability_heartbeat",
            "schedule": 30.0,
        },
        "wazuh-alert-sync": {
            "task": "security_toolbox.sync_wazuh_alerts",
            "schedule": float(settings.wazuh_poll_seconds),
        },
        "sweep-deployment-timeouts": {
            "task": "security_toolbox.sweep_deployment_timeouts",
            "schedule": 60.0,
        },
    },
)
