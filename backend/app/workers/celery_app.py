from celery import Celery
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
celery_app.conf.update(
    task_track_started=True,
    task_time_limit=1800,
    worker_prefetch_multiplier=1,
    result_expires=3600,
    task_default_queue="default",
    task_routes={
        "security_toolbox.run_probe_deployment": {"queue": settings.deployment_worker_queue},
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
