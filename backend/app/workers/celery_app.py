from celery import Celery
from app.core.config import settings

celery_app = Celery("security_toolbox", broker=settings.celery_broker_url, backend=settings.celery_result_backend, include=["app.workers.tasks"])
celery_app.conf.update(
    task_track_started=True,
    task_time_limit=1800,
    worker_prefetch_multiplier=1,
    result_expires=3600,
    beat_schedule={
        "cleanup-pcap-retention": {
            "task": "security_toolbox.cleanup_pcap_retention",
            "schedule": 3600.0,
        },
        "worker-capability-heartbeat": {
            "task": "security_toolbox.worker_capability_heartbeat",
            "schedule": 30.0,
        },
    },
)
