"""Compatibility facade over the split worker task modules.

The tasks themselves live in ``analysis_tasks``, ``notification_tasks`` and
``maintenance_tasks``; task orchestration lives in ``app.application.analysis``
and task-row persistence in ``app.services.task_service``. This module only
re-exports the old names so existing imports keep working - do not add task
implementations here.
"""

from app.application.analysis import (  # noqa: F401
    _capture_exposure,
    _finding_signature,
    _merge_findings,
    _recent_findings,
    _run_correlations_and_alerts,
    _upsert_incident,
    run_pipeline,
)
from app.services.task_service import create_task, update_task  # noqa: F401
from app.workers.analysis_tasks import (  # noqa: F401
    _nuclei_to_detection,
    _supersede_file_derivations,
    analyze_pcap_task,
    asset_task,
    metadata_task,
    network_scan_task,
)
from app.workers.maintenance_tasks import (  # noqa: F401
    WORKER_CAPABILITY_TTL,
    _worker_capability,
    cleanup_pcap_retention_task,
    expire_remote_probe_tasks,
    sync_intelligence_task,
    wazuh_alerts_task,
    worker_capability_heartbeat,
)
from app.workers.notification_tasks import _delivery_backoff, deliver_alert_task  # noqa: F401
from app.workers.task_runtime import (  # noqa: F401
    _finish,
    _mark_failed,
    _mark_running,
    task_guard,
)
