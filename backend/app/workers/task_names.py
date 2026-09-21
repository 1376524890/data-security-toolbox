"""Registered Celery task names.

The names are a compatibility boundary (beat schedule, task routes and any
external caller address tasks by name), so they live in one import-free module
that both the task decorators and the dispatch port read.
"""

SYNC_INTELLIGENCE = "security_toolbox.sync_intelligence"
WORKER_CAPABILITY_HEARTBEAT = "security_toolbox.worker_capability_heartbeat"
DELIVER_ALERT = "security_toolbox.deliver_alert"
ANALYZE_METADATA = "security_toolbox.analyze_metadata"
ANALYZE_PCAP = "security_toolbox.analyze_pcap"
ANALYZE_ASSETS = "security_toolbox.analyze_assets"
NETWORK_SCAN = "security_toolbox.network_scan"
FILE_SOURCE_SCAN = "security_toolbox.file_source_scan"
FILE_SOURCE_SCHEDULE = "security_toolbox.file_source_schedule"
DATABASE_SCAN = "security_toolbox.database_scan"
CLEANUP_PCAP_RETENTION = "security_toolbox.cleanup_pcap_retention"
SYNC_WAZUH_ALERTS = "security_toolbox.sync_wazuh_alerts"
EXPIRE_PROBE_TASKS = "security_toolbox.expire_probe_tasks"
RUN_PROBE_DEPLOYMENT = "security_toolbox.run_probe_deployment"
SWEEP_DEPLOYMENT_TIMEOUTS = "security_toolbox.sweep_deployment_timeouts"
