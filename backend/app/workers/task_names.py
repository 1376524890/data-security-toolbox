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
#: Runs on a short beat: ingest outruns the hourly retention sweep by orders
#: of magnitude, so the disk cap has to be checked while there is still time.
ENFORCE_PCAP_STORAGE_CAP = "security_toolbox.enforce_pcap_storage_cap"
SYNC_WAZUH_ALERTS = "security_toolbox.sync_wazuh_alerts"
EXPIRE_PROBE_TASKS = "security_toolbox.expire_probe_tasks"
RUN_PROBE_DEPLOYMENT = "security_toolbox.run_probe_deployment"
SWEEP_DEPLOYMENT_TIMEOUTS = "security_toolbox.sweep_deployment_timeouts"
#: Keeps the stored probe status in step with the derivation the console shows
#: (see services.probe_status): nothing else ever wrote ``offline`` back when a
#: probe stopped heartbeating, so the column and the list disagreed forever.
MARK_STALE_PROBES_OFFLINE = "security_toolbox.mark_stale_probes_offline"
