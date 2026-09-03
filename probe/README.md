# Probe Agent

The probe is a long-running daemon responsible for capture, local spooling,
authenticated upload, heartbeat, and lightweight local inventory. Detection,
risk, and alerting run in the backend analysis worker.

Requires Python 3.11+ (`tomllib`, `datetime.UTC`), `requests`, `psutil`, and
`dumpcap` (preferred) or `tcpdump`.

## Install

```bash
sudo ./install.sh
```

Edit `/etc/data-security-toolbox/probe.toml`, set the bootstrap token, then restart:

```bash
sudo systemctl restart data-security-toolbox-probe
```

The service runs as `dstprobe` with `CAP_NET_RAW` and `CAP_NET_ADMIN`, uses
`Restart=always` and `RestartSec=5`, and never runs as root.

## Manual run

```bash
python3 probe.py --config ./probe.toml
```

## Behavior

- Capture uses `dumpcap` first and falls back to `tcpdump`.
- Segments are written to `spool/*.pcapng.partial`, fsynced, then atomically renamed.
- Uploads use `X-Probe-ID` and `X-Probe-Token`; retries use exponential backoff.
- Full spool stops capture and reports `capture_status=degraded` instead of deleting evidence.
- Local IP comes from the configured capture interface, never from an external resolver.
- Asset inventory checks only configured local ports and requires `connect_ex() == 0`.
- Asset inventory also grabs a short banner (`recv`) per open port to aid service fingerprinting.
- When `agent.file_interval_seconds > 0` and `agent.paths` are set, the probe uploads each target
  file's content to `/api/v1/files/upload` so the backend can run sensitive-data analysis on real
  bytes (PII/secret/YARA). Each record includes `sha256` and `md5`.
- Registration persists `probe_id + token` to `agent.identity_path` (0600) and never re-enrolls on
  restart.
