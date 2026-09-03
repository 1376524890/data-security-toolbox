# Data Security Toolbox V3.1 — Acceptance Test

This document records the final, stable acceptance procedure. It is intentionally
non-historical and only describes how to verify the system on a controlled,
isolated network.

## Topology

```
┌──────────────────────────┐
│ Security Platform        │ 10.66.0.10
│  Frontend / FastAPI      │
│  PostgreSQL / Redis      │
│  Celery Worker           │
│  Zeek / Suricata / tshark│
└────────────▲─────────────┘
             │ PCAP upload
┌────────────┴─────────────┐
│ Monitored Host           │ 10.66.0.20
│  Probe (dstprobe)        │
│  nginx test service      │
└────────────▲─────────────┘
             │ test traffic
┌────────────┴─────────────┐
│ Security Test Client     │ 10.66.0.30
└──────────────────────────┘
```

All traffic must be against the private 10.66.0.0/24 test net only. Never target
public hosts.

## Prerequisites

- Docker + Docker Compose v2
- `dumpcap` / `tcpdump` (Probe host), `tshark`, `zeek`, `suricata` (Worker image)
- Strong `SECRET_KEY`, `ADMIN_PASSWORD`, `POSTGRES_PASSWORD`, `PROBE_BOOTSTRAP_TOKEN`
- Probe identity dir `/etc/data-security-toolbox` owned by `dstprobe` (0700), identity file 0600
- Probe runs as `dstprobe` with `CAP_NET_RAW`, `CAP_NET_ADMIN`

## Commands

```bash
# Build and start the production stack
docker compose build
docker compose up -d
docker compose ps

# Backend unit/integration tests
cd backend && pytest -q

# Frontend static checks (no runtime changes)
cd frontend && npm test && npx vue-tsc --noEmit && npm run build

# Compose validation
docker compose config

# Probe (re)start
systemctl restart data-security-toolbox-probe
```

## Test Scenarios & Expected Results

| # | Scenario | Expected |
|---|----------|----------|
| 0 | Normal HTTP/DNS/TCP/SSH flow 10 min | Probe online, segments uploaded, spool falls, no alert flood |
| 1 | `nmap -sT -Pn -p 1-100 10.66.0.20` | NETWORK_PORT_SCAN → Risk → Incident → Alert → SSE → browser |
| 2 | Cross-segment scan (3×15s segments, each < threshold) | Exactly one rolling port-scan Finding, not zero, not dozens |
| 3 | HTTP with `User-Agent: sqlmap-test` | `engine=zeek`, `rule_id=ZEK_HTTP_UA_001`, request visible in PCAP HTTP tab |
| 4 | HTTP with `User-Agent: DST-E2E-TEST-2026` via imported rule | `engine=suricata`, expected SID fired |
| 5 | Two PCAPs with A-UNIQUE / B-UNIQUE markers, concurrency ≥ 2 | No cross-contamination |
| 6 | Same probe_id + segment_id uploaded twice | PcapRecord=1, Task=1, no finding/alert flood |
| 7 | Same behavior within 300 s | 1 Alert instance, occurrence_count grows |
| 8 | Resolved alert, then same behavior after suppress window | New Alert instance; old stays resolved |
| 9 | Backend down 60 s | Probe keeps capturing, spool grows, auto backfill on recovery |
| 10 | Worker down | Tasks pending, backpressure 429 + Retry-After, recover and drain |
| 11 | Redis down | System reports degraded, recovers; rolling state limits noted |
| 12 | PostgreSQL down | Backend fails, Probe spools, backfill on recovery |
| 13 | Probe restart | Same probe_id, same token, no rotation, sequence continues |
| 14 | Probe capture permission | `dstprobe` can capture; CAP_NET_RAW/NET_ADMIN effective |
| 15 | Spool full | Probe degraded, capture stops, evidence preserved, heartbeat spool_full |
| 16 | Corrupt PCAP upload | Task → Failed (never stuck Running), PCAP marked failed |
| 17 | PCAP larger than index limit | total_packet_count > indexed_packet_count; detection covers full PCAP |
| 18 | Frontend SSE with real browser 5–10 min | Live notification, badge update, click opens exact alert |
| 19 | ACK / Resolve | DB + UI consistent; no "new alert" toast on ACK |
| 20 | Alert → Finding → Incident → PCAP navigation | Evidence traceable to Flow/Packet/HTTP/DNS/TLS |
| 21 | Sensitive data upload | DataAsset + Finding + Risk; samples masked, secrets not shown |
| 22 | Offline IOC import + matching traffic | Local IOC real hit (not just display) |
| 23 | Security Report PDF | Real assets/findings/incidents/alerts/risk/PCAP evidence; Chinese fonts OK |

## Failure Criteria

Any of the following means the acceptance has FAILED and must be fixed before
continuing to the next stage:

- Probe restart changes identity or rotates token
- Cross-segment scan produces 0 or dozens of findings
- Offline Suricata rule does not fire
- Zeek/Suricata analysis contaminates concurrent runs
- A resolved alert swallows a recurrence
- A Celery task stays `Running`
- Worker capability health is wrong
- SSE does not deliver in-browser
- Probe outage recovery loses packets
- Spool loses segments

## Metrics

- Detection latency (attack→alert, upload→alert, alert→frontend): P95 ≤ 90 s target
- Probe RSS < 100 MB; average CPU < 5% on low traffic
- Spool trends to ~0 during healthy operation
- No stuck tasks, no unbounded memory growth, no alert storm on normal traffic
