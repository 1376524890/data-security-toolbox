#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:?usage: $0 <private-target-ip> [port-range]}"
RANGE="${2:-1-100}"

python3 - "$TARGET" <<'PY'
import ipaddress
import sys

ip = ipaddress.ip_address(sys.argv[1])
private = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]
if not any(ip in network for network in private):
    print("refusing non-private target", file=sys.stderr)
    sys.exit(2)
PY

attack_started_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "attack_started_at=${attack_started_at}"
echo "running authorized port scan against ${TARGET}:${RANGE}"
nmap -sT -Pn -p "${RANGE}" "${TARGET}" >/dev/null
attack_finished_at="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "attack_finished_at=${attack_finished_at}"
echo "waiting for backend alert pipeline"
sleep 15
echo "segment_uploaded_at / analysis_finished_at / alert_created_at / frontend_received_at are recorded by the platform"
echo "check Alert Center or GET /api/v1/alerts?severity=High"
