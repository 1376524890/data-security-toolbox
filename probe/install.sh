#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/data-security-toolbox"
PROBE_DIR="${APP_DIR}/probe"
CONFIG_DIR="/etc/data-security-toolbox"
SPOOL_DIR="/var/lib/data-security-toolbox/spool"
SERVICE="data-security-toolbox-probe"

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

if ! id dstprobe >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin dstprobe
fi

mkdir -p "${APP_DIR}" "${PROBE_DIR}" "${CONFIG_DIR}" "${SPOOL_DIR}"
cp probe.py requirements.txt "${PROBE_DIR}/"
chmod 0755 "${PROBE_DIR}/probe.py"
chown -R dstprobe:dstprobe "${PROBE_DIR}" "${SPOOL_DIR}"

if [[ ! -f "${CONFIG_DIR}/probe.toml" ]]; then
  cat > "${CONFIG_DIR}/probe.toml" <<'EOF'
[server]
url = "https://security-platform.local"
verify_tls = true
ca_file = "/etc/data-security-toolbox/ca.pem"

[capture]
interface = "eth0"
segment_seconds = 30
segment_max_mb = 64

[spool]
path = "/var/lib/data-security-toolbox/spool"
max_mb = 2048
retention_seconds = 86400

[agent]
heartbeat_seconds = 30
asset_interval_seconds = 900
file_interval_seconds = 0
bootstrap_token = "CHANGE_ME"
token_path = "/etc/data-security-toolbox/probe.token"
ports = [22, 80, 443, 445, 3306, 5432, 6379, 8080]
paths = []
max_files = 50
demo = false
EOF
fi
chown dstprobe:dstprobe "${CONFIG_DIR}/probe.toml"
chmod 0600 "${CONFIG_DIR}/probe.toml"
chown dstprobe:dstprobe "${CONFIG_DIR}"
chmod 0700 "${CONFIG_DIR}"

cat > "/etc/systemd/system/${SERVICE}.service" <<EOF
[Unit]
Description=Data Security Toolbox Probe
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=dstprobe
Group=dstprobe
ExecStart=/usr/bin/python3 ${PROBE_DIR}/probe.py --config ${CONFIG_DIR}/probe.toml
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${SPOOL_DIR} ${CONFIG_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE}"
systemctl restart "${SERVICE}"
echo "installed ${SERVICE}"
