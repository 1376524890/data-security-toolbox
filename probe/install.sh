#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/data-security-toolbox"
PROBE_DIR="${APP_DIR}/probe"
SHARED_DIR="${APP_DIR}/shared"
VENV_DIR="${APP_DIR}/venv"
CONFIG_DIR="/etc/data-security-toolbox"
SPOOL_DIR="/var/lib/data-security-toolbox/spool"
RULES_DIR="/var/lib/data-security-toolbox/rules"
CACHE_DIR="/var/lib/data-security-toolbox/cache"
SERVICE="data-security-toolbox-probe"
INSTALL_ONLY=0
CONFIG_SRC=""
CA_SRC=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --install-only) INSTALL_ONLY=1; shift ;;
    --config) CONFIG_SRC="$2"; shift 2 ;;
    --ca) CA_SRC="$2"; shift 2 ;;
    --skip-deps) SKIP_DEPS=1; shift ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

if ! id dstprobe >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin dstprobe
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${APP_DIR}" "${PROBE_DIR}" "${SHARED_DIR}" "${CONFIG_DIR}" "${SPOOL_DIR}" "${RULES_DIR}" "${CACHE_DIR}"
cp "${SCRIPT_DIR}/probe.py" "${SCRIPT_DIR}/scanner.py" "${SCRIPT_DIR}/data_assets.py" "${SCRIPT_DIR}/ruleset_client.py" "${SCRIPT_DIR}/requirements.txt" "${PROBE_DIR}/"

# The detection engine is shared with the platform, so it ships as its own
# package next to `probe/`: probe.py resolves `shared.sensitive_detection` from
# its parent directory. A package without it cannot detect anything, so this is
# a hard failure instead of a silently degraded install.
if [[ ! -d "${SCRIPT_DIR}/shared/sensitive_detection" ]]; then
  echo "error: probe package is missing shared/sensitive_detection" >&2
  exit 1
fi
# The scan budgets, fingerprints, samplers and parsers are shared too. Without
# them the inventory job fails at import time, so treat it as a hard failure.
if [[ ! -d "${SCRIPT_DIR}/shared/scanning" ]]; then
  echo "error: probe package is missing shared/scanning" >&2
  exit 1
fi
rm -rf "${SHARED_DIR}/sensitive_detection" "${SHARED_DIR}/scanning"
cp -R "${SCRIPT_DIR}/shared/sensitive_detection" "${SCRIPT_DIR}/shared/scanning" "${SHARED_DIR}/"
find "${SHARED_DIR}" -name '__pycache__' -type d -prune -exec rm -rf {} +
if [[ -f "${SCRIPT_DIR}/shared/__init__.py" ]]; then
  cp "${SCRIPT_DIR}/shared/__init__.py" "${SHARED_DIR}/__init__.py"
fi

chmod 0755 "${PROBE_DIR}/probe.py"
chown -R dstprobe:dstprobe "${PROBE_DIR}" "${SHARED_DIR}" "${SPOOL_DIR}" "${RULES_DIR}" "${CACHE_DIR}"
chmod 0700 "${RULES_DIR}" "${CACHE_DIR}"

# Capture tool provisioning: prefer a bundled binary, then a distro package.
CAPTURE_TOOL=""
if command -v dumpcap >/dev/null 2>&1; then
  CAPTURE_TOOL="dumpcap"
elif command -v tcpdump >/dev/null 2>&1; then
  CAPTURE_TOOL="tcpdump"
elif [[ -x "${SCRIPT_DIR}/bin/dumpcap" ]]; then
  install -m 0755 "${SCRIPT_DIR}/bin/dumpcap" /usr/local/bin/dumpcap
  CAPTURE_TOOL="dumpcap"
elif [[ -x "${SCRIPT_DIR}/bin/tcpdump" ]]; then
  install -m 0755 "${SCRIPT_DIR}/bin/tcpdump" /usr/local/bin/tcpdump
  CAPTURE_TOOL="tcpdump"
else
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -y >/dev/null 2>&1 || true
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tcpdump >/dev/null 2>&1 || true
  elif command -v yum >/dev/null 2>&1; then
    yum install -y tcpdump >/dev/null 2>&1 || true
  fi
  if command -v dumpcap >/dev/null 2>&1; then CAPTURE_TOOL="dumpcap"
  elif command -v tcpdump >/dev/null 2>&1; then CAPTURE_TOOL="tcpdump"
  fi
fi
if [[ -n "${CAPTURE_TOOL}" ]]; then
  BIN_PATH="$(command -v "${CAPTURE_TOOL}")"
  setcap cap_net_raw,cap_net_admin+eip "${BIN_PATH}" 2>/dev/null || true
  echo "capture tool: ${CAPTURE_TOOL} (${BIN_PATH})"
else
  echo "warning: no capture tool available; probe will run in Lite mode" >&2
fi

# Prepare an isolated venv with the required runtime dependencies.
PYTHON="${PYTHON:-python3}"
if [[ "${SKIP_DEPS:-0}" -ne 1 ]]; then
  if [[ ! -x "${VENV_DIR}/bin/python" ]]; then
    "${PYTHON}" -m venv "${VENV_DIR}"
  fi
  "${VENV_DIR}/bin/pip" install --upgrade pip >/dev/null 2>&1 || true
  if [[ -d "${SCRIPT_DIR}/wheels" ]]; then
    "${VENV_DIR}/bin/pip" install --no-index --find-links "${SCRIPT_DIR}/wheels" -r "${PROBE_DIR}/requirements.txt" || \
      "${VENV_DIR}/bin/pip" install -r "${PROBE_DIR}/requirements.txt"
  else
    "${VENV_DIR}/bin/pip" install -r "${PROBE_DIR}/requirements.txt"
  fi
  chown -R dstprobe:dstprobe "${VENV_DIR}"
else
  VENV_DIR=""
fi

# Atomically install the config: write to a temp file then move into place.
if [[ -n "${CONFIG_SRC}" && -f "${CONFIG_SRC}" ]]; then
  TMP_CONFIG="${CONFIG_DIR}/probe.toml.tmp"
  cp "${CONFIG_SRC}" "${TMP_CONFIG}"
  mv "${TMP_CONFIG}" "${CONFIG_DIR}/probe.toml"
else
  if [[ ! -f "${CONFIG_DIR}/probe.toml" ]]; then
    TMP_CONFIG="${CONFIG_DIR}/probe.toml.tmp"
    cat > "${TMP_CONFIG}" <<'EOF'
[server]
url = "https://security-platform.local"
verify_tls = true
ca_file = "/etc/data-security-toolbox/ca.pem"

[capture]
interface = "eth0"
segment_seconds = 30
segment_max_mb = 64
enabled = true

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
    mv "${TMP_CONFIG}" "${CONFIG_DIR}/probe.toml"
  fi
fi
chown dstprobe:dstprobe "${CONFIG_DIR}/probe.toml"
chmod 0600 "${CONFIG_DIR}/probe.toml"
chown dstprobe:dstprobe "${CONFIG_DIR}"
chmod 0700 "${CONFIG_DIR}"

if [[ -n "${CA_SRC}" && -f "${CA_SRC}" ]]; then
  cp "${CA_SRC}" "${CONFIG_DIR}/ca.pem"
  chown dstprobe:dstprobe "${CONFIG_DIR}/ca.pem"
  chmod 0644 "${CONFIG_DIR}/ca.pem"
fi

if [[ -n "${VENV_DIR}" ]]; then
  PY_BIN="${VENV_DIR}/bin/python"
else
  PY_BIN="/usr/bin/python3"
fi

cat > "/etc/systemd/system/${SERVICE}.service" <<EOF
[Unit]
Description=Data Security Toolbox Probe
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=dstprobe
Group=dstprobe
ExecStart=${PY_BIN} ${PROBE_DIR}/probe.py --config ${CONFIG_DIR}/probe.toml
Restart=always
RestartSec=5
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${SPOOL_DIR} ${RULES_DIR} ${CACHE_DIR} ${CONFIG_DIR}
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable "${SERVICE}"
if [[ "${INSTALL_ONLY}" -eq 0 ]]; then
  systemctl restart "${SERVICE}"
fi
echo "installed ${SERVICE}"
