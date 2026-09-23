#!/usr/bin/env bash
set -euo pipefail

APP_DIR="/opt/data-security-toolbox"
PROBE_DIR="${APP_DIR}/probe"
SHARED_DIR="${APP_DIR}/shared"
RUNTIME_DIR="${APP_DIR}/runtime"
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
    --skip-deps) echo "self-contained packages cannot skip runtime validation" >&2; exit 2 ;;
    *) echo "unknown option: $1" >&2; exit 2 ;;
  esac
done

if [[ ${EUID} -ne 0 ]]; then
  echo "run as root" >&2
  exit 1

# The runtime is bundled; these are the only host tools the installer itself
# needs (tar to unpack it, systemd to run it, shadow/coreutils to set up the
# service account). Fail once, with the full list, instead of halfway through.
MISSING_TOOLS=()
for tool in tar systemctl useradd id chown find dirname mktemp; do
  command -v "${tool}" >/dev/null 2>&1 || MISSING_TOOLS+=("${tool}")
done
if [[ ${#MISSING_TOOLS[@]} -gt 0 ]]; then
  echo "error: target host is missing required tools: ${MISSING_TOOLS[*]}" >&2
  echo "       (the probe runtime and its dependencies are bundled; these host tools are not)" >&2
  exit 1
fi
fi

# Validate the complete runtime before replacing a running installation.
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
for path in "${APP_DIR}" "${PROBE_DIR}" "${SHARED_DIR}" "${RUNTIME_DIR}" "${CONFIG_DIR}"; do
  [[ ! -L "${path}" ]] || { echo "refusing symlink install path: ${path}" >&2; exit 1; }
done
[[ -f "${SCRIPT_DIR}/runtime.tar.gz" ]] || { echo "missing bundled runtime" >&2; exit 1; }
mkdir -p "${APP_DIR}"
RUNTIME_STAGE="$(mktemp -d "${APP_DIR}/.runtime-XXXXXXXX")"
trap 'rm -rf -- "${RUNTIME_STAGE}"' EXIT
tar -xzf "${SCRIPT_DIR}/runtime.tar.gz" -C "${RUNTIME_STAGE}"
"${RUNTIME_STAGE}/runtime/bin/python" -X utf8 -s "${SCRIPT_DIR}/runtime_check.py" --runtime "${RUNTIME_STAGE}/runtime"
# No pip/apt, host Python or old venv is consulted. Stop the old process before switching libraries.
if systemctl is-active --quiet "${SERVICE}"; then systemctl stop "${SERVICE}"; fi
rm -rf -- "${RUNTIME_DIR}"
mv "${RUNTIME_STAGE}/runtime" "${RUNTIME_DIR}"
chown -R root:root "${RUNTIME_DIR}"
cp "${SCRIPT_DIR}/run-probe.sh" "${APP_DIR}/run-probe.sh"
chmod 0755 "${APP_DIR}/run-probe.sh"

# `uninstall.sh` removes the dstprobe account and a bundled capture tool only
# when this installer is what created them, so record both decisions on disk.
CREATED_USER=0
if ! id dstprobe >/dev/null 2>&1; then
  useradd --system --no-create-home --shell /usr/sbin/nologin dstprobe
  CREATED_USER=1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "${APP_DIR}" "${PROBE_DIR}" "${SHARED_DIR}" "${CONFIG_DIR}" "${SPOOL_DIR}" "${RULES_DIR}" "${CACHE_DIR}"
if [[ "${CREATED_USER}" -eq 1 ]]; then
  : > "${APP_DIR}/.created-user"
fi
cp "${SCRIPT_DIR}/probe.py" "${SCRIPT_DIR}/scanner.py" "${SCRIPT_DIR}/data_assets.py" "${SCRIPT_DIR}/ruleset_client.py" "${SCRIPT_DIR}/requirements.txt" "${PROBE_DIR}/"
if [[ -f "${SCRIPT_DIR}/uninstall.sh" ]]; then
  cp "${SCRIPT_DIR}/uninstall.sh" "${APP_DIR}/uninstall.sh"
  chmod 0755 "${APP_DIR}/uninstall.sh"
fi

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

# Capture binaries and shared libraries live under RUNTIME_DIR, never /usr/local/bin.
# Legacy .installed-capture-tool markers remain for the unchanged uninstaller.

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
# BPF expression applied at capture time; empty captures everything. A push
# deployment fills this in with the platform's own address.
filter = ""
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
max_files = 0
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

cat > "/etc/systemd/system/${SERVICE}.service" <<EOF
[Unit]
Description=Data Security Toolbox Probe
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=dstprobe
Group=dstprobe
ExecStart=${APP_DIR}/run-probe.sh --config ${CONFIG_DIR}/probe.toml
Restart=always
RestartSec=5
# See run-probe.sh: pin UTF-8 so a C/POSIX host locale cannot break logging.
Environment=PYTHONUTF8=1 PYTHONIOENCODING=utf-8
# Read-only inventory access, including administrator-selected private directories.
AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN CAP_DAC_READ_SEARCH
CapabilityBoundingSet=CAP_NET_RAW CAP_NET_ADMIN CAP_DAC_READ_SEARCH
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
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
