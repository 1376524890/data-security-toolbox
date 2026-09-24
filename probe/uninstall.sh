#!/usr/bin/env bash
#
# Remove the 数据安全监测检测工具箱 probe (data-security-toolbox-probe) from this host.
#
# Everything deleted here comes from the fixed allow-list below, which mirrors
# install.sh. Paths are never taken from command-line arguments or from a file
# on disk: an uninstaller that removes whatever a mutable file names is a
# privilege-escalation primitive, and this one runs as root. The markers that
# install.sh drops in APP_DIR are only used to decide whether an *optional*
# artifact (a bundled capture tool, the dstprobe account) was created by us.

set -euo pipefail

APP_DIR="/opt/data-security-toolbox"
PROBE_DIR="${APP_DIR}/probe"
SHARED_DIR="${APP_DIR}/shared"
VENV_DIR="${APP_DIR}/venv"
CONFIG_DIR="/etc/data-security-toolbox"
DATA_DIR="/var/lib/data-security-toolbox"
SPOOL_DIR="${DATA_DIR}/spool"
RULES_DIR="${DATA_DIR}/rules"
CACHE_DIR="${DATA_DIR}/cache"
SERVICE="data-security-toolbox-probe"
UNIT_FILE="/etc/systemd/system/${SERVICE}.service"
PROBE_USER="dstprobe"
CAPTURE_MARKER="${APP_DIR}/.installed-capture-tool"
USER_MARKER="${APP_DIR}/.created-user"

KEEP_DATA=0
KEEP_USER=0
FORCE_USER=0
DRY_RUN=0

usage() {
  cat <<'EOF'
usage: uninstall.sh [--keep-data] [--keep-user] [--remove-user] [--dry-run]

  --keep-data    keep captured segments, rule cache and spool state
                 (/var/lib/data-security-toolbox)
  --keep-user    keep the dstprobe system account
  --remove-user  delete the dstprobe account even when it was not created by
                 this probe (the default keeps an account it cannot prove it made)
  --dry-run      report what would be removed without changing anything
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keep-data) KEEP_DATA=1; shift ;;
    --keep-user) KEEP_USER=1; shift ;;
    --remove-user) FORCE_USER=1; shift ;;
    --dry-run)   DRY_RUN=1; shift ;;
    -h|--help)   usage; exit 0 ;;
    *) echo "unknown option: $1" >&2; exit 1 ;;
  esac
done

if [[ "${EUID}" -ne 0 ]]; then
  echo "run as root" >&2
  exit 1
fi

REMOVED=()
ABSENT=()
KEPT=()
FAILED=()
BYTES_FREED=0
FILES_FREED=0

log() { printf 'probe uninstall: %s\n' "$*"; }

# Read the installer's markers once, before anything is deleted.
#
# Both markers live inside APP_DIR, which this script removes, so a check made
# after that deletion reads a file that is already gone and silently takes the
# safe-but-wrong branch: the account was never deleted even on the hosts where
# the probe had created it. Snapshot the decisions here, act on them at the end.
CREATED_USER=0
if [[ -f "${USER_MARKER}" ]]; then
  CREATED_USER=1
fi
CAPTURE_TOOL_PATH=""
CAPTURE_TOOL_MARKER_INVALID=""
if [[ -f "${CAPTURE_MARKER}" ]]; then
  recorded_capture=$(head -n 1 "${CAPTURE_MARKER}" | tr -d '[:space:]')
  case "${recorded_capture}" in
    /usr/local/bin/dumpcap|/usr/local/bin/tcpdump) CAPTURE_TOOL_PATH="${recorded_capture}" ;;
    *) CAPTURE_TOOL_MARKER_INVALID="${recorded_capture}" ;;
  esac
fi

# Safety net for a root-owned rm -rf: absolute, never "/", never top-level.
assert_safe_path() {
  local path="$1" depth
  if [[ "${path}" != /* || "${path}" == "/" || "${#path}" -lt 12 ]]; then
    log "refusing to remove unsafe path: ${path}" >&2
    return 1
  fi
  depth=$(awk -F/ '{print NF-1}' <<<"${path}")
  if [[ "${depth}" -lt 2 ]]; then
    log "refusing to remove top-level path: ${path}" >&2
    return 1
  fi
  return 0
}

path_bytes() { du -sb -- "$1" 2>/dev/null | awk '{print $1}' || echo 0; }

path_files() { find -- "$1" -xdev 2>/dev/null | wc -l || echo 0; }

# Remove one allow-listed path and record the outcome. A path that is already
# gone counts as success so the uninstaller stays idempotent.
remove_path() {
  local path="$1" label="$2" bytes files
  if ! assert_safe_path "${path}"; then
    FAILED+=("${label}")
    return 0
  fi
  if [[ -L "${path}" ]]; then
    # Drop the link itself and never follow it into another tree.
    if [[ "${DRY_RUN}" -eq 1 ]]; then
      log "would remove symlink ${path}"
    else
      rm -f -- "${path}"
      log "removed symlink ${path}"
    fi
    REMOVED+=("${label}")
    return 0
  fi
  if [[ ! -e "${path}" ]]; then
    ABSENT+=("${label}")
    return 0
  fi
  bytes=$(path_bytes "${path}")
  files=$(path_files "${path}")
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log "would remove ${path} (${files} files, ${bytes} bytes)"
    REMOVED+=("${label}")
    return 0
  fi
  if rm -rf -- "${path}" && [[ ! -e "${path}" ]]; then
    BYTES_FREED=$((BYTES_FREED + bytes))
    FILES_FREED=$((FILES_FREED + files))
    log "removed ${path} (${files} files, ${bytes} bytes)"
    REMOVED+=("${label}")
  else
    log "FAILED to remove ${path}" >&2
    FAILED+=("${label}")
  fi
}

stop_service() {
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log "would stop and disable ${SERVICE}"
    return 0
  fi
  if command -v systemctl >/dev/null 2>&1; then
    systemctl stop "${SERVICE}" >/dev/null 2>&1 || true
    systemctl disable "${SERVICE}" >/dev/null 2>&1 || true
    systemctl reset-failed "${SERVICE}" >/dev/null 2>&1 || true
  fi
  # A probe that is still alive keeps rewriting spool state underneath the
  # removals below, so terminate anything still running from the probe tree.
  if command -v pgrep >/dev/null 2>&1 && pgrep -f "${PROBE_DIR}/probe.py" >/dev/null 2>&1; then
    pkill -f "${PROBE_DIR}/probe.py" >/dev/null 2>&1 || true
    sleep 1
    pkill -9 -f "${PROBE_DIR}/probe.py" >/dev/null 2>&1 || true
  fi
  log "stopped and disabled ${SERVICE}"
}

remove_unit() {
  if [[ ! -f "${UNIT_FILE}" ]]; then
    ABSENT+=("systemd-unit")
    return 0
  fi
  remove_path "${UNIT_FILE}" "systemd-unit"
  if [[ "${DRY_RUN}" -eq 0 ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
  fi
}

# A bundled capture tool was copied into /usr/local/bin by install.sh and must
# not outlive the probe. The marker is only a hint: a value outside
# /usr/local/bin is reported instead of trusted and deleted.
remove_bundled_capture_tool() {
  if [[ -z "${CAPTURE_TOOL_PATH}" && -z "${CAPTURE_TOOL_MARKER_INVALID}" ]]; then
    ABSENT+=("bundled-capture-tool")
    return 0
  fi
  if [[ -n "${CAPTURE_TOOL_MARKER_INVALID}" ]]; then
    log "ignoring unexpected capture tool marker: ${CAPTURE_TOOL_MARKER_INVALID}" >&2
    FAILED+=("bundled-capture-tool")
    return 0
  fi
  remove_path "${CAPTURE_TOOL_PATH}" "bundled-capture-tool"
}

remove_probe_user() {
  if [[ "${KEEP_USER}" -eq 1 ]]; then
    KEPT+=("user:${PROBE_USER}")
    return 0
  fi
  if ! id -u "${PROBE_USER}" >/dev/null 2>&1; then
    ABSENT+=("user:${PROBE_USER}")
    return 0
  fi
  if [[ "${FORCE_USER}" -ne 1 && "${CREATED_USER}" -eq 1 ]]; then
    log "account ${PROBE_USER} was created by this probe"
  elif [[ "${FORCE_USER}" -ne 1 ]]; then
    log "account ${PROBE_USER} predates the probe; keeping it (use --remove-user to force)" >&2
    KEPT+=("user:${PROBE_USER}")
    return 0
  fi
  if command -v pgrep >/dev/null 2>&1 && pgrep -u "${PROBE_USER}" >/dev/null 2>&1; then
    log "account ${PROBE_USER} still owns running processes; keeping it" >&2
    FAILED+=("user:${PROBE_USER}")
    return 0
  fi
  if [[ "${DRY_RUN}" -eq 1 ]]; then
    log "would remove account ${PROBE_USER}"
    REMOVED+=("user:${PROBE_USER}")
    return 0
  fi
  if userdel "${PROBE_USER}" >/dev/null 2>&1 && ! id -u "${PROBE_USER}" >/dev/null 2>&1; then
    log "removed account ${PROBE_USER}"
    REMOVED+=("user:${PROBE_USER}")
  else
    log "FAILED to remove account ${PROBE_USER}" >&2
    FAILED+=("user:${PROBE_USER}")
  fi
}

# ---------------------------------------------------------------------------
# Main flow
# ---------------------------------------------------------------------------
log "uninstalling ${SERVICE} from $(hostname)"

stop_service
remove_unit

if [[ "${KEEP_DATA}" -eq 1 ]]; then
  KEPT+=("data-dir")
  log "keeping ${DATA_DIR} (--keep-data)"
else
  # Spool first: captured segments are the probe's production data and the
  # largest thing on disk, so report them separately from the tree root.
  remove_path "${SPOOL_DIR}" "spool"
  remove_path "${RULES_DIR}" "rules"
  remove_path "${CACHE_DIR}" "cache"
  remove_path "${DATA_DIR}" "data-dir"
fi

remove_bundled_capture_tool
remove_path "${VENV_DIR}" "venv"
remove_path "${PROBE_DIR}" "probe-dir"
remove_path "${SHARED_DIR}" "shared-dir"
remove_path "${CONFIG_DIR}" "config-dir"
remove_path "${APP_DIR}" "app-dir"
remove_probe_user

# Machine-readable summary. The platform parses the single DST_UNINSTALL line to
# tell a clean removal from a partial one; the human-readable log stays above it.
json_array() {
  local out="[" first=1 item
  for item in "$@"; do
    [[ -n "${item}" ]] || continue
    if [[ "${first}" -eq 0 ]]; then out+=","; fi
    out+="\"${item//\"/\\\"}\""
    first=0
  done
  printf '%s]' "${out}"
}

ok=true
if [[ "${#FAILED[@]}" -gt 0 ]]; then ok=false; fi

printf 'DST_UNINSTALL {"ok":%s,"dry_run":%s,"removed":%s,"absent":%s,"kept":%s,"failed":%s,"bytes_freed":%s,"files_freed":%s}\n' \
  "${ok}" "${DRY_RUN}" \
  "$(json_array ${REMOVED[@]+"${REMOVED[@]}"})" \
  "$(json_array ${ABSENT[@]+"${ABSENT[@]}"})" \
  "$(json_array ${KEPT[@]+"${KEPT[@]}"})" \
  "$(json_array ${FAILED[@]+"${FAILED[@]}"})" \
  "${BYTES_FREED}" "${FILES_FREED}"

if [[ "${ok}" == true ]]; then
  log "uninstall complete"
  exit 0
fi
log "uninstall finished with errors" >&2
exit 2
