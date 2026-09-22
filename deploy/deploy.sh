#!/usr/bin/env bash
#
# 数据安全工具箱 —— 一键部署（离线 / arm64）
#
#   ./deploy.sh                   按 deploy.conf 一键跑完：载入镜像 → 生成 .env → 起容器 → 等健康
#   ./deploy.sh --dry-run         只看会写入的 .env 与将执行的命令
#   ./deploy.sh --force           .env 里的 auto 口令全部重新生成
#   ./deploy.sh --http-port 8443 --api-port 8001
#   ./deploy.sh --config /etc/dst.conf
#
# 参数全部在 deploy.conf（唯一配置入口）；命令行覆盖 > deploy.conf > 内置默认值。
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

CONF="$ROOT/deploy.conf"
FORCE=0 DRY_RUN=0 LOAD=1
WANT_INTERACTIVE=0 WANT_NONINTERACTIVE=0
OVR_PROJECT="" OVR_DATA_ROOT="" OVR_HTTP_PORT="" OVR_API_PORT="" OVR_BACKEND_URL="" OVR_ADMIN_PASSWORD=""

die()  { echo "错误：$*" >&2; exit 1; }
note() { echo "==> $*"; }

usage() {
  sed -n '3,12p' "$0" | sed 's/^# \{0,1\}//'
  cat <<'TXT'

可用参数：
  --config FILE          配置文件（默认 ./deploy.conf）
  --project NAME         compose 项目名
  --data-root DIR        数据目录
  --http-port N          控制台端口
  --api-port N           API / 探针端口
  --backend-url URL      探针回连地址（如 http://192.168.1.20:8000）
  --admin-password PW    直接指定管理员口令
  --no-load              跳过 docker load（镜像已在本地时）
  --force                重新生成 .env 里的 auto 口令
  --interactive          强制交互式配置（即使 stdin 不是终端）
  --non-interactive      不提问，全用 deploy.conf 与内置默认
  --dry-run              只打印不执行（配 --interactive 可先交互看一遍会写入什么）
  -h, --help             本帮助
TXT
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --config)         CONF="${2:-}"; shift 2 ;;
    --project)        OVR_PROJECT="${2:-}"; shift 2 ;;
    --data-root)      OVR_DATA_ROOT="${2:-}"; shift 2 ;;
    --http-port)      OVR_HTTP_PORT="${2:-}"; shift 2 ;;
    --api-port)       OVR_API_PORT="${2:-}"; shift 2 ;;
    --backend-url)    OVR_BACKEND_URL="${2:-}"; shift 2 ;;
    --admin-password) OVR_ADMIN_PASSWORD="${2:-}"; shift 2 ;;
    --no-load)        LOAD=0; shift ;;
    --force)          FORCE=1; shift ;;
    --interactive|-i) WANT_INTERACTIVE=1; shift ;;
    --non-interactive|--yes|-y) WANT_NONINTERACTIVE=1; shift ;;
    --dry-run)        DRY_RUN=1; shift ;;
    -h|--help)        usage; exit 0 ;;
    *) die "未知参数 $1（--help 查看可用项）" ;;
  esac
done

[[ -f "$CONF" ]] || die "找不到配置文件 $CONF"
# shellcheck disable=SC1090
set -a; . "$CONF"; set +a

# 命令行覆盖
[[ -n "$OVR_PROJECT" ]]        && PROJECT="$OVR_PROJECT"
[[ -n "$OVR_DATA_ROOT" ]]      && DATA_ROOT="$OVR_DATA_ROOT"
[[ -n "$OVR_HTTP_PORT" ]]      && HTTP_PORT="$OVR_HTTP_PORT"
[[ -n "$OVR_API_PORT" ]]       && API_PORT="$OVR_API_PORT"
[[ -n "$OVR_BACKEND_URL" ]]    && DEPLOYMENT_BACKEND_URL="$OVR_BACKEND_URL"
[[ -n "$OVR_ADMIN_PASSWORD" ]] && ADMIN_PASSWORD="$OVR_ADMIN_PASSWORD"

PROJECT="${PROJECT:-source}"
DATA_ROOT="${DATA_ROOT:-./deploy-data}"
HTTP_PORT="${HTTP_PORT:-8080}"
API_PORT="${API_PORT:-8000}"
PULL_POLICY="${PULL_POLICY:-never}"

# --------------------------------------------------------------- 环境自检
command -v docker >/dev/null 2>&1 || die "未找到 docker（需要 Docker Engine 20.10+）"
docker info >/dev/null 2>&1 || die "docker 守护进程不可用（没有权限？试试 sudo，或加入 docker 组）"
docker compose version >/dev/null 2>&1 || die "需要 docker compose v2（v1 不能解析本 compose 文件）"
ARCH="$(uname -m)"
case "$ARCH" in
  aarch64|arm64) : ;;
  *) die "本包镜像是 arm64，当前主机是 $ARCH（x86_64 请用 amd64 包，不要用 QEMU 跑生产）" ;;
esac

host_ip() {  # 本机对外 IP：给探针的默认回连地址，也是交互提示里的默认值
  local ip=""
  command -v hostname >/dev/null 2>&1 && ip="$(hostname -I 2>/dev/null | awk '{print $1}')"
  [[ -z "$ip" ]] && command -v ip >/dev/null 2>&1 && \
    ip="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}')"
  printf '%s' "${ip:-127.0.0.1}"
}

# --------------------------------------------------------------- 交互式配置
# 必要参数由操作者现场录入（回车 = 采用方括号里的默认值，口令留空 = 自动生成）。
# 非口令项在部署前写回 deploy.conf，否则重跑 deploy.sh 会把它们退回文件里的旧值；
# 口令与密钥只留在 .env（chmod 600），不进 deploy.conf 这种会进版本库的文件。
if [[ "$WANT_NONINTERACTIVE" -eq 1 ]]; then
  INTERACTIVE=0
elif [[ "$WANT_INTERACTIVE" -eq 1 || -t 0 ]]; then
  INTERACTIVE=1
else
  INTERACTIVE=0
fi

prompt_val() {  # prompt_val VAR 标签 默认值
  local name="$1" label="$2" shown="$3" ans=""
  printf '  %-24s [%s] > ' "$label" "$shown"
  IFS= read -r ans || ans=""
  [[ -z "$ans" ]] && return 0
  printf -v "$name" '%s' "$ans"
}
prompt_secret() {  # prompt_secret VAR 标签 —— 留空 = 自动生成 / 沿用 .env
  local name="$1" label="$2" ans=""
  printf '  %-24s （留空 = 自动生成）> ' "$label"
  IFS= read -rs ans || ans=""
  printf '\n'
  [[ -z "$ans" ]] && return 0
  printf -v "$name" '%s' "$ans"
}
conf_set() {  # conf_set KEY VALUE —— 只改 deploy.conf 里的赋值行（没有就追加）
  local key="$1" val="$2" tmp="$CONF.tmp.$$"
  if [[ ! -w "$CONF" ]]; then
    note "deploy.conf 不可写，跳过写回 $key"
    return 0
  fi
  # 保留行尾注释：deploy.conf 每行都是 `KEY=值  # 中文说明`，值里不会出现 " #"。
  if awk -v k="$key" -v v="$val" \
      'BEGIN{h=0} $0 ~ "^" k "=" {cmt=""; if (match($0, /[ \t]#/)) cmt=substr($0, RSTART); print k "=" v cmt; h=1; next}
       {print} END{if(!h) print k "=" v}' \
      "$CONF" > "$tmp"; then
    mv "$tmp" "$CONF"
  else
    rm -f "$tmp"
    note "写回 $key 失败（deploy.conf 未改动）"
  fi
}

if [[ "$INTERACTIVE" -eq 1 ]]; then
  echo
  echo "==> 交互式配置（全部参数都在 deploy.conf，这里只问现场必须定下来的几项）"
  prompt_val PROJECT "compose 项目名" "$PROJECT"
  prompt_val DATA_ROOT "数据目录" "$DATA_ROOT"
  prompt_val HTTP_PORT "控制台端口" "$HTTP_PORT"
  prompt_val API_PORT "API/探针端口" "$API_PORT"
  if [[ -z "${DEPLOYMENT_BACKEND_URL:-}" || "${DEPLOYMENT_BACKEND_URL}" == auto ]]; then
    default_backend="http://$(host_ip):${API_PORT}"
  else
    default_backend="$DEPLOYMENT_BACKEND_URL"
  fi
  prompt_val DEPLOYMENT_BACKEND_URL "探针回连地址" "$default_backend"
  prompt_val ADMIN_USERNAME "管理员账号" "${ADMIN_USERNAME:-admin}"
  prompt_val POSTGRES_DB "数据库名" "${POSTGRES_DB:-security_toolbox}"
  prompt_val POSTGRES_USER "数据库用户" "${POSTGRES_USER:-security}"
  echo "  口令与密钥（留空自动生成；重跑会沿用 .env 里已有的值）"
  prompt_secret ADMIN_PASSWORD "管理员口令"
  prompt_secret POSTGRES_PASSWORD "数据库口令"
  prompt_secret SECRET_KEY "平台密钥 SECRET_KEY"
  prompt_secret PROBE_BOOTSTRAP_TOKEN "探针注册令牌"
  prompt_secret DEPLOYMENT_SECRET_KEY "下发密钥（生成后不可更换）"
  printf '  配置可选集成（通知 / 威胁情报 / 主机审计）？[y/N] > '
  read -r ans || ans=""
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    prompt_val WEBHOOK_URL "告警 webhook 地址" "${WEBHOOK_URL:-}"
    prompt_secret WEBHOOK_SECRET "webhook 密钥"
    prompt_val SMTP_HOST "SMTP 主机" "${SMTP_HOST:-}"
    prompt_val SMTP_PORT "SMTP 端口" "${SMTP_PORT:-587}"
    prompt_val SMTP_USER "SMTP 用户" "${SMTP_USER:-}"
    prompt_secret SMTP_PASSWORD "SMTP 口令"
    prompt_val SMTP_FROM "邮件发件人" "${SMTP_FROM:-}"
    prompt_val SMTP_TO "邮件收件人" "${SMTP_TO:-}"
    prompt_val URLHAUS_AUTH_KEY "URLhaus key" "${URLHAUS_AUTH_KEY:-}"
    prompt_val CUSTOM_INTEL_URL "自定义情报源 URL" "${CUSTOM_INTEL_URL:-}"
    prompt_secret CUSTOM_INTEL_TOKEN "自定义情报源令牌"
    prompt_val MISP_URL "MISP URL" "${MISP_URL:-}"
    prompt_secret MISP_API_KEY "MISP API Key"
    prompt_val WAZUH_URL "Wazuh URL" "${WAZUH_URL:-}"
    prompt_val WAZUH_USER "Wazuh 用户" "${WAZUH_USER:-}"
    prompt_secret WAZUH_PASSWORD "Wazuh 口令"
    prompt_val OSQUERY_SOCKET "osquery socket" "${OSQUERY_SOCKET:-}"
  fi
  echo
  printf '  项目名 %s ／ 数据目录 %s\n' "$PROJECT" "$DATA_ROOT"
  printf '  控制台 http://%s:%s ／ API http://%s:%s\n' \
    "$(host_ip)" "$HTTP_PORT" "$(host_ip)" "$API_PORT"
  # 只说明口令从哪来，不把口令本身打进终端（会被 scrollback 和日志记下来）。
  case "${ADMIN_PASSWORD:-auto}" in
    ""|auto|AUTO|changeme) pw_state="自动生成（部署结束打印）" ;;
    *)                     pw_state="按你刚才输入的值" ;;
  esac
  printf '  管理员 %s ／ 口令 %s\n' "${ADMIN_USERNAME:-admin}" "$pw_state"
  printf '  探针回连 %s\n' "$DEPLOYMENT_BACKEND_URL"
  printf '  按以上参数部署？[Y/n] > '
  read -r ans || ans=""
  [[ "$ans" =~ ^[Nn]$ ]] && die "已取消，未改动任何文件"
  for key in PROJECT DATA_ROOT HTTP_PORT API_PORT DEPLOYMENT_BACKEND_URL ADMIN_USERNAME \
             POSTGRES_DB POSTGRES_USER WEBHOOK_URL SMTP_HOST SMTP_PORT SMTP_USER SMTP_FROM SMTP_TO \
             URLHAUS_AUTH_KEY CUSTOM_INTEL_URL MISP_URL WAZUH_URL WAZUH_USER OSQUERY_SOCKET; do
    new="$(eval "printf '%s' \"\${$key:-}\"")"
    old="$(grep -m1 "^$key=" "$CONF" || true)"
    old="${old#*=}"
    old="${old%%#*}"                       # 去掉行尾注释
    old="${old%"${old##*[![:space:]]}"}"   # 去掉尾部空白
    if [[ -n "$new" && "$new" != "$old" ]]; then
      if [[ "$DRY_RUN" -eq 1 ]]; then
        note "将写回 deploy.conf：$key=$new"
      else
        conf_set "$key" "$new"
        note "deploy.conf 已更新：$key=$new"
      fi
    fi
  done
fi

# --------------------------------------------------------------- 取值解析
# 现有 .env 里的值（.env 是生成物，但 auto 项要沿用，避免每次部署换钥）
env_get() {
  [[ -f .env ]] || return 0
  local line
  line="$(grep -m1 "^$1=" .env || true)"
  printf '%s' "${line#*=}"
}
gen() {  # gen LEN  → 无空格随机串（口令类）
  head -c 512 /dev/urandom | LC_ALL=C tr -dc 'A-Za-z0-9' | head -c "$1"
}
gen_b64() {  # gen_b64 LEN → base64（DEPLOYMENT_SECRET_KEY 沿用既有格式）
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 "$1" | tr -d '\n'
  else
    head -c "$1" /dev/urandom | base64 | tr -d '\n'
  fi
}
resolve_auto() {  # resolve_auto NAME  LEN  MODE(hex|b64)
  local name="$1" len="$2" mode="${3:-hex}" cur existing
  cur="$(eval "printf '%s' \"\${$name:-}\"")"
  case "$cur" in
    ""|auto|AUTO|changeme|replace-*)
      if [[ "$FORCE" -eq 0 ]]; then
        existing="$(env_get "$name")"
        if [[ -n "$existing" ]]; then
          printf -v "$name" '%s' "$existing"; return 0
        fi
      fi
      if [[ "$mode" == b64 ]]; then printf -v "$name" '%s' "$(gen_b64 "$len")"
      else printf -v "$name" '%s' "$(gen "$len")"; fi
      ;;
  esac
}

resolve_auto POSTGRES_PASSWORD 32 hex
resolve_auto SECRET_KEY 48 hex
resolve_auto ADMIN_PASSWORD 20 hex
resolve_auto PROBE_BOOTSTRAP_TOKEN 40 hex
resolve_auto DEPLOYMENT_SECRET_KEY 32 b64
ADMIN_USERNAME="${ADMIN_USERNAME:-admin}"
POSTGRES_DB="${POSTGRES_DB:-security_toolbox}"
POSTGRES_USER="${POSTGRES_USER:-security}"

if [[ -z "${DEPLOYMENT_BACKEND_URL:-}" || "${DEPLOYMENT_BACKEND_URL}" == "auto" ]]; then
  DEPLOYMENT_BACKEND_URL="http://$(host_ip):${API_PORT}"
fi
if [[ -z "${DLP_SELF_ENDPOINTS:-}" || "${DLP_SELF_ENDPOINTS}" == "auto" ]]; then
  DLP_SELF_ENDPOINTS="${HTTP_PORT},${API_PORT},5432,6379,5555"
fi

# 其余参数的内置默认（deploy.conf 没写的用这些）
APP_ENV="${APP_ENV:-production}"
TEST_DATA_IMPORT_ENABLED="${TEST_DATA_IMPORT_ENABLED:-false}"
DEPLOYMENT_VERIFY_HOST_KEY="${DEPLOYMENT_VERIFY_HOST_KEY:-true}"
DLP_IGNORE_OWN_TRAFFIC="${DLP_IGNORE_OWN_TRAFFIC:-true}"
ALERT_SUPPRESS_WINDOW_SECONDS="${ALERT_SUPPRESS_WINDOW_SECONDS:-300}"
MAX_UPLOAD_MB="${MAX_UPLOAD_MB:-2048}"
PCAP_INDEX_LIMIT="${PCAP_INDEX_LIMIT:-10000}"
PCAP_RETENTION_DAYS="${PCAP_RETENTION_DAYS:-7}"
PCAP_STORAGE_MAX_GB="${PCAP_STORAGE_MAX_GB:-100}"
QUEUE_PENDING_MAX="${QUEUE_PENDING_MAX:-200}"
QUEUE_OLDEST_PENDING_SECONDS="${QUEUE_OLDEST_PENDING_SECONDS:-900}"
PROBE_AGENT_VERSION="${PROBE_AGENT_VERSION:-3.7.0}"
BACKEND_IMAGE="${BACKEND_IMAGE:-source-backend:latest}"
WORKER_IMAGE="${WORKER_IMAGE:-source-worker:latest}"
FRONTEND_IMAGE="${FRONTEND_IMAGE:-source-frontend:latest}"

render_env() {
  cat <<ENV
# 本文件由 deploy.sh 从 deploy.conf 生成 —— 改参数请改 deploy.conf，不要手改这里。
APP_ENV=${APP_ENV}
TEST_DATA_IMPORT_ENABLED=${TEST_DATA_IMPORT_ENABLED}
POSTGRES_DB=${POSTGRES_DB}
POSTGRES_USER=${POSTGRES_USER}
POSTGRES_PASSWORD=${POSTGRES_PASSWORD}
SECRET_KEY=${SECRET_KEY}
ADMIN_USERNAME=${ADMIN_USERNAME}
ADMIN_PASSWORD=${ADMIN_PASSWORD}
PROBE_BOOTSTRAP_TOKEN=${PROBE_BOOTSTRAP_TOKEN}
HTTP_PORT=${HTTP_PORT}
API_PORT=${API_PORT}
DEPLOYMENT_SECRET_KEY=${DEPLOYMENT_SECRET_KEY}
DEPLOYMENT_BACKEND_URL=${DEPLOYMENT_BACKEND_URL}
DEPLOYMENT_CA_FILE=${DEPLOYMENT_CA_FILE:-}
DEPLOYMENT_KNOWN_HOSTS=${DEPLOYMENT_KNOWN_HOSTS:-}
DEPLOYMENT_VERIFY_HOST_KEY=${DEPLOYMENT_VERIFY_HOST_KEY}
PROBE_AGENT_VERSION=${PROBE_AGENT_VERSION}
PCAP_INDEX_LIMIT=${PCAP_INDEX_LIMIT}
PCAP_RETENTION_DAYS=${PCAP_RETENTION_DAYS}
PCAP_STORAGE_MAX_GB=${PCAP_STORAGE_MAX_GB}
QUEUE_PENDING_MAX=${QUEUE_PENDING_MAX}
QUEUE_OLDEST_PENDING_SECONDS=${QUEUE_OLDEST_PENDING_SECONDS}
ALERT_SUPPRESS_WINDOW_SECONDS=${ALERT_SUPPRESS_WINDOW_SECONDS}
MAX_UPLOAD_MB=${MAX_UPLOAD_MB}
NUCLEI_BIN=${NUCLEI_BIN:-nuclei}
NUCLEI_TEMPLATES_DIR=${NUCLEI_TEMPLATES_DIR:-/app/data/nuclei-templates}
WEBHOOK_URL=${WEBHOOK_URL:-}
WEBHOOK_SECRET=${WEBHOOK_SECRET:-}
SMTP_HOST=${SMTP_HOST:-}
SMTP_PORT=${SMTP_PORT:-587}
SMTP_USER=${SMTP_USER:-}
SMTP_PASSWORD=${SMTP_PASSWORD:-}
SMTP_FROM=${SMTP_FROM:-}
SMTP_TO=${SMTP_TO:-}
URLHAUS_AUTH_KEY=${URLHAUS_AUTH_KEY:-}
CUSTOM_INTEL_URL=${CUSTOM_INTEL_URL:-}
CUSTOM_INTEL_TOKEN=${CUSTOM_INTEL_TOKEN:-}
MISP_URL=${MISP_URL:-}
MISP_API_KEY=${MISP_API_KEY:-}
WAZUH_URL=${WAZUH_URL:-}
WAZUH_USER=${WAZUH_USER:-}
WAZUH_PASSWORD=${WAZUH_PASSWORD:-}
WAZUH_VERIFY_TLS=${WAZUH_VERIFY_TLS:-true}
WAZUH_POLL_SECONDS=${WAZUH_POLL_SECONDS:-60}
WAZUH_ALERT_LIMIT=${WAZUH_ALERT_LIMIT:-200}
OSQUERY_SOCKET=${OSQUERY_SOCKET:-}
DLP_IGNORE_OWN_TRAFFIC=${DLP_IGNORE_OWN_TRAFFIC}
DLP_SELF_ENDPOINTS=${DLP_SELF_ENDPOINTS}
DATA_ROOT=${DATA_ROOT}
PULL_POLICY=${PULL_POLICY}
BACKEND_IMAGE=${BACKEND_IMAGE}
WORKER_IMAGE=${WORKER_IMAGE}
FRONTEND_IMAGE=${FRONTEND_IMAGE}
ENV
}

write_env() {
  render_env > "$ROOT/.env"
  chmod 600 "$ROOT/.env"
}

if [[ "$DRY_RUN" -eq 1 ]]; then
  note "配置来源：$CONF"
  note "已解析参数（--dry-run：不写盘、不载入镜像、不起容器）"
  printf '    控制台   http://%s:%s\n    API      http://%s:%s/api/v1/health\n' \
    "$(host_ip)" "$HTTP_PORT" "$(host_ip)" "$API_PORT"
  printf '    管理员   %s / %s\n' "$ADMIN_USERNAME" "$ADMIN_PASSWORD"
  printf '    探针回连 %s\n    数据目录 %s\n    项目名   %s\n' \
    "$DEPLOYMENT_BACKEND_URL" "$DATA_ROOT" "$PROJECT"
  echo
  echo "----- 将写入 .env 的内容（.env 是生成物）-----"
  render_env
  echo "----------------------------------------------"
  exit 0
fi

# --------------------------------------------------------------- 载入镜像
IMAGES_TAR="${IMAGES_TAR:-$ROOT/dist-offline/security-toolbox-images.tar}"
if [[ "$LOAD" -eq 1 ]]; then
  [[ -f "$IMAGES_TAR" ]] || die "缺少镜像包 $IMAGES_TAR（或加 --no-load 跳过载入）"
  note "载入镜像（约 3 GB，首次需要几分钟）：$(basename "$IMAGES_TAR")"
  docker load -i "$IMAGES_TAR"
else
  note "跳过 docker load（--no-load）"
fi

# --------------------------------------------------------------- 生成配置
note "写入 .env（来自 $CONF）"
write_env

DATA="${DATA_ROOT}"
mkdir -p "$DATA/backend" "$DATA/postgres" "$DATA/redis" .local/deployment

# backend / worker 以容器内 appuser(uid 10001) 运行，而 bind mount 目录是 docker 以 root 建的：
# 不授权给 10001，容器会因无法创建 /app/data/storage 反复重启（PermissionError）。
# 有 root 直接 chown；没有 root（只在 docker 组里）就用包内镜像跑一次 chown。
if [[ "$(id -u)" -eq 0 ]]; then
  # `id -u` 为 0 时上面那个短路表达式会直接进 `:`，chown 永远不执行，
  # 于是 sudo 部署（README 的主路径）必然卡在 PermissionError，必须显式分支。
  chown -R 10001:10001 "$DATA/backend"
elif ! chown -R 10001:10001 "$DATA/backend" 2>/dev/null; then
  note "用容器把 $DATA/backend 授权给容器用户 10001"
  docker run --rm -v "$(cd "$DATA/backend" && pwd):/data" --entrypoint chown \
    "${BASE_CHOWN_IMAGE:-redis:7.4-alpine}" -R 10001:10001 /data
fi

# --------------------------------------------------------------- 端口预检
# 只在"本项目还没有容器"时检查：重复执行不再因为自家容器占用端口而报错。
if [[ -z "$(docker ps -aq --filter "label=com.docker.compose.project=$PROJECT")" ]]; then
  for port in "$HTTP_PORT" "$API_PORT"; do
    if command -v ss >/dev/null 2>&1 && ss -ltn "sport = :$port" 2>/dev/null | tail -n +2 | grep -q .; then
      die "端口 $port 已被占用（ss -ltnp | grep :$port）。换端口：./deploy.sh --http-port 8443 --api-port 8001"
    fi
  done
fi

# --------------------------------------------------------------- 启动
note "启动服务（docker compose up -d --no-build --pull never）"
PULL_POLICY="$PULL_POLICY" docker compose -p "$PROJECT" -f docker-compose.yml \
  up -d --no-build --pull never

note "等待 backend 健康（最多 180 秒）"
status="missing"
for _ in $(seq 1 60); do
  cid="$(docker compose -p "$PROJECT" -f docker-compose.yml ps -q backend 2>/dev/null || true)"
  status="$(docker inspect -f '{{.State.Health.Status}}' "$cid" 2>/dev/null || echo missing)"
  [[ "$status" == healthy ]] && break
  sleep 3
done
if [[ "$status" != healthy ]]; then
  echo "警告：backend 未在 180 秒内进入 healthy。排查："
  echo "  docker compose -p $PROJECT -f docker-compose.yml logs --tail=200 backend"
fi

# --------------------------------------------------------------- 结束
echo
echo "================= 部署完成 ================="
printf '控制台      http://%s:%s        （/ 数据大屏 · /cockpit 综合驾驶舱）\n' "$(host_ip)" "$HTTP_PORT"
printf 'API/健康    http://%s:%s/api/v1/health\n' "$(host_ip)" "$API_PORT"
printf '管理员      %s / %s\n' "$ADMIN_USERNAME" "$ADMIN_PASSWORD"
printf '探针回连    %s\n' "$DEPLOYMENT_BACKEND_URL"
printf '数据目录    %s（容器重建不丢，备份这个目录即可）\n' "$DATA"
echo
echo "下一步自检："
echo "  docker compose -p $PROJECT -f docker-compose.yml ps"
echo "  curl -s http://127.0.0.1:$API_PORT/api/v1/health"
echo "  curl -s -o /dev/null -w '%{http_code}\\n' http://127.0.0.1:$HTTP_PORT/"
echo "停止（保留数据）：./undeploy.sh"
