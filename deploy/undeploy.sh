#!/usr/bin/env bash
#
# 停止并移除容器（数据保留在 deploy-data/，重新 ./deploy.sh 即可恢复）。
#
#   ./undeploy.sh              # 按 deploy.conf 的 PROJECT 停栈
#   ./undeploy.sh --purge      # 连数据目录一起删掉（危险：库、报告、上报文件全没）
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"

PROJECT="${PROJECT:-source}"
DATA_ROOT="${DATA_ROOT:-./deploy-data}"
PURGE=0
CONF="$ROOT/deploy.conf"

for arg in "$@"; do
  case "$arg" in
    --purge) PURGE=1 ;;
    -h|--help) sed -n '3,7p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "未知参数 $arg" >&2; exit 1 ;;
  esac
done

if [[ -f "$CONF" ]]; then
  # 只取 PROJECT / DATA_ROOT，避免把口令注进环境
  PROJECT="$(grep -m1 '^PROJECT=' "$CONF" | cut -d= -f2-)"
  DATA_ROOT="$(grep -m1 '^DATA_ROOT=' "$CONF" | cut -d= -f2-)"
  PROJECT="${PROJECT:-source}"
  DATA_ROOT="${DATA_ROOT:-./deploy-data}"
fi

docker compose -p "$PROJECT" -f docker-compose.yml down --remove-orphans

if [[ "$PURGE" -eq 1 ]]; then
  echo "警告：--purge 会删除 $DATA_ROOT（数据库、报告、上报文件）。"
  read -r -p "确认请输入 yes：" answer
  [[ "$answer" == "yes" ]] || { echo "已取消。"; exit 0; }
  python3 - <<PY
import shutil, pathlib
p = pathlib.Path("$DATA_ROOT")
if p.exists():
    shutil.rmtree(p)
    print("已删除", p)
PY
else
  echo "容器已移除；数据目录 $DATA_ROOT 原样保留。"
fi
