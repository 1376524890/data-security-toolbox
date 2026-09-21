#!/usr/bin/env bash
# Apply to the existing v2.14.0 offline deployment directory, never a new Compose project.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
[[ $# -eq 1 ]] || { echo "usage: sudo bash $0 /path/to/existing/platform" >&2; exit 2; }
TARGET="$(cd "$1" && pwd)"
for file in docker-compose.yml docker-compose.offline.yml .env; do
  [[ -f "${TARGET}/${file}" ]] || { echo "missing ${TARGET}/${file}" >&2; exit 1; }
done
cd "${ROOT}"
sha256sum -c CHECKSUMS.sha256
cd "${TARGET}"
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.offline.yml)
[[ -n "$("${COMPOSE[@]}" ps -q backend)" ]] || {
  echo "No existing backend found; use the original directory and COMPOSE_PROJECT_NAME." >&2; exit 1;
}
STAMP="$(date +%Y%m%d-%H%M%S)"
cp -p .env ".env.before-probe-3.7.0-${STAMP}"
cp -p docker-compose.offline.yml "docker-compose.offline.yml.before-probe-3.7.0-${STAMP}"
docker load -i "${ROOT}/platform-images.tar"
mkdir -p probe_packages/probe-3.7.0
cp -a "${ROOT}/probe_packages/probe-3.7.0/." probe_packages/probe-3.7.0/
# Patch only application image tags; keep original ports, volumes and project configuration.
for service in backend worker beat deployment-worker; do
  sed -i "s|dst-toolbox/${service}:2\.14\.0\(-probe3\.7\.0\)\?\([[:space:]]\|$\)|dst-toolbox/${service}:2.14.0-probe3.7.0\2|g" docker-compose.offline.yml
  grep -q "dst-toolbox/${service}:2.14.0-probe3.7.0" docker-compose.offline.yml || {
    echo "Unexpected image for ${service}; restore the saved Compose file and inspect it." >&2; exit 1;
  }
done
if grep -q '^PROBE_AGENT_VERSION=' .env; then
  sed -i 's/^PROBE_AGENT_VERSION=.*/PROBE_AGENT_VERSION=3.7.0/' .env
else
  printf '\nPROBE_AGENT_VERSION=3.7.0\n' >> .env
fi
"${COMPOSE[@]}" config -q
"${COMPOSE[@]}" up -d --no-build --no-deps --force-recreate backend worker beat deployment-worker
"${COMPOSE[@]}" exec -T backend python -c \
  'from app.deployment.package import find_package; from app.deployment.runtime import check_runtime; from app.core.config import settings; assert settings.probe_agent_version == "3.7.0"; print([(a, find_package(a)["manifest"]["runtime"]["self_contained"]) for a in ("amd64", "arm64")])'
echo 'Platform updated. Existing probes were not changed; create a deployment from the console.'
echo "Rollback configuration backups: *before-probe-3.7.0-${STAMP} (old image tags retained)."
