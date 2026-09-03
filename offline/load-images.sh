#!/usr/bin/env bash
set -euo pipefail

ARCHIVE_DIR="${1:-./dist-offline/images}"
if [[ ! -d "${ARCHIVE_DIR}" ]]; then
  echo "image archive not found: ${ARCHIVE_DIR}" >&2
  exit 1
fi

for archive in "${ARCHIVE_DIR}"/*.tar; do
  [[ -f "${archive}" ]] || continue
  echo "loading ${archive}"
  docker load -i "${archive}"
done

echo "offline images loaded"
