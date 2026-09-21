#!/bin/sh
set -eu
test "$(dpkg --print-architecture)" = "$1"
export PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tshark tcpdump
python -m pip install --only-binary=:all: -r /tmp/requirements.txt
python /build/collect.py
