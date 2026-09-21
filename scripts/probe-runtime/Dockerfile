FROM python:3.11-slim@sha256:9534e5a8e315485d4061ed659af0fd78a284c015f9b73661b41d6bab25604534

ENV PIP_DISABLE_PIP_VERSION_CHECK=1 PIP_NO_CACHE_DIR=1
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    tshark tcpdump && rm -rf /var/lib/apt/lists/*
COPY probe/requirements.txt /tmp/requirements.txt
RUN python -m pip install --only-binary=:all: -r /tmp/requirements.txt
COPY scripts/probe-runtime/collect.py /tmp/collect.py
RUN python /tmp/collect.py
