ARG BASE_IMAGE
FROM ${BASE_IMAGE}
# Only the deployment preflight changes in this platform patch.
COPY backend/app/deployment/preflight.py backend/app/deployment/runtime.py /app/app/deployment/
ENV PROBE_AGENT_VERSION=3.7.0
