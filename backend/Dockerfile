FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    libpcap0.8 libxml2-dev libxslt1-dev libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf-2.0-0 fonts-noto-cjk tshark && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt requirements-optional.txt ./
RUN pip install --no-cache-dir --timeout 120 --retries 5 -r requirements.txt -r requirements-optional.txt
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini .
COPY scripts ./scripts
RUN useradd -m -u 10001 appuser && mkdir -p /app/data/storage /app/data/reports /app/data/integrations /app/data/offline && chown -R appuser:appuser /app

FROM base AS api
USER appuser
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

FROM zeek/zeek:latest AS zeek-runtime

FROM base AS analysis-worker
USER root
COPY --from=zeek-runtime /usr/local/zeek /usr/local/zeek
# Zeek is built on Debian 13 (trixie) against Node 20; copy its shared library
# tree (libnode, libuv, ICU, ...) so the binary can run on the same distro base.
COPY --from=zeek-runtime /usr/lib/aarch64-linux-gnu/ /usr/lib/aarch64-linux-gnu/
ENV PATH="/usr/local/zeek/bin:${PATH}"
RUN apt-get update && \
    apt-get install -y --no-install-recommends tshark suricata nmap ffmpeg && \
    rm -rf /var/lib/apt/lists/*
USER appuser
CMD ["celery", "-A", "app.workers.celery_app.celery_app", "worker", "--loglevel=info", "--concurrency=2"]
