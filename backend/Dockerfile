FROM python:3.11-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Debian 13 (trixie) renamed libpcap0.8 -> libpcap0.8t64, so use the new name.
# libpangoft2 / harfbuzz / fontconfig are runtime deps of WeasyPrint.
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
    libpcap0.8t64 libxml2-dev libxslt1-dev libcairo2 libpango-1.0-0 libpangocairo-1.0-0 \
    libpangoft2-1.0-0 libgdk-pixbuf-2.0-0 libharfbuzz0b libfontconfig1 fonts-noto-cjk tshark && \
    rm -rf /var/lib/apt/lists/*

# The build context is the repository root so the shared detection package
# (`shared/sensitive_detection`) ships in every image, exactly as the probe
# receives it. Sibling services import it through app/services/sensitive_engine.
WORKDIR /app
COPY backend/requirements.txt backend/requirements-optional.txt ./
RUN pip install --no-cache-dir --timeout 120 --retries 5 -r requirements.txt -r requirements-optional.txt
COPY backend/app ./app
COPY backend/alembic ./alembic
COPY backend/alembic.ini .
COPY backend/scripts ./scripts
COPY shared ./shared
RUN useradd -m -u 10001 appuser && mkdir -p /app/data/storage /app/data/reports /app/data/integrations /app/data/offline && chown -R appuser:appuser /app

# Zeek ships a self-contained install under /usr/local/zeek plus the system
# shared-libraries it links against (libnode, libuv, ICU, ...). The Zeek image is
# multi-arch (amd64 + arm64), so detect the Debian multiarch lib dir inside the
# Zeek stage and stage only the lib tree. We copy the libs into a dedicated path
# and point LD_LIBRARY_PATH at it instead of overwriting the base image's system
# libs, which keeps the base image stable across architecture.
FROM zeek/zeek:latest AS zeek-runtime
RUN case "$(dpkg --print-architecture)" in \
        amd64) d=x86_64-linux-gnu ;; \
        arm64) d=aarch64-linux-gnu ;; \
        *) echo "unsupported zeek architecture: $(dpkg --print-architecture)" >&2; exit 1 ;; \
    esac && \
    mkdir -p /opt/zeek-runtime-libs && \
    cp -a "/usr/lib/$d/." /opt/zeek-runtime-libs/

FROM base AS api
USER root
# Ship Zeek + Suricata in the API image so the engine health/status reported by
# the API container matches the analysis worker instead of showing "unavailable".
COPY --from=zeek-runtime /usr/local/zeek /usr/local/zeek
COPY --from=zeek-runtime /opt/zeek-runtime-libs /usr/local/zeek/lib/system
ENV PATH="/usr/local/zeek/bin:${PATH}" \
    LD_LIBRARY_PATH="/usr/local/zeek/lib/system:${LD_LIBRARY_PATH}"
RUN apt-get update && \
    apt-get install -y --no-install-recommends suricata nmap && \
    rm -rf /var/lib/apt/lists/*
USER appuser
EXPOSE 8000
CMD ["sh", "-c", "alembic upgrade head && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

FROM base AS analysis-worker
USER root
COPY --from=zeek-runtime /usr/local/zeek /usr/local/zeek
COPY --from=zeek-runtime /opt/zeek-runtime-libs /usr/local/zeek/lib/system
ENV PATH="/usr/local/zeek/bin:${PATH}" \
    LD_LIBRARY_PATH="/usr/local/zeek/lib/system:${LD_LIBRARY_PATH}"
RUN apt-get update && \
    apt-get install -y --no-install-recommends tshark suricata nmap ffmpeg curl unzip && \
    rm -rf /var/lib/apt/lists/*
# Install nuclei (active vulnerability scanner) for the network-scan pipeline.
# The archive ships in the build context (backend/third_party/nuclei) so a build
# never reaches GitHub; see that directory's README and scripts/fetch_third_party.py.
COPY backend/third_party/nuclei /tmp/nuclei-src
ARG NUCLEI_VERSION=v3.11.1
RUN arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
        amd64) narch=amd64 ;; \
        arm64) narch=arm64 ;; \
        *) echo "unsupported nuclei architecture: $arch" >&2; exit 1 ;; \
    esac; \
    zip="/tmp/nuclei-src/nuclei_${NUCLEI_VERSION#v}_linux_${narch}.zip"; \
    bin="/tmp/nuclei-src/nuclei_${narch}"; \
    if [ -f "$zip" ] && unzip -tq "$zip" >/dev/null 2>&1; then \
        unzip -o "$zip" -d /usr/local/bin/ nuclei; \
    elif [ -f "$bin" ]; then \
        install -m 0755 "$bin" /usr/local/bin/nuclei; \
    else \
        echo "missing $zip (or $bin) — run 'python scripts/fetch_third_party.py' on the build host" >&2; \
        exit 1; \
    fi; \
    chmod 0755 /usr/local/bin/nuclei && rm -rf /tmp/nuclei-src && /usr/local/bin/nuclei -version
USER appuser
CMD ["celery", "-A", "app.workers.celery_app.celery_app", "worker", "--loglevel=info", "--concurrency=2"]
