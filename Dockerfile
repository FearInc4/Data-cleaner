# Data Cleaner: one container, data in /data.
#
# Supply-chain hardening:
#   - base image pinned by digest (Dependabot proposes updates)
#   - every Python dependency pinned by version AND sha256 hash (requirements.lock)
#   - runs as an unprivileged user; works with a read-only root filesystem
FROM python:3.14-slim@sha256:a2b82f3c48559aa0a8446d9af49826b6e2b2016f4cd2afabfe6013ec53729170

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app/src \
    DATACLEANER_DATA_DIR=/data \
    DATACLEANER_HOST=0.0.0.0 \
    DATACLEANER_PORT=8080

# Pick up Debian security fixes released after the base image was built.
RUN apt-get update \
 && apt-get upgrade -y --no-install-recommends \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.lock ./
RUN pip install --require-hashes --no-deps -r requirements.lock \
 # pip isn't needed at runtime, and the copy in the base image carries known CVEs.
 && pip uninstall -y pip \
 && useradd --system --uid 10001 --home-dir /nonexistent --shell /usr/sbin/nologin datacleaner \
 && mkdir -p /data && chown datacleaner /data && chmod 700 /data
COPY --chown=root:root src ./src
COPY --chown=root:root LICENSE README.md ./

USER datacleaner
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s \
  CMD ["python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"]
CMD ["python", "-m", "datacleaner", "serve"]
