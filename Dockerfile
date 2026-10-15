# Data Cleaner: single container, data in /data.
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DATACLEANER_DATA_DIR=/data \
    DATACLEANER_HOST=0.0.0.0 \
    DATACLEANER_PORT=8080

WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install . && useradd --system --uid 10001 --home /app datacleaner && mkdir -p /data && chown datacleaner /data

USER datacleaner
VOLUME ["/data"]
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s --start-period=20s \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=4).status == 200 else 1)"
CMD ["datacleaner", "serve"]
