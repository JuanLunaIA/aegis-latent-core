# Aegis Latent Core — production image (Python 3.12)
FROM python:3.12-slim AS builder

WORKDIR /build
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY aegis ./aegis
COPY integrations ./integrations

RUN pip install --no-cache-dir .

FROM python:3.12-slim

RUN groupadd -g 10001 aegis && useradd -u 10001 -g aegis -m -s /usr/sbin/nologin aegis

WORKDIR /app
COPY --from=builder /usr/local /usr/local
COPY aegis /app/aegis
COPY integrations /app/integrations

RUN mkdir -p /data && chown aegis:aegis /data

USER aegis
ENV AEGIS_LOG_LEVEL=INFO \
    AEGIS_WAL_PATH=/data/aegis.wal.jsonl \
    AEGIS_RATE_LIMIT_BACKEND=memory

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8080/health')"

CMD ["uvicorn", "aegis.proxy.app:app", "--host", "0.0.0.0", "--port", "8080"]
