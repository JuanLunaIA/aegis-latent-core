# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
#
# Aegis Latent Core v3.1.0 — strict production image (Python 3.12)
#
# Build: docker build -f deploy/docker/Dockerfile -t aegis-latent-core:3.1.0 .
# Run with host-provided profiles and bounded privileges:
# docker run --read-only --cap-drop=ALL --security-opt no-new-privileges=true \
#   --security-opt seccomp=/etc/aegis/seccomp.json \
#   --security-opt apparmor=aegis-latent-core \
#   --tmpfs /tmp:rw,noexec,nosuid,size=64m -p 8080:8080 \
#   --env-file .env -v /var/lib/aegis:/data aegis-latent-core:3.1.0
#
# Required env vars:
#   AEGIS_BACKEND_API_KEY   — upstream LLM API key
#   AEGIS_API_KEYS          — comma-separated proxy client keys
#   AEGIS_SIGNING_KEY       — dedicated strong signing key, at least 32 bytes
#
# Optional:
#   AEGIS_PROVIDER          — openai | anthropic | gemini | openrouter (default: openai)
#   AEGIS_PROVIDER_MODEL    — override upstream model name
#   AEGIS_WAF_STRICT_MODE   — true for hardened deployments
#   AEGIS_SSL_CERTFILE      — path to TLS server cert (mount as volume)
#   AEGIS_SSL_KEYFILE       — path to TLS server key
#   AEGIS_MTLS_REQUIRED     — true to require client certs

# ── Stage 1: build & install ─────────────────────────────────────────────────
FROM python:3.12-slim AS builder

WORKDIR /build

RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy only what pip needs to resolve dependencies
COPY pyproject.toml README.md ./
COPY aegis ./aegis
COPY aegis_server ./aegis_server
COPY integrations ./integrations

# Install the package (SQLite backend included; add extras as needed)
RUN pip install --no-cache-dir ".[storage-sqlite]"

# ── Stage 2: minimal runtime image ───────────────────────────────────────────
FROM python:3.12-slim

LABEL org.opencontainers.image.title="Aegis Latent Core" \
      org.opencontainers.image.version="3.1.0" \
      org.opencontainers.image.description="Strict LLM gateway with durable signed forensic evidence" \
      org.opencontainers.image.licenses="AGPL-3.0"

# Non-root user — principle of least privilege
RUN groupadd -g 10001 aegis \
    && useradd -u 10001 -g aegis -m -s /usr/sbin/nologin aegis

WORKDIR /app

# Copy installed packages from builder
COPY --from=builder /usr/local /usr/local

# Copy application source (needed for dynamic imports)
COPY aegis ./aegis
COPY aegis_server ./aegis_server
COPY integrations ./integrations
COPY deploy/seccomp/aegis.json /etc/aegis/seccomp.json

# Persistent data directory — mount a volume here in production
RUN mkdir -p /data && chown aegis:aegis /data

USER aegis

# Runtime defaults (all overridable via env vars or --env-file)
ENV AEGIS_LOG_LEVEL=INFO \
    AEGIS_WAL_PATH=/data/aegis.wal.jsonl \
    AEGIS_SECURITY_ENFORCEMENT_MODE=strict \
    AEGIS_REQUIRE_DURABLE_EVIDENCE=true \
    AEGIS_REQUIRE_DISTRIBUTED_LIMITER=true \
    AEGIS_REQUIRE_LSM=true \
    AEGIS_REQUIRE_SECCOMP=true \
    AEGIS_RATE_LIMIT_BACKEND=redis \
    AEGIS_DEBUG_MODE=false \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

EXPOSE 8080

# Deep healthcheck using the v3.1.0 /health endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "\
import urllib.request, json, sys; \
resp = urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4); \
body = json.loads(resp.read()); \
sys.exit(0 if body.get('status') == 'healthy' else 1)"

# Entry point registered in pyproject.toml [project.scripts]
CMD ["aegis-server"]
