# --- STAGE 1: Build ---
FROM python:3.14-slim AS builder

# Install build dependencies for Rust and Python extensions
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    build-essential \
    pkg-config \
    libssl-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /build
COPY . .

# Create virtual environment and install dependencies
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"
RUN pip install --no-cache-dir -r requirements.txt

# Build the Rust extension (aegis_rust)
# We assume the build script is handled by a setup.py or similar in the project root
RUN pip install .

# --- STAGE 2: Production (SISTEMA INEXPUGNABLE: Distroless) ---
FROM gcr.io/distroless/python3-debian12


# Create a non-privileged user for rootless execution
RUN groupadd -g 10001 aegis && \
    useradd -u 10001 -g aegis -m -s /sbin/nologin aegis

# Install only runtime dependencies (mimalloc for S1.2)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy only the virtual environment from the builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:${PATH}"

# Copy application code
WORKDIR /app
COPY aegis /app/aegis
COPY deploy /app/deploy

# Set permissions for the rootless user
# Note: In distroless, we must ensure the user exists in the image or use UID/GID
# Since distroless lacks 'chown', we handle permissions in the builder stage or via an init container.
# For this implementation, we assume the runtime user is handled by the orchestrator (K8s)


# Create a dedicated volume for the WAL (The only writable part of the FS)
RUN mkdir -p /data && chown aegis:aegis /data

# Switch to rootless user
USER aegis

# Security: No shell access, no root privileges
# Environment variables for the app
ENV AEGIS_LOG_LEVEL=INFO
ENV AEGIS_WAL_PATH=/data/aegis.wal.jsonl

EXPOSE 8080

# Execute as non-root
CMD ["uvicorn", "aegis.proxy.app:create_app", "--host", "0.0.0.0", "--port", "8080", "--workers", "1"]
