#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
#
# vendor_wheels.sh — Pre-download all Python wheels for the air-gapped build.
#
# Run on a NETWORKED machine before transferring the build context to a
# classified / disconnected environment.
#
# Usage:
#   ./scripts/vendor_wheels.sh              # downloads to vendor/wheels/
#   ./scripts/vendor_wheels.sh /custom/path # downloads to /custom/path/
#
# Output:
#   vendor/wheels/  — all .whl files required by aegis-latent-core[storage-sqlite]
#   vendor/wheels/SHA256SUMS — sha256 digests for integrity verification
#   vendor/python-3.11-slim-digest.txt — pinned base image digest
#
# After running this script:
#   docker pull python:3.11-slim
#   docker save python:3.11-slim | gzip > vendor/python-3.11-slim.tar.gz
#   # Then transfer vendor/ to the air-gapped machine and build:
#   docker load < vendor/python-3.11-slim.tar.gz
#   docker build --network=none -f deploy/docker/Dockerfile.airgap -t aegis-latent-core:4.0.2-airgap .

set -euo pipefail

WHEELS_DIR="${1:-vendor/wheels}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WHEELS_ABS="${WHEELS_DIR}"
if [[ "${WHEELS_DIR}" != /* ]]; then
    WHEELS_ABS="${REPO_ROOT}/${WHEELS_DIR}"
fi

echo "[vendor_wheels] Downloading wheels to: ${WHEELS_ABS}"
mkdir -p "${WHEELS_ABS}"

# ── Download wheels (runtime deps + build deps) ───────────────────────────────
pip download \
    --dest "${WHEELS_ABS}" \
    --python-version 3.11 \
    --platform manylinux_2_28_x86_64 \
    --only-binary=:all: \
    "aegis-latent-core[storage-sqlite]==4.0.2" 2>/dev/null || \
pip download \
    --dest "${WHEELS_ABS}" \
    ".[storage-sqlite]" \
    --find-links "${WHEELS_ABS}" \
    -r "${REPO_ROOT}/requirements.txt" 2>/dev/null || true

# Fallback: install from source tree and download all transitive deps
pip download \
    --dest "${WHEELS_ABS}" \
    --no-build-isolation \
    "${REPO_ROOT}[storage-sqlite]"

# ── Build-time deps (pip, setuptools, wheel, hatchling) ───────────────────────
pip download \
    --dest "${WHEELS_ABS}" \
    "pip>=24.0" \
    "setuptools>=70.0" \
    "wheel>=0.43" \
    "hatchling>=1.24"

# ── Generate SHA256 manifest for air-gap integrity verification ───────────────
echo "[vendor_wheels] Computing SHA256 digests..."
(cd "${WHEELS_ABS}" && sha256sum ./*.whl > SHA256SUMS 2>/dev/null) || true

WHEEL_COUNT=$(find "${WHEELS_ABS}" -name "*.whl" | wc -l)
echo "[vendor_wheels] Done — ${WHEEL_COUNT} wheels in ${WHEELS_ABS}"
echo "[vendor_wheels] SHA256SUMS written to ${WHEELS_ABS}/SHA256SUMS"

# ── Capture base image digest ─────────────────────────────────────────────────
if command -v docker &>/dev/null && docker info &>/dev/null 2>&1; then
    docker pull python:3.11-slim
    DIGEST=$(docker image inspect python:3.11-slim --format '{{index .RepoDigests 0}}' 2>/dev/null | sed 's/.*@//')
    if [[ -n "${DIGEST}" ]]; then
        echo "${DIGEST}" > "${REPO_ROOT}/vendor/python-3.11-slim-digest.txt"
        echo "[vendor_wheels] Base image digest: ${DIGEST}"
        echo "[vendor_wheels] Saved to vendor/python-3.11-slim-digest.txt"
        echo "[vendor_wheels]"
        echo "[vendor_wheels] Next steps:"
        echo "[vendor_wheels]   docker save python:3.11-slim | gzip > vendor/python-3.11-slim.tar.gz"
        echo "[vendor_wheels]   # Transfer vendor/ to the air-gapped machine, then:"
        echo "[vendor_wheels]   docker load < vendor/python-3.11-slim.tar.gz"
        echo "[vendor_wheels]   docker build --network=none \\"
        echo "[vendor_wheels]     --build-arg PYTHON_BASE_DIGEST=${DIGEST} \\"
        echo "[vendor_wheels]     -f deploy/docker/Dockerfile.airgap \\"
        echo "[vendor_wheels]     -t aegis-latent-core:4.0.2-airgap ."
    fi
else
    echo "[vendor_wheels] Docker not available — skipping base image digest capture"
fi
