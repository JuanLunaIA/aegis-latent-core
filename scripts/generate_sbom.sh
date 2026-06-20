#!/bin/bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
# Aegis Latent Core — SBOM Generation Script
# Licensed under AGPLv3 / Commercial

set -euo pipefail

OUTPUT_FILE="aegis-sbom.json"

# Pin the Syft version for reproducible, auditable SBOM generation.
# Override via environment: SYFT_VERSION=v1.2.3 ./scripts/generate_sbom.sh
SYFT_VERSION="${SYFT_VERSION:-v1.0.0}"
SYFT_INSTALL_URL="https://raw.githubusercontent.com/anchore/syft/main/install.sh"

# Set SYFT_INSTALL_SHASUM to the known-good SHA256 of the installer script
# for the chosen SYFT_VERSION to enable checksum verification.
SYFT_INSTALL_SHASUM="${SYFT_INSTALL_SHASUM:-}"

echo "Generating SBOM for Aegis Latent Core..."

# Check if syft is installed; if not, download it temporarily
if ! command -v syft &> /dev/null; then
    echo "syft not found. Downloading pinned version ${SYFT_VERSION}..."
    SYFT_INSTALL_SCRIPT="$(mktemp /tmp/syft-install-XXXXXX.sh)"

    curl -sSfL "${SYFT_INSTALL_URL}" -o "${SYFT_INSTALL_SCRIPT}"

    if [ -n "${SYFT_INSTALL_SHASUM}" ]; then
        echo "Verifying Syft installer checksum..."
        ACTUAL_SHASUM="$(sha256sum "${SYFT_INSTALL_SCRIPT}" | awk '{print $1}')"
        if [ "${ACTUAL_SHASUM}" != "${SYFT_INSTALL_SHASUM}" ]; then
            echo "Syft installer checksum verification FAILED."
            echo "Expected: ${SYFT_INSTALL_SHASUM}"
            echo "Actual:   ${ACTUAL_SHASUM}"
            rm -f "${SYFT_INSTALL_SCRIPT}"
            exit 1
        fi
    else
        echo "WARNING: SYFT_INSTALL_SHASUM not set; skipping checksum verification."
        echo "Set SYFT_INSTALL_SHASUM to the expected SHA256 for stronger supply-chain guarantees."
    fi

    sh "${SYFT_INSTALL_SCRIPT}" -b /tmp "syft@${SYFT_VERSION}"
    rm -f "${SYFT_INSTALL_SCRIPT}"
    SYFT_CMD="/tmp/syft"
else
    SYFT_CMD="$(command -v syft)"
fi

"${SYFT_CMD}" . -o json > "${OUTPUT_FILE}"

echo "SBOM generated at ${OUTPUT_FILE}"
echo "Attach this file to Releases for supply-chain compliance (Executive Order 14028)."
