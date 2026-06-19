#!/bin/bash
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
# Aegis Latent Core — SBOM Generation Script
# Licensed under AGPLv3 / Commercial

set -e

OUTPUT_FILE="aegis-sbom.json"

echo "Generating SBOM for Aegis Latent Core..."

# Check if syft is installed; if not, download it temporarily
if ! command -v syft &> /dev/null; then
    echo "syft not found. Downloading..."
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /tmp
    SYFT_CMD="/tmp/syft"
else
    SYFT_CMD="syft"
fi

$SYFT_CMD . -o json > "$OUTPUT_FILE"

echo "SBOM generated at $OUTPUT_FILE"
echo "Attach this file to Releases for supply-chain compliance (Executive Order 14028)."
