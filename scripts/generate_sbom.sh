#!/bin/bash
# Aegis Latent Core — SBOM Generation Script
# Licensed under AGPLv3 / Commercial

set -e

OUTPUT_FILE="aegis-sbom.json"

echo "🔍 Generando SBOM para Aegis Latent Core..."

# Verificar si syft está instalado, si no, descargarlo temporalmente
if ! command -v syft &> /dev/null; then
    echo "📦 Syft no encontrado. Descargando..."
    curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /tmp
    SYFT_CMD="/tmp/syft"
else
    SYFT_CMD="syft"
fi

$SYFT_CMD . -o json > "$OUTPUT_FILE"

echo "✅ SBOM generado exitosamente en $OUTPUT_FILE"
echo "🛡️ Este archivo debe adjuntarse a los Releases para cumplimiento normativo (Executive Order 14028)."
