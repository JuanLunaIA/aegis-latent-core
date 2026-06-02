#!/usr/bin/env bash
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
# Prueba rápida contra un AEGIS en ejecución (puerto 8080 por defecto).
# Uso:  ./scripts/smoke_test.sh
# Requiere: curl, jq (opcional)

set -euo pipefail

BASE_URL="${AEGIS_BASE_URL:-http://localhost:8080}"
API_KEY="${AEGIS_TEST_API_KEY:-sk-aegis-key1}"
AUDIT_KEY="${AEGIS_TEST_AUDIT_KEY:-sk-audit-readonly-key}"

echo "==> Health"
curl -sf "${BASE_URL}/health"
echo

echo "==> Audit health"
curl -sf "${BASE_URL}/v1/audit/health" \
  -H "Authorization: Bearer ${AUDIT_KEY}"
echo

echo "==> Chat (puede fallar si el backend LLM no está disponible)"
if curl -sf "${BASE_URL}/v1/chat/completions" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"model":"llama3.2","messages":[{"role":"user","content":"ping"}]}' \
  -o /tmp/aegis_smoke.json; then
  echo "Chat OK"
  command -v jq >/dev/null && jq -r '.choices[0].message.content // .error.message // .' /tmp/aegis_smoke.json
else
  echo "Chat falló (¿Ollama/backend levantado y modelo existente?)"
  exit 1
fi

echo "==> Smoke test completado"
