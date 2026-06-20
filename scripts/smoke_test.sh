#!/usr/bin/env bash
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
# Quick smoke test against a running AEGIS instance (default port 8080).
# Usage:  ./scripts/smoke_test.sh
# Requires: curl, jq (optional)

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

echo "==> Chat (may fail if the LLM backend is not running)"
if curl -sf "${BASE_URL}/v1/chat/completions" \
  -H "Authorization: Bearer ${API_KEY}" \
  -H "Content-Type: application/json" \
  -d '{"model":"llama3.2","messages":[{"role":"user","content":"ping"}]}' \
  -o /tmp/aegis_smoke.json; then
  echo "Chat OK"
  command -v jq >/dev/null && jq -r '.choices[0].message.content // .error.message // .' /tmp/aegis_smoke.json
else
  echo "Chat failed (is Ollama/backend running with the requested model?)"
  exit 1
fi

echo "==> Smoke test complete"
