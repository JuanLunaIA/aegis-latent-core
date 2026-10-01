#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
#
# One command for the licence + version + documentation gates.
# Usage: bash scripts/verify_all.sh [--full]   (--full adds the whole pytest suite)
set -u
PY="${PYTHON:-.venv/bin/python}"
[ -x "$PY" ] || PY=python3
fail=0
run() { # name, command...
  local name="$1"; shift
  if "$@" >/tmp/verify_all.out 2>&1; then echo "PASS  $name"
  else echo "FAIL  $name"; tail -8 /tmp/verify_all.out | sed 's/^/        /'; fail=1; fi
}
EXPECT_SHA=cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30
run "LICENSE is verbatim Apache-2.0" bash -c "[ \"\$(sha256sum LICENSE | cut -d' ' -f1)\" = $EXPECT_SHA ]"
run "LICENSE+NOTICE inside SDK packages" bash -c "cmp LICENSE sdk/python/LICENSE && cmp LICENSE sdk/typescript/LICENSE && cmp NOTICE sdk/python/NOTICE && cmp NOTICE sdk/typescript/NOTICE"
run "Release contract (14 anchors)" "$PY" scripts/verify_release_contract.py
run "License headers idempotent" bash -c "$PY scripts/apply_license_headers.py | grep -q 'Updated 0 files'"
run "License files + metadata tests" "$PY" -m pytest -q -p no:cacheprovider tests/test_license_files.py tests/test_documentation_currency.py tests/test_ai_context.py
run "verify_documentation --strict" "$PY" tools/docs/verify_documentation.py --root . --strict
run "verify_claims" "$PY" scripts/verify_claims.py
run "verify_docs" "$PY" scripts/verify_docs.py
run "Import reachability" "$PY" scripts/verify_import_reachability.py
run "AI-context manifest current" "$PY" scripts/generate_ai_context_manifest.py --check
run "Module inventory current" "$PY" scripts/generate_module_inventory.py --check
run "ruff check" "$PY" -m ruff check .
run "ruff format" "$PY" -m ruff format --check .
run "git diff --check" git diff --check
[ -f scripts/verify_links.sh ] && run "verify_links" bash scripts/verify_links.sh
[ "${1:-}" = "--full" ] && run "full pytest" "$PY" -m pytest -n auto -q -p no:cacheprovider
echo; [ $fail = 0 ] && echo "ALL GATES PASSED" || echo "SOME GATES FAILED"
exit $fail
