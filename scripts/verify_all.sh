#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
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
EXPECT_SHA=$(cut -d' ' -f1 docs/legal/LICENSE.sha256)
run "LICENSE matches its published pin" bash -c "[ \"\$(sha256sum LICENSE | cut -d' ' -f1)\" = $EXPECT_SHA ]"
run "SDKs carry Apache-2.0 LICENSE and NOTICE" bash -c "cmp sdk/python/LICENSE sdk/typescript/LICENSE && grep -q 'Apache License' sdk/python/LICENSE && cmp sdk/python/NOTICE sdk/typescript/NOTICE && grep -q 'Apache' sdk/python/NOTICE"
run "Release contract (14 anchors)" "$PY" scripts/verify_release_contract.py
run "License headers current" "$PY" scripts/apply_license_headers.py --check
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
