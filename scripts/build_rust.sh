#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
set -euo pipefail
# Reproducible helper to build aegis_rust_v2 using maturin in an isolated venv.
# Usage: ./scripts/build_rust.sh [python-executable]
PYTHON=${1:-python}
echo "Using $PYTHON"
if ! command -v "$PYTHON" >/dev/null 2>&1; then
  echo "Python executable $PYTHON not found" >&2
  exit 1
fi
VENV=".venv-rust-build"
$PYTHON -m venv "$VENV"
# shellcheck source=/dev/null
. "$VENV/bin/activate"
python -m pip install -U pip setuptools wheel maturin || true
export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1
if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1 && ! command -v clang >/dev/null 2>&1; then
  echo "C compiler not found (cc/gcc/clang). Install build-essential or equivalent." >&2
  exit 2
fi
cd aegis_rust_v2
maturin develop --release
echo "Built aegis_rust_v2 into current venv"
