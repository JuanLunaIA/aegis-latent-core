#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
# Build Aegis Rust extension with embedded profile (minimized for edge/OT deployment)
# Usage: bash scripts/build_embedded.sh [TARGET]
# Default target: current platform. Set TARGET for cross-compile e.g. aarch64-unknown-linux-musl

set -euo pipefail

TARGET="${1:-}"
FEATURES="embedded"

cd "$(dirname "$0")/../aegis_rust_v2"

if [ -n "$TARGET" ]; then
    maturin build --profile embedded --features "$FEATURES" --target "$TARGET"
else
    maturin build --profile embedded --features "$FEATURES"
fi

echo "Embedded build complete. Wheels in aegis_rust_v2/target/wheels/"
