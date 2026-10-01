#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
# Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
#
# Azure Phase-0 price readback (EXEC_BASELINE G12). Run it before citing a price.
#   Reads the Azure list prices the investor pack tags VERIFIED from the public
#   Azure Retail Prices API and writes prices_verified_<UTC date>.json.
#   Read-only: no Azure login, no subscription, nothing created or spent.
#   Exit 0 all match the pack; 3 a price changed (rebuild the pack); 4 a meter
#   returned no row; 1 the API could not be reached.
#
# Usage:
#   deploy/azure/phase0/00_query_prices.sh [--out-dir evidence/benchmarks/azure]
set -euo pipefail
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "${1:-}" in -h|--help) sed -n '6,14p' "$0"; exit 0 ;; esac
command -v python3 >/dev/null || { echo "python3 not found" >&2; exit 1; }
exec python3 "$HERE/query_prices.py" "$@"
