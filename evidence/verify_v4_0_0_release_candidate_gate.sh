#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
set -euo pipefail
cd "$(dirname "$0")"
sha256sum --check v4_0_0_release_candidate_gate_2026-08-24.sha256
