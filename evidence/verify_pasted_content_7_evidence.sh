#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
sha256sum --check pasted_content_7_readme_overhaul_2026-08-25.sha256
