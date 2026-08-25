#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")"
sha256sum --check v4_0_0_post_merge_release_readiness_2026-08-25.sha256
