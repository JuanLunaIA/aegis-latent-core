#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

set -euo pipefail

if [[ $# -ne 2 ]]; then
  printf 'usage: %s <vMAJOR.MINOR.PATCH> <tag-target-commit>\n' "$0" >&2
  exit 2
fi

readonly release_tag="$1"
readonly tag_target="$2"
readonly expected_identity="https://github.com/JuanLunaIA/aegis-latent-core/.github/workflows/create_release_tag.yml@refs/heads/main"
readonly expected_issuer="https://token.actions.githubusercontent.com"

if [[ ! "${release_tag}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]]; then
  printf 'release tag is not canonical stable SemVer: %s\n' "${release_tag}" >&2
  exit 2
fi
if [[ ! "${tag_target}" =~ ^[0-9a-f]{40}$ ]]; then
  printf 'tag target is not a full commit SHA: %s\n' "${tag_target}" >&2
  exit 2
fi

readonly gitsign_bin="$(scripts/install_gitsign.sh)"

git fetch --no-tags origin main
test "$(git cat-file -t "refs/tags/${release_tag}")" = tag
test "$(git rev-list -n 1 "refs/tags/${release_tag}")" = "${tag_target}"
"${gitsign_bin}" verify-tag \
  --certificate-identity "${expected_identity}" \
  --certificate-oidc-issuer "${expected_issuer}" \
  "${release_tag}"
git merge-base --is-ancestor "${tag_target}" origin/main
