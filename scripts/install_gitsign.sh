#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

set -euo pipefail

readonly GITSIGN_VERSION="0.17.1"
readonly GITSIGN_SHA256="69213a8a0813a151e5a47d0060862952ff833a845d57309dff76f7ba6600abae"
readonly GITSIGN_ASSET="gitsign_${GITSIGN_VERSION}_linux_amd64"
readonly GITSIGN_URL="https://github.com/sigstore/gitsign/releases/download/v${GITSIGN_VERSION}/${GITSIGN_ASSET}"

case "$(uname -s)-$(uname -m)" in
  Linux-x86_64) ;;
  *)
    printf 'unsupported gitsign installer platform: %s-%s\n' "$(uname -s)" "$(uname -m)" >&2
    exit 2
    ;;
esac

install_root="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/aegis-gitsign-${GITSIGN_VERSION}"
install_path="${install_root}/gitsign"
mkdir -p "${install_root}"

if [[ ! -x "${install_path}" ]]; then
  temporary_path="${install_path}.download"
  rm -f "${temporary_path}"
  curl --proto '=https' --tlsv1.2 --fail --silent --show-error --location \
    "${GITSIGN_URL}" --output "${temporary_path}"
  printf '%s  %s\n' "${GITSIGN_SHA256}" "${temporary_path}" | sha256sum --check --status
  chmod 0755 "${temporary_path}"
  mv "${temporary_path}" "${install_path}"
fi

actual_sha256="$(sha256sum "${install_path}" | awk '{print $1}')"
if [[ "${actual_sha256}" != "${GITSIGN_SHA256}" ]]; then
  printf 'installed gitsign digest mismatch: expected %s, got %s\n' \
    "${GITSIGN_SHA256}" "${actual_sha256}" >&2
  exit 2
fi

printf '%s\n' "${install_path}"
