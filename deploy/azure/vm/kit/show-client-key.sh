#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
# Print the generated client and audit API keys (they exist only on the VM).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
. ./kit.env
[ "$SSH_SOURCE" != none ] || { echo "this kit opens no SSH rule; re-create with --ssh-source" >&2; exit 1; }
ssh ${SSH_OPTS:-} -o StrictHostKeyChecking=accept-new "$ADMIN_USER@$DNS_LABEL.$LOCATION.cloudapp.azure.com" 'sudo aegis-show-client-key'
