#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
# Store the upstream LLM provider key on the VM. The key is read silently and sent over SSH stdin.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
. ./kit.env
[ "$SSH_SOURCE" != none ] || { echo "this kit opens no SSH rule; use: az vm run-command or re-create with --ssh-source" >&2; exit 1; }
read -r -s -p "Provider API key (input hidden): " KEY; echo
printf '%s\n' "$KEY" | ssh ${SSH_OPTS:-} -o StrictHostKeyChecking=accept-new "$ADMIN_USER@$DNS_LABEL.$LOCATION.cloudapp.azure.com" 'sudo aegis-set-backend-key'
unset KEY
