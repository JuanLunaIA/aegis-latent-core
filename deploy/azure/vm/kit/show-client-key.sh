#!/usr/bin/env bash
# Print the generated client and audit API keys (they exist only on the VM).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
. ./kit.env
[ "$SSH_SOURCE" != none ] || { echo "this kit opens no SSH rule; re-create with --ssh-source" >&2; exit 1; }
ssh ${SSH_OPTS:-} -o StrictHostKeyChecking=accept-new "$ADMIN_USER@$DNS_LABEL.$LOCATION.cloudapp.azure.com" 'sudo aegis-show-client-key'
