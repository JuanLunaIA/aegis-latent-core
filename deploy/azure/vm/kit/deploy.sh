#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
# Deploy this kit: resource group + VM + data disk + TLS. Prompts before spending; prints no secret.
#   ./deploy.sh [--yes]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
. ./kit.env
YES=0; [ "${1:-}" = "--yes" ] && YES=1
log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }

command -v az >/dev/null || { echo "Azure CLI not found: https://aka.ms/installazurecli" >&2; exit 1; }
az account show -o none 2>/dev/null || { echo "not logged in: run 'az login'" >&2; exit 1; }
SUB=$(az account show --query name -o tsv)

SSH_SOURCE_CIDR=""
if [ "$SSH_SOURCE" = auto ]; then
  SSH_SOURCE_CIDR="$(curl -fsS -m 10 https://checkip.amazonaws.com | tr -d '[:space:]')/32" \
    || { echo "could not detect your public IP; re-run create with --ssh-source <CIDR> or none" >&2; exit 1; }
elif [ "$SSH_SOURCE" != none ]; then
  SSH_SOURCE_CIDR="$SSH_SOURCE"
fi

echo "Subscription : $SUB"
echo "Resource grp : $RG ($LOCATION)"
echo "VM           : $VM_SIZE, ${DATA_DISK_GB} GiB Premium SSD data disk"
echo "URL          : https://$DNS_LABEL.$LOCATION.cloudapp.azure.com"
echo "SSH allowed  : ${SSH_SOURCE_CIDR:-nobody (no SSH rule)}"
echo "Budget alert : ${BUDGET_USD:-0} USD/month -> ${BUDGET_EMAIL:-none}"
if [ "$YES" != 1 ]; then
  read -r -p "Create these billable resources? [y/N] " A
  [ "$A" = y ] || [ "$A" = Y ] || { echo "aborted"; exit 1; }
fi

log "1/3 resource group"
az group create -n "$RG" -l "$LOCATION" --tags app=aegis-latent-core managedBy=aegis-azure-kit -o none

log "2/3 deployment (VM boot + cloud-init takes several minutes)"
az deployment group create -g "$RG" -n "$NAME-kit" -f main.bicep -p @main.parameters.json \
  -p sshSourceCidr="$SSH_SOURCE_CIDR" budgetStart="$(date -u +%Y-%m-01)" -o none

URL="https://$DNS_LABEL.$LOCATION.cloudapp.azure.com"
log "3/3 waiting for $URL/health (image pull, Let's Encrypt certificate)"
CODE=000
for _ in $(seq 60); do
  CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 10 "$URL/health" || true)
  [ "$CODE" = 200 ] && break
  sleep 10
done
log "GET /health -> $CODE"
[ "$CODE" = 200 ] || { echo "not healthy yet: see README.md > Troubleshooting" >&2; exit 1; }

cat <<MSG

DONE. Gateway is up at $URL
Next:
  1. Store your LLM provider key:   ./set-backend-key.sh
  2. Fetch your generated API keys: ./show-client-key.sh
  3. Verify end to end:             ./verify.sh
MSG
