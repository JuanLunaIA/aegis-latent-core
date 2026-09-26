#!/usr/bin/env bash
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
#
# Azure Phase-0 guardrails (REG-H07): run BEFORE creating anything billable.
#   1. confirms an Azure login and prints the target subscription for you to confirm
#   2. registers the resource providers the kits need
#   3. creates the resource group, tagged
#   4. creates subscription budget alerts at 50 / 80 / 95 % actual and 100 % forecast
# It creates no compute, storage or network resource. Idempotent; prints no secret.
#
# Usage:
#   deploy/azure/phase0/phase0_guardrails.sh --email you@example.com --budget 200 [--rg aegis-rg] [--location eastus] [--yes]
set -euo pipefail

RG=aegis-rg; LOC=eastus; BUDGET=""; EMAIL=""; YES=0
while [ $# -gt 0 ]; do
  case "$1" in
    --rg) RG=$2; shift 2 ;;
    --location) LOC=$2; shift 2 ;;
    --budget) BUDGET=$2; shift 2 ;;
    --email) EMAIL=$2; shift 2 ;;
    --yes) YES=1; shift ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done
[ -n "$BUDGET" ] && [ -n "$EMAIL" ] || { echo "--budget and --email are required" >&2; exit 2; }
[[ "$BUDGET" =~ ^[0-9]+$ ]] || { echo "--budget must be a whole number of USD" >&2; exit 2; }
[[ "$EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+$ ]] || { echo "--email is not an address" >&2; exit 2; }
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }

command -v az >/dev/null || { echo "Azure CLI not found: https://aka.ms/installazurecli" >&2; exit 1; }
az account show -o none 2>/dev/null || { echo "not logged in: run 'az login'" >&2; exit 1; }
SUB_NAME=$(az account show --query name -o tsv); SUB_STATE=$(az account show --query state -o tsv)
log "subscription: $SUB_NAME ($SUB_STATE)"
[ "$SUB_STATE" = Enabled ] || { echo "subscription is not Enabled" >&2; exit 1; }
if [ "$YES" != 1 ]; then
  read -r -p "Apply Phase-0 guardrails to '$SUB_NAME'? [y/N] " A
  [ "$A" = y ] || [ "$A" = Y ] || { echo "aborted"; exit 1; }
fi

log "1/3 resource providers"
for p in Microsoft.Compute Microsoft.Network Microsoft.Storage Microsoft.Consumption Microsoft.ContainerService; do
  az provider register -n "$p" -o none
done
for p in Microsoft.Compute Microsoft.Network Microsoft.Storage Microsoft.Consumption; do
  for _ in $(seq 60); do
    [ "$(az provider show -n "$p" --query registrationState -o tsv)" = Registered ] && break
    sleep 10
  done
  [ "$(az provider show -n "$p" --query registrationState -o tsv)" = Registered ] || { echo "ABORT: $p not Registered" >&2; exit 1; }
done

log "2/3 resource group $RG ($LOC)"
az group create -n "$RG" -l "$LOC" --tags app=aegis-latent-core managedBy=aegis-phase0 -o none

log "3/3 subscription budget alerts"
START=$(date -u +%Y-%m-01)
az deployment sub create -l "$LOC" -n aegis-phase0-budget -f "$HERE/budget.bicep" \
  -p amountUsd="$BUDGET" contactEmail="$EMAIL" startDate="$START" -o none

log "DONE_PHASE0 rg=$RG budget_usd=$BUDGET alerts=50/80/95 actual + 100 forecast (notification only; Azure does not stop spend)"
