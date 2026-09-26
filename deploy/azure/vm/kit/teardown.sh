#!/usr/bin/env bash
# Delete EVERYTHING in the resource group, including the WAL disk and its evidence. Irreversible.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
. ./kit.env
echo "This deletes resource group '$RG' and all evidence on its WAL disk."
echo "Back up first if the WAL matters: see docs/operations/BACKUP_RESTORE.md"
read -r -p "Type the resource group name to confirm: " C
[ "$C" = "$RG" ] || { echo "aborted"; exit 1; }
az group delete -n "$RG" --yes --no-wait
echo "deletion started"
