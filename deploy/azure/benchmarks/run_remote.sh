#!/usr/bin/env bash
# From your workstation: run the VM benchmark over SSH and retrieve the artifact.
#   SSH_OPTS='-i ~/.ssh/other_key' ./run_remote.sh <kit-dir> [commit]      (commit defaults to this checkout's HEAD; it must be pushed)
set -euo pipefail
KIT=${1:?kit directory}; COMMIT=${2:-$(git rev-parse HEAD)}
HERE=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
. "$KIT/kit.env"
[ "$SSH_SOURCE" != none ] || { echo "kit has no SSH rule" >&2; exit 1; }
HOST="$ADMIN_USER@$DNS_LABEL.$LOCATION.cloudapp.azure.com"
scp ${SSH_OPTS:-} -o StrictHostKeyChecking=accept-new "$HERE/run_azure_benchmarks.sh" "$HOST:/tmp/run_azure_benchmarks.sh"
ssh ${SSH_OPTS:-} -o StrictHostKeyChecking=accept-new "$HOST" "sudo bash /tmp/run_azure_benchmarks.sh --commit $COMMIT --out /tmp/azure-bench.json"
DEST="$HERE/../../../evidence/benchmarks/azure"; mkdir -p "$DEST"
STAMP=$(date -u +%F)
scp ${SSH_OPTS:-} -o StrictHostKeyChecking=accept-new "$HOST:/tmp/azure-bench.json" "$DEST/azure_${VM_SIZE}_${LOCATION}_${STAMP}.json"
echo "artifact: $DEST/azure_${VM_SIZE}_${LOCATION}_${STAMP}.json"
