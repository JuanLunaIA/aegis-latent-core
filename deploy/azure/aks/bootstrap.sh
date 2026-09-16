#!/usr/bin/env bash
# Provision AKS for aegis-latent-core and install the chart in strict mode.
# Run from the repo root in Azure Cloud Shell with these commits checked out.
# Idempotent where Azure allows it; never prints secret values.
set -euo pipefail

RG=aegis-core-rg
# Location/SKU validated 2026-09-16 against this subscription: Standard_D2s_v5 is
# NotAvailableForSubscription in eastus (location and zones) but unrestricted in
# chilecentral with zones 1-3 (Standard_B2als_v2 must be re-checked with az vm list-skus). ACR and Key Vault stay in eastus; cross-region is supported.
LOC=${LOC:-chilecentral}
AKS=aegis-aks
ACR=aegiscoreacr
KV=aegis-vault-prod
UAMI=aegis-uami
NS=aegis
SA=aegis                       # = fullnameOverride in values-aks.yaml
# Budget: 2x D2s_v5 + P10 OS disks ran ~8.3 USD/day (retail, chilecentral, 2026-09-16),
# burning a 200 USD credit in ~24 days. 2x B2als_v2 (2 vCPU/4 GiB, AKS system-pool minimum)
# with 32 GiB P4 OS disks is ~3.1 USD/day and keeps one replica per zone.
NODE_SIZE=${NODE_SIZE:-Standard_B2als_v2}
OS_DISK_GB=${OS_DISK_GB:-32}
NODE_COUNT=${NODE_COUNT:-2}    # chart spreads 2 replicas across zones and hosts
# Set ZONES="" for regions/SKUs without zone access (AvailabilityZoneNotSupported).
ZONES=${ZONES-1 2}
read -r -a ZONE_ARGS <<< "${ZONES:+--zones $ZONES}"
HERE=deploy/azure/aks

log() { printf '[%s] %s\n' "$(date -u +%FT%TZ)" "$*"; }
[ -f "$HERE/values-aks.yaml" ] || { echo "run from the aegis-latent-core repo root"; exit 1; }

log "1/8 resource providers"
for p in Microsoft.Compute Microsoft.Network Microsoft.ContainerService; do
  az provider register -n "$p" -o none
  for _ in $(seq 60); do
    [ "$(az provider show -n "$p" --query registrationState -o tsv)" = Registered ] && break
    sleep 10
  done
  [ "$(az provider show -n "$p" --query registrationState -o tsv)" = Registered ] || { echo "ABORT: $p not Registered"; exit 1; }
done

log "2/8 image build from this checkout (ACR Tasks; no push to GitHub needed)"
# The tag names the exact commit, so a dirty tree would publish unreviewed code under it.
[ -z "$(git status --porcelain --untracked-files=no)" ] || { echo "ABORT: uncommitted changes"; exit 1; }
TAG="sha-$(git rev-parse --short=12 HEAD)"
if ! az acr repository show-tags -n "$ACR" --repository aegis-latent-core -o tsv 2>/dev/null | grep -qx "$TAG"; then
  az acr build -r "$ACR" -t "aegis-latent-core:$TAG" -f deploy/docker/Dockerfile . -o none
fi

log "3/8 AKS cluster"
if ! az aks show -g "$RG" -n "$AKS" -o none 2>/dev/null; then
  az aks create -g "$RG" -n "$AKS" -l "$LOC" --tier free \
    --node-count "$NODE_COUNT" --node-vm-size "$NODE_SIZE" --node-osdisk-size "$OS_DISK_GB" "${ZONE_ARGS[@]}" --os-sku Ubuntu \
    --network-plugin azure --network-plugin-mode overlay --network-dataplane cilium \
    --enable-oidc-issuer --enable-workload-identity \
    --enable-addons azure-keyvault-secrets-provider \
    --attach-acr "$ACR" \
    --auto-upgrade-channel patch --node-os-upgrade-channel NodeImage \
    --no-ssh-key -o none
fi

log "4/8 workload identity federation for $NS/$SA"
ISSUER=$(az aks show -g "$RG" -n "$AKS" --query oidcIssuerProfile.issuerUrl -o tsv)
CLIENT_ID=$(az identity show -g "$RG" -n "$UAMI" --query clientId -o tsv)
TENANT_ID=$(az account show --query tenantId -o tsv)
if ! az identity federated-credential show -g "$RG" --identity-name "$UAMI" -n aks-aegis-sa -o none 2>/dev/null; then
  az identity federated-credential create -g "$RG" --identity-name "$UAMI" -n aks-aegis-sa \
    --issuer "$ISSUER" --subject "system:serviceaccount:$NS:$SA" \
    --audiences api://AzureADTokenExchange -o none
fi

if ! az identity federated-credential show -g "$RG" --identity-name "$UAMI" -n aks-aegis-redis-sa -o none 2>/dev/null; then
  az identity federated-credential create -g "$RG" --identity-name "$UAMI" -n aks-aegis-redis-sa \
    --issuer "$ISSUER" --subject "system:serviceaccount:$NS:aegis-redis" \
    --audiences api://AzureADTokenExchange -o none
fi

log "5/8 secrets into Key Vault (values never printed)"
if ! az keyvault secret show --vault-name "$KV" -n aegis-redis-password --query id -o none 2>/dev/null; then
  # hex: URL-safe inside redis://:<password>@host
  az keyvault secret set --vault-name "$KV" -n aegis-redis-password --value "$(openssl rand -hex 32)" -o none
fi
if ! az keyvault secret show --vault-name "$KV" -n aegis-api-key-principals-json --query id -o none 2>/dev/null; then
  P=$(az containerapp show -g "$RG" -n aegis-api \
    --query "properties.template.containers[0].env[?name=='AEGIS_API_KEY_PRINCIPALS_JSON'].value | [0]" -o tsv)
  [ -n "$P" ] || { echo "ABORT: principal mapping not found on aegis-api"; exit 1; }
  az keyvault secret set --vault-name "$KV" -n aegis-api-key-principals-json --value "$P" -o none
  unset P
fi

log "6/8 cluster resources"
az aks get-credentials -g "$RG" -n "$AKS" --overwrite-existing -o none
sed -e "s|__UAMI_CLIENT_ID__|$CLIENT_ID|g" -e "s|__TENANT_ID__|$TENANT_ID|g" \
  "$HERE/cluster-resources.yaml" | kubectl apply -f -
kubectl -n "$NS" rollout status deploy/aegis-redis --timeout=180s

log "7/8 helm release"
VALUES=$(mktemp)
trap 'rm -f "$VALUES"' EXIT
sed -e "s|__UAMI_CLIENT_ID__|$CLIENT_ID|g" -e "s|__IMAGE_TAG__|$TAG|g" "$HERE/values-aks.yaml" > "$VALUES"
# Without zones, a zone-keyed DoNotSchedule constraint can leave pods Pending if nodes lack the label.
SPREAD=()
[ -n "$ZONES" ] || SPREAD=(--set-json 'topologySpreadConstraints=[{"maxSkew":1,"topologyKey":"kubernetes.io/hostname","whenUnsatisfiable":"DoNotSchedule"}]')
# An interrupted upgrade (Cloud Shell sessions drop) leaves the newest revision in
# pending-upgrade/pending-rollback and locks the release. A lock older than the 10m
# helm timeout cannot belong to a live operation, so that revision record is dropped;
# helm then upgrades from the previous (failed or deployed) revision.
kubectl -n "$NS" get secrets -l owner=helm,name=aegis \
  -o jsonpath='{range .items[*]}{.metadata.name} {.metadata.labels.status} {.metadata.creationTimestamp}{"\n"}{end}' |
while read -r s st ts; do
  case "$st" in pending-upgrade|pending-rollback) ;; *) continue ;; esac
  if [ $(( $(date -u +%s) - $(date -u -d "$ts" +%s) )) -gt 900 ]; then
    log "dropping stale helm lock $s ($st since $ts)"
    kubectl -n "$NS" delete secret "$s"
  else
    echo "ABORT: helm release $st since $ts may still be running; retry in 15m"; exit 1
  fi
done
# An interrupted first install leaves the release locked in pending-install with
# nothing ever deployed; only that state is cleared (PVCs are not Helm-owned and stay).
if helm -n "$NS" status aegis -o json 2>/dev/null | grep -q '"status":"pending-install"' \
   && [ "$(helm -n "$NS" history aegis -o json | grep -c '"status":"deployed"')" = 0 ]; then
  log "clearing interrupted first install"
  helm -n "$NS" uninstall aegis --wait
fi
# A StatefulSet never adopts a same-named pod still owned by a deleted predecessor,
# and it is not re-queued when that pod finally goes: install only once none is terminating.
terminating() {
  kubectl -n "$NS" get pods -l app.kubernetes.io/instance=aegis \
    -o jsonpath='{range .items[?(@.metadata.deletionTimestamp)]}{.metadata.name}{" "}{end}'
}
for _ in $(seq 60); do
  [ -z "$(terminating)" ] && break
  log "waiting for terminating pods: $(terminating)"; sleep 10
done
[ -z "$(terminating)" ] || { echo "ABORT: pods stuck terminating; kubectl -n $NS describe pod"; exit 1; }
helm upgrade --install aegis deploy/helm -n "$NS" -f "$VALUES" "${SPREAD[@]}" --wait --timeout 10m

log "8/8 smoke test"
kubectl -n "$NS" get pods -o wide
kubectl -n "$NS" port-forward svc/aegis 18080:80 >/dev/null 2>&1 &
PF=$!
sleep 5
CODE=$(curl -s -o /dev/null -w '%{http_code}' -m 10 http://127.0.0.1:18080/health || true)
kill "$PF" 2>/dev/null || true
log "GET /health -> $CODE"
if [ "$CODE" != 200 ]; then
  echo "SMOKE_FAILED: kubectl -n $NS logs sts/aegis --tail=60"
  exit 1
fi
log "DONE_AKS image=$TAG"
