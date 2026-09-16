#!/usr/bin/env bash
# Provision AKS for aegis-latent-core and install the chart in strict mode.
# Run from the repo root in Azure Cloud Shell, after this commit is pushed to main.
# Idempotent where Azure allows it; never prints secret values.
set -euo pipefail

RG=aegis-core-rg
LOC=eastus
AKS=aegis-aks
ACR=aegiscoreacr
KV=aegis-vault-prod
UAMI=aegis-uami
NS=aegis
SA=aegis                       # = fullnameOverride in values-aks.yaml
NODE_SIZE=${NODE_SIZE:-Standard_D2s_v5}
NODE_COUNT=${NODE_COUNT:-2}    # chart spreads 2 replicas across zones and hosts
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

log "2/8 image build from origin/main (ACR Tasks)"
TAG="sha-$(git ls-remote https://github.com/JuanLunaIA/aegis-latent-core.git refs/heads/main | cut -c1-12)"
[ "$TAG" != "sha-" ] || { echo "ABORT: cannot resolve origin/main"; exit 1; }
if ! az acr repository show-tags -n "$ACR" --repository aegis-latent-core -o tsv 2>/dev/null | grep -qx "$TAG"; then
  az acr build -r "$ACR" -t "aegis-latent-core:$TAG" -f deploy/docker/Dockerfile \
    "https://github.com/JuanLunaIA/aegis-latent-core.git#main" -o none
fi

log "3/8 AKS cluster"
if ! az aks show -g "$RG" -n "$AKS" -o none 2>/dev/null; then
  az aks create -g "$RG" -n "$AKS" -l "$LOC" --tier free \
    --node-count "$NODE_COUNT" --node-vm-size "$NODE_SIZE" --zones 1 2 --os-sku Ubuntu \
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

log "5/8 principal mapping into Key Vault (copied from aegis-api, digest only)"
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
helm upgrade --install aegis deploy/helm -n "$NS" -f "$VALUES" --wait --timeout 10m

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
