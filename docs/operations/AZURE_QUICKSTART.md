# Azure Quickstart

**Audience:** someone with an Azure subscription and no Kubernetes experience.
**Scope:** from an empty subscription to a running strict-mode gateway on one VM, and back to nothing.
**Boundary:** this is the [option B](AZURE_INSTALL_OPTIONS.md#b-azure-vm-kit-recommended-starting-point) path: one node, one chain, no failover. It is a source-baseline pilot, not a capacity or availability statement. See [Boundaries](../BOUNDARIES.md).

---

## Before you start

| You need | Check |
| --- | --- |
| Azure CLI 2.60 or newer | `az version` |
| Python 3.9 or newer | `python3 --version` |
| An SSH key pair | `ls ~/.ssh/id_ed25519.pub` (create with `ssh-keygen -t ed25519`) |
| Your LLM provider API key | Ready to paste; it is never written to a file on your machine |
| A budget you accept | Retail VM price: `aegis_azure_kit.py estimate` |

## 1. Log in and set guardrails (about 3 minutes)

```bash
az login
deploy/azure/phase0/phase0_guardrails.sh --email you@example.com --budget 200
```

Phase 0 registers the resource providers, creates a tagged resource group and a subscription budget with alerts at 50, 80 and 95 %. It creates nothing billable. Alerts notify you; Azure does not stop spending at the budget.

## 2. Preflight

```bash
python deploy/azure/kit-creator/aegis_azure_kit.py doctor --region eastus --dns-label my-aegis
```

Fix every `FAIL`. A `vm size` failure means your subscription cannot create that size in that region: try another `--region` or `--vm-size` and run `doctor` again.

## 3. Generate the kit

```bash
python deploy/azure/kit-creator/aegis_azure_kit.py create \
  --name my-aegis --region eastus --dns-label my-aegis \
  --budget 50 --email you@example.com
python deploy/azure/kit-creator/aegis_azure_kit.py verify aegis-azure-kits/my-aegis
```

Nothing has touched Azure yet.

## 4. Deploy (about 5-10 minutes)

```bash
cd aegis-azure-kits/my-aegis
./deploy.sh
```

The script lists what it will create and asks before spending. It finishes when `https://my-aegis.<region>.cloudapp.azure.com/health` returns 200.

## 5. Configure and verify

```bash
./set-backend-key.sh    # paste your provider key (hidden)
./show-client-key.sh    # the API key your applications send
./verify.sh             # ALL CHECKS PASSED, or the failing check
```

Send a request with the client key as a bearer token to `https://<your-name>/v1/chat/completions`.

## 6. Measure it on your VM (optional)

[Azure Benchmarks](../benchmarks/AZURE_BENCHMARKS.md) describes the harness and how to record your own numbers.

## 7. Remove everything

```bash
./teardown.sh
```

This deletes the resource group and the WAL disk with its evidence. Back up first if the evidence matters.

## Troubleshooting

| Symptom | Look at |
| --- | --- |
| `deploy.sh` waits at `/health` | `az vm run-command invoke -g <rg> -n <name>-vm --command-id RunShellScript --scripts "cloud-init status --long; docker ps -a; journalctl -u aegis --no-pager \| tail -50"` |
| Gateway restarts in a loop | Its log names the unmet strict invariant. Fix the cause; do not relax the setting |
| Certificate never issues | The DNS label must resolve to the VM's IP, and ports 80 and 443 must be open |
| Provider errors after `verify.sh` passes | `set-backend-key.sh` was not run, or the key is wrong |
