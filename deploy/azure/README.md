# deploy/azure

Everything the repository ships for running the gateway on Azure. Start with the decision guide: [Azure Install Options](../../docs/operations/AZURE_INSTALL_OPTIONS.md).

| Directory | What it is | Status |
| --- | --- | --- |
| [`kit-creator/`](kit-creator/aegis_azure_kit.py) | `doctor`, `estimate`, `create`, `verify`: generates a self-contained VM kit | Tested offline (`tests/test_azure_kit.py`) and against a live subscription on 2026-09-26 |
| [`vm/`](vm/main.bicep) | Source of the VM kit: Bicep, Docker Compose, Caddy, first-boot scripts, lifecycle scripts | Deployed and measured once |
| [`phase0/`](phase0/phase0_guardrails.sh) | Providers, tagged resource group, subscription budget alerts (`REG-H07`) | `budget.bicep` validated against Azure; the script was not run end to end |
| [`benchmarks/`](benchmarks/run_azure_benchmarks.sh) | Harness that records disk and gateway numbers on the VM | Run once: [Azure Benchmarks](../../docs/benchmarks/AZURE_BENCHMARKS.md) |
| [`aks/`](aks/bootstrap.sh) | Operator-authored AKS path (Envoy Gateway, Key Vault CSI, workload identity) | Owner-run; needs pre-provisioned ACR, Key Vault and identity. Do not "clean up" without reading `git log` for this directory |

## Fastest path

```bash
az login
python deploy/azure/kit-creator/aegis_azure_kit.py doctor --region <region>
python deploy/azure/kit-creator/aegis_azure_kit.py create --name my-aegis --region <region>
cd aegis-azure-kits/my-aegis && ./deploy.sh
```

Full walkthrough: [Azure Quickstart](../../docs/operations/AZURE_QUICKSTART.md). Reference: [Azure Kit Creator](../../docs/operations/AZURE_KIT_CREATOR.md).

## Rules for this directory

- No secret, subscription ID or tenant ID is committed. `tests/test_azure_kit.py` scans for GUIDs.
- The WAL lives on a Managed Disk, never on Azure Files ([why](../../docs/operations/STORAGE_REQUIREMENTS.md)).
- Strict enforcement stays on. Do not add a flag that turns a strict invariant off to make a deployment start.
