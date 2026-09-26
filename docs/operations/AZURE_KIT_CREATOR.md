# Azure Kit Creator

**Audience:** operators who want an Azure deployment without writing infrastructure code.
**Scope:** the `aegis_azure_kit.py` command, what a generated kit contains, and what it refuses to do.
**Boundary:** the creator writes files locally. It never creates an Azure resource; only the generated `deploy.sh` does, after asking. The kit is a source-baseline deployment: target acceptance of storage, network, identity and key custody remains yours. See [Boundaries](../BOUNDARIES.md).

---

## Commands

```bash
python deploy/azure/kit-creator/aegis_azure_kit.py <command>
```

| Command | Touches Azure | Purpose |
| --- | --- | --- |
| `doctor` | Read-only `az` calls | Checks the CLI, login, subscription state, resource providers, whether your subscription can create the VM size in the region, and whether the DNS label is free. `az vm list-skus` can take about two minutes. `--offline` skips every Azure call |
| `estimate` | Public HTTPS GET to `prices.azure.com` | Live retail price of the VM size |
| `create` | No | Writes a kit directory |
| `verify <kit>` | No | Checks `SHA256SUMS`, flags unlisted files, and scans for secret-shaped strings and GUIDs |

## `create` options

| Option | Default | Notes |
| --- | --- | --- |
| `--profile` | `vm` | `aks` is refused: its bootstrap needs pre-provisioned resources ([options](AZURE_INSTALL_OPTIONS.md#c-aks)) |
| `--name` | `aegis` | 3-20 chars, `a-z 0-9 -` |
| `--region` | `eastus` | Run `doctor` first: size availability varies per subscription |
| `--vm-size` | `Standard_B2als_v2` | |
| `--ssh-key` | `~/.ssh/id_ed25519.pub` | Public key only; a private key is refused |
| `--ssh-source` | `auto` | `auto` opens SSH to your current IP only, `none` opens no SSH, or give a CIDR. `0.0.0.0/0` is refused |
| `--budget`, `--email` | off | Monthly budget with alerts at 50, 80 and 95 % actual and 100 % forecast. Alerts notify; Azure does not stop spend |
| `--image` | `ghcr.io/juanlunaia/aegis-latent-core:5.0.1` | Accepts `repo@sha256:<digest>`; pin a digest for reproducibility |
| `--provider`, `--backend-url` | `openai`, `https://api.openai.com` | HTTPS only |
| `--zone`, `--data-disk-gb` | none, `32` | |

Every value is validated against a strict pattern before it reaches a shell script or the VM's first-boot configuration.

## What a kit contains

| File | Role |
| --- | --- |
| `main.bicep`, `main.parameters.json` | The whole deployment: network, NSG, public IP, VM (Trusted Launch), Premium data disk, optional budget |
| `assets/` | Compose file, Caddyfile, systemd unit, and the on-VM scripts that format the disk and generate secrets |
| `deploy.sh` | Shows subscription, region, size and cost-bearing items, asks, deploys, waits for `/health` |
| `set-backend-key.sh`, `show-client-key.sh` | Move your provider key onto the VM, and read the generated client key back, over SSH stdin/stdout |
| `verify.sh` | Read-only end-to-end checks (TLS health, HTTP redirect, unauthenticated request refused) |
| `teardown.sh` | Deletes the resource group, **including the WAL disk**; requires typing the group name |
| `kit.env`, `SHA256SUMS`, `README.md` | Parameters (no secret), integrity, per-kit instructions |

## What the kit does not do

| Not done | Why |
| --- | --- |
| Put a secret or a subscription or tenant ID in any file | Secrets are generated on the VM at first boot with `openssl rand`; the kit scans itself for this |
| Back up the WAL disk | Snapshot policy is an operator decision; see [Backup and Restore](BACKUP_RESTORE.md) |
| Provide HA, multi-region or global ordering | One node, one chain |
| Use Key Vault or an HSM | Listed as the upgrade path; `REG-H08` tracks the decision |
| Establish capacity, availability or cost | See [Azure Benchmarks](../benchmarks/AZURE_BENCHMARKS.md) for what has actually been measured |
