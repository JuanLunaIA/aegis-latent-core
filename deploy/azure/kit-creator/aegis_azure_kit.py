#!/usr/bin/env python3
# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Aegis Azure Kit Creator: generate a ready-to-deploy Azure kit for the gateway.

Commands
--------
``doctor``    Preflight: Azure CLI, login, providers, VM SKU availability, DNS label.
``create``    Write a self-contained kit directory (Bicep + scripts + README).
``verify``    Check a kit's SHA256SUMS and scan it for secret-shaped content.
``estimate``  Fetch the live retail price of the VM size from prices.azure.com.

The kit contains no secret and no subscription or tenant identifier. Every secret is
generated on the VM at first boot (``vm/assets/aegis-bootstrap-secrets``). Nothing here
touches Azure except ``doctor`` (read-only ``az`` calls) and ``estimate`` (a public,
unauthenticated HTTPS GET). ``create`` is purely local.

Only the ``vm`` profile is automated. ``aks`` is refused with an explanation: the AKS path
in ``deploy/azure/aks`` depends on pre-provisioned ACR/Key Vault/identity resources.

Standard library only; Python 3.9+.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import secrets
import shlex
import shutil
import subprocess
import sys
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path

VM_SOURCE = Path(__file__).resolve().parents[1] / "vm"
DEFAULT_IMAGE = "ghcr.io/juanlunaia/aegis-latent-core:5.0.1"
PROVIDERS = ("openai", "anthropic", "gemini", "openrouter")
REQUIRED_PROVIDERS = ("Microsoft.Compute", "Microsoft.Network", "Microsoft.Storage")

_NAME = re.compile(r"^[a-z][a-z0-9-]{2,19}$")
_LABEL = re.compile(r"^[a-z][a-z0-9-]{1,38}[a-z0-9]$")
_REGION = re.compile(r"^[a-z0-9]{3,30}$")
_SIZE = re.compile(r"^Standard_[A-Za-z0-9_]{2,40}$")
_IMAGE = re.compile(r"^[a-z0-9][a-z0-9./_-]*(:[A-Za-z0-9_.-]+|@sha256:[0-9a-f]{64})$")
_URL = re.compile(r"^https://[A-Za-z0-9.-]+(:[0-9]{2,5})?(/[A-Za-z0-9._~/-]*)?$")
_EMAIL = re.compile(r"^[^@\s'\"$`\\]+@[^@\s'\"$`\\]+$")
_CIDR = re.compile(r"^(\d{1,3}\.){3}\d{1,3}/\d{1,2}$")
_GUID = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
_SECRET_SHAPES = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
)


class KitError(Exception):
    """A user-facing failure: bad input, missing tool, or a failed check."""


@dataclass(frozen=True)
class Check:
    name: str
    status: str  # PASS | FAIL | WARN | SKIP
    detail: str


# ── validation ────────────────────────────────────────────────────────────────


def _require(pattern: re.Pattern[str], value: str, what: str) -> str:
    if not pattern.match(value):
        raise KitError(f"invalid {what}: {value!r}")
    return value


def validate_ssh_source(value: str) -> str:
    if value in {"auto", "none"}:
        return value
    if not _CIDR.match(value) or any(int(o) > 255 for o in value.split("/")[0].split(".")):
        raise KitError(f"invalid --ssh-source (want auto, none or an IPv4 CIDR): {value!r}")
    if int(value.split("/")[1]) > 32:
        raise KitError(f"invalid CIDR prefix: {value!r}")
    if value.startswith("0.0.0.0/0"):
        raise KitError("--ssh-source 0.0.0.0/0 would expose SSH to the whole internet; refused")
    return value


def read_public_key(path: Path) -> str:
    try:
        text = path.expanduser().read_text().strip()
    except OSError as exc:
        raise KitError(f"cannot read SSH public key {path}: {exc.strerror}") from exc
    if "PRIVATE KEY" in text:
        raise KitError(f"{path} is a PRIVATE key; pass the .pub file")
    if not re.match(r"^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp\d+) [A-Za-z0-9+/=]+( .*)?$", text):
        raise KitError(f"{path} does not look like an SSH public key")
    return text


# ── az helpers ────────────────────────────────────────────────────────────────


def _az(*args: str) -> object:
    try:
        out = subprocess.run(  # noqa: S603 - argv list, no shell, fixed 'az' verb
            ["az", *args, "-o", "json"], capture_output=True, text=True, timeout=600, check=True
        ).stdout
    except (OSError, subprocess.SubprocessError) as exc:
        detail = getattr(exc, "stderr", "") or str(exc)
        raise KitError(detail.strip().splitlines()[-1] if detail.strip() else "az failed") from exc
    return json.loads(out) if out.strip() else None


def doctor(region: str, vm_size: str, dns_label: str | None, offline: bool) -> list[Check]:
    checks: list[Check] = []
    checks.append(
        Check(
            "python",
            "PASS" if sys.version_info >= (3, 9) else "FAIL",
            sys.version.split()[0],
        )
    )
    if offline:
        return [*checks, Check("azure checks", "SKIP", "--offline")]
    if shutil.which("az") is None:
        return [*checks, Check("azure cli", "FAIL", "install: https://aka.ms/installazurecli")]
    checks.append(Check("azure cli", "PASS", "found"))
    try:
        acct = _az("account", "show")
    except KitError:
        return [*checks, Check("azure login", "FAIL", "run: az login")]
    assert isinstance(acct, dict)
    state = str(acct.get("state"))
    checks.append(
        Check(
            "subscription",
            "PASS" if state == "Enabled" else "FAIL",
            f"{acct.get('name')} ({state})",
        )
    )
    try:
        provs = _az("provider", "list", "--query", "[].{n:namespace,s:registrationState}")
        registered = {p["n"] for p in provs if p["s"] == "Registered"}  # type: ignore[union-attr,index]
        for ns in REQUIRED_PROVIDERS:
            checks.append(
                Check(
                    f"provider {ns}",
                    "PASS" if ns in registered else "WARN",
                    "Registered" if ns in registered else f"az provider register -n {ns}",
                )
            )
    except KitError as exc:
        checks.append(Check("providers", "WARN", str(exc)))
    try:
        skus = _az(
            "vm", "list-skus", "-l", region, "--size", vm_size, "--resource-type", "virtualMachines"
        )
        if not skus:
            checks.append(
                Check(
                    "vm size",
                    "FAIL",
                    f"{vm_size} is not offered to this subscription in {region} (try another size or region)",
                )
            )
        else:
            restrictions = skus[0].get("restrictions") or []  # type: ignore[index,union-attr]
            if restrictions:
                reasons = sorted({r.get("reasonCode", "?") for r in restrictions})
                checks.append(
                    Check(
                        "vm size", "FAIL", f"{vm_size} restricted in {region}: {', '.join(reasons)}"
                    )
                )
            else:
                zones = skus[0].get("locationInfo", [{}])[0].get("zones", [])  # type: ignore[index,union-attr]
                checks.append(
                    Check(
                        "vm size",
                        "PASS",
                        f"{vm_size} available in {region}; zones {zones or 'none'}",
                    )
                )
    except KitError as exc:
        checks.append(Check("vm size", "WARN", str(exc)))
    if dns_label:
        try:
            sub = str(acct.get("id"))
            url = (
                f"https://management.azure.com/subscriptions/{sub}/providers/Microsoft.Network/"
                f"locations/{region}/CheckDnsNameAvailability?domainNameLabel={dns_label}"
                "&api-version=2023-09-01"
            )
            free = _az("rest", "--method", "get", "--url", url)
            ok = bool(free and free.get("available"))  # type: ignore[union-attr]
            checks.append(
                Check(
                    "dns label",
                    "PASS" if ok else "FAIL",
                    f"{dns_label}.{region}.cloudapp.azure.com",
                )
            )
        except KitError as exc:
            checks.append(Check("dns label", "WARN", str(exc)))
    return checks


def estimate(region: str, vm_size: str) -> str:
    flt = (
        f"serviceName eq 'Virtual Machines' and armRegionName eq '{region}' "
        f"and armSkuName eq '{vm_size}' and priceType eq 'Consumption'"
    )
    url = "https://prices.azure.com/api/retail/prices?" + urllib.parse.urlencode({"$filter": flt})
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:  # noqa: S310 - fixed https host
            items = json.load(resp).get("Items", [])
    except (OSError, ValueError) as exc:
        raise KitError(f"could not reach prices.azure.com: {exc}") from exc
    linux = [
        i
        for i in items
        if "Windows" not in i.get("productName", "")
        and "Spot" not in i.get("skuName", "")
        and "Low Priority" not in i.get("skuName", "")
    ]
    if not linux:
        raise KitError(f"no retail price found for {vm_size} in {region}")
    hourly = min(float(i["retailPrice"]) for i in linux)
    return (
        f"{vm_size} in {region}: {hourly:.4f} USD/hour retail list price "
        f"(~{hourly * 730:.2f} USD/month at 730 h). Source: prices.azure.com, fetched now. "
        "Excludes the data disk, OS disk, public IP, bandwidth and any discount or credit."
    )


# ── create / verify ───────────────────────────────────────────────────────────


def create_kit(opts: argparse.Namespace) -> Path:
    if opts.profile != "vm":
        raise KitError(
            "profile 'aks' is not automated: deploy/azure/aks/bootstrap.sh needs pre-provisioned "
            "ACR, Key Vault and managed identity. Use --profile vm, or follow "
            "docs/operations/AZURE_INSTALL_OPTIONS.md."
        )
    name = _require(_NAME, opts.name, "--name (3-20 chars: a-z 0-9 -, starts with a letter)")
    label = _require(_LABEL, opts.dns_label or f"{name}-{secrets.token_hex(3)}", "--dns-label")
    region = _require(_REGION, opts.region, "--region")
    size = _require(_SIZE, opts.vm_size, "--vm-size")
    image = _require(_IMAGE, opts.image, "--image")
    backend = _require(_URL, opts.backend_url, "--backend-url (https://host[:port][/path])")
    if opts.provider not in PROVIDERS:
        raise KitError(f"--provider must be one of {', '.join(PROVIDERS)}")
    if opts.zone not in {"", "1", "2", "3"}:
        raise KitError("--zone must be 1, 2, 3 or empty")
    if not 4 <= opts.data_disk_gb <= 1024:
        raise KitError("--data-disk-gb must be between 4 and 1024")
    ssh_source = validate_ssh_source(opts.ssh_source)
    budget = int(opts.budget or 0)
    if budget < 0:
        raise KitError("--budget must be >= 0")
    email = opts.email or ""
    if budget and not _EMAIL.match(email):
        raise KitError("--email is required (and must be an address) when --budget > 0")
    pubkey = read_public_key(Path(opts.ssh_key))

    out = Path(opts.out).expanduser().resolve() / name
    if out.exists() and any(out.iterdir()):
        raise KitError(f"{out} exists and is not empty; choose another --out or --name")
    out.mkdir(parents=True, exist_ok=True)

    shutil.copy2(VM_SOURCE / "main.bicep", out / "main.bicep")
    shutil.copytree(VM_SOURCE / "assets", out / "assets")
    for script in sorted((VM_SOURCE / "kit").glob("*.sh")):
        shutil.copy2(script, out / script.name)

    env = {
        "NAME": name,
        "RG": opts.resource_group or f"{name}-rg",
        "LOCATION": region,
        "DNS_LABEL": label,
        "VM_SIZE": size,
        "DATA_DISK_GB": str(opts.data_disk_gb),
        "ADMIN_USER": "azureuser",
        "SSH_SOURCE": ssh_source,
        "BUDGET_USD": str(budget),
        "BUDGET_EMAIL": email,
    }
    (out / "kit.env").write_text(
        "# Generated by aegis_azure_kit.py. Contains no secret.\n"
        + "".join(f"{k}={shlex.quote(v)}\n" for k, v in env.items())
    )
    params = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {
            "name": {"value": name},
            "location": {"value": region},
            "dnsLabel": {"value": label},
            "vmSize": {"value": size},
            "sshPublicKey": {"value": pubkey},
            "zone": {"value": opts.zone},
            "dataDiskGb": {"value": opts.data_disk_gb},
            "image": {"value": image},
            "provider": {"value": opts.provider},
            "backendUrl": {"value": backend},
            "budgetUsd": {"value": budget},
            "budgetEmail": {"value": email},
        },
    }
    (out / "main.parameters.json").write_text(json.dumps(params, indent=2) + "\n")
    (out / "README.md").write_text(_readme(env, image))
    _write_sums(out)
    return out


def _readme(env: dict[str, str], image: str) -> str:
    url = f"https://{env['DNS_LABEL']}.{env['LOCATION']}.cloudapp.azure.com"
    return f"""# Aegis Azure kit: {env["NAME"]}

Generated by `aegis_azure_kit.py`. Contains no secret and no subscription identifier.

| | |
|---|---|
| Resource group | `{env["RG"]}` ({env["LOCATION"]}) |
| VM | `{env["VM_SIZE"]}`, Ubuntu 24.04 LTS, Trusted Launch |
| WAL disk | {env["DATA_DISK_GB"]} GiB Premium SSD, ext4, one writer |
| URL | {url} |
| Image | `{image}` |

## Deploy

```bash
az login
./deploy.sh            # shows what it will create and asks before spending
./set-backend-key.sh   # your LLM provider key, over SSH stdin
./show-client-key.sh   # the API key clients use
./verify.sh            # read-only end-to-end checks
```

## Troubleshooting

- `az vm run-command invoke -g {env["RG"]} -n {env["NAME"]}-vm --command-id RunShellScript --scripts "cloud-init status --long; docker ps; journalctl -u aegis --no-pager | tail -50"`
- Certificate not issued: the DNS label must resolve to the VM and ports 80/443 must be reachable.
- `strict` startup refusal: read the container log; do not relax a strict setting to make it start.

## Delete everything

`./teardown.sh` deletes the resource group **and the WAL disk with its evidence**. Back up first.

Boundaries and trade-offs: `docs/operations/AZURE_INSTALL_OPTIONS.md` in the repository. This kit is
a source-baseline deployment; target acceptance of storage, network, identity and key custody is yours.
"""


def _write_sums(root: Path) -> None:
    lines = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS"):
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        lines.append(f"{digest}  {path.relative_to(root).as_posix()}\n")
    (root / "SHA256SUMS").write_text("".join(lines))


def verify_kit(root: Path) -> list[Check]:
    sums = root / "SHA256SUMS"
    if not sums.is_file():
        return [Check("SHA256SUMS", "FAIL", "missing")]
    checks: list[Check] = []
    listed: set[str] = set()
    bad = []
    for line in sums.read_text().splitlines():
        digest, _, rel = line.partition("  ")
        listed.add(rel)
        target = root / rel
        if not target.is_file() or hashlib.sha256(target.read_bytes()).hexdigest() != digest:
            bad.append(rel)
    extra = sorted(
        p.relative_to(root).as_posix()
        for p in root.rglob("*")
        if p.is_file() and p.name != "SHA256SUMS" and p.relative_to(root).as_posix() not in listed
    )
    checks.append(
        Check("checksums", "FAIL" if bad else "PASS", ", ".join(bad) or f"{len(listed)} files")
    )
    checks.append(Check("unlisted files", "FAIL" if extra else "PASS", ", ".join(extra) or "none"))
    findings = []
    for path in sorted(p for p in root.rglob("*") if p.is_file() and p.name != "SHA256SUMS"):
        text = path.read_text(errors="replace")
        if _GUID.search(text):
            findings.append(f"{path.relative_to(root)}: GUID (subscription/tenant id?)")
        for shape in _SECRET_SHAPES:
            if shape.search(text):
                findings.append(f"{path.relative_to(root)}: secret-shaped string")
    checks.append(
        Check("secret scan", "FAIL" if findings else "PASS", "; ".join(findings) or "clean")
    )
    return checks


# ── CLI ───────────────────────────────────────────────────────────────────────


def _print_checks(checks: list[Check]) -> int:
    for c in checks:
        print(f"{c.status:<5} {c.name}: {c.detail}")
    return 1 if any(c.status == "FAIL" for c in checks) else 0


def _ask(prompt: str, default: str) -> str:
    if not sys.stdin.isatty():
        return default
    reply = input(f"{prompt} [{default}]: ").strip()
    return reply or default


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="aegis_azure_kit", description=__doc__.split("\n\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("doctor", help="preflight checks (read-only az calls)")
    d.add_argument("--region", default="eastus")
    d.add_argument("--vm-size", default="Standard_B2als_v2")
    d.add_argument("--dns-label")
    d.add_argument("--offline", action="store_true", help="skip every Azure call")

    c = sub.add_parser("create", help="write a kit directory (local only)")
    c.add_argument("--profile", default="vm", choices=["vm", "aks"])
    c.add_argument("--name", default=None)
    c.add_argument("--region", default=None)
    c.add_argument("--dns-label", default=None)
    c.add_argument("--resource-group", default=None)
    c.add_argument("--vm-size", default="Standard_B2als_v2")
    c.add_argument("--zone", default="")
    c.add_argument("--data-disk-gb", type=int, default=32)
    c.add_argument("--image", default=DEFAULT_IMAGE)
    c.add_argument("--provider", default="openai")
    c.add_argument("--backend-url", default="https://api.openai.com")
    c.add_argument("--ssh-key", default="~/.ssh/id_ed25519.pub")
    c.add_argument("--ssh-source", default="auto", help="auto (your IP), none, or an IPv4 CIDR")
    c.add_argument("--budget", type=int, default=0, help="monthly USD budget alert; 0 disables")
    c.add_argument("--email", default="")
    c.add_argument("--out", default="./aegis-azure-kits")
    c.add_argument("--yes", action="store_true", help="never prompt; use defaults")

    v = sub.add_parser("verify", help="check a kit's checksums and scan it for secrets")
    v.add_argument("kit")

    e = sub.add_parser("estimate", help="live retail price for the VM size")
    e.add_argument("--region", default="eastus")
    e.add_argument("--vm-size", default="Standard_B2als_v2")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.cmd == "doctor":
            return _print_checks(doctor(args.region, args.vm_size, args.dns_label, args.offline))
        if args.cmd == "estimate":
            print(estimate(args.region, args.vm_size))
            return 0
        if args.cmd == "verify":
            return _print_checks(verify_kit(Path(args.kit)))
        if not args.yes:
            args.name = args.name or _ask("Kit name", "aegis")
            args.region = args.region or _ask("Azure region", "eastus")
        args.name = args.name or "aegis"
        args.region = args.region or "eastus"
        out = create_kit(args)
        print(f"kit written to {out}\nnext: cd {out} && ./deploy.sh")
        return 0
    except KitError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
