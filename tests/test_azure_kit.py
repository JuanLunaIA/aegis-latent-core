# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Deterministic checks for the Azure VM kit and its kit creator (no Azure access)."""

from __future__ import annotations

import importlib.util
import re
import shutil
import subprocess
import sys
from pathlib import Path
from types import ModuleType

import pytest
import yaml

ROOT = Path(__file__).parents[1]
AZURE = ROOT / "deploy/azure"
VM = AZURE / "vm"
PUBKEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLEEXAMPLE test"


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "aegis_azure_kit", AZURE / "kit-creator/aegis_azure_kit.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # dataclasses resolves annotations through sys.modules
    spec.loader.exec_module(module)
    return module


kit = _load()


@pytest.fixture
def pubkey(tmp_path: Path) -> Path:
    path = tmp_path / "id.pub"
    path.write_text(PUBKEY + "\n")
    return path


def _create(tmp_path: Path, pubkey: Path, *extra: str) -> Path:
    args = kit.build_parser().parse_args(
        [
            "create",
            "--yes",
            "--name",
            "demo",
            "--region",
            "eastus",
            "--ssh-key",
            str(pubkey),
            "--ssh-source",
            "none",
            "--out",
            str(tmp_path / "out"),
            *extra,
        ]
    )
    return kit.create_kit(args)


def test_create_writes_complete_kit_that_verifies(tmp_path: Path, pubkey: Path) -> None:
    out = _create(tmp_path, pubkey, "--budget", "50", "--email", "ops@example.com")
    names = {p.relative_to(out).as_posix() for p in out.rglob("*") if p.is_file()}
    for required in (
        "main.bicep",
        "main.parameters.json",
        "kit.env",
        "deploy.sh",
        "verify.sh",
        "teardown.sh",
        "set-backend-key.sh",
        "show-client-key.sh",
        "README.md",
        "SHA256SUMS",
        "assets/cloud-init.yaml",
        "assets/docker-compose.yml",
    ):
        assert required in names
    assert all(c.status == "PASS" for c in kit.verify_kit(out))


def test_verify_detects_tampering_and_secrets(tmp_path: Path, pubkey: Path) -> None:
    out = _create(tmp_path, pubkey)
    (out / "deploy.sh").write_text((out / "deploy.sh").read_text() + "# x\n")
    assert any(c.status == "FAIL" and c.name == "checksums" for c in kit.verify_kit(out))
    kit._write_sums(out)
    (out / "extra.txt").write_text("subscription 00000000-1111-2222-3333-444444444444")
    statuses = {c.name: c.status for c in kit.verify_kit(out)}
    assert statuses["unlisted files"] == "FAIL"
    kit._write_sums(out)
    assert {c.name: c.status for c in kit.verify_kit(out)}["secret scan"] == "FAIL"


def test_kit_env_is_shell_safe_and_scripts_parse(tmp_path: Path, pubkey: Path) -> None:
    out = _create(tmp_path, pubkey)
    for script in [
        *out.glob("*.sh"),
        *(out / "assets").glob("aegis-*"),
        AZURE / "phase0/phase0_guardrails.sh",
    ]:
        subprocess.run(["bash", "-n", str(script)], check=True)  # noqa: S603
    probe = subprocess.run(  # noqa: S603
        ["bash", "-c", f". {out}/kit.env && echo $RG $SSH_SOURCE"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert probe.stdout.split() == ["demo-rg", "none"]


@pytest.mark.parametrize(
    ("flag", "value"),
    [
        ("--name", "Bad Name"),
        ("--region", "east us"),
        ("--vm-size", "B2"),
        ("--image", "img; rm -rf /"),
        ("--backend-url", "http://plain.example"),
        ("--backend-url", "https://a.example/x y"),
        ("--ssh-source", "0.0.0.0/0"),
        ("--ssh-source", "999.1.1.1/32"),
        ("--zone", "9"),
        ("--data-disk-gb", "1"),
        ("--provider", "nope"),
    ],
)
def test_create_rejects_unsafe_input(tmp_path: Path, pubkey: Path, flag: str, value: str) -> None:
    with pytest.raises(kit.KitError):
        _create(tmp_path, pubkey, flag, value)


def test_budget_needs_email_and_private_key_is_refused(tmp_path: Path, pubkey: Path) -> None:
    with pytest.raises(kit.KitError):
        _create(tmp_path, pubkey, "--budget", "10")
    private = tmp_path / "id"
    private.write_text(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n"
    )
    with pytest.raises(kit.KitError, match="PRIVATE"):
        kit.read_public_key(private)


def test_refuses_nonempty_output_and_aks_profile(tmp_path: Path, pubkey: Path) -> None:
    _create(tmp_path, pubkey)
    with pytest.raises(kit.KitError, match="not empty"):
        _create(tmp_path, pubkey)
    with pytest.raises(kit.KitError, match="aks"):
        _create(tmp_path / "other", pubkey, "--profile", "aks")


def test_doctor_offline_makes_no_azure_call(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(kit, "_az", lambda *a: (_ for _ in ()).throw(AssertionError("az called")))
    checks = kit.doctor("eastus", "Standard_B2als_v2", None, offline=True)
    assert {c.status for c in checks} <= {"PASS", "SKIP"}


def test_parameters_file_matches_bicep_params(tmp_path: Path, pubkey: Path) -> None:
    out = _create(tmp_path, pubkey)
    bicep = (out / "main.bicep").read_text()
    declared = set(re.findall(r"^param (\w+) ", bicep, re.M))
    supplied = set(
        __import__("json").loads((out / "main.parameters.json").read_text())["parameters"]
    )
    assert supplied <= declared
    required = set(re.findall(r"^param (\w+) \w+$", bicep, re.M))  # no default value
    assert required <= supplied | {"sshSourceCidr"}


def test_bicep_takes_no_secret_parameter() -> None:
    bicep = (VM / "main.bicep").read_text()
    assert "@secure" not in bicep
    assert (
        not re.search(r"param \w*(key|secret|password|token)\w* ", bicep, re.I | re.M)
        or "sshPublicKey" in bicep
    )
    assert len(re.findall(r"^param \w*(?:secret|password|token)\w* ", bicep, re.I | re.M)) == 0


def test_cloud_init_renders_to_valid_yaml_and_fits_customdata_limit() -> None:
    import base64

    bicep = (VM / "main.bicep").read_text()
    text = (VM / "assets/cloud-init.yaml").read_text()
    b64_assets = {
        "__COMPOSE_B64__": "docker-compose.yml",
        "__CADDY_B64__": "Caddyfile",
        "__UNIT_B64__": "aegis.service",
        "__DISK_B64__": "aegis-prepare-disk",
        "__SECRETS_B64__": "aegis-bootstrap-secrets",
        "__SETKEY_B64__": "aegis-set-backend-key",
        "__SHOWKEY_B64__": "aegis-show-client-key",
    }
    for placeholder, asset in b64_assets.items():
        assert f"'{placeholder}'" in bicep  # Bicep wires every placeholder
        assert f"assets/{asset}" in bicep
        text = text.replace(
            placeholder, base64.b64encode((VM / "assets" / asset).read_bytes()).decode()
        )
    for plain, value in {
        "__IMAGE__": "ghcr.io/x/y:1",
        "__FQDN__": "a.eastus.cloudapp.azure.com",
        "__PROVIDER__": "openai",
        "__BACKEND_URL__": "https://api.openai.com",
    }.items():
        text = text.replace(plain, value)
    assert not re.search(r"__[A-Z0-9_]+__", text)
    doc = yaml.safe_load(text)
    assert {f["path"] for f in doc["write_files"]} >= {
        "/opt/aegis/docker-compose.yml",
        "/etc/aegis/kit.env",
    }
    assert len(base64.b64encode(text.encode())) < 60_000  # Azure customData limit is 64 KiB


def test_compose_keeps_strict_posture_and_does_not_publish_redis() -> None:
    compose = yaml.safe_load((VM / "assets/docker-compose.yml").read_text())
    aegis, redis, caddy = (compose["services"][n] for n in ("aegis", "redis", "caddy"))
    env = aegis["environment"]
    assert env["AEGIS_SECURITY_ENFORCEMENT_MODE"] == "strict"
    assert env["AEGIS_REQUIRE_DURABLE_EVIDENCE"] == "true"
    assert env["AEGIS_REQUIRE_LSM"] == "true"
    assert env["AEGIS_REQUIRE_SECCOMP"] == "true"
    assert env["AEGIS_WORKERS"] == "1"  # one writer per WAL path
    assert aegis["read_only"] is True
    assert aegis["cap_drop"] == ["ALL"]
    assert "ports" not in aegis
    assert "ports" not in redis
    assert compose["networks"]["backend"]["internal"] is True
    assert redis["networks"] == ["backend"]
    assert set(caddy["ports"]) == {"80:80", "443:443"}
    assert "seccomp=unconfined" not in str(aegis["security_opt"])


def test_bootstrap_secrets_env_names_are_read_by_the_gateway_chart() -> None:
    script = (VM / "assets/aegis-bootstrap-secrets").read_text()
    chart = (ROOT / "deploy/helm/templates/statefulset.yaml").read_text()
    for var in re.findall(r'echo "(AEGIS_[A-Z_]+)=', script):
        assert f"name: {var}" in chart, var
    assert "docker run --rm -i -e AEGIS_AUTH_IDENTITY_HMAC_KEY" in script  # key never in argv
    assert "-x" not in script.split("\n")[1]  # no xtrace that would print secrets


def test_no_owner_identifiers_in_kit_sources() -> None:
    guid = re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I)
    for path in [
        *VM.rglob("*"),
        *(AZURE / "phase0").rglob("*"),
        *(AZURE / "kit-creator").rglob("*"),
    ]:
        if path.is_file() and path.suffix != ".pyc":
            assert not guid.search(path.read_text()), path


@pytest.mark.skipif(shutil.which("az") is None, reason="Azure CLI not installed")
def test_bicep_compiles() -> None:
    for bicep in (VM / "main.bicep", AZURE / "phase0/budget.bicep"):
        result = subprocess.run(  # noqa: S603
            ["az", "bicep", "build", "--file", str(bicep), "--stdout"],
            capture_output=True,
            text=True,
        )
        if "Bicep CLI not found" in result.stderr:
            pytest.skip("Bicep CLI not installed")
        assert result.returncode == 0, result.stderr
