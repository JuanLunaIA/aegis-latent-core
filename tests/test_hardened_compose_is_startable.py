# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The hardened compose file asks for everything strict startup needs, and the
container smoke test runs the image in the same posture (REG-D80, REG-D81).

The 2026-09-24 smoke test found that ``deploy/docker/docker-compose.yml`` could
not produce a serving gateway: it never supplied the identity key or principal
mapping strict mode refuses to start without, its only network was
``internal: true`` (no route to the upstream or Redis, no published port), and
the AppArmor profile it names granted no write to the ``/data`` WAL volume.
These checks keep the file, the profile and ``scripts/container_smoke_test.py``
(which CI runs under that profile) from drifting apart again.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

from aegis.config import AegisSettings

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "deploy/docker/docker-compose.yml"
PROFILE = ROOT / "deploy/apparmor/aegis.profile"
SMOKE = ROOT / "scripts/container_smoke_test.py"
DOCKERFILE = ROOT / "deploy/docker/Dockerfile"


def _service() -> dict[str, Any]:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    service: dict[str, Any] = compose["services"]["aegis"]
    return service


def _image_env() -> dict[str, str]:
    text = DOCKERFILE.read_text(encoding="utf-8")
    return dict(re.findall(r"^(?:ENV\s+|\s+)(AEGIS_[A-Z0-9_]+)=(\S+?)\s*\\?$", text, re.M))


def test_compose_supplies_every_value_strict_startup_requires() -> None:
    env = {**_image_env(), **{k: str(v) for k, v in _service()["environment"].items()}}
    assert env["AEGIS_SECURITY_ENFORCEMENT_MODE"] == "strict"
    # Every setting validate_runtime_invariants() demands in strict API-key mode.
    for name in (
        "AEGIS_API_KEYS",
        "AEGIS_SIGNING_KEY",
        "AEGIS_AUTH_IDENTITY_HMAC_KEY",
        "AEGIS_API_KEY_PRINCIPALS_JSON",
        "AEGIS_REDIS_URL",
        "AEGIS_BACKEND_URL",
        "AEGIS_BACKEND_API_KEY",
    ):
        assert name in env, f"compose never sets {name}; strict startup refuses without it"
        assert AegisSettings.model_fields.get(name.removeprefix("AEGIS_").lower()) is not None
    assert env["AEGIS_RATE_LIMIT_BACKEND"] == "redis"


def test_compose_network_can_reach_the_upstream_and_be_reached() -> None:
    compose = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    for name in _service().get("networks", []):
        assert not compose["networks"][name].get("internal"), (
            f"network {name} is internal: no egress to the upstream or Redis, no published port"
        )


def test_the_apparmor_profile_lets_the_image_write_its_wal() -> None:
    wal_path = {k: str(v) for k, v in _service()["environment"].items()}["AEGIS_WAL_PATH"]
    wal_dir = str(Path(wal_path).parent)
    profile = PROFILE.read_text(encoding="utf-8")
    assert re.search(rf"^\s*{re.escape(wal_dir)}/\*\* rw\w*k", profile, re.M), (
        f"{PROFILE.name} grants no read/write/lock under {wal_dir}, where compose keeps the WAL"
    )
    assert re.search(r"^\s*/usr/local/bin/\*\* \w*m\w*ix", profile, re.M), (
        "the profile must let the container run the image's interpreter"
    )
    name = re.search(r"^profile (\S+)", profile, re.M)
    assert name is not None
    assert f"apparmor={name.group(1)}" in _service()["security_opt"]


def test_the_smoke_test_runs_the_compose_posture() -> None:
    service = _service()
    smoke = SMOKE.read_text(encoding="utf-8")
    assert service["read_only"] is True
    assert '"--read-only"' in smoke
    assert service["cap_drop"] == ["ALL"]
    assert '"--cap-drop", "ALL"' in smoke
    assert "no-new-privileges:true" in service["security_opt"]
    assert '"no-new-privileges:true"' in smoke
    for tmpfs in service["tmpfs"]:
        assert f'"{tmpfs}"' in smoke, f"smoke test does not mount tmpfs {tmpfs} as compose does"
    for volume in service["volumes"]:
        target = volume.split(":", 1)[1]
        assert f':{target}"' in smoke, f"smoke test does not mount {target} as compose does"
