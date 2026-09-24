# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""``python -m aegis.auth.principal`` produces a mapping strict mode accepts (REG-D81).

Strict mode refuses to start unless every API key has an explicit principal
mapping keyed by an HMAC digest of the key — and nothing in the repository
produced one. The hardened compose file did not even ask for it, so following
it ended in "strict API-key mode requires an explicit principal mapping per
key". The generator uses the gateway's own digest and validation rules, so a
mapping it prints is one the gateway accepts, and one it refuses is one the
gateway would refuse.
"""

from __future__ import annotations

import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

import pytest

from aegis.auth.principal import build_api_key_principals
from aegis.config import AegisSettings

ROOT = Path(__file__).resolve().parents[1]
IDENTITY = secrets.token_hex(32)
GRANTS = {
    "sk-proxy-key": {
        "tenant_id": "hospital-a",
        "roles": ["proxy_user"],
        "scopes": ["proxy:completions"],
    },
    "sk-audit-key": {
        "tenant_id": "hospital-a",
        "roles": ["audit_reader"],
        "scopes": ["audit:read"],
    },
}


def _strict(mapping: dict[str, dict[str, object]]) -> AegisSettings:
    return AegisSettings(
        security_enforcement_mode="strict",
        backend_url="https://llm.example/v1",
        backend_api_key="sk-upstream",
        api_keys="sk-proxy-key,sk-audit-key",
        signing_key=secrets.token_hex(32),
        auth_identity_hmac_key=IDENTITY,
        api_key_principals_json=json.dumps(mapping),
        rate_limit_backend="redis",
        require_durable_evidence=True,
    )


def test_the_generated_mapping_satisfies_strict_startup() -> None:
    mapping = build_api_key_principals(IDENTITY, GRANTS)
    cfg = _strict(mapping)
    cfg.validate_runtime_invariants()
    assert set(mapping) == {cfg.api_key_principal_digest(key) for key in GRANTS}
    assert "sk-proxy-key" not in json.dumps(mapping)


def test_strict_startup_still_refuses_a_missing_entry() -> None:
    mapping = build_api_key_principals(IDENTITY, {"sk-proxy-key": GRANTS["sk-proxy-key"]})
    with pytest.raises(ValueError, match="explicit principal mapping"):
        _strict(mapping).validate_runtime_invariants()


@pytest.mark.parametrize(
    ("grant", "message"),
    [
        ({"tenant_id": "", "roles": ["proxy_user"], "scopes": []}, "tenant_id"),
        ({"tenant_id": "t", "roles": ["root"], "scopes": []}, "root"),
        ({"tenant_id": "t", "roles": ["proxy_user"], "scopes": ["audit:read"]}, "exceed"),
        ({"tenant_id": "t", "roles": ["proxy_user"], "scopes": ["everything"]}, "unsupported"),
    ],
)
def test_a_grant_the_gateway_would_refuse_is_refused_here(
    grant: dict[str, object], message: str
) -> None:
    with pytest.raises(ValueError, match=message):
        build_api_key_principals(IDENTITY, {"sk-x": grant})


def test_a_short_identity_key_is_refused() -> None:
    with pytest.raises(ValueError, match="at least 32 bytes"):
        build_api_key_principals("short", GRANTS)


def test_the_command_reads_stdin_and_never_prints_a_key() -> None:
    env = {**os.environ, "PYTHONPATH": str(ROOT), "AEGIS_AUTH_IDENTITY_HMAC_KEY": IDENTITY}
    ok = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-m", "aegis.auth.principal"],
        input=json.dumps(GRANTS),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert ok.returncode == 0, ok.stderr
    assert json.loads(ok.stdout) == build_api_key_principals(IDENTITY, GRANTS)
    assert "sk-proxy-key" not in ok.stdout + ok.stderr

    refused = subprocess.run(  # noqa: S603 - fixed argv
        [sys.executable, "-m", "aegis.auth.principal"],
        input=json.dumps({"sk-secret-value": {"tenant_id": "t", "roles": ["nope"]}}),
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    assert refused.returncode == 2
    assert "sk-secret-value" not in refused.stdout + refused.stderr
