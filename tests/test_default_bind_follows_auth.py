# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""An unauthenticated gateway does not listen on every interface by default (REG-D75).

The 2026-09-24 gatekeeper pass ran the README quickstart
(``AEGIS_AUTH_DISABLED=true``, "isolated local evaluation") and saw
``Uvicorn running on http://0.0.0.0:8080``: a forwarder holding the operator's
backend API key, with no credential check, reachable from the network. The
default now follows authentication; an explicit host always wins.
"""

from __future__ import annotations

import pytest

from aegis.config import AegisSettings

BASE = {"backend_api_key": "sk-test", "backend_url": "http://mock-upstream"}


def _settings(**overrides: object) -> AegisSettings:
    return AegisSettings(**{**BASE, **overrides})


def test_auth_disabled_without_an_explicit_host_binds_loopback() -> None:
    cfg = _settings(auth_disabled=True, debug_mode=True)
    assert cfg.host == "127.0.0.1"


def test_an_explicit_host_is_respected_even_with_auth_disabled() -> None:
    cfg = _settings(auth_disabled=True, debug_mode=True, host="0.0.0.0")
    assert cfg.host == "0.0.0.0"


def test_an_explicit_host_from_the_environment_is_respected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AEGIS_HOST", "0.0.0.0")
    cfg = _settings(auth_disabled=True, debug_mode=True)
    assert cfg.host == "0.0.0.0"


def test_authenticated_deployments_keep_the_all_interfaces_default() -> None:
    cfg = _settings(api_keys="sk-valid")
    assert cfg.host == "0.0.0.0"
