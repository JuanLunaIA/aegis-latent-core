# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Start-up licence posture (decision D6).

The source line is commercially licensed, so a production (strict) gateway must
carry a verified Ed25519 token. An evaluator gets 30 days with a warning on every
start; after that, or with ``AEGIS_LICENSE_MODE=required``, start is refused. A
token that is configured but bad refuses start in every mode: silently running
unlicensed would hide the mistake from the operator who meant to license it.
"""

from __future__ import annotations

import json

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from aegis.licensing.startup import (
    EVALUATION_SECONDS,
    StartupLicenseError,
    check_startup_license,
)
from tests.licensing.test_license_validator import _mint, _public_hex

KEY = Ed25519PrivateKey.generate()
NOW = 1_800_000_000


def _env(token: str | None = None) -> dict[str, str]:
    env = {"AEGIS_LICENSE_ROOT_PUBKEY": _public_hex(KEY)}
    if token is not None:
        env["AEGIS_LICENSE_TOKEN"] = token
    return env


def _check(tmp_path, env, *, mode="strict", license_mode="evaluation", now=NOW):
    return check_startup_license(
        enforcement_mode=mode,
        license_mode=license_mode,
        marker=tmp_path / "wal.evaluation.json",
        env=env,
        now=now,
    )


def test_valid_token_is_licensed_in_strict_and_required(tmp_path) -> None:
    result = _check(tmp_path, _env(_mint(KEY)), license_mode="required", now=None)
    assert result.status == "licensed"
    assert result.entitlement is not None
    assert result.entitlement.customer_id == "acme-corp"
    assert not (tmp_path / "wal.evaluation.json").exists()


@pytest.mark.parametrize("mode", ["strict", "development"])
def test_bad_token_refuses_start_in_every_mode(tmp_path, mode) -> None:
    other = Ed25519PrivateKey.generate()
    for token in (_mint(other), "not-a-token", _mint(KEY, ttl_seconds=-10)):
        with pytest.raises(StartupLicenseError):
            _check(tmp_path, _env(token), mode=mode, now=None)


def test_token_without_root_key_refuses_start(tmp_path) -> None:
    with pytest.raises(StartupLicenseError):
        _check(tmp_path, {"AEGIS_LICENSE_TOKEN": _mint(KEY)}, now=None)


def test_development_without_token_starts(tmp_path) -> None:
    assert _check(tmp_path, {}, mode="development").status == "development"


def test_required_without_token_refuses(tmp_path) -> None:
    with pytest.raises(StartupLicenseError):
        _check(tmp_path, {}, license_mode="required")


def test_evaluation_window_counts_from_the_first_strict_start(tmp_path) -> None:
    first = _check(tmp_path, {})
    assert first.status == "evaluation"
    assert first.evaluation_ends_at == NOW + EVALUATION_SECONDS
    later = _check(tmp_path, {}, now=NOW + EVALUATION_SECONDS - 1)
    assert later.evaluation_ends_at == NOW + EVALUATION_SECONDS, "the window does not restart"
    with pytest.raises(StartupLicenseError):
        _check(tmp_path, {}, now=NOW + EVALUATION_SECONDS)


@pytest.mark.parametrize("content", ["garbage", json.dumps({"started_at": NOW + 99}), "{}"])
def test_unreadable_or_future_marker_refuses(tmp_path, content) -> None:
    (tmp_path / "wal.evaluation.json").write_text(content)
    with pytest.raises(StartupLicenseError):
        _check(tmp_path, {})
