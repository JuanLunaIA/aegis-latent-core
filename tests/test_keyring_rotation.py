# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import asyncio
import json
import os
import time

import pytest

from aegis_server.crypto.keyring import KeyringConfigurationError, RotatingHMACSigner

KEY_OLD = "o" * 64
KEY_NEW = "n" * 64


def write_keyring(path, active_key_id="key-new", keys=None):
    payload = {
        "version": 1,
        "active_key_id": active_key_id,
        "keys": keys
        or [
            {"key_id": "key-old", "secret": KEY_OLD, "state": "verify"},
            {"key_id": "key-new", "secret": KEY_NEW, "state": "active"},
        ],
    }
    path.write_text(json.dumps(payload, sort_keys=True), encoding="utf-8")
    os.chmod(path, 0o600)


def test_initial_load_exposes_active_key_id(tmp_path):
    path = tmp_path / "keyring.json"
    write_keyring(path)
    signer = RotatingHMACSigner(str(path), reload_interval_s=0)
    assert signer.current_key_id == "key-new"
    assert signer.reload_failures == 0


def test_sign_and_verify_accepts_active_and_overlap_keys(tmp_path):
    path = tmp_path / "keyring.json"
    write_keyring(path)
    signer = RotatingHMACSigner(str(path), reload_interval_s=0)

    async def exercise():
        signature, key_id = await signer.sign_payload_with_metadata(b"payload")
        assert key_id == "key-new"
        assert await signer.verify(b"payload", signature)

        old_signer = RotatingHMACSigner(
            str(path),
            reload_interval_s=0,
        )
        old_signer._snapshot = old_signer._validate_snapshot(
            {
                "version": 1,
                "active_key_id": "key-old",
                "keys": [
                    {"key_id": "key-old", "secret": KEY_OLD, "state": "active"},
                ],
            },
            (0, 0, 0),
        )
        old_signature = await old_signer.sign_payload(b"payload")
        assert await signer.verify(b"payload", old_signature)

    asyncio.run(exercise())


def test_atomic_reload_retains_previous_snapshot_on_invalid_file(tmp_path):
    path = tmp_path / "keyring.json"
    write_keyring(path)
    signer = RotatingHMACSigner(str(path), reload_interval_s=0)
    path.write_text('{"version": 1, "active_key_id": "key-new", "keys": [}', encoding="utf-8")
    assert signer.current_key_id == "key-new"
    assert signer.reload_failures == 1


def test_reload_switches_active_key_without_restart(tmp_path):
    path = tmp_path / "keyring.json"
    write_keyring(path)
    signer = RotatingHMACSigner(str(path), reload_interval_s=0)
    write_keyring(
        path,
        active_key_id="key-rotated",
        keys=[
            {
                "key_id": "key-new",
                "secret": KEY_NEW,
                "state": "verify",
                "expires_at": time.time() + 60,
            },
            {"key_id": "key-rotated", "secret": "r" * 64, "state": "active"},
        ],
    )
    assert signer.current_key_id == "key-rotated"


def test_expired_overlap_key_is_not_accepted(tmp_path):
    path = tmp_path / "keyring.json"
    write_keyring(
        path,
        active_key_id="key-new",
        keys=[
            {
                "key_id": "key-old",
                "secret": KEY_OLD,
                "state": "verify",
                "expires_at": time.time() - 1,
            },
            {"key_id": "key-new", "secret": KEY_NEW, "state": "active"},
        ],
    )
    signer = RotatingHMACSigner(str(path), reload_interval_s=0)

    async def exercise():
        old_signer = RotatingHMACSigner(str(path), reload_interval_s=300)
        old_signer._snapshot = old_signer._validate_snapshot(
            {
                "version": 1,
                "active_key_id": "key-old",
                "keys": [{"key_id": "key-old", "secret": KEY_OLD, "state": "active"}],
            },
            (0, 0, 0),
        )
        old_signature = await old_signer.sign_payload(b"payload")
        assert not await signer.verify(b"payload", old_signature)

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"version": 2, "active_key_id": "key-new", "keys": []},
        {
            "version": 1,
            "active_key_id": "key-new",
            "keys": [{"key_id": "key-new", "secret": "weak", "state": "active"}],
        },
        {
            "version": 1,
            "active_key_id": "key-new",
            "keys": [{"key_id": "bad space", "secret": KEY_NEW, "state": "active"}],
        },
    ],
)
def test_invalid_initial_keyring_is_blocking(tmp_path, payload):
    path = tmp_path / "keyring.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    with pytest.raises(KeyringConfigurationError):
        RotatingHMACSigner(str(path))


def test_initial_load_rejects_group_or_other_readable_keyring(tmp_path):
    path = tmp_path / "keyring.json"
    write_keyring(path)
    os.chmod(path, 0o640)
    with pytest.raises(KeyringConfigurationError, match="initial keyring load failed"):
        RotatingHMACSigner(str(path))
