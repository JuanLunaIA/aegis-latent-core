# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis_server.crypto and aegis_server.storage factory functions."""

from __future__ import annotations

import pytest

from aegis_server.crypto import LocalHMACSigner, SignerProvider, get_signer
from aegis_server.storage import StorageProvider, get_provider


# ── aegis_server.crypto.get_signer ───────────────────────────────────────────


def _enterprise_settings(**kwargs):
    from aegis_server.config import EnterpriseSettings

    defaults = {
        "api_keys": "test-key",
        "storage_provider": "sqlite",
        "signer_provider": "hmac",
    }
    defaults.update(kwargs)
    return EnterpriseSettings(**defaults)


def test_get_signer_hmac_returns_local_hmac_signer():
    settings = _enterprise_settings(
        signer_provider="hmac",
        hmac_signing_key="a" * 32,
    )
    signer = get_signer(settings)
    assert isinstance(signer, LocalHMACSigner)


def test_get_signer_hmac_missing_key_raises():
    settings = _enterprise_settings(
        signer_provider="hmac",
        hmac_signing_key="",
    )
    with pytest.raises(ValueError, match="AEGIS_HMAC_SIGNING_KEY"):
        get_signer(settings)


def test_get_signer_unknown_backend_raises():
    from unittest.mock import MagicMock

    settings = MagicMock()
    settings.signer_provider = "unknown_backend"
    with pytest.raises(ValueError, match="Unknown signer_provider"):
        get_signer(settings)


def test_get_signer_result_is_signer_provider():
    settings = _enterprise_settings(
        signer_provider="hmac",
        hmac_signing_key="x" * 32,
    )
    signer = get_signer(settings)
    assert isinstance(signer, SignerProvider)


# ── aegis_server.crypto __getattr__ ──────────────────────────────────────────


def test_crypto_getattr_unknown_raises():
    import aegis_server.crypto as crypto_mod

    with pytest.raises(AttributeError, match="has no attribute"):
        _ = crypto_mod.NonExistentSymbol


# ── aegis_server.storage.get_provider ────────────────────────────────────────


def test_get_provider_sqlite_returns_sqlite_provider():
    from aegis_server.storage.sqlite_provider import SQLiteStorageProvider

    settings = _enterprise_settings(
        storage_provider="sqlite",
        sqlite_path="./test_audit.db",
    )
    provider = get_provider(settings)
    assert isinstance(provider, SQLiteStorageProvider)


def test_get_provider_unknown_backend_raises():
    from unittest.mock import MagicMock

    settings = MagicMock()
    settings.storage_provider = "cassandra"
    with pytest.raises(ValueError, match="Unknown storage_provider"):
        get_provider(settings)


def test_get_provider_result_is_storage_provider():
    from aegis_server.storage.sqlite_provider import SQLiteStorageProvider

    settings = _enterprise_settings(storage_provider="sqlite")
    provider = get_provider(settings)
    assert isinstance(provider, StorageProvider)


# ── aegis_server.storage __getattr__ ─────────────────────────────────────────


def test_storage_getattr_sqlite_provider():
    import aegis_server.storage as storage_mod
    from aegis_server.storage.sqlite_provider import SQLiteStorageProvider

    resolved = storage_mod.SQLiteStorageProvider
    assert resolved is SQLiteStorageProvider


def test_storage_getattr_unknown_raises():
    import aegis_server.storage as storage_mod

    with pytest.raises(AttributeError, match="has no attribute"):
        _ = storage_mod.NoSuchProvider


# ── get_settings singleton ────────────────────────────────────────────────────


def test_get_settings_returns_enterprise_settings():
    # Clear the LRU cache first to avoid cross-test contamination
    from aegis_server.config import EnterpriseSettings, get_settings

    get_settings.cache_clear()
    result = get_settings()
    assert isinstance(result, EnterpriseSettings)


def test_get_settings_is_cached():
    from aegis_server.config import get_settings

    get_settings.cache_clear()
    r1 = get_settings()
    r2 = get_settings()
    assert r1 is r2
