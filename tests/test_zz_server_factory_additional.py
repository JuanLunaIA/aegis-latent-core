# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Additional server factory tests for missing vault/postgres/dynamo paths."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock

import pytest

# ── sys.modules stubs for optional backends ───────────────────────────────────

# hvac stub (must be before import of vault_signer)
if "hvac" not in sys.modules:
    _hvac_exc = MagicMock()
    _hvac_exc.Forbidden = type("Forbidden", (Exception,), {})
    _hvac_exc.VaultNotInitialized = type("VaultNotInitialized", (Exception,), {})
    _hvac_exc.VaultError = type("VaultError", (Exception,), {})
    _hvac_mod = MagicMock()
    _hvac_mod.exceptions = _hvac_exc
    sys.modules["hvac"] = _hvac_mod
    sys.modules["hvac.exceptions"] = _hvac_exc

# asyncpg stub
if "asyncpg" not in sys.modules:
    sys.modules["asyncpg"] = MagicMock()

# aioboto3 / boto3 stubs
if "aioboto3" not in sys.modules:
    sys.modules["aioboto3"] = MagicMock()
if "boto3" not in sys.modules:
    sys.modules["boto3"] = MagicMock()
if "boto3.dynamodb" not in sys.modules:
    sys.modules["boto3.dynamodb"] = MagicMock()
if "boto3.dynamodb.conditions" not in sys.modules:
    _cond = MagicMock()
    _cond.Key = MagicMock()
    sys.modules["boto3.dynamodb.conditions"] = _cond
if "botocore" not in sys.modules:
    sys.modules["botocore"] = MagicMock()
if "botocore.exceptions" not in sys.modules:
    _botocore_exc = MagicMock()
    sys.modules["botocore.exceptions"] = _botocore_exc

from aegis_server.config import EnterpriseSettings  # noqa: E402
from aegis_server.crypto import get_signer  # noqa: E402
from aegis_server.storage import get_provider as get_storage  # noqa: E402


def _enterprise_settings(**kwargs) -> EnterpriseSettings:
    defaults = {
        "signer_provider": "hmac",
        "hmac_signing_key": "a" * 32,
        "storage_provider": "sqlite",
        "sqlite_path": "/tmp/test.db",
    }
    defaults.update(kwargs)
    return EnterpriseSettings(**defaults)


# ── aegis_server.crypto __getattr__ — VaultSigner (lines 45-47) ──────────────


def test_crypto_getattr_vault_signer_returns_class():
    """__getattr__('VaultSigner') imports and returns VaultSigner class (45-47)."""
    import aegis_server.crypto as crypto_mod
    VaultSigner = crypto_mod.__getattr__("VaultSigner")
    assert VaultSigner.__name__ == "VaultSigner"


# ── get_signer — vault path (lines 72-74) ────────────────────────────────────


def test_get_signer_vault_path_returns_vault_signer():
    """signer_provider='vault' → imports VaultSigner (lines 72-74)."""
    from aegis_server.crypto.vault_signer import VaultSigner

    settings = _enterprise_settings(
        signer_provider="vault",
        vault_url="http://localhost:8200",
        vault_transit_key="aegis-key",
        vault_token="test-token",
    )

    signer = get_signer(settings)
    assert isinstance(signer, VaultSigner)


# ── get_storage — postgres path (lines 79-81) ────────────────────────────────


def test_get_storage_postgres_path():
    """storage_provider='postgres' → imports PostgreSQLStorageProvider (79-81)."""
    from aegis_server.storage.postgres_provider import PostgreSQLStorageProvider

    settings = _enterprise_settings(
        storage_provider="postgres",
        postgres_dsn="postgresql://user:pass@localhost:5432/aegis",
    )

    provider = get_storage(settings)
    assert isinstance(provider, PostgreSQLStorageProvider)


# ── get_storage — dynamodb path (lines 88-90) ────────────────────────────────


def test_get_storage_dynamodb_path():
    """storage_provider='dynamodb' → imports DynamoDBStorageProvider (88-90)."""
    from aegis_server.storage.dynamodb_provider import DynamoDBStorageProvider

    settings = _enterprise_settings(
        storage_provider="dynamodb",
        dynamodb_table="aegis-audit",
        dynamodb_region="us-east-1",
    )

    provider = get_storage(settings)
    assert isinstance(provider, DynamoDBStorageProvider)
