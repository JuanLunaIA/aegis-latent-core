# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis_server.config — EnterpriseSettings validation and factory."""

from __future__ import annotations

import os

import pytest

from aegis_server.config import EnterpriseSettings


def _settings(**overrides) -> EnterpriseSettings:
    """Create EnterpriseSettings with safe defaults for testing."""
    defaults: dict = {
        "api_keys": "test-key-a,test-key-b",
        "storage_provider": "sqlite",
        "signer_provider": "hmac",
    }
    defaults.update(overrides)
    return EnterpriseSettings(**defaults)


# ── default values ────────────────────────────────────────────────────────────


def test_default_host():
    s = _settings()
    assert s.host == "0.0.0.0"


def test_default_port():
    s = _settings()
    assert s.port == 8080


def test_default_workers():
    s = _settings()
    assert s.workers == 1


def test_default_log_level():
    s = _settings()
    assert s.log_level == "INFO"


def test_default_storage_provider():
    s = _settings()
    assert s.storage_provider == "sqlite"


def test_default_sqlite_path():
    s = _settings()
    assert s.sqlite_path == "./aegis_audit.db"


def test_default_signer_provider():
    s = _settings()
    assert s.signer_provider == "hmac"


def test_default_compliance_export_dir():
    s = _settings()
    assert s.compliance_export_dir == "./aegis_exports"


# ── get_api_keys ──────────────────────────────────────────────────────────────


def test_get_api_keys_parses_csv():
    s = _settings(api_keys="key-a,key-b,key-c")
    keys = s.get_api_keys()
    assert keys == {"key-a", "key-b", "key-c"}


def test_get_api_keys_strips_whitespace():
    s = _settings(api_keys="  key-a , key-b  ")
    keys = s.get_api_keys()
    assert "key-a" in keys
    assert "key-b" in keys


def test_get_api_keys_empty_returns_empty_set():
    s = _settings(api_keys="")
    assert s.get_api_keys() == set()


def test_get_api_keys_filters_empty_entries():
    s = _settings(api_keys="key-a,,key-b,")
    keys = s.get_api_keys()
    assert "" not in keys
    assert len(keys) == 2


# ── get_audit_api_keys ────────────────────────────────────────────────────────


def test_get_audit_api_keys_uses_audit_keys_when_set():
    s = _settings(api_keys="proxy-key", audit_api_keys="audit-key")
    audit_keys = s.get_audit_api_keys()
    assert "audit-key" in audit_keys
    assert "proxy-key" not in audit_keys


def test_get_audit_api_keys_falls_back_to_api_keys():
    s = _settings(api_keys="proxy-key", audit_api_keys="")
    audit_keys = s.get_audit_api_keys()
    assert "proxy-key" in audit_keys


def test_get_audit_api_keys_empty_when_both_empty():
    s = _settings(api_keys="", audit_api_keys="")
    assert s.get_audit_api_keys() == set()


# ── validators ────────────────────────────────────────────────────────────────


def test_postgres_dsn_required_for_postgres_provider():
    with pytest.raises(ValueError, match="AEGIS_POSTGRES_DSN"):
        _settings(storage_provider="postgres", postgres_dsn="")


def test_postgres_dsn_accepted():
    s = _settings(
        storage_provider="postgres",
        postgres_dsn="postgresql://user:pass@localhost:5432/aegis",
    )
    assert s.storage_provider == "postgres"


def test_vault_url_required_for_vault_signer():
    with pytest.raises(ValueError, match="AEGIS_VAULT_URL"):
        _settings(signer_provider="vault", vault_url="")


def test_vault_signer_requires_token_or_approle():
    with pytest.raises(ValueError, match="AEGIS_VAULT_TOKEN"):
        _settings(
            signer_provider="vault",
            vault_url="https://vault.example.com",
            vault_token="",
            vault_role_id="",
            vault_secret_id="",
        )


def test_vault_signer_with_token_accepted():
    s = _settings(
        signer_provider="vault",
        vault_url="https://vault.example.com",
        vault_token="s.abc123",
    )
    assert s.signer_provider == "vault"


def test_vault_signer_with_approle_accepted():
    s = _settings(
        signer_provider="vault",
        vault_url="https://vault.example.com",
        vault_token="",
        vault_role_id="role-id-x",
        vault_secret_id="secret-id-y",
    )
    assert s.signer_provider == "vault"


# ── field constraints ─────────────────────────────────────────────────────────


def test_port_range_constraint_low():
    with pytest.raises(Exception):
        _settings(port=0)


def test_port_range_constraint_high():
    with pytest.raises(Exception):
        _settings(port=65536)


def test_workers_must_be_at_least_1():
    with pytest.raises(Exception):
        _settings(workers=0)


def test_kl_alert_threshold_must_be_positive():
    with pytest.raises(Exception):
        _settings(kl_alert_threshold=0)


def test_top_logprobs_range():
    s = _settings(top_logprobs=10)
    assert s.top_logprobs == 10
    with pytest.raises(Exception):
        _settings(top_logprobs=21)


# ── log_level literal ─────────────────────────────────────────────────────────


def test_log_level_accepts_debug():
    s = _settings(log_level="DEBUG")
    assert s.log_level == "DEBUG"


def test_log_level_accepts_error():
    s = _settings(log_level="ERROR")
    assert s.log_level == "ERROR"


# ── api_keys strip validator ──────────────────────────────────────────────────


def test_api_keys_leading_trailing_whitespace_stripped():
    s = _settings(api_keys="  key-one  ")
    # Strip validator should process the raw string before splitting
    # get_api_keys then splits on comma — result depends on strip
    keys = s.get_api_keys()
    assert "key-one" in keys


# ── DynamoDB defaults ─────────────────────────────────────────────────────────


def test_dynamodb_default_table():
    s = _settings()
    assert s.dynamodb_table == "aegis-audit-nodes"


def test_dynamodb_default_region():
    s = _settings()
    assert s.dynamodb_region == "us-east-1"
