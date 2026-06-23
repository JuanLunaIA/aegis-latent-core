# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.hardware_token — Domain 1.2 hardware-bound session tokens."""

from __future__ import annotations

import dataclasses
import time

import pytest

from aegis.core.hardware_token import (
    HardwareToken,
    HardwareTokenError,
    HardwareTokenManager,
    TokenBackend,
    TokenValidationResult,
)

# ── Fixtures ──────────────────────────────────────────────────────────────────

_TEST_KEY = bytes.fromhex("a" * 64)  # 32-byte all-0xaa key — not a real secret
_TEST_KEY_HEX = "a" * 64


@pytest.fixture
def mgr() -> HardwareTokenManager:
    """Software-backend manager with a known test key."""
    return HardwareTokenManager(
        signing_key=_TEST_KEY,
        ttl_seconds=3600,
        backend=TokenBackend.SOFTWARE,
    )


@pytest.fixture
def token(mgr: HardwareTokenManager) -> HardwareToken:
    return mgr.issue(subject="user:alice", tenant_id="acme")


# ── issue() ───────────────────────────────────────────────────────────────────


class TestIssue:
    def test_returns_hardware_token(self, mgr: HardwareTokenManager) -> None:
        tok = mgr.issue(subject="user:alice", tenant_id="acme")
        assert isinstance(tok, HardwareToken)

    def test_token_id_is_uuid_string(self, token: HardwareToken) -> None:
        import uuid

        uuid.UUID(token.token_id)  # raises ValueError on invalid UUID

    def test_subject_preserved(self, mgr: HardwareTokenManager) -> None:
        tok = mgr.issue(subject="user:bob", tenant_id="acme")
        assert tok.subject == "user:bob"

    def test_tenant_id_preserved(self, mgr: HardwareTokenManager) -> None:
        tok = mgr.issue(subject="user:alice", tenant_id="tenant-x")
        assert tok.tenant_id == "tenant-x"

    def test_issued_at_is_recent(self, token: HardwareToken) -> None:
        assert abs(token.issued_at - time.time()) < 5

    def test_expires_at_is_ttl_after_issued(self, mgr: HardwareTokenManager) -> None:
        mgr2 = HardwareTokenManager(
            signing_key=_TEST_KEY, ttl_seconds=7200, backend=TokenBackend.SOFTWARE
        )
        tok = mgr2.issue(subject="u", tenant_id="t")
        assert abs((tok.expires_at - tok.issued_at) - 7200) < 1

    def test_backend_is_software(self, token: HardwareToken) -> None:
        assert token.backend is TokenBackend.SOFTWARE

    def test_attestation_data_is_bytes(self, token: HardwareToken) -> None:
        assert isinstance(token.attestation_data, bytes)

    def test_attestation_data_is_32_bytes(self, token: HardwareToken) -> None:
        # HMAC-SHA256 produces 32 bytes
        assert len(token.attestation_data) == 32

    def test_token_hash_is_hex_string(self, token: HardwareToken) -> None:
        assert isinstance(token.token_hash, str)
        bytes.fromhex(token.token_hash)  # raises ValueError on invalid hex

    def test_token_hash_is_64_hex_chars(self, token: HardwareToken) -> None:
        assert len(token.token_hash) == 64  # SHA-256 → 32 bytes → 64 hex chars

    def test_different_subjects_produce_different_tokens(self, mgr: HardwareTokenManager) -> None:
        tok_a = mgr.issue(subject="user:alice", tenant_id="acme")
        tok_b = mgr.issue(subject="user:bob", tenant_id="acme")
        assert tok_a.token_id != tok_b.token_id
        assert tok_a.attestation_data != tok_b.attestation_data
        assert tok_a.token_hash != tok_b.token_hash

    def test_token_hash_changes_when_subject_changes(self, mgr: HardwareTokenManager) -> None:
        tok_a = mgr.issue(subject="user:alice", tenant_id="acme")
        tok_b = mgr.issue(subject="user:carol", tenant_id="acme")
        assert tok_a.token_hash != tok_b.token_hash

    def test_token_hash_changes_when_tenant_changes(self, mgr: HardwareTokenManager) -> None:
        tok_a = mgr.issue(subject="user:alice", tenant_id="acme")
        tok_b = mgr.issue(subject="user:alice", tenant_id="other-tenant")
        assert tok_a.token_hash != tok_b.token_hash

    def test_token_is_frozen(self, token: HardwareToken) -> None:
        with pytest.raises((dataclasses.FrozenInstanceError, AttributeError, TypeError)):
            token.subject = "tampered"  # type: ignore[misc]


# ── validate() — happy path ───────────────────────────────────────────────────


class TestValidateValid:
    def test_fresh_token_is_valid(self, mgr: HardwareTokenManager, token: HardwareToken) -> None:
        result = mgr.validate(token)
        assert result.valid is True

    def test_result_contains_token(self, mgr: HardwareTokenManager, token: HardwareToken) -> None:
        result = mgr.validate(token)
        assert result.token is token

    def test_reason_is_valid(self, mgr: HardwareTokenManager, token: HardwareToken) -> None:
        result = mgr.validate(token)
        assert result.reason == "valid"

    def test_backend_used_is_software(
        self, mgr: HardwareTokenManager, token: HardwareToken
    ) -> None:
        result = mgr.validate(token)
        assert result.backend_used is TokenBackend.SOFTWARE


# ── validate() — expired ──────────────────────────────────────────────────────


class TestValidateExpired:
    def test_expired_token_invalid(self, mgr: HardwareTokenManager) -> None:
        tok = mgr.issue(subject="user:alice", tenant_id="acme")
        # Backdate expiry to the past
        expired = dataclasses.replace(tok, expires_at=tok.issued_at - 1)
        result = mgr.validate(expired)
        assert result.valid is False

    def test_expired_reason_mentions_expired(self, mgr: HardwareTokenManager) -> None:
        tok = mgr.issue(subject="user:alice", tenant_id="acme")
        expired = dataclasses.replace(tok, expires_at=tok.issued_at - 1)
        result = mgr.validate(expired)
        assert "expir" in result.reason.lower()


# ── validate() — tampered attestation ────────────────────────────────────────


class TestValidateTampered:
    def test_tampered_attestation_data_fails(self, mgr: HardwareTokenManager) -> None:
        tok = mgr.issue(subject="user:alice", tenant_id="acme")
        tampered = dataclasses.replace(tok, attestation_data=b"\xff" * 32)
        result = mgr.validate(tampered)
        assert result.valid is False

    def test_tampered_attestation_reason(self, mgr: HardwareTokenManager) -> None:
        tok = mgr.issue(subject="user:alice", tenant_id="acme")
        tampered = dataclasses.replace(tok, attestation_data=b"\x00" * 32)
        result = mgr.validate(tampered)
        assert "attestation" in result.reason.lower() or "tamper" in result.reason.lower()

    def test_tampered_token_hash_fails(self, mgr: HardwareTokenManager) -> None:
        tok = mgr.issue(subject="user:alice", tenant_id="acme")
        bad_hash = "0" * 64
        # Re-derive correct attestation so only hash is wrong
        tampered = dataclasses.replace(tok, token_hash=bad_hash)
        result = mgr.validate(tampered)
        assert result.valid is False

    def test_tampered_token_hash_reason(self, mgr: HardwareTokenManager) -> None:
        tok = mgr.issue(subject="user:alice", tenant_id="acme")
        tampered = dataclasses.replace(tok, token_hash="f" * 64)
        result = mgr.validate(tampered)
        # Either attestation or hash mismatch — both indicate tampering
        assert result.valid is False


# ── revoke() / is_revoked() ───────────────────────────────────────────────────


class TestRevocation:
    def test_revoke_makes_token_invalid(
        self, mgr: HardwareTokenManager, token: HardwareToken
    ) -> None:
        mgr.revoke(token.token_id)
        result = mgr.validate(token)
        assert result.valid is False

    def test_is_revoked_false_before_revoke(
        self, mgr: HardwareTokenManager, token: HardwareToken
    ) -> None:
        assert mgr.is_revoked(token.token_id) is False

    def test_is_revoked_true_after_revoke(
        self, mgr: HardwareTokenManager, token: HardwareToken
    ) -> None:
        mgr.revoke(token.token_id)
        assert mgr.is_revoked(token.token_id) is True

    def test_revoke_reason_mentions_revoked(
        self, mgr: HardwareTokenManager, token: HardwareToken
    ) -> None:
        mgr.revoke(token.token_id)
        result = mgr.validate(token)
        assert "revok" in result.reason.lower()

    def test_revoke_unknown_id_does_not_raise(self, mgr: HardwareTokenManager) -> None:
        mgr.revoke("00000000-0000-0000-0000-000000000000")  # no-op, should not raise


# ── from_env() ────────────────────────────────────────────────────────────────


class TestFromEnv:
    def test_reads_signing_key_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AEGIS_SIGNING_KEY", _TEST_KEY_HEX)
        monkeypatch.delenv("AEGIS_TOKEN_TTL_SECONDS", raising=False)
        monkeypatch.setenv("AEGIS_TOKEN_BACKEND", "software")
        mgr = HardwareTokenManager.from_env()
        assert mgr.backend is TokenBackend.SOFTWARE

    def test_reads_ttl_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AEGIS_SIGNING_KEY", _TEST_KEY_HEX)
        monkeypatch.setenv("AEGIS_TOKEN_TTL_SECONDS", "7200")
        monkeypatch.setenv("AEGIS_TOKEN_BACKEND", "software")
        mgr = HardwareTokenManager.from_env()
        tok = mgr.issue(subject="u", tenant_id="t")
        assert abs((tok.expires_at - tok.issued_at) - 7200) < 2

    def test_missing_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("AEGIS_SIGNING_KEY", raising=False)
        with pytest.raises(HardwareTokenError, match="AEGIS_SIGNING_KEY"):
            HardwareTokenManager.from_env()

    def test_empty_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AEGIS_SIGNING_KEY", "")
        with pytest.raises(HardwareTokenError):
            HardwareTokenManager.from_env()

    def test_invalid_hex_key_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("AEGIS_SIGNING_KEY", "not-valid-hex!")
        with pytest.raises(HardwareTokenError):
            HardwareTokenManager.from_env()


# ── Empty signing key ─────────────────────────────────────────────────────────


class TestSigningKeyValidation:
    def test_empty_bytes_raises(self) -> None:
        with pytest.raises(HardwareTokenError):
            HardwareTokenManager(signing_key=b"", ttl_seconds=3600)

    def test_non_empty_key_accepted(self) -> None:
        mgr = HardwareTokenManager(signing_key=b"x" * 32, backend=TokenBackend.SOFTWARE)
        assert mgr.backend is TokenBackend.SOFTWARE


# ── backend property ──────────────────────────────────────────────────────────


class TestBackend:
    def test_backend_is_software_in_ci(self, mgr: HardwareTokenManager) -> None:
        # CI environments never expose /dev/tpm0 — backend must be SOFTWARE
        assert mgr.backend is TokenBackend.SOFTWARE

    def test_is_tpm_available_returns_bool(self) -> None:
        result = HardwareTokenManager._is_tpm_available()
        assert isinstance(result, bool)

    def test_is_tpm_available_does_not_raise(self) -> None:
        HardwareTokenManager._is_tpm_available()  # must not raise


# ── TokenValidationResult.to_dict() ──────────────────────────────────────────


class TestToDict:
    def test_to_dict_has_required_keys(
        self, mgr: HardwareTokenManager, token: HardwareToken
    ) -> None:
        result = mgr.validate(token)
        d = result.to_dict()
        required = {
            "valid",
            "token_id",
            "subject",
            "tenant_id",
            "issued_at",
            "expires_at",
            "backend",
            "reason",
            "backend_used",
        }
        assert required.issubset(d.keys())

    def test_to_dict_valid_true(self, mgr: HardwareTokenManager, token: HardwareToken) -> None:
        d = mgr.validate(token).to_dict()
        assert d["valid"] is True

    def test_to_dict_invalid_token_none_fields(self, mgr: HardwareTokenManager) -> None:
        result = TokenValidationResult(
            valid=False, token=None, reason="no token", backend_used=TokenBackend.SOFTWARE
        )
        d = result.to_dict()
        assert d["token_id"] is None
        assert d["subject"] is None

    def test_to_dict_backend_is_string(
        self, mgr: HardwareTokenManager, token: HardwareToken
    ) -> None:
        d = mgr.validate(token).to_dict()
        assert isinstance(d["backend_used"], str)
