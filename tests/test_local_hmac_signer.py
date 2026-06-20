# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis_server.crypto.base — LocalHMACSigner and SignerProvider ABC."""

from __future__ import annotations

import pytest
import pytest_asyncio

from aegis_server.crypto.base import LocalHMACSigner, SignerProvider, _MIN_KEY_BYTES


# ── Constants ──────────────────────────────────────────────────────────────────


def test_min_key_bytes_is_32():
    assert _MIN_KEY_BYTES == 32


# ── SignerProvider default verify ─────────────────────────────────────────────


@pytest.mark.asyncio
async def test_signer_provider_default_verify_returns_false():
    class _Concrete(SignerProvider):
        async def sign_payload(self, data: bytes) -> str:
            return "sig"

    provider = _Concrete()
    result = await provider.verify(b"data", "sig")
    assert result is False


def test_signer_provider_scheme_default():
    class _Concrete(SignerProvider):
        async def sign_payload(self, data: bytes) -> str:
            return "sig"

    assert _Concrete.scheme == "unknown"


# ── LocalHMACSigner construction ───────────────────────────────────────────────


def test_local_hmac_signer_rejects_empty_key():
    with pytest.raises(ValueError, match="non-empty"):
        LocalHMACSigner("")


def test_local_hmac_signer_rejects_short_key():
    with pytest.raises(ValueError, match="at least"):
        LocalHMACSigner("short")


def test_local_hmac_signer_accepts_32_byte_key():
    key = "a" * 32
    signer = LocalHMACSigner(key)
    assert signer is not None


def test_local_hmac_signer_accepts_long_key():
    key = "x" * 64
    signer = LocalHMACSigner(key)
    assert signer is not None


def test_local_hmac_signer_allow_weak_bypasses_length_check():
    signer = LocalHMACSigner("short", allow_weak=True)
    assert signer is not None


def test_local_hmac_signer_scheme():
    signer = LocalHMACSigner("a" * 32)
    assert signer.scheme == "hmac-sha256"


# ── sign_payload ──────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_sign_payload_returns_64_char_hex():
    signer = LocalHMACSigner("a" * 32)
    result = await signer.sign_payload(b"test data")
    assert isinstance(result, str)
    assert len(result) == 64
    # Must be valid hex
    bytes.fromhex(result)


@pytest.mark.asyncio
async def test_sign_payload_deterministic():
    signer = LocalHMACSigner("b" * 32)
    r1 = await signer.sign_payload(b"same payload")
    r2 = await signer.sign_payload(b"same payload")
    assert r1 == r2


@pytest.mark.asyncio
async def test_sign_payload_different_data_different_sig():
    signer = LocalHMACSigner("c" * 32)
    r1 = await signer.sign_payload(b"payload-a")
    r2 = await signer.sign_payload(b"payload-b")
    assert r1 != r2


@pytest.mark.asyncio
async def test_sign_payload_different_keys_different_sig():
    s1 = LocalHMACSigner("k" * 32)
    s2 = LocalHMACSigner("m" * 32)
    r1 = await s1.sign_payload(b"data")
    r2 = await s2.sign_payload(b"data")
    assert r1 != r2


# ── verify ────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_valid_signature():
    signer = LocalHMACSigner("d" * 32)
    sig = await signer.sign_payload(b"hello")
    assert await signer.verify(b"hello", sig) is True


@pytest.mark.asyncio
async def test_verify_wrong_data_returns_false():
    signer = LocalHMACSigner("e" * 32)
    sig = await signer.sign_payload(b"original")
    assert await signer.verify(b"tampered", sig) is False


@pytest.mark.asyncio
async def test_verify_wrong_signature_returns_false():
    signer = LocalHMACSigner("f" * 32)
    assert await signer.verify(b"data", "00" * 32) is False


@pytest.mark.asyncio
async def test_verify_wrong_length_signature_returns_false():
    signer = LocalHMACSigner("g" * 32)
    # Not 64 chars
    assert await signer.verify(b"data", "aabbcc") is False


@pytest.mark.asyncio
async def test_verify_uppercase_hex_normalized():
    signer = LocalHMACSigner("h" * 32)
    sig = await signer.sign_payload(b"case test")
    # Uppercase should still verify (compare_digest after lower())
    upper_sig = sig.upper()
    if len(upper_sig) == 64:
        assert await signer.verify(b"case test", upper_sig) is True


# ── generate_key ──────────────────────────────────────────────────────────────


def test_generate_key_returns_64_char_hex():
    key = LocalHMACSigner.generate_key()
    assert isinstance(key, str)
    assert len(key) == 64
    bytes.fromhex(key)  # must be valid hex


def test_generate_key_is_unique():
    k1 = LocalHMACSigner.generate_key()
    k2 = LocalHMACSigner.generate_key()
    assert k1 != k2


def test_generate_key_can_be_used_as_signer_key():
    key = LocalHMACSigner.generate_key()
    # A generated key is 64 hex chars = 64 bytes when encoded → passes length check
    signer = LocalHMACSigner(key)
    assert signer is not None
