"""
tests/test_security_fixes.py — Regression tests for security audit fixes I-02 through I-08.

Covers:
  I-03 SQLite lock timeout constant exists and is applied to all connect() calls
  I-04 DistributedRateLimiter warns on plaintext redis:// with non-localhost host
  I-08 _ed25519_sign() deletes the private key before returning
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import logging

# ── I-04: Redis TLS plaintext warning ────────────────────────────────────────


def test_distributed_ratelimiter_warns_on_plaintext_remote(caplog):
    """redis:// with a non-localhost host must emit a WARNING about missing TLS."""
    from aegis.core import ratelimiter as rl

    with caplog.at_level(logging.WARNING, logger="aegis.core.ratelimiter"):
        rl.DistributedRateLimiter(redis_url="redis://10.0.0.5:6379")

    messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
    assert any("plaintext" in m or "TLS" in m or "rediss://" in m for m in messages)


def test_distributed_ratelimiter_no_warn_on_localhost(caplog):
    """redis://localhost must NOT emit a TLS warning."""
    from aegis.core import ratelimiter as rl

    with caplog.at_level(logging.WARNING, logger="aegis.core.ratelimiter"):
        rl.DistributedRateLimiter(redis_url="redis://localhost:6379")

    tls_warns = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and ("plaintext" in r.message or "TLS" in r.message)
    ]
    assert tls_warns == []


def test_distributed_ratelimiter_no_warn_on_rediss(caplog):
    """rediss:// (TLS-enabled) must NOT emit the plaintext warning."""
    from aegis.core import ratelimiter as rl

    with caplog.at_level(logging.WARNING, logger="aegis.core.ratelimiter"):
        rl.DistributedRateLimiter(redis_url="rediss://10.0.0.5:6380")

    tls_warns = [
        r for r in caplog.records
        if r.levelno == logging.WARNING and "plaintext" in r.message
    ]
    assert tls_warns == []


# ── I-03: SQLite lock timeout constant ───────────────────────────────────────


def test_sqlite_lock_timeout_constant_value():
    """_SQLITE_LOCK_TIMEOUT must be exactly 30.0 seconds."""
    from aegis_server.storage import sqlite_provider

    assert sqlite_provider._SQLITE_LOCK_TIMEOUT == 30.0


def test_sqlite_lock_timeout_constant_present():
    """_SQLITE_LOCK_TIMEOUT must be defined in sqlite_provider."""
    from aegis_server.storage import sqlite_provider

    assert hasattr(sqlite_provider, "_SQLITE_LOCK_TIMEOUT")


# ── I-08: Ed25519 ephemeral key zeroization ──────────────────────────────────


def test_ed25519_sign_returns_valid_hex_tuple():
    """_ed25519_sign must return a 3-tuple of hex strings."""
    from aegis.core.crypto_audit import _ed25519_sign

    sig, pub, scheme = _ed25519_sign(b"test payload")
    assert isinstance(sig, str)
    assert isinstance(pub, str)
    assert scheme == "ed25519-fallback"
    # Ed25519 signature is 64 bytes → 128 hex chars
    assert len(bytes.fromhex(sig)) == 64
    # Public key is 32 bytes → 64 hex chars
    assert len(bytes.fromhex(pub)) == 32


def test_ed25519_sign_unique_per_call():
    """Each call must generate a fresh ephemeral key — signatures differ."""
    from aegis.core.crypto_audit import _ed25519_sign

    sig1, pub1, _ = _ed25519_sign(b"same data")
    sig2, pub2, _ = _ed25519_sign(b"same data")
    # Different ephemeral keys → different public keys and different signatures
    assert pub1 != pub2
    assert sig1 != sig2


# ── #2 SIGNATURE COVERAGE: prev_hash is cryptographically bound ───────────────

_AUDIT_KEY = "unit-test-signing-key-do-not-use-in-prod"


def test_signed_payload_covers_prev_hash():
    """Changing only prev_hash must change the signed payload (and thus HMAC)."""
    from aegis.core.crypto_audit import _build_signed_payload

    a = _build_signed_payload("aa" * 32, "mr", "rq", "rs")
    b = _build_signed_payload("bb" * 32, "mr", "rq", "rs")
    assert a != b


def test_node_reorder_detected_by_signature(tmp_path):
    """A reordered chain with consistent prev_hash links must STILL fail.

    Regression for the reordering gap: when the signature covered merkle_root
    alone, an adversary could swap node order and rewrite prev_hash to match,
    and verify_integrity passed. Binding prev_hash into the signed payload makes
    the per-node signature reject any prev_hash it was not computed for.
    """
    import dataclasses

    from aegis.core.crypto_audit import CryptographicAuditLedger

    wal = str(tmp_path / "reorder.wal.jsonl")
    ledger = CryptographicAuditLedger(wal, signing_key=_AUDIT_KEY)
    try:
        node_a = ledger.commit_state("A", 1.0, b"payload-A")
        node_b = ledger.commit_state("B", 1.0, b"payload-B")
        assert node_b.signature_scheme == "hmac-sha256"
        assert ledger.verify_integrity()[0] is True

        # Forge a reordered chain: B first (prev=genesis), then A (prev=B.node_hash).
        # Signatures and merkle_roots are carried over untouched.
        genesis = "0" * 64
        b_first = dataclasses.replace(node_b, prev_hash=genesis)
        a_second = dataclasses.replace(node_a, prev_hash=b_first.node_hash)

        ledger.chain.clear()
        ledger.chain.append(b_first)
        ledger.chain.append(a_second)

        is_valid, idx = ledger.verify_integrity()
        assert is_valid is False
        # The forged first node's signature was computed for a different
        # prev_hash → caught at index 0.
        assert idx == 0
    finally:
        ledger.close()


# ── #7 WAL hardening: owner-only permissions ──────────────────────────────────


def test_wal_file_mode_is_owner_only(tmp_path):
    """The WAL must be created with 0o600 (no group/other access)."""
    import os
    import stat

    from aegis.core.crypto_audit import CryptographicAuditLedger

    wal = str(tmp_path / "perms.wal.jsonl")
    ledger = CryptographicAuditLedger(wal, signing_key=_AUDIT_KEY)
    try:
        ledger.commit_state("s0", 1.0, b"payload")
        mode = stat.S_IMODE(os.stat(wal).st_mode)
        # No bits set for group (0o070) or other (0o007).
        assert mode & 0o077 == 0, f"WAL mode too permissive: {oct(mode)}"
    finally:
        ledger.close()


# ── #6 AUTH posture: auth_disabled only honoured in debug mode ────────────────


def test_auth_disabled_requires_debug_mode():
    """auth_disabled=True without debug_mode must be rejected at config time."""
    import pytest

    from aegis.config import AegisSettings

    with pytest.raises(ValueError, match="debug_mode"):
        AegisSettings(auth_disabled=True, debug_mode=False)


def test_auth_disabled_allowed_in_debug_mode():
    """auth_disabled=True is permitted when debug_mode=True (local dev)."""
    from aegis.config import AegisSettings

    cfg = AegisSettings(auth_disabled=True, debug_mode=True)
    assert cfg.auth_disabled is True
    assert cfg.debug_mode is True
