# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.mlkem_session — FIPS 203 ML-KEM (Kyber-1024) session key bootstrap.

Provides Kyber-1024 key encapsulation for ephemeral session key establishment
in compliance with NIST FIPS 203.  A responder generates a keypair; the
initiator encapsulates against the public key, producing a shared secret and
ciphertext; the responder decapsulates to recover the same shared secret.

This module is a soft dependency: when ``kyber-py`` is not installed,
``HAS_MLKEM`` is ``False`` and all operations raise ``MLKEMUnavailableError``
rather than crashing the import.

Key sizes (Kyber-1024 / ML-KEM-1024):
  - Public key:    1568 bytes
  - Secret key:    3168 bytes
  - Ciphertext:    1568 bytes
  - Shared secret:   32 bytes
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# ── Optional kyber-py import ──────────────────────────────────────────────────

try:
    from kyber_py.kyber import Kyber1024 as _Kyber1024

    HAS_MLKEM: bool = True
except ModuleNotFoundError:
    _Kyber1024 = None  # type: ignore[assignment]
    HAS_MLKEM = False
    logger.warning(
        "kyber-py not installed — ML-KEM session bootstrap unavailable. "
        "Install with: pip install kyber-py"
    )

# ── Constants ─────────────────────────────────────────────────────────────────

PK_SIZE: int = 1568
SK_SIZE: int = 3168
CIPHERTEXT_SIZE: int = 1568
SHARED_SECRET_SIZE: int = 32


# ── Exceptions ────────────────────────────────────────────────────────────────


class MLKEMError(Exception):
    """Base error for ML-KEM session bootstrap failures."""


class MLKEMUnavailableError(MLKEMError):
    """Raised when kyber-py is not installed."""


class MLKEMSizeError(MLKEMError):
    """Raised when a key or ciphertext has an unexpected byte length."""


# ── Data types ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class MLKEMKeyPair:
    """Immutable Kyber-1024 keypair produced by :meth:`MLKEMSessionBootstrap.generate_keypair`."""

    public_key: bytes
    secret_key: bytes

    def __post_init__(self) -> None:
        if len(self.public_key) != PK_SIZE:
            raise MLKEMSizeError(f"public_key must be {PK_SIZE} bytes, got {len(self.public_key)}")
        if len(self.secret_key) != SK_SIZE:
            raise MLKEMSizeError(f"secret_key must be {SK_SIZE} bytes, got {len(self.secret_key)}")


# ── Core class ────────────────────────────────────────────────────────────────


class MLKEMSessionBootstrap:
    """
    Kyber-1024 (FIPS 203 ML-KEM-1024) session key bootstrap.

    Usage::

        # Responder side
        kp = MLKEMSessionBootstrap.generate_keypair()
        # send kp.public_key to initiator

        # Initiator side
        shared_secret, ciphertext = MLKEMSessionBootstrap.encapsulate(kp.public_key)
        # send ciphertext back to responder; use shared_secret locally

        # Responder side
        shared_secret = MLKEMSessionBootstrap.decapsulate(kp.secret_key, ciphertext)
        # both parties now share the same 32-byte secret
    """

    @staticmethod
    def _require_mlkem() -> None:
        if not HAS_MLKEM:
            raise MLKEMUnavailableError(
                "kyber-py is required for ML-KEM operations. Install with: pip install kyber-py"
            )

    @classmethod
    def generate_keypair(cls) -> MLKEMKeyPair:
        """Generate a fresh Kyber-1024 keypair."""
        cls._require_mlkem()
        pk, sk = _Kyber1024.keygen()
        return MLKEMKeyPair(public_key=bytes(pk), secret_key=bytes(sk))

    @classmethod
    def encapsulate(cls, public_key: bytes) -> tuple[bytes, bytes]:
        """
        Encapsulate against *public_key*.

        Returns ``(shared_secret, ciphertext)`` — both as :class:`bytes`.
        The 32-byte ``shared_secret`` is for local use; the 1568-byte
        ``ciphertext`` is sent to the keypair owner.
        """
        cls._require_mlkem()
        if len(public_key) != PK_SIZE:
            raise MLKEMSizeError(f"public_key must be {PK_SIZE} bytes, got {len(public_key)}")
        shared_secret, ciphertext = _Kyber1024.encaps(public_key)
        return bytes(shared_secret), bytes(ciphertext)

    @classmethod
    def decapsulate(cls, secret_key: bytes, ciphertext: bytes) -> bytes:
        """
        Decapsulate *ciphertext* with *secret_key*.

        Returns the 32-byte shared secret that matches the one produced
        by the encapsulating party.
        """
        cls._require_mlkem()
        if len(secret_key) != SK_SIZE:
            raise MLKEMSizeError(f"secret_key must be {SK_SIZE} bytes, got {len(secret_key)}")
        if len(ciphertext) != CIPHERTEXT_SIZE:
            raise MLKEMSizeError(
                f"ciphertext must be {CIPHERTEXT_SIZE} bytes, got {len(ciphertext)}"
            )
        shared_secret = _Kyber1024.decaps(secret_key, ciphertext)
        return bytes(shared_secret)

    @classmethod
    def full_exchange(cls) -> tuple[MLKEMKeyPair, bytes, bytes]:
        """
        Run a complete local encapsulate/decapsulate exchange for testing.

        Returns ``(keypair, shared_secret, ciphertext)``.
        """
        kp = cls.generate_keypair()
        shared_secret, ciphertext = cls.encapsulate(kp.public_key)
        recovered = cls.decapsulate(kp.secret_key, ciphertext)
        if shared_secret != recovered:
            raise MLKEMError("ML-KEM self-test failed: shared secrets do not match")
        return kp, shared_secret, ciphertext


# ── Self-test / __main__ ──────────────────────────────────────────────────────

if __name__ == "__main__":  # pragma: no cover
    if not HAS_MLKEM:
        print("kyber-py not available.")
    else:
        kp, ss, ct = MLKEMSessionBootstrap.full_exchange()
        print(f"pk={len(kp.public_key)}B  sk={len(kp.secret_key)}B  ct={len(ct)}B  ss={len(ss)}B")
        print(f"shared_secret[:8] = {ss[:8].hex()}")
        print("ML-KEM-1024 self-test PASSED")
