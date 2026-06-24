# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.pqc_tls — real hybrid post-quantum key exchange (X25519 + ML-KEM-1024).

Replaces a prior *simulated* module whose "X25519" and "Kyber" secrets were both
``sha256(local_priv || remote_pub)`` — not an actual Diffie-Hellman (the two
parties would never derive the same value) and providing no post-quantum
security at all.

This implementation composes two real primitives, exactly as TLS 1.3 hybrid
groups (e.g. ``X25519MLKEM768``) do:

* **X25519** classical ECDH (`cryptography`), and
* **ML-KEM-1024** (FIPS 203) post-quantum KEM (`aegis.core.mlkem_session`).

The session secret is ``HKDF-SHA256(x25519_ss ‖ mlkem_ss)``. It stays secure as
long as **either** primitive is unbroken: a classical attacker must also break
ML-KEM; a quantum attacker must also break X25519 ("Store Now, Decrypt Later"
resistance).

Honesty contract
----------------
Hybrid PQC requires the post-quantum half. When the ML-KEM backend (``kyber-py``)
is unavailable this module raises :class:`HybridKEMUnavailableError` rather than
silently downgrading to classical-only — a silent downgrade would be exactly the
kind of false assurance this module was rewritten to remove.

Protocol (initiator ⇄ responder)
--------------------------------
1. Initiator constructs ``HybridPQCExchange()`` and sends ``get_public_keys()``.
2. Responder calls :meth:`HybridPQCExchange.responder_respond` with the
   initiator's public keys, obtaining ``(responder_message, shared_secret)`` and
   sends ``responder_message`` back.
3. Initiator calls :meth:`initiator_derive` with the responder message and
   obtains the identical ``shared_secret``.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from aegis.core.mlkem_session import (
    HAS_MLKEM,
    MLKEMSessionBootstrap,
    MLKEMUnavailableError,
)

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

X25519_PUBLIC_BYTES = 32
MLKEM_PUBLIC_BYTES = 1568
MLKEM_CIPHERTEXT_BYTES = 1568
HYBRID_SECRET_BYTES = 32
_HKDF_INFO = b"aegis-hybrid-x25519-mlkem1024-v1"


# ── Exceptions ────────────────────────────────────────────────────────────────


class HybridKEMError(Exception):
    """Base class for hybrid key-exchange failures."""


class HybridKEMUnavailableError(HybridKEMError):
    """Raised when the post-quantum half (ML-KEM-1024) is unavailable."""


# ── Wire types ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class HybridPublicKey:
    """Initiator's public material: raw X25519 public key + ML-KEM public key."""

    x25519_pk: bytes
    mlkem_pk: bytes


@dataclass(frozen=True)
class HybridResponderMessage:
    """Responder's reply: its X25519 public key + the ML-KEM ciphertext."""

    x25519_pk: bytes
    mlkem_ciphertext: bytes


@dataclass(frozen=True)
class HybridSharedSecret:
    """The derived 32-byte hybrid session secret."""

    secret: bytes
    pqc_verified: bool


# ── Helpers ───────────────────────────────────────────────────────────────────


def backend_available() -> bool:
    """``True`` when the ML-KEM-1024 backend is installed (hybrid is possible)."""
    return HAS_MLKEM


def _hybrid_kdf(x25519_ss: bytes, mlkem_ss: bytes) -> bytes:
    """HKDF-SHA256 over the concatenated classical+PQ secrets (domain-separated)."""
    return HKDF(
        algorithm=hashes.SHA256(),
        length=HYBRID_SECRET_BYTES,
        salt=None,
        info=_HKDF_INFO,
    ).derive(x25519_ss + mlkem_ss)


# ── Exchange ──────────────────────────────────────────────────────────────────


class HybridPQCExchange:
    """Initiator side of an X25519 + ML-KEM-1024 hybrid key exchange.

    Raises
    ------
    HybridKEMUnavailableError
        At construction when the ML-KEM backend is unavailable (no classical-only
        downgrade is permitted).
    """

    __slots__ = ("_x_priv", "_mlkem_kp")

    def __init__(self) -> None:
        if not HAS_MLKEM:
            raise HybridKEMUnavailableError(
                "ML-KEM-1024 backend unavailable; hybrid PQC key exchange refuses to "
                "downgrade to classical-only (install kyber-py to enable)"
            )
        self._x_priv = X25519PrivateKey.generate()
        self._mlkem_kp = MLKEMSessionBootstrap.generate_keypair()

    def get_public_keys(self) -> HybridPublicKey:
        """Return the initiator's public X25519 + ML-KEM keys for the responder."""
        return HybridPublicKey(
            x25519_pk=self._x_priv.public_key().public_bytes_raw(),
            mlkem_pk=self._mlkem_kp.public_key,
        )

    @staticmethod
    def responder_respond(
        initiator_pub: HybridPublicKey,
    ) -> tuple[HybridResponderMessage, HybridSharedSecret]:
        """Responder: ECDH against the initiator's X25519 key, encapsulate ML-KEM,
        and derive the hybrid secret. Returns the message to send back plus the
        secret to use locally.
        """
        if not HAS_MLKEM:
            raise HybridKEMUnavailableError("ML-KEM-1024 backend unavailable")
        if len(initiator_pub.x25519_pk) != X25519_PUBLIC_BYTES:
            raise HybridKEMError(
                f"x25519 public key must be {X25519_PUBLIC_BYTES} bytes, "
                f"got {len(initiator_pub.x25519_pk)}"
            )
        resp_x_priv = X25519PrivateKey.generate()
        x25519_ss = resp_x_priv.exchange(X25519PublicKey.from_public_bytes(initiator_pub.x25519_pk))
        try:
            mlkem_ss, ciphertext = MLKEMSessionBootstrap.encapsulate(initiator_pub.mlkem_pk)
        except MLKEMUnavailableError as exc:  # pragma: no cover - guarded above
            raise HybridKEMUnavailableError(str(exc)) from exc
        secret = _hybrid_kdf(x25519_ss, mlkem_ss)
        message = HybridResponderMessage(
            x25519_pk=resp_x_priv.public_key().public_bytes_raw(),
            mlkem_ciphertext=ciphertext,
        )
        return message, HybridSharedSecret(secret=secret, pqc_verified=True)

    def initiator_derive(self, responder_message: HybridResponderMessage) -> HybridSharedSecret:
        """Initiator: ECDH against the responder's X25519 key, decapsulate ML-KEM,
        and derive the identical hybrid secret.
        """
        if len(responder_message.x25519_pk) != X25519_PUBLIC_BYTES:
            raise HybridKEMError(
                f"x25519 public key must be {X25519_PUBLIC_BYTES} bytes, "
                f"got {len(responder_message.x25519_pk)}"
            )
        x25519_ss = self._x_priv.exchange(
            X25519PublicKey.from_public_bytes(responder_message.x25519_pk)
        )
        mlkem_ss = MLKEMSessionBootstrap.decapsulate(
            self._mlkem_kp.secret_key, responder_message.mlkem_ciphertext
        )
        secret = _hybrid_kdf(x25519_ss, mlkem_ss)
        return HybridSharedSecret(secret=secret, pqc_verified=True)

    def verify_quantum_resistance(self) -> bool:
        """``True`` when this exchange is genuinely post-quantum (ML-KEM active)."""
        return HAS_MLKEM
