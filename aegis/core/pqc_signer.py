# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.pqc_signer — the single, real post-quantum signer (ML-DSA-65 / FIPS 204).

This module replaces two prior *simulated* modules (``pqc.py`` and
``pqc_provider.py``) that advertised "ML-DSA (Dilithium)" signatures but actually
computed an HMAC / SHAKE digest and, in one case, accepted **any** signature as
valid. Those modules manufactured false cryptographic assurance and have been
removed.

``PQCSigner`` performs genuine CRYSTALS-Dilithium (ML-DSA-65) signing and
verification via the Rust extension (`pqcrypto-mldsa`, FIPS 204). The parameter
sizes are fixed by the standard:

==================  ============
Artifact            Size (bytes)
==================  ============
Public key          1952
Private key         4032
Signature           3309
==================  ============

Honesty contract
----------------
There is **no simulated fallback**. When the Rust backend is unavailable the
signer reports ``is_available == False`` and ``backend == "unavailable"``, and
``sign`` raises :class:`PQCUnavailableError`. Callers that need a guaranteed
signature must fall back to the real HMAC-SHA256 audit signer in
``aegis.core.crypto_audit`` — never to a fake ML-DSA. Construct with
``require_real=True`` to refuse to instantiate at all without a real backend.

Key lifetime
------------
By default a ``PQCSigner`` generates a fresh in-process keypair whose public key
is published alongside each signature for verification. For a **persistent**
signing identity that survives restarts, export the identity with
:meth:`PQCSigner.public_key` + :meth:`PQCSigner.export_private_key`, store both
halves under encryption / access control, and reload them with
:meth:`PQCSigner.from_keys`. Both halves are required because an ML-DSA-65 secret
key does not embed the full public key (``t1``); the Rust ``keypair_from_bytes``
constructor validates each half before reconstructing the keypair.
"""

from __future__ import annotations

import logging

logger = logging.getLogger(__name__)

# ── Soft Rust-extension import (consistent with rust_integration / mlkem_session) ──
try:
    import aegis_rust  # type: ignore[import]

    _HAS_RUST = True
except Exception as _exc:  # pragma: no cover - exercised only without the extension
    aegis_rust = None  # type: ignore[assignment]
    _HAS_RUST = False
    logger.debug("aegis_rust extension not available (%s); ML-DSA signing disabled", _exc)


# ── FIPS 204 ML-DSA-65 parameter sizes ────────────────────────────────────────

ALGORITHM = "ml-dsa-65"
PUBLIC_KEY_BYTES = 1952
PRIVATE_KEY_BYTES = 4032
SIGNATURE_BYTES = 3309


# ── Exceptions ────────────────────────────────────────────────────────────────


class PQCUnavailableError(RuntimeError):
    """Raised when a real ML-DSA-65 operation is requested but the backend is absent."""


# ── Module-level helpers ──────────────────────────────────────────────────────


def backend_available() -> bool:
    """Return ``True`` when the real ML-DSA-65 backend can be used."""
    return _HAS_RUST


# ── Signer ────────────────────────────────────────────────────────────────────


class PQCSigner:
    """Real ML-DSA-65 (FIPS 204) signer backed by the Rust ``pqcrypto-mldsa`` crate.

    Parameters
    ----------
    require_real:
        When ``True``, raise :class:`PQCUnavailableError` at construction time if
        the real backend is unavailable, rather than producing an inert signer.
        Use this on any code path that must not silently degrade.
    """

    ALGORITHM = ALGORITHM
    PUBLIC_KEY_BYTES = PUBLIC_KEY_BYTES
    PRIVATE_KEY_BYTES = PRIVATE_KEY_BYTES
    SIGNATURE_BYTES = SIGNATURE_BYTES

    __slots__ = ("_kp", "_backend")

    def __init__(self, *, require_real: bool = False) -> None:
        self._kp = None
        self._backend = "unavailable"
        if _HAS_RUST:
            try:
                self._kp = aegis_rust.generate_pqc_keypair()
                self._backend = "ml-dsa-65-rust"
            except Exception as exc:  # pragma: no cover - backend present but failing
                logger.warning("ML-DSA-65 keypair generation failed: %s", exc)
                self._kp = None
        if require_real and self._kp is None:
            raise PQCUnavailableError(
                "real ML-DSA-65 backend unavailable; refusing to operate with "
                "require_real=True (no simulated fallback exists)"
            )

    # ── Alternate constructor: persistent identity ────────────────────────────

    @classmethod
    def from_keys(cls, public_key: bytes, private_key: bytes) -> PQCSigner:
        """Load a persistent ML-DSA-65 signing identity from stored key bytes.

        Reconstructs the in-process keypair from a previously-exported
        ``(public_key, private_key)`` pair via the Rust ``keypair_from_bytes``
        constructor. Both halves are required because an ML-DSA-65 secret key
        does not embed the full public key.

        Raises
        ------
        PQCUnavailableError
            When the real Rust backend is unavailable (never loads a fake identity).
        ValueError
            When the key bytes are malformed or the wrong size (raised by the
            backend's ML-DSA-65 decoder).
        TypeError
            When *public_key* or *private_key* is not bytes-like.
        """
        if not _HAS_RUST:
            raise PQCUnavailableError(
                "real ML-DSA-65 backend unavailable; cannot load a persistent identity"
            )
        if not (
            isinstance(public_key, (bytes, bytearray, memoryview))
            and isinstance(private_key, (bytes, bytearray, memoryview))
        ):
            raise TypeError("public_key and private_key must be bytes-like")
        signer = cls.__new__(cls)
        signer._kp = aegis_rust.keypair_from_bytes(bytes(public_key), bytes(private_key))
        signer._backend = "ml-dsa-65-rust"
        return signer

    # ── Status ────────────────────────────────────────────────────────────────

    @property
    def is_available(self) -> bool:
        """``True`` when this signer holds a real ML-DSA-65 keypair."""
        return self._kp is not None

    @property
    def backend(self) -> str:
        """``"ml-dsa-65-rust"`` when real, else ``"unavailable"`` (never a sim label)."""
        return self._backend

    @property
    def algorithm(self) -> str:
        return self.ALGORITHM

    @property
    def public_key(self) -> bytes:
        """The ML-DSA-65 public key (1952 bytes) to publish alongside signatures."""
        if self._kp is None:
            raise PQCUnavailableError("no real ML-DSA-65 keypair available")
        return bytes(self._kp.public_key)

    def export_private_key(self) -> bytes:
        """Return the raw ML-DSA-65 private key (4032 bytes) for **persistence**.

        This is the signing secret. The caller is responsible for storing it
        under encryption / access control (e.g. sealed to a TEE or wrapped by
        ``AEGIS_SIGNING_KEY``) and must never log, print, or commit it. Pair the
        result with :attr:`public_key` and reload via :meth:`from_keys`.

        Raises
        ------
        PQCUnavailableError
            When no real ML-DSA-65 keypair is held.
        """
        if self._kp is None:
            raise PQCUnavailableError("no real ML-DSA-65 keypair available")
        return bytes(self._kp.private_key)

    # ── Operations ──────────────────────────────────────────────────────────

    def sign(self, message: bytes) -> bytes:
        """Produce a real ML-DSA-65 signature over *message*.

        Raises
        ------
        PQCUnavailableError
            When no real backend is available (no fake signature is ever returned).
        TypeError
            When *message* is not bytes-like.
        """
        if self._kp is None:
            raise PQCUnavailableError(
                "ML-DSA-65 signing requested but backend unavailable; fall back to "
                "the HMAC-SHA256 audit signer, not a simulated signature"
            )
        if not isinstance(message, (bytes, bytearray, memoryview)):
            raise TypeError("message must be bytes-like")
        return bytes(self._kp.sign(bytes(message)))

    @staticmethod
    def verify(message: bytes, signature: bytes, public_key: bytes) -> bool:
        """Verify an ML-DSA-65 signature. Returns ``False`` on any failure or when
        the backend is unavailable — it never accepts an unverifiable signature.
        """
        if not _HAS_RUST:
            return False
        if not (
            isinstance(message, (bytes, bytearray, memoryview))
            and isinstance(signature, (bytes, bytearray, memoryview))
            and isinstance(public_key, (bytes, bytearray, memoryview))
        ):
            return False
        try:
            return bool(
                aegis_rust.verify_pqc_signature(bytes(message), bytes(signature), bytes(public_key))
            )
        except Exception:
            return False
