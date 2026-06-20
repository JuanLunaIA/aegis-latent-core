# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.phi_encryption — AES-256-GCM field-level encryption for PHI payloads.

Provides per-tenant data-encryption-key (DEK) derivation and AES-256-GCM
authenticated encryption for audit node ``payload`` bytes when PHI
de-identification is enabled (``AEGIS_PHI_DEIDENTIFY=true``).

Key hierarchy
-------------
::

    AEGIS_PHI_MASTER_KEY (32 bytes, env var)
         │
         └── HKDF-SHA256(info="phi-dek:" + tenant_id) → per-tenant DEK (32 bytes)
                                                              │
                                                              └── AES-256-GCM(nonce=random 12 bytes)
                                                                       → encrypted payload

Ciphertext layout (bytes)
-------------------------
::

    [  0 – 11 ] nonce        (96-bit, random, non-repeating)
    [ 12 – end] ciphertext + 16-byte GCM authentication tag

The GCM tag is appended by ``cryptography`` automatically.  Total overhead
per encrypted payload: 28 bytes (12 nonce + 16 tag).

Usage::

    encryptor = PHIPayloadEncryptor(master_key=os.urandom(32))

    # Encrypt before writing to WAL
    ct = encryptor.encrypt("tenant-abc", payload_bytes)

    # Decrypt when reading back
    pt = encryptor.decrypt("tenant-abc", ct)
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_NONCE_SIZE = 12   # 96-bit nonce (NIST SP 800-38D recommended)
_KEY_SIZE = 32     # 256-bit AES key
_HKDF_HASH = hashes.SHA256()


class PHIEncryptionError(ValueError):
    """Raised when decryption fails (wrong key, corrupted ciphertext, or tampered tag)."""


class PHIPayloadEncryptor:
    """AES-256-GCM field-level encryptor with per-tenant DEK derivation.

    Parameters
    ----------
    master_key:
        32-byte master encryption key.  Must be sourced from ``AEGIS_PHI_MASTER_KEY``
        (or equivalent Vault secret) — never derived from ``AEGIS_SIGNING_KEY``.
    salt:
        Optional 16-byte HKDF salt.  When None a fixed zero-salt is used (HKDF
        still provides domain-separation via the ``info`` parameter).  For maximum
        security supply a random per-deployment salt stored alongside the master key.
    """

    def __init__(self, master_key: bytes, salt: bytes | None = None) -> None:
        if len(master_key) != _KEY_SIZE:
            raise ValueError(
                f"master_key must be exactly {_KEY_SIZE} bytes, got {len(master_key)}"
            )
        self._master_key = master_key
        self._salt = salt  # None → HKDF uses all-zero salt (still secure with info)
        self._dek_cache: dict[str, bytes] = {}

    def _derive_dek(self, tenant_id: str) -> bytes:
        """Derive a 256-bit DEK for *tenant_id* using HKDF-SHA256."""
        if tenant_id in self._dek_cache:
            return self._dek_cache[tenant_id]
        info = b"phi-dek:" + tenant_id.encode()
        dek = HKDF(
            algorithm=_HKDF_HASH,
            length=_KEY_SIZE,
            salt=self._salt,
            info=info,
        ).derive(self._master_key)
        self._dek_cache[tenant_id] = dek
        return dek

    def encrypt(self, tenant_id: str, plaintext: bytes) -> bytes:
        """Encrypt *plaintext* under the per-tenant DEK.

        Returns
        -------
        bytes
            ``nonce (12 bytes) || AES-256-GCM ciphertext+tag``.
        """
        dek = self._derive_dek(tenant_id)
        nonce = os.urandom(_NONCE_SIZE)
        ct = AESGCM(dek).encrypt(nonce, plaintext, associated_data=None)
        return nonce + ct

    def decrypt(self, tenant_id: str, ciphertext: bytes) -> bytes:
        """Decrypt *ciphertext* under the per-tenant DEK.

        Parameters
        ----------
        tenant_id:
            Must match the tenant_id used during encryption.
        ciphertext:
            As returned by :meth:`encrypt` — nonce prefix + ciphertext + tag.

        Raises
        ------
        PHIEncryptionError
            When the ciphertext is too short, the GCM tag is invalid (tampered),
            or the wrong tenant key is used.
        """
        if len(ciphertext) < _NONCE_SIZE + 16:  # nonce + minimum 16-byte tag
            raise PHIEncryptionError(
                f"Ciphertext too short ({len(ciphertext)} bytes); "
                f"expected at least {_NONCE_SIZE + 16} bytes."
            )
        dek = self._derive_dek(tenant_id)
        nonce = ciphertext[:_NONCE_SIZE]
        ct = ciphertext[_NONCE_SIZE:]
        try:
            return AESGCM(dek).decrypt(nonce, ct, associated_data=None)
        except Exception as exc:
            raise PHIEncryptionError(
                "AES-256-GCM decryption failed — ciphertext may be tampered, "
                "truncated, or encrypted with a different tenant key."
            ) from exc
