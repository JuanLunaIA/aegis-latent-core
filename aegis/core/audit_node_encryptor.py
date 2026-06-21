# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.audit_node_encryptor — AES-256-GCM envelope encryption for IL6 audit nodes.

Provides per-tenant AES-256-GCM authenticated encryption for serialized
:class:`~aegis.core.crypto_audit.AuditNode` JSON payloads when operating at
DoD Impact Level 6 (IL6) or any deployment requiring data-at-rest protection
for audit records.

Key hierarchy
-------------
::

    AEGIS_AUDIT_MASTER_KEY (32 bytes)
         │
         └── HKDF-SHA256(info="audit-node-dek:" + tenant_id) → per-tenant DEK
                   │
                   └── AES-256-GCM(nonce=random 12 bytes, aad=node_hash_bytes)
                            → encrypted node envelope

The ``node_hash`` is bound as GCM Additional Authenticated Data (AAD).
This cryptographically ties the ciphertext to a specific hash-chain position:
swapping an encrypted blob from one node to another position yields a GCM tag
authentication failure on decrypt, preventing cross-node replay.

Ciphertext envelope layout (bytes)
------------------------------------
::

    [  0 –  11 ] nonce        (96-bit random)
    [ 12 –  end] AES-256-GCM ciphertext + 16-byte authentication tag

Total overhead per encrypted node: 28 bytes (12 nonce + 16 GCM tag).

Usage::

    import os, json
    from aegis.core.audit_node_encryptor import AuditNodeEncryptor

    master_key = os.urandom(32)  # in production: from AEGIS_AUDIT_MASTER_KEY
    enc = AuditNodeEncryptor(master_key=master_key)

    # Encrypt before persisting to WAL
    node_dict = audit_node.to_dict()
    node_hash = audit_node.node_hash
    ciphertext = enc.encrypt_node(tenant_id="tenant-abc", node_dict=node_dict, node_hash=node_hash)

    # Decrypt for verification or export
    recovered = enc.decrypt_node(tenant_id="tenant-abc", ciphertext=ciphertext, node_hash=node_hash)
    assert recovered == node_dict

Environment variables
---------------------
``AEGIS_AUDIT_MASTER_KEY``
    Hex-encoded 32-byte master key.  Do NOT reuse ``AEGIS_SIGNING_KEY`` or
    ``AEGIS_PHI_MASTER_KEY`` — key separation is required for defense in depth.
    Example: ``export AEGIS_AUDIT_MASTER_KEY=$(python -c "import os,binascii;print(binascii.hexlify(os.urandom(32)).decode())")``
"""

from __future__ import annotations

import json
import os

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

_NONCE_SIZE = 12   # 96-bit (NIST SP 800-38D recommended)
_KEY_SIZE = 32     # AES-256
_HKDF_HASH = hashes.SHA256()
_HKDF_INFO_PREFIX = b"audit-node-dek:"


class AuditNodeEncryptionError(ValueError):
    """Raised when decryption or key derivation fails."""


class AuditNodeEncryptor:
    """Per-tenant AES-256-GCM encryptor for audit node payloads.

    Parameters
    ----------
    master_key:
        32-byte master encryption key.  Sourced from ``AEGIS_AUDIT_MASTER_KEY``;
        must be distinct from the signing key and PHI master key.
    salt:
        Optional 16-byte HKDF salt.  ``None`` uses the all-zero HKDF default;
        supply a per-deployment random salt for maximum security.
    """

    def __init__(self, master_key: bytes, salt: bytes | None = None) -> None:
        if len(master_key) != _KEY_SIZE:
            raise ValueError(
                f"master_key must be exactly {_KEY_SIZE} bytes, got {len(master_key)}"
            )
        self._master_key = master_key
        self._salt = salt
        self._dek_cache: dict[str, bytes] = {}

    # ── Encryption ────────────────────────────────────────────────────────────

    def encrypt_node(
        self,
        tenant_id: str,
        node_dict: dict[str, object],
        node_hash: str,
    ) -> bytes:
        """Encrypt a serialized audit node dict.

        Parameters
        ----------
        tenant_id:
            Per-tenant DEK derivation input.
        node_dict:
            ``audit_node.to_dict()`` output — must be JSON-serializable.
        node_hash:
            The node's hash-chain hash (from ``audit_node.node_hash``).
            Bound as GCM AAD to tie the ciphertext to this hash-chain position.

        Returns
        -------
        bytes
            ``nonce (12 bytes) || AES-256-GCM ciphertext + tag``.
        """
        plaintext = json.dumps(node_dict, separators=(",", ":"), sort_keys=True).encode()
        aad = node_hash.encode()
        dek = self._derive_dek(tenant_id)
        nonce = os.urandom(_NONCE_SIZE)
        ct: bytes = AESGCM(dek).encrypt(nonce, plaintext, associated_data=aad)
        return nonce + ct

    def decrypt_node(
        self,
        tenant_id: str,
        ciphertext: bytes,
        node_hash: str,
    ) -> dict[str, object]:
        """Decrypt an encrypted audit node envelope.

        Parameters
        ----------
        tenant_id:
            Must match the tenant_id used during encryption.
        ciphertext:
            As returned by :meth:`encrypt_node`.
        node_hash:
            The same ``node_hash`` value that was passed to :meth:`encrypt_node`.

        Returns
        -------
        dict[str, object]
            Deserialized audit node dict.

        Raises
        ------
        AuditNodeEncryptionError
            If the ciphertext is too short, the GCM tag is invalid (tampered or
            wrong key), or the ``node_hash`` AAD does not match.
        """
        _min_len = _NONCE_SIZE + 16  # nonce + GCM tag minimum
        if len(ciphertext) < _min_len:
            raise AuditNodeEncryptionError(
                f"Ciphertext too short ({len(ciphertext)} bytes); "
                f"expected at least {_min_len} bytes."
            )
        aad = node_hash.encode()
        dek = self._derive_dek(tenant_id)
        nonce = ciphertext[:_NONCE_SIZE]
        ct = ciphertext[_NONCE_SIZE:]
        try:
            plaintext = AESGCM(dek).decrypt(nonce, ct, associated_data=aad)
        except Exception as exc:
            raise AuditNodeEncryptionError(
                "AES-256-GCM decryption failed — ciphertext may be tampered, "
                "encrypted with a different tenant key, or the node_hash AAD "
                "does not match."
            ) from exc
        return dict(json.loads(plaintext.decode()))

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> AuditNodeEncryptor:
        """Construct from ``AEGIS_AUDIT_MASTER_KEY`` (hex-encoded).

        Raises
        ------
        AuditNodeEncryptionError
            When the environment variable is absent or not a valid 32-byte hex key.
        """
        raw = os.environ.get("AEGIS_AUDIT_MASTER_KEY", "")
        if not raw:
            raise AuditNodeEncryptionError(
                "AEGIS_AUDIT_MASTER_KEY is not set; "
                "audit node encryption requires a 32-byte master key."
            )
        try:
            key = bytes.fromhex(raw)
        except ValueError as exc:
            raise AuditNodeEncryptionError(
                "AEGIS_AUDIT_MASTER_KEY is not valid hex."
            ) from exc
        if len(key) != _KEY_SIZE:
            raise AuditNodeEncryptionError(
                f"AEGIS_AUDIT_MASTER_KEY must be 32 bytes (64 hex chars), "
                f"got {len(key)} bytes."
            )
        return cls(master_key=key)

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _derive_dek(self, tenant_id: str) -> bytes:
        """Derive a 256-bit DEK for *tenant_id* using HKDF-SHA256.

        Cached per instance to avoid repeated HKDF computation.
        """
        if tenant_id in self._dek_cache:
            return self._dek_cache[tenant_id]
        info = _HKDF_INFO_PREFIX + tenant_id.encode()
        dek: bytes = HKDF(
            algorithm=_HKDF_HASH,
            length=_KEY_SIZE,
            salt=self._salt,
            info=info,
        ).derive(self._master_key)
        self._dek_cache[tenant_id] = dek
        return dek

    def clear_dek_cache(self) -> None:
        """Remove all cached DEKs from memory (call before process exit)."""
        self._dek_cache.clear()
