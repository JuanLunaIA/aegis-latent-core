# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis_server.crypto.base — Signing provider interface and HMAC-SHA256 fallback.

Defines ``SignerProvider``, the async ABC that all signing backends implement,
and ``LocalHMACSigner``, the local HMAC-SHA256 implementation suitable for
self-hosted deployments and development environments.

For enterprise deployments requiring HSM-backed key isolation, see
``VaultSigner`` in ``aegis_server.crypto.vault_signer``.

Dependencies:
    Python 3.11+ stdlib only (hashlib, hmac, secrets).
"""

from __future__ import annotations

import abc
import hashlib
import hmac
import logging
import secrets

logger = logging.getLogger(__name__)

# Minimum key length enforced at construction time (NIST SP 800-107 §5.3.4
# recommends key length ≥ hash output length = 32 bytes for HMAC-SHA256).
_MIN_KEY_BYTES: int = 32


class SignerProvider(abc.ABC):
    """
    Abstract interface for Aegis cryptographic signing backends.

    Implementations must be safe for concurrent async usage.  The
    ``sign_payload`` method must be idempotent: the same ``data`` bytes
    must always produce a verifiable signature.

    Scheme identifier
    -----------------
    Each implementation must expose a ``scheme`` class attribute (``str``)
    recording the algorithm name stored in audit node metadata, e.g.
    ``"hmac-sha256"`` or ``"vault-transit-ml-dsa-65"``.
    """

    scheme: str = "unknown"

    @abc.abstractmethod
    async def sign_payload(self, data: bytes) -> str:
        """
        Produce a deterministic, verifiable signature for ``data``.

        Args:
            data: Arbitrary byte sequence to sign (typically the Merkle root
                  bytes of an audit chain link).

        Returns:
            Hex-encoded signature string.  The encoding and length depend on
            the underlying algorithm:
            - HMAC-SHA256: 64 hex chars
            - Vault Transit ML-DSA-65: variable hex chars per Dilithium spec

        Raises:
            RuntimeError: On unrecoverable signing failures (key unavailable,
                          Vault unreachable after all retries, etc.).
        """

    async def verify(self, data: bytes, signature_hex: str) -> bool:
        """
        Verify a signature produced by this provider.

        Not all backends support offline verification (e.g. Vault Transit
        asymmetric keys without access to the public key export endpoint).
        The default implementation returns ``False`` to signal
        "verification not supported".

        Args:
            data:          The original byte sequence that was signed.
            signature_hex: The hex-encoded signature to verify.

        Returns:
            ``True`` if the signature is valid; ``False`` otherwise or when
            verification is not supported by the backend.
        """
        return False


class LocalHMACSigner(SignerProvider):
    """
    HMAC-SHA256 signing using a local key.

    Suitable for:
    - Single-node self-hosted deployments.
    - Development and testing environments.
    - Deployments where key material is managed by an external secret store
      (e.g. Kubernetes Secrets, AWS SSM Parameter Store) and injected at
      startup as an environment variable.

    NOT suitable for:
    - Multi-node deployments that must verify signatures across nodes without
      sharing the raw key (use Vault Transit with asymmetric keys instead).
    - Environments requiring FIPS 140-3 compliance (use VaultSigner).
    - Environments where HSM-enforced key non-exportability is required.

    Security requirements:
    - ``signing_key`` must be at least 32 bytes of uniformly random data.
    - Never reuse an HMAC key across environments (dev/staging/prod).
    - Rotate the key annually or on suspected compromise; old nodes remain
      verifiable against the old key only.

    Args:
        signing_key: Raw key string (will be UTF-8 encoded).
                     Must be at least ``_MIN_KEY_BYTES`` (32) bytes long.
        allow_weak:  Override the minimum-length check.  Only for tests.

    Raises:
        ValueError: If the key is empty or shorter than the minimum.
    """

    scheme: str = "hmac-sha256"

    def __init__(self, signing_key: str, *, allow_weak: bool = False) -> None:
        if not signing_key:
            raise ValueError(
                "LocalHMACSigner requires a non-empty signing_key. "
                "Set AEGIS_HMAC_SIGNING_KEY in your environment."
            )
        key_bytes = signing_key.encode("utf-8")
        if not allow_weak and len(key_bytes) < _MIN_KEY_BYTES:
            raise ValueError(
                f"LocalHMACSigner signing_key must be at least {_MIN_KEY_BYTES} "
                f"bytes; got {len(key_bytes)}.  Use a stronger key or set "
                "allow_weak=True in tests only."
            )
        self._key: bytes = key_bytes

    async def sign_payload(self, data: bytes) -> str:
        """
        Compute HMAC-SHA256 of ``data`` and return as a 64-char hex string.

        This is a CPU-bound operation but completes in < 1 µs for typical
        audit payloads — no executor offload needed.

        Args:
            data: Byte sequence to sign.

        Returns:
            64-character lowercase hex HMAC-SHA256 digest.
        """
        mac = hmac.new(self._key, data, hashlib.sha256)
        return mac.hexdigest()

    async def verify(self, data: bytes, signature_hex: str) -> bool:
        """
        Constant-time HMAC verification.

        Args:
            data:          Original byte sequence.
            signature_hex: 64-char hex HMAC to verify against.

        Returns:
            ``True`` iff the signature is valid and correctly formatted.
        """
        if len(signature_hex) != 64:
            return False
        expected = await self.sign_payload(data)
        return hmac.compare_digest(expected, signature_hex.lower())

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def generate_key(cls) -> str:
        """
        Generate a cryptographically secure random signing key (64 hex chars).

        Use this during initial setup only.  Store the result in a secrets
        manager — never in source code.

        Returns:
            64-character hex string (32 random bytes).
        """
        return secrets.token_hex(32)
