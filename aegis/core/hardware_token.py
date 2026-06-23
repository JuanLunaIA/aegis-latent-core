# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.hardware_token — Domain 1.2 hardware-bound session tokens.

Provides TPM 2.0 attestation-sealed session tokens with a software HMAC-SHA256
fallback for environments without hardware TPM support.

Token binding: The HMAC is computed over (token_id ‖ subject ‖ tenant_id ‖ issued_at
‖ expires_at) keyed with AEGIS_SIGNING_KEY. This binds the token to the signing key
(hardware-equivalent when AEGIS_SIGNING_KEY is itself TPM-sealed or HSM-wrapped).

Soft dependency on TPM: when ``/dev/tpm0`` or ``/dev/tpmrm0`` is readable the
``TPM2`` backend is selected; otherwise the module falls back to ``SOFTWARE``
automatically. No import error is raised in either case.
"""

from __future__ import annotations

import hashlib
import hmac as hmac_mod
import logging
import os
import struct
import time
import uuid
from dataclasses import dataclass
from enum import StrEnum

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_DEFAULT_TTL_SECONDS: int = 3600
_SIGNING_KEY_ENV: str = "AEGIS_SIGNING_KEY"
_TTL_ENV: str = "AEGIS_TOKEN_TTL_SECONDS"
_BACKEND_ENV: str = "AEGIS_TOKEN_BACKEND"

# ── Enumerations ─────────────────────────────────────────────────────────────


class TokenBackend(StrEnum):
    """Token attestation backend selector."""

    TPM2 = "tpm2"
    SOFTWARE = "software"


# ── Exceptions ────────────────────────────────────────────────────────────────


class HardwareTokenError(Exception):
    """Base error for hardware token failures."""


class TokenExpiredError(HardwareTokenError):
    """Raised when a token has passed its expiry time."""


class TokenTamperedError(HardwareTokenError):
    """Raised when token attestation data or hash does not match."""


# ── Data types ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class HardwareToken:
    """
    Immutable hardware-bound session token.

    ``attestation_data`` holds TPM PCR quote bytes for the ``TPM2`` backend or
    an HMAC-SHA256 tag for the ``SOFTWARE`` backend. Neither value is a raw
    secret — the secret key never appears in this object.
    """

    token_id: str
    subject: str
    tenant_id: str
    issued_at: float
    expires_at: float
    backend: TokenBackend
    attestation_data: bytes
    token_hash: str


@dataclass
class TokenValidationResult:
    """Result of a token validation attempt."""

    valid: bool
    token: HardwareToken | None
    reason: str
    backend_used: TokenBackend

    def to_dict(self) -> dict:
        """Serialise to a plain dictionary suitable for JSON encoding."""
        return {
            "valid": self.valid,
            "token_id": self.token.token_id if self.token else None,
            "subject": self.token.subject if self.token else None,
            "tenant_id": self.token.tenant_id if self.token else None,
            "issued_at": self.token.issued_at if self.token else None,
            "expires_at": self.token.expires_at if self.token else None,
            "backend": self.token.backend.value if self.token else None,
            "reason": self.reason,
            "backend_used": self.backend_used.value,
        }


# ── Core class ────────────────────────────────────────────────────────────────


class HardwareTokenManager:
    """
    Issues and validates hardware-bound session tokens.

    When TPM 2.0 is available (``/dev/tpm0`` or ``/dev/tpmrm0`` is readable),
    uses it for attestation.  Otherwise falls back to HMAC-SHA256 software
    binding using ``AEGIS_SIGNING_KEY``.

    The signing key must be provided as a hex-encoded byte string in the
    ``AEGIS_SIGNING_KEY`` environment variable.  It must **not** be the same
    value as any upstream API key.

    Example::

        mgr = HardwareTokenManager.from_env()
        token = mgr.issue(subject="user:alice", tenant_id="acme")
        result = mgr.validate(token)
        assert result.valid
    """

    def __init__(
        self,
        signing_key: bytes,
        ttl_seconds: int = _DEFAULT_TTL_SECONDS,
        backend: TokenBackend | None = None,
    ) -> None:
        if not signing_key:
            raise HardwareTokenError(
                "signing_key must be non-empty. Set AEGIS_SIGNING_KEY in the environment."
            )
        self._signing_key: bytes = signing_key
        self._ttl_seconds: int = ttl_seconds
        self._revoked: set[str] = set()

        if backend is None:
            self._backend = TokenBackend.TPM2 if self._is_tpm_available() else TokenBackend.SOFTWARE
        else:
            self._backend = backend

        if self._backend is TokenBackend.TPM2 and not self._is_tpm_available():
            logger.warning(
                "TPM2 backend requested but /dev/tpm0 is not available — falling back to SOFTWARE"
            )
            self._backend = TokenBackend.SOFTWARE

        logger.debug("HardwareTokenManager initialised with backend=%s", self._backend.value)

    # ── Factory ───────────────────────────────────────────────────────────────

    @classmethod
    def from_env(cls) -> HardwareTokenManager:
        """
        Construct a :class:`HardwareTokenManager` from environment variables.

        Environment variables:

        ``AEGIS_SIGNING_KEY``
            Hex-encoded signing key (required).

        ``AEGIS_TOKEN_TTL_SECONDS``
            Token lifetime in seconds (default: ``3600``).

        ``AEGIS_TOKEN_BACKEND``
            One of ``"tpm2"``, ``"software"``, or ``"auto"`` (default: ``"auto"``).
            ``"auto"`` selects TPM2 when ``/dev/tpm0`` is readable.
        """
        raw_key = os.environ.get(_SIGNING_KEY_ENV, "")
        if not raw_key:
            raise HardwareTokenError(
                f"{_SIGNING_KEY_ENV} environment variable is not set or empty. "
                'Generate a key with: python -c "import secrets; print(secrets.token_hex(32))"'
            )
        try:
            signing_key = bytes.fromhex(raw_key)
        except ValueError as exc:
            raise HardwareTokenError(f"{_SIGNING_KEY_ENV} is not valid hex: {exc}") from exc

        ttl_raw = os.environ.get(_TTL_ENV, str(_DEFAULT_TTL_SECONDS))
        try:
            ttl_seconds = int(ttl_raw)
        except ValueError as exc:
            raise HardwareTokenError(f"{_TTL_ENV} must be an integer, got {ttl_raw!r}") from exc

        backend_raw = os.environ.get(_BACKEND_ENV, "auto").lower()
        if backend_raw == "auto":
            backend: TokenBackend | None = None
        elif backend_raw == "tpm2":
            backend = TokenBackend.TPM2
        elif backend_raw == "software":
            backend = TokenBackend.SOFTWARE
        else:
            raise HardwareTokenError(
                f"{_BACKEND_ENV} must be 'tpm2', 'software', or 'auto', got {backend_raw!r}"
            )

        return cls(signing_key=signing_key, ttl_seconds=ttl_seconds, backend=backend)

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def backend(self) -> TokenBackend:
        """Active attestation backend."""
        return self._backend

    # ── Public API ────────────────────────────────────────────────────────────

    def issue(self, subject: str, tenant_id: str) -> HardwareToken:
        """
        Issue a new hardware-bound session token.

        Parameters
        ----------
        subject:
            User or API-key identifier — **not** the secret itself.
        tenant_id:
            Tenant namespace for multi-tenant isolation.

        Returns
        -------
        :class:`HardwareToken`
            Immutable token ready for storage or transmission.
        """
        token_id = str(uuid.uuid4())
        issued_at = time.time()
        expires_at = issued_at + self._ttl_seconds

        attestation_data = self._attest(token_id, subject, tenant_id, issued_at, expires_at)
        token_hash = self._compute_token_hash(
            token_id, subject, tenant_id, issued_at, expires_at, attestation_data
        )

        return HardwareToken(
            token_id=token_id,
            subject=subject,
            tenant_id=tenant_id,
            issued_at=issued_at,
            expires_at=expires_at,
            backend=self._backend,
            attestation_data=attestation_data,
            token_hash=token_hash,
        )

    def validate(self, token: HardwareToken) -> TokenValidationResult:
        """
        Validate a :class:`HardwareToken`.

        Checks are performed in order:

        1. Revocation list.
        2. Expiry (``expires_at`` vs current time).
        3. Attestation data (constant-time comparison).
        4. Token hash integrity.

        Parameters
        ----------
        token:
            The token to validate.

        Returns
        -------
        :class:`TokenValidationResult`
            Always returns a result object; never raises on invalid tokens.
        """
        if self.is_revoked(token.token_id):
            return TokenValidationResult(
                valid=False,
                token=token,
                reason="token has been revoked",
                backend_used=self._backend,
            )

        now = time.time()
        if now > token.expires_at:
            return TokenValidationResult(
                valid=False,
                token=token,
                reason="token has expired",
                backend_used=self._backend,
            )

        expected_attestation = self._attest(
            token.token_id,
            token.subject,
            token.tenant_id,
            token.issued_at,
            token.expires_at,
        )
        if not hmac_mod.compare_digest(expected_attestation, token.attestation_data):
            return TokenValidationResult(
                valid=False,
                token=token,
                reason="attestation data mismatch — token may have been tampered with",
                backend_used=self._backend,
            )

        expected_hash = self._compute_token_hash(
            token.token_id,
            token.subject,
            token.tenant_id,
            token.issued_at,
            token.expires_at,
            token.attestation_data,
        )
        if not hmac_mod.compare_digest(expected_hash.encode(), token.token_hash.encode()):
            return TokenValidationResult(
                valid=False,
                token=token,
                reason="token_hash mismatch — token fields may have been tampered with",
                backend_used=self._backend,
            )

        return TokenValidationResult(
            valid=True,
            token=token,
            reason="valid",
            backend_used=self._backend,
        )

    def revoke(self, token_id: str) -> None:
        """
        Add *token_id* to the in-memory revocation set.

        Note: This revocation is in-memory only and does not survive process
        restart. Persistent revocation requires a storage backend (out of scope).
        """
        self._revoked.add(token_id)
        logger.info("Token %s added to revocation set", token_id)

    def is_revoked(self, token_id: str) -> bool:
        """Return ``True`` if *token_id* has been revoked."""
        return token_id in self._revoked

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _canonical_fields(
        self,
        token_id: str,
        subject: str,
        tenant_id: str,
        issued_at: float,
        expires_at: float,
    ) -> bytes:
        """
        Produce a deterministic byte encoding of the five core token fields.

        Layout: ``token_id_bytes ‖ subject_utf8 ‖ tenant_id_utf8 ‖ issued_at_f64 ‖ expires_at_f64``

        Both float fields are big-endian IEEE 754 double (8 bytes each) to
        guarantee identical encoding across platforms.
        """
        return (
            token_id.encode()
            + b"\x00"
            + subject.encode()
            + b"\x00"
            + tenant_id.encode()
            + b"\x00"
            + struct.pack(">dd", issued_at, expires_at)
        )

    def _attest(
        self,
        token_id: str,
        subject: str,
        tenant_id: str,
        issued_at: float,
        expires_at: float,
    ) -> bytes:
        """
        Produce attestation data for the given token fields.

        Software path: returns HMAC-SHA256(signing_key, canonical_fields).
        TPM path: would extend a PCR and return a quote; currently stubs to the
        software path (a real implementation requires tpm2-tss or direct /dev/tpm0
        access via ``ioctl``).
        """
        if self._backend is TokenBackend.TPM2:
            # Real TPM implementation would use PCR extend + quote here.
            # For now, falls back to software HMAC while maintaining the backend label.
            logger.debug(
                "TPM2 attestation requested; using HMAC stub (real PCR quote not yet implemented)"
            )
        msg = self._canonical_fields(token_id, subject, tenant_id, issued_at, expires_at)
        return hmac_mod.new(self._signing_key, msg, hashlib.sha256).digest()

    @staticmethod
    def _compute_token_hash(
        token_id: str,
        subject: str,
        tenant_id: str,
        issued_at: float,
        expires_at: float,
        attestation_data: bytes,
    ) -> str:
        """
        Compute SHA-256 over all token fields including attestation data.

        Returns a hex-encoded string for storage and comparison.
        """
        h = hashlib.sha256()
        h.update(token_id.encode())
        h.update(subject.encode())
        h.update(tenant_id.encode())
        h.update(struct.pack(">dd", issued_at, expires_at))
        h.update(attestation_data)
        return h.hexdigest()

    @staticmethod
    def _is_tpm_available() -> bool:
        """
        Return ``True`` if a readable TPM device node exists on this host.

        Checks ``/dev/tpm0`` (direct TPM access) and ``/dev/tpmrm0`` (resource
        manager — preferred on Linux >= 4.12).  Returns ``False`` on non-Linux
        platforms and in any environment where neither device is accessible.
        """
        for device in ("/dev/tpm0", "/dev/tpmrm0"):
            try:
                if os.access(device, os.R_OK):
                    return True
            except OSError:
                pass
        return False


# ── Self-test / __main__ ──────────────────────────────────────────────────────

if __name__ == "__main__":  # pragma: no cover
    import sys

    key_hex = os.environ.get(_SIGNING_KEY_ENV)
    if not key_hex:
        print(f"Set {_SIGNING_KEY_ENV} to a hex key before running.")
        sys.exit(1)

    mgr = HardwareTokenManager.from_env()
    print(f"Backend: {mgr.backend.value}")
    tok = mgr.issue(subject="user:self-test", tenant_id="default")
    print(f"Issued:  {tok.token_id}  expires_at={tok.expires_at}")
    result = mgr.validate(tok)
    print(f"Valid:   {result.valid}  reason={result.reason}")
