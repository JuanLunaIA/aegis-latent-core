"""Fail-closed TEE discovery and attestation-policy boundary.

This module does not load an enclave or authenticate vendor quote formats. Device
presence is discovery evidence only. A deployment must supply a verifier backend
that authenticates vendor evidence before policy evaluation can succeed.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import hmac
import logging
import math
import os
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol

logger = logging.getLogger(__name__)

_SGX_DEVICES = ("/dev/sgx_enclave", "/dev/isgx")
_SEV_DEVICE = "/dev/sev"
_TDX_DEVICE = "/dev/tdx_guest"
_MAX_EVIDENCE_BYTES = 1_048_576


def _tee_device_available() -> str | None:
    """Return the first visible TEE device node, without asserting usability."""
    for path in (*_SGX_DEVICES, _SEV_DEVICE, _TDX_DEVICE):
        if os.path.exists(path):
            return path
    return None


@dataclass(frozen=True)
class AttestationReport:
    """Legacy unauthenticated report shape.

    Instances are caller-controlled metadata and are never accepted as hardware
    attestation. The type remains importable for compatibility only.
    """

    enclave_id: str
    measurement: str
    signer_id: str
    is_genuine: bool
    timestamp: float


@dataclass(frozen=True)
class VerifiedAttestationClaims:
    """Normalized claims returned by an authenticated vendor-specific verifier."""

    tee_type: str
    enclave_id: str
    measurement: str
    signer_id: str
    nonce: bytes
    issued_at: float
    debug: bool
    tcb_status: str
    report_data: bytes


@dataclass(frozen=True)
class AttestationPolicy:
    """Exact policy applied after cryptographic evidence authentication."""

    tee_type: str
    allowed_measurements: frozenset[str]
    allowed_signers: frozenset[str]
    max_age_seconds: float
    allowed_tcb_statuses: frozenset[str] = frozenset({"OK"})
    allow_debug: bool = False

    def __post_init__(self) -> None:
        if not self.tee_type:
            raise ValueError("tee_type must be non-empty")
        if not self.allowed_measurements:
            raise ValueError("allowed_measurements must be non-empty")
        if not self.allowed_signers:
            raise ValueError("allowed_signers must be non-empty")
        if not math.isfinite(self.max_age_seconds) or self.max_age_seconds <= 0:
            raise ValueError("max_age_seconds must be finite and positive")
        if not self.allowed_tcb_statuses:
            raise ValueError("allowed_tcb_statuses must be non-empty")


class AttestationVerifier(Protocol):
    """Vendor adapter that authenticates evidence before returning claims."""

    def verify(self, evidence: bytes, nonce: bytes) -> VerifiedAttestationClaims:
        """Authenticate bounded evidence and return normalized claims."""


class AttestationUnavailableError(RuntimeError):
    """Raised when no authenticated attestation backend is configured."""


def evaluate_attestation_claims(
    claims: VerifiedAttestationClaims,
    policy: AttestationPolicy,
    *,
    expected_nonce: bytes,
    expected_report_data: bytes,
    now: float,
) -> bool:
    """Evaluate authenticated claims against exact policy and freshness bounds."""
    if not all(
        isinstance(value, str) and 0 < len(value) <= 4096
        for value in (
            claims.tee_type,
            claims.enclave_id,
            claims.measurement,
            claims.signer_id,
            claims.tcb_status,
        )
    ):
        return False
    if not isinstance(claims.debug, bool):
        return False
    if not isinstance(claims.nonce, bytes) or not 16 <= len(claims.nonce) <= 64:
        return False
    if not isinstance(claims.report_data, bytes) or not 1 <= len(claims.report_data) <= 64:
        return False
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        return False
    if isinstance(claims.issued_at, bool) or not isinstance(claims.issued_at, (int, float)):
        return False
    if not math.isfinite(float(now)) or not math.isfinite(float(claims.issued_at)):
        return False
    age = float(now) - float(claims.issued_at)
    if age < 0 or age > policy.max_age_seconds:
        return False
    if claims.tee_type != policy.tee_type:
        return False
    if claims.measurement not in policy.allowed_measurements:
        return False
    if claims.signer_id not in policy.allowed_signers:
        return False
    if claims.tcb_status not in policy.allowed_tcb_statuses:
        return False
    if claims.debug and not policy.allow_debug:
        return False
    if not hmac.compare_digest(claims.nonce, expected_nonce):
        return False
    return hmac.compare_digest(claims.report_data, expected_report_data)


class TEEManager:
    """Discover a TEE device and evaluate evidence through an explicit verifier.

    The current repository has no enclave loader or vendor quote verifier. Thus
    :meth:`initialize_enclave` records discovery but returns ``False`` and never
    marks local execution protected. Remote evidence can be evaluated only when
    a deployment injects both a verifier backend and an exact policy.
    """

    def __init__(
        self,
        tee_type: str = "SGX",
        *,
        verifier: AttestationVerifier | None = None,
        policy: AttestationPolicy | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.tee_type = tee_type
        self._verifier = verifier
        self._policy = policy
        self._clock = clock
        self._is_enclave_active = False
        self._verified_claims: VerifiedAttestationClaims | None = None
        self._device_path: str | None = None

    @property
    def device_path(self) -> str | None:
        """Return discovered device-node path, if any; this is not attestation."""
        return self._device_path

    @property
    def attestation_verified(self) -> bool:
        """Return whether the latest backend-authenticated evidence passed policy."""
        return self._verified_claims is not None

    def initialize_enclave(self) -> bool:
        """Discover a device but fail closed because no enclave loader is integrated."""
        self._verified_claims = None
        self._is_enclave_active = False
        self._device_path = _tee_device_available()
        if self._device_path is None:
            logger.warning("No SGX/SEV/TDX device node is visible")
        else:
            logger.warning(
                "TEE device node %s is visible, but no enclave loader is integrated; "
                "device presence does not establish isolation",
                self._device_path,
            )
        return False

    def generate_attestation_quote(self) -> AttestationReport:
        """Refuse quote generation until a vendor-specific loader is integrated."""
        raise AttestationUnavailableError(
            "hardware quote generation is unavailable; no SGX/SEV-SNP/TDX backend is integrated"
        )

    def verify_remote_attestation(self, report: AttestationReport) -> bool:
        """Reject the legacy caller-controlled report shape unconditionally."""
        del report
        self._verified_claims = None
        logger.error("legacy AttestationReport is unauthenticated and cannot establish attestation")
        return False

    def verify_evidence(
        self,
        evidence: bytes,
        *,
        nonce: bytes,
        expected_report_data: bytes,
    ) -> bool:
        """Authenticate bounded evidence through the configured backend and policy."""
        self._verified_claims = None
        if self._verifier is None or self._policy is None:
            raise AttestationUnavailableError(
                "attestation verifier and policy must both be configured"
            )
        if not isinstance(evidence, bytes) or not evidence:
            raise ValueError("evidence must be non-empty bytes")
        if len(evidence) > _MAX_EVIDENCE_BYTES:
            raise ValueError("evidence exceeds the 1 MiB bound")
        if not isinstance(nonce, bytes) or not 16 <= len(nonce) <= 64:
            raise ValueError("nonce must be between 16 and 64 bytes")
        if not isinstance(expected_report_data, bytes) or not 1 <= len(expected_report_data) <= 64:
            raise ValueError("expected_report_data must be between 1 and 64 bytes")

        try:
            claims = self._verifier.verify(evidence, nonce)
        except Exception as exc:
            logger.error("attestation verifier rejected evidence: %s", type(exc).__name__)
            return False
        if not isinstance(claims, VerifiedAttestationClaims):
            logger.error("attestation verifier returned an invalid claims type")
            return False
        try:
            now = self._clock()
            accepted = evaluate_attestation_claims(
                claims,
                self._policy,
                expected_nonce=nonce,
                expected_report_data=expected_report_data,
                now=now,
            )
        except Exception as exc:
            logger.error("attestation claim evaluation failed closed: %s", type(exc).__name__)
            return False
        if accepted:
            self._verified_claims = claims
        return accepted

    def is_protected(self) -> bool:
        """Return true only for a loaded local enclave with verified evidence."""
        return self._is_enclave_active and self._verified_claims is not None
