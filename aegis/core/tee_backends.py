# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Concrete :class:`~aegis.core.tee_manager.AttestationVerifier` backends.

`tee_manager` supplies the seam — a verifier protocol, an exact policy, and a
fail-closed evaluator. This module supplies the three implementations of that
seam the deployment story needs, and each one is honest about what it is:

``NitroBackend``, ``SevSnpBackend``
    Platform adapters for AWS Nitro Enclaves and AMD SEV-SNP. Neither
    authenticates anything today. Without the platform device they refuse and
    name the device; *with* it they still refuse, because a device node is
    discovery evidence and not an attestation — the same position
    ``TEEManager.initialize_enclave`` already takes. They exist so that
    integrating a vendor verifier is a change inside one class rather than a
    change to the call sites, and so that a deployment that believes it has
    attestation gets an error instead of a silent pass.

``RecordedAttestationBackend``
    Replays a captured document so the policy path can be exercised without
    hardware. It authenticates nothing whatsoever.

**Why a replayed document cannot become production attestation.** The recorded
backend does not need a guard rail bolted onto it, because
``evaluate_attestation_claims`` already defeats it. A recorded document carries
the nonce and the issue time it was captured with, both frozen. Production
issues a *fresh* random nonce per challenge and reads a real clock, so the
recorded claims fail the ``compare_digest`` on nonce and fail the ``max_age``
bound. The document can only satisfy policy when the caller supplies the very
nonce it was recorded against *and* pins the clock to the recording — which is
to say, in a test. Replay is refused by the freshness check that was already
there, not by an honour system.
"""

from __future__ import annotations

import logging
import os
from dataclasses import replace

from aegis.core.tee_manager import (
    AttestationUnavailableError,
    AttestationVerifier,
    VerifiedAttestationClaims,
)

logger = logging.getLogger(__name__)

NITRO_DEVICE = "/dev/nsm"
SEV_GUEST_DEVICE = "/dev/sev-guest"


class _PlatformBackend(AttestationVerifier):
    """Shared refusal logic for a vendor adapter with no verifier integrated.

    ``AttestationVerifier`` is inherited explicitly rather than satisfied
    structurally. ``TEEManager`` accepts the protocol structurally either way,
    but naming it as a base makes mypy reject a drifted ``verify`` signature at
    build time — otherwise the drift surfaces at runtime in a deployment that
    has the hardware, which is the most expensive place to find it.
    """

    #: Whether this backend can, even in principle, authenticate vendor evidence.
    LIVE = True

    DEVICE: str = ""
    PLATFORM: str = ""
    VENDOR_REQUIREMENT: str = ""

    def __init__(self, *, device_path: str | None = None) -> None:
        self._device_path = device_path if device_path is not None else self.DEVICE

    @property
    def device_path(self) -> str:
        return self._device_path

    def device_present(self) -> bool:
        """Report device visibility. This is discovery, never attestation."""
        return os.path.exists(self._device_path)

    def verify(self, evidence: bytes, nonce: bytes) -> VerifiedAttestationClaims:
        """Refuse, naming precisely what is missing.

        Two distinct refusals rather than one, because they send an operator to
        different places: no device means the workload is not running on the
        platform it thinks it is, while a present device means the platform is
        right and the verifier is the missing piece.
        """
        del evidence, nonce
        if not self.device_present():
            raise AttestationUnavailableError(
                f"{self.PLATFORM} attestation is unavailable: {self._device_path} is not "
                f"present, so this workload is not running under {self.PLATFORM}"
            )
        raise AttestationUnavailableError(
            f"{self.PLATFORM} attestation is unavailable: {self._device_path} is present, "
            f"but no {self.VENDOR_REQUIREMENT} is integrated. Device presence is discovery "
            f"evidence and does not establish attestation."
        )


class NitroBackend(_PlatformBackend):
    """AWS Nitro Enclaves adapter over the Nitro Security Module.

    A real implementation reads a COSE_Sign1 attestation document from
    ``/dev/nsm``, validates its certificate chain to the AWS Nitro root, and
    checks the PCR set. None of that is integrated, so this refuses.
    """

    DEVICE = NITRO_DEVICE
    PLATFORM = "AWS Nitro Enclaves"
    VENDOR_REQUIREMENT = "NSM COSE_Sign1 verifier or AWS Nitro root certificate chain"


class SevSnpBackend(_PlatformBackend):
    """AMD SEV-SNP guest adapter over the SEV guest device.

    A real implementation requests an attestation report through
    ``SNP_GET_REPORT``, verifies the VCEK/VLEK signature against the AMD root,
    and checks the measurement and TCB version. None of that is integrated, so
    this refuses.
    """

    DEVICE = SEV_GUEST_DEVICE
    PLATFORM = "AMD SEV-SNP"
    VENDOR_REQUIREMENT = "SNP report verifier or AMD VCEK/VLEK certificate chain"


class RecordedAttestationBackend(AttestationVerifier):
    """Replay captured claims so the policy path can run without hardware.

    This authenticates nothing. It ignores the evidence bytes entirely and
    returns the claims it was constructed with, which is exactly why it must
    never stand in for a platform backend. See the module docstring for why
    ``evaluate_attestation_claims`` structurally prevents that rather than
    merely discouraging it.

    ``bind_nonce`` exists for the one legitimate test shape that would otherwise
    be impossible to express: exercising *policy* rejection (a bad measurement,
    a stale TCB status) without the nonce check masking it. It rewrites the
    replayed nonce to whatever was challenged, so it defeats the freshness
    check on purpose and is off by default.
    """

    #: This backend cannot authenticate evidence, by construction.
    LIVE = False

    def __init__(
        self,
        claims: VerifiedAttestationClaims,
        *,
        bind_nonce: bool = False,
    ) -> None:
        if not isinstance(claims, VerifiedAttestationClaims):
            raise TypeError("claims must be a VerifiedAttestationClaims instance")
        self._claims = claims
        self._bind_nonce = bind_nonce
        self.calls = 0
        logger.warning(
            "RecordedAttestationBackend constructed: it replays a captured document and "
            "authenticates nothing. It must not be configured as a production verifier."
        )

    def verify(self, evidence: bytes, nonce: bytes) -> VerifiedAttestationClaims:
        """Return the recorded claims, ignoring the evidence entirely."""
        del evidence
        self.calls += 1
        if self._bind_nonce:
            return replace(self._claims, nonce=nonce)
        return self._claims
