# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Machine-readable, conservative capability reporting for :mod:`aegis.crypto`.

A capability's presence in this report is not a certification. In particular,
algorithm names that correspond to FIPS standards do not establish that this
package, its native extensions, or a deployment has been FIPS validated.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Literal

from aegis.core.mlkem_session import HAS_MLKEM
from aegis.core.pqc_signer import backend_available as ml_dsa_backend_available

CapabilityStatus = Literal[
    "implemented",
    "optional-runtime",
    "stub",
    "external-validation-required",
]


@dataclass(frozen=True)
class CryptoCapability:
    """A factual description of one cryptographic capability or assurance claim."""

    name: str
    status: CapabilityStatus
    available: bool
    real: bool
    module: str
    detail: str
    proof_complexity: str | None = None
    fips_validated: bool = False
    external_validation_required: bool = False

    def to_dict(self) -> dict[str, str | bool | None]:
        """Return a JSON-compatible representation of this capability."""
        return asdict(self)


def collect_capabilities() -> tuple[CryptoCapability, ...]:
    """Return a stable, side-effect-free report for the current runtime.

    ``available`` describes this process, while ``status`` describes how the
    repository supplies the capability. Thus an optional runtime can be
    available without being reclassified as an unconditional implementation.
    """
    ml_dsa_available = ml_dsa_backend_available()
    return (
        CryptoCapability(
            name="mmr_sha256",
            status="implemented",
            available=True,
            real=True,
            module="aegis.core.mmr",
            detail="Pure-Python append-only Merkle Mountain Range with inclusion proofs.",
            proof_complexity="O(log n)",
        ),
        CryptoCapability(
            name="ml_dsa_65_signing",
            status="optional-runtime",
            available=ml_dsa_available,
            real=ml_dsa_available,
            module="aegis.core.pqc_signer",
            detail=(
                "ML-DSA-65 operations use the optional aegis_rust backend; there is no "
                "simulated fallback. The algorithm label is not a FIPS validation claim."
            ),
        ),
        CryptoCapability(
            name="ml_kem_1024_session_bootstrap",
            status="optional-runtime",
            available=HAS_MLKEM,
            real=HAS_MLKEM,
            module="aegis.core.mlkem_session",
            detail=(
                "Session bootstrap requires the optional kyber-py runtime. Availability "
                "does not establish protocol integration or FIPS validation."
            ),
        ),
        CryptoCapability(
            name="zk_audit_proofs",
            status="stub",
            available=True,
            real=False,
            module="aegis.core.zk_proof",
            detail=(
                "The API emits and checks deterministic SHA-256 test artifacts; it provides "
                "no zero-knowledge, soundness, or native proving assurance."
            ),
        ),
        CryptoCapability(
            name="fips_module_validation",
            status="external-validation-required",
            available=False,
            real=False,
            module="aegis.crypto.capabilities",
            detail=(
                "No FIPS module or deployment validation is claimed; validation must be "
                "established for the deployed module and operating environment externally."
            ),
            external_validation_required=True,
        ),
    )


def capability_report() -> tuple[dict[str, str | bool | None], ...]:
    """Return the current capabilities as immutable-order JSON-compatible records."""
    return tuple(capability.to_dict() for capability in collect_capabilities())


__all__ = [
    "CapabilityStatus",
    "CryptoCapability",
    "capability_report",
    "collect_capabilities",
]
