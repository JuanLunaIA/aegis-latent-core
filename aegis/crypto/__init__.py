# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Truthful facade for the cryptographic APIs that Aegis currently exposes.

The MMR implementation is usable without optional dependencies. PQC operations
require their documented optional runtimes and never simulate success. The ZK
classes are exported as explicit test stubs; they are not real ZK proofs. No
export from this package constitutes a FIPS validation claim.
"""

from aegis.core.mlkem_session import (
    MLKEMError,
    MLKEMKeyPair,
    MLKEMSessionBootstrap,
    MLKEMSizeError,
    MLKEMUnavailableError,
)
from aegis.core.mmr import (
    MerkleMountainRange,
    MMRInclusionProofV1,
    MMRNode,
    MMRPeak,
    MMRProofStep,
)
from aegis.core.pqc_signer import PQCSigner, PQCUnavailableError
from aegis.core.pqc_tls import (
    HybridKEMError,
    HybridKEMUnavailableError,
    HybridPQCExchange,
    HybridPublicKey,
    HybridResponderMessage,
    HybridSharedSecret,
)
from aegis.core.zk_proof import (
    ProofSystem,
    ZKProofRequest,
    ZKProofResult,
    ZKProofUnavailableError,
    ZKProver,
    ZKVerificationResult,
    ZKVerifier,
)
from aegis.crypto.capabilities import (
    CapabilityStatus,
    CryptoCapability,
    capability_report,
    collect_capabilities,
)

__all__ = [
    "CapabilityStatus",
    "CryptoCapability",
    "HybridKEMError",
    "HybridKEMUnavailableError",
    "HybridPQCExchange",
    "HybridPublicKey",
    "HybridResponderMessage",
    "HybridSharedSecret",
    "MLKEMError",
    "MLKEMKeyPair",
    "MLKEMSessionBootstrap",
    "MLKEMSizeError",
    "MLKEMUnavailableError",
    "MMRInclusionProofV1",
    "MMRNode",
    "MMRPeak",
    "MMRProofStep",
    "MerkleMountainRange",
    "PQCSigner",
    "PQCUnavailableError",
    "ProofSystem",
    "ZKProver",
    "ZKProofRequest",
    "ZKProofResult",
    "ZKProofUnavailableError",
    "ZKVerificationResult",
    "ZKVerifier",
    "capability_report",
    "collect_capabilities",
]
