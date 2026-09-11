# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Truthful facade for the cryptographic APIs that Aegis currently exposes.

The MMR implementation is usable without optional dependencies. PQC operations
require their documented optional runtimes and never simulate success. The ZK
classes are exported as explicit test stubs; they are not real ZK proofs. No
export from this package constitutes a FIPS validation claim.

Two zero-knowledge surfaces are exported and they are not the same thing. The
``ZKProver``/``ZKVerifier`` classes are the stubs described above. The
``generate_zk_proof``/``verify_zk_proof`` functions are the real Spartan circuit
(``CLM-089``, boundary in
``docs/institutional/DOC-08_ZERO_KNOWLEDGE_INCLUSION.md``) — compiled out of
every default build, so ``has_zk_native()`` is ``False`` and they raise unless
the extension was built with ``zk-spartan``. What the real one proves is that
the ledger *contains a record asserting* a WAF pass; it does not re-execute the
WAF and does not establish that anything was safe.
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
from aegis.core.zk_native import (
    ZKNativeUnavailableError,
    generate_zk_proof,
    has_zk_native,
    split_passed_leaf,
    verify_zk_proof,
    zk_verifier_key,
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
    "ZKNativeUnavailableError",
    "ZKProofRequest",
    "ZKProofResult",
    "ZKProofUnavailableError",
    "ZKProver",
    "ZKVerificationResult",
    "ZKVerifier",
    "capability_report",
    "collect_capabilities",
    "generate_zk_proof",
    "has_zk_native",
    "split_passed_leaf",
    "verify_zk_proof",
    "zk_verifier_key",
]
