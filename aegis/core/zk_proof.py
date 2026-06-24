# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.zk_proof — Domain 4.2 ZK-SNARK/STARK proof stubs.

Provides a structured API-compatible stub for ZK proof generation and
verification, pending integration with Rust-based bellman (Groth16/PLONK)
and winterfell (STARK) crates.

The stub generates deterministic proof bytes as:
    SHA-256(audit_node_hash ‖ chain_root ‖ proof_system)
enabling full API-compatible integration testing without native ZK libraries.

Real ZK computation requires:
  - bellman crate  — Groth16 and PLONK
  - winterfell crate — STARK
These are not yet integrated; see HAS_ZK_NATIVE below.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import time
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

# ── Availability flag ─────────────────────────────────────────────────────────

HAS_ZK_NATIVE: bool = False  # True when bellman/halo2 Rust extension loaded

# ── Enums ─────────────────────────────────────────────────────────────────────


class ProofSystem(str, Enum):  # noqa: UP042 — roadmap API requires str+Enum signature
    """Supported ZK proof systems."""

    GROTH16 = "groth16"  # ZK-SNARK, trusted setup, most efficient
    PLONK = "plonk"  # ZK-SNARK, universal setup
    STARK = "stark"  # ZK-STARK, post-quantum, no trusted setup


# ── Exceptions ────────────────────────────────────────────────────────────────


class ZKProofUnavailableError(Exception):
    """Raised when the full ZK proof library (bellman/halo2) is not available."""


# ── Data types ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class ZKProofRequest:
    """Request parameters for a single ZK proof generation."""

    proof_system: ProofSystem
    audit_node_hash: str  # hex SHA-256 of the node being proved
    chain_root: str  # hex MMR root at time of proof
    include_node_content: bool = False  # False = privacy-preserving


@dataclass(frozen=True)
class ZKProofResult:
    """Result of a single ZK proof generation."""

    proof_bytes: bytes  # serialized proof (stub = SHA-256 of inputs)
    proof_system: ProofSystem
    public_inputs: list[str]  # [audit_node_hash, chain_root, timestamp_hex]
    verification_key_hash: str  # SHA-256 of verification key (stub = fixed placeholder)
    generated_at: float  # UTC epoch

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict."""
        return {
            "proof_bytes_hex": self.proof_bytes.hex(),
            "proof_system": self.proof_system.value,
            "public_inputs": list(self.public_inputs),
            "verification_key_hash": self.verification_key_hash,
            "generated_at": self.generated_at,
        }

    def to_base64(self) -> str:
        """Return proof_bytes encoded as URL-safe base64."""
        return base64.b64encode(self.proof_bytes).decode("ascii")


@dataclass(frozen=True)
class ZKVerificationResult:
    """Result of verifying a ZK proof."""

    valid: bool
    proof_system: ProofSystem
    verified_at: float
    reason: str

    def to_dict(self) -> dict:
        """Serialize to a JSON-compatible dict."""
        return {
            "valid": self.valid,
            "proof_system": self.proof_system.value,
            "verified_at": self.verified_at,
            "reason": self.reason,
        }


# ── Internal helpers ──────────────────────────────────────────────────────────


def _derive_proof_bytes(
    audit_node_hash: str,
    chain_root: str,
    proof_system: ProofSystem,
) -> bytes:
    """
    Deterministic stub proof bytes: SHA-256(audit_node_hash ‖ chain_root ‖ proof_system).

    This produces a unique, reproducible digest for each unique combination of
    inputs, enabling correctness testing of the API surface without native ZK.
    """
    payload = (
        audit_node_hash.encode()
        + b"\x00"
        + chain_root.encode()
        + b"\x00"
        + proof_system.value.encode()
    )
    return hashlib.sha256(payload).digest()


def _derive_vk_hash(proof_system: ProofSystem) -> str:
    """Derive stub verification key hash from the proof system name."""
    return hashlib.sha256(b"stub-vk-" + proof_system.value.encode()).hexdigest()


# ── Core classes ──────────────────────────────────────────────────────────────


class ZKProver:
    """
    Structured stub for ZK proof generation.

    The stub generates deterministic proof bytes as
        SHA-256(audit_node_hash ‖ chain_root ‖ proof_system)
    to enable API-compatible integration testing.  Real ZK computation requires
    the bellman (Groth16/PLONK) or winterfell (STARK) Rust crates — not yet
    integrated.

    Usage::

        prover = ZKProver()
        request = ZKProofRequest(
            proof_system=ProofSystem.GROTH16,
            audit_node_hash="ab12...",
            chain_root="cd34...",
        )
        result = prover.generate_proof(request)
        assert prover.is_stub  # always True until real library integrated

    Honesty contract
    ----------------
    Construct with ``require_real=True`` on any path that must not rely on a
    non-sound stub proof: it raises :class:`ZKProofUnavailableError` at
    construction while ``HAS_ZK_NATIVE`` is ``False``, so production code can
    refuse to operate rather than silently emitting a stub proof that provides no
    zero-knowledge soundness.
    """

    def __init__(self, *, require_real: bool = False) -> None:
        if require_real and not HAS_ZK_NATIVE:
            raise ZKProofUnavailableError(
                "real ZK backend (bellman/halo2/winterfell) is not integrated; "
                "refusing to operate with require_real=True (stub proofs are not sound)"
            )

    def generate_proof(self, request: ZKProofRequest) -> ZKProofResult:
        """
        Generate a ZK proof for the given request.

        In stub mode the proof bytes are deterministic:
            SHA-256(audit_node_hash ‖ chain_root ‖ proof_system)
        """
        now = time.time()
        proof_bytes = _derive_proof_bytes(
            request.audit_node_hash,
            request.chain_root,
            request.proof_system,
        )
        public_inputs = [
            request.audit_node_hash,
            request.chain_root,
            hex(int(now)),
        ]
        vk_hash = _derive_vk_hash(request.proof_system)
        logger.debug(
            "ZKProver.generate_proof [stub] proof_system=%s node_hash=%.8s",
            request.proof_system.value,
            request.audit_node_hash,
        )
        return ZKProofResult(
            proof_bytes=proof_bytes,
            proof_system=request.proof_system,
            public_inputs=public_inputs,
            verification_key_hash=vk_hash,
            generated_at=now,
        )

    def generate_batch_proof(self, requests: list[ZKProofRequest]) -> list[ZKProofResult]:
        """Generate one proof per request, preserving order."""
        return [self.generate_proof(req) for req in requests]

    @property
    def is_stub(self) -> bool:
        """Always True until real ZK library is integrated."""
        return True


class ZKVerifier:
    """
    Structured stub for ZK proof verification.

    Stub verification re-derives the expected proof bytes using the same
    deterministic function as :class:`ZKProver` and checks equality.
    A tampered ``proof_bytes`` value will therefore produce ``valid=False``.
    """

    def verify(self, result: ZKProofResult) -> ZKVerificationResult:
        """
        Verify a ZK proof result.

        Stub: re-derives expected proof bytes from public_inputs[0] (audit_node_hash)
        and public_inputs[1] (chain_root), then compares with result.proof_bytes.
        """
        now = time.time()
        if len(result.public_inputs) < 2:  # noqa: PLR2004
            return ZKVerificationResult(
                valid=False,
                proof_system=result.proof_system,
                verified_at=now,
                reason="public_inputs must contain at least [audit_node_hash, chain_root]",
            )
        audit_node_hash = result.public_inputs[0]
        chain_root = result.public_inputs[1]
        expected = _derive_proof_bytes(audit_node_hash, chain_root, result.proof_system)
        if result.proof_bytes == expected:
            return ZKVerificationResult(
                valid=True,
                proof_system=result.proof_system,
                verified_at=now,
                reason="stub verification passed",
            )
        return ZKVerificationResult(
            valid=False,
            proof_system=result.proof_system,
            verified_at=now,
            reason="proof_bytes do not match expected stub derivation",
        )

    def verify_batch(self, results: list[ZKProofResult]) -> list[ZKVerificationResult]:
        """Verify each proof result in order, returning one result per input."""
        return [self.verify(r) for r in results]
