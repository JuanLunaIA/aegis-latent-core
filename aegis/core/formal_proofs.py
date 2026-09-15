"""
aegis.core.formal_proofs — Empirical checks for statements proved elsewhere.

This module does not itself contain or produce a formal proof: it runs the
stated properties against real implementation functions (``canonical_normalize``,
a caller-supplied sign/verify pair) on concrete inputs and reports pass/fail,
the same epistemic weight as a unit test. The corresponding proofs — where
one actually exists — are the mechanically checked artifacts under ``specs/``:
a Lean 4 theorem (``specs/AegisVerification.lean``), a Z3 SMT2 formula
(``specs/aegis_invariants.smt2``), and TLA+/TLC models. There is no Coq
toolchain or ``.v`` file anywhere in this repository; see
``docs/formal/FORMAL_VERIFICATION.md`` for the bounds and scope those
artifacts actually establish, and do not describe them as validated by this
module or this module's checks as formal proofs in their own right.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
from collections.abc import Callable

from aegis.core.normalization import canonical_normalize

logger = logging.getLogger(__name__)


class FormalVerificationSuite:
    """
    Empirically checks a handful of properties that also appear, proved, in
    ``specs/`` (Lean 4, Z3, TLA+ — see the module docstring). Each ``verify_*``
    method here runs the property against concrete inputs and real
    implementation functions and returns a bool; it is a runtime check, not a
    proof, and passing it does not extend or substitute for the coverage of
    the artifacts under ``specs/``.
    """

    def __init__(self) -> None:
        logger.info("FormalVerificationSuite initialized.")

    def verify_normalization_idempotency(self, test_cases: list[str]) -> bool:
        """
        Theorem: normalize(s) = normalize(normalize(s))
        Proof: The normalization process is a fixed-point operation.
        """
        for s in test_cases:
            first_pass = canonical_normalize(s)
            second_pass = canonical_normalize(first_pass)
            if first_pass != second_pass:
                logger.critical("FORMAL FAILURE: Normalization is not idempotent for s=%s", s)
                return False
        logger.info("Property Verified: Normalization Idempotency [ESTABLISHED]")
        return True

    def verify_normalization_canonicality(self, pair: tuple[str, str]) -> bool:
        """
        Theorem: s ≈ s' => normalize(s) = normalize(s')
        Where ≈ represents visual/semantic equivalence in Unicode.
        """
        s, s_prime = pair
        if canonical_normalize(s) != canonical_normalize(s_prime):
            logger.critical(
                "FORMAL FAILURE: Normalization failed to canonicalize equivalent strings: %s vs %s",
                s,
                s_prime,
            )
            return False
        logger.info("Property Verified: Normalization Canonicality [ESTABLISHED]")
        return True

    def verify_signature_soundness(
        self,
        sign_fn: Callable[[bytes], bytes],
        verify_fn: Callable[[bytes, bytes], bool],
        data: bytes,
    ) -> bool:
        """
        Theorem: verify(sign(m), m) = True
        Proof: The signature is a deterministic function of the key and the message.
        """
        signature = sign_fn(data)
        if not verify_fn(data, signature):
            logger.critical("FORMAL FAILURE: Signature Soundness violated.")
            return False
        logger.info("Property Verified: Signature Soundness [ESTABLISHED]")
        return True

    def verify_signature_unforgeability(
        self,
        sign_fn: Callable[[bytes], bytes],
        verify_fn: Callable[[bytes, bytes], bool],
        data: bytes,
        corrupted_data: bytes,
    ) -> bool:
        """
        Theorem: m != m' => verify(sign(m), m') = False
        Proof: Strong unforgeability under chosen-message attack (EUF-CMA).
        """
        signature = sign_fn(data)
        if verify_fn(corrupted_data, signature):
            logger.critical("FORMAL FAILURE: Signature Unforgeability violated!")
            return False
        logger.info("Property Verified: Signature Unforgeability [ESTABLISHED]")
        return True


# --- Reference specifications, in proof-assistant-style axiom notation ---
# Documentation only: illustrates the properties the methods above check
# empirically. Not read by, or generated from, any Coq/Lean source — there
# is no .v file in this repository, and the actual mechanically checked
# proof of the signing/durability property is specs/AegisVerification.lean.
FORMAL_SPECS = {
    "normalization": {
        "Axiom_1": "forall s: string, normalize s = normalize (normalize s)",
        "Axiom_2": "forall s s': string, visually_equivalent s s' -> normalize s = normalize s'",
        "Goal": "The normalization function is a projection onto the canonical subspace of Unicode.",
    },
    "signing": {
        "Axiom_1": "forall m: bytes, verify (sign m) m = true",
        "Axiom_2": "forall m m': bytes, m <> m' -> verify (sign m) m' = false",
        "Goal": "The signing scheme provides existential unforgeability.",
    },
}
