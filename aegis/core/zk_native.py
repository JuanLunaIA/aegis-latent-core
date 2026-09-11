# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Python entry point for the zero-knowledge inclusion proof.

This is the **real** construction, and it is a different thing from
``aegis.core.zk_proof``. That module is an explicit stub (``HAS_ZK_NATIVE`` is
``False``, "proofs" are digests) and stays exactly as it is; ``CLM-019`` records
it as a stub and that record remains true. Nothing here promotes it.

What is here is a thin, honest wrapper over the Rust circuit in
``aegis_rust_v2/src/zk_mmr.rs``. Three things it deliberately does not do:

* **It does not import the extension at module scope.** ``aegis.crypto`` re-exports
  these names, and a top-level import would make that whole package unimportable
  on a pure-Python checkout.
* **It does not simulate.** Every path on which a proof cannot be produced
  raises. There is no fallback that returns something proof-shaped.
* **It does not decide what a proof means.** The boundary is
  ``docs/institutional/DOC-08_ZERO_KNOWLEDGE_INCLUSION.md`` and the claim is
  ``CLM-089``. The proof attests that the ledger contains a record asserting a
  WAF pass — not that the WAF ran correctly, and not that anything was safe.

The capability is compiled out of every default build, so in every wheel this
repository publishes :func:`has_zk_native` returns ``False`` and the other
functions raise. Branch on it rather than assuming.
"""

from __future__ import annotations

from typing import Any

from aegis.core.forensic import WAF_VERDICT_PASSED

__all__ = [
    "PASSED_SUFFIX",
    "ZKNativeUnavailableError",
    "generate_zk_proof",
    "has_zk_native",
    "verify_zk_proof",
    "zk_verifier_key",
]

#: The bytes a canonical forensic leaf ends with when the verdict is recorded as
#: ``passed``. The circuit compiles these in as constants, which is what makes a
#: ``blocked`` leaf unprovable rather than merely rejected.
#:
#: Derived from the vocabulary rather than typed twice, so a change to the
#: verdict spelling cannot leave this behind.
PASSED_SUFFIX = b',"waf_verdict":"' + WAF_VERDICT_PASSED.encode() + b'"}'


class ZKNativeUnavailableError(RuntimeError):
    """Raised when the proving capability is not present in this build.

    A subclass of :class:`RuntimeError` so the Rust binding's own refusal and
    this module's refusal can be caught the same way.
    """


def _extension() -> Any:
    """Return the compiled extension, or explain precisely why there isn't one."""
    try:
        import aegis_rust
    except ImportError as exc:
        raise ZKNativeUnavailableError(
            "the aegis_rust extension is not installed, so no zero-knowledge "
            "proof can be produced or checked. No proof is simulated."
        ) from exc
    if not getattr(aegis_rust, "has_zk_native", None):
        raise ZKNativeUnavailableError(
            "the installed aegis_rust extension predates the zero-knowledge "
            "binding. Rebuild it from this tree."
        )
    return aegis_rust


def has_zk_native() -> bool:
    """Whether this installation can produce and check proofs.

    ``False`` in every default build. This is the discovery call; it never
    raises, so a caller can branch without handling an exception.
    """
    try:
        return bool(_extension().has_zk_native())
    except ZKNativeUnavailableError:
        return False


def zk_verifier_key(prefix_len: int, path_depth: int, peak_count: int) -> bytes:
    """Derive the verifier key for a proof shape.

    A verifier calls this **themselves**. A key accepted from whoever supplied
    the proof establishes nothing — it is the prover's own claim about what is
    being proved, exactly as a root supplied by the prover is. Derivation is
    deterministic in the shape, which is what makes refusing one practical.

    Expensive, and expensive in proportion to the shape.
    """
    key: bytes = _extension().zk_verifier_key(prefix_len, path_depth, peak_count)
    return key


def generate_zk_proof(
    leaf_prefix: bytes,
    siblings: list[bytes],
    sibling_is_left: list[bool],
    peaks: list[bytes],
) -> tuple[bytes, bytes, bytes]:
    """Prove that a leaf recording ``waf_verdict = passed`` sits under a root.

    ``leaf_prefix`` is the canonical leaf bytes **minus** :data:`PASSED_SUFFIX`.
    Use :func:`split_passed_leaf` rather than slicing by hand.

    Returns ``(proof, verifier_key, committed_root)``. The root is **derived from
    the witness**, not supplied — compare it against the root you trust before
    relying on the proof, because a proof of inclusion in a tree the prover built
    is perfectly valid and worth nothing.

    Raises when the witness does not satisfy the circuit, which is what happens
    for a leaf recording ``blocked`` or recording no verdict at all: the suffix
    is a circuit constant, so no such preimage exists.
    """
    result: tuple[bytes, bytes, bytes] = _extension().generate_zk_proof(
        leaf_prefix, siblings, sibling_is_left, peaks
    )
    return result


def verify_zk_proof(proof: bytes, verifier_key: bytes, trusted_root: bytes) -> bool:
    """Check a proof against a root obtained independently of its supplier.

    ``True`` only when the proof verifies **and** commits to ``trusted_root``. A
    well-formed proof about a different tree returns ``False``; malformed bytes
    raise.
    """
    verified: bool = _extension().verify_zk_proof(proof, verifier_key, trusted_root)
    return verified


def split_passed_leaf(leaf: bytes) -> bytes:
    """Return the prefix of a canonical leaf that records ``passed``.

    Raises if the leaf does not record one. Slicing by hand would silently
    produce a prefix for a ``blocked`` or verdict-free leaf, and the failure
    would then surface seconds later as an unsatisfiable circuit rather than
    here as the mistake it is.
    """
    if not leaf.endswith(PASSED_SUFFIX):
        raise ValueError(
            "this leaf does not record a passed WAF verdict, so there is nothing "
            "for the circuit to prove about it"
        )
    return leaf[: -len(PASSED_SUFFIX)]
