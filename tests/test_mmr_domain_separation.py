# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Domain separation in the v2 MMR, and the weakness it closes.

The v1 construction hashes a leaf as ``SHA-256(payload)`` and an interior node
as ``SHA-256(ascii(left_hex) || ascii(right_hex))``. Neither input carries a tag
saying which case it is, so a leaf whose payload happens to be the 128-character
concatenation of two child digests hashes to exactly the interior node over
those children. ``verify_portable_inclusion`` accepts caller-supplied leaf
bytes, so a third party can be handed such a payload and cannot tell a leaf from
an interior node.

v2 prefixes every hash input with a one-byte domain tag and consumes raw 32-byte
digests rather than their hex text, which is the RFC 6962 §2.1 remedy.

These tests assert both halves: that v1 really is confusable (so the fix is not
guarding a hypothetical), and that v2 is not.
"""

from __future__ import annotations

import hashlib

import pytest

from aegis.core.mmr import (
    HASH_SCHEME_V1,
    HASH_SCHEME_V2,
    MMR_ALGORITHM_V1,
    MMR_ALGORITHM_V2,
    MMR_PROOF_VERSION_V1,
    MMR_PROOF_VERSION_V2,
    MerkleMountainRange,
    MMRInclusionProofV1,
    v2_bagged_root,
    v2_leaf_hash,
    v2_node_hash,
)


def _v1_leaf(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _v1_node(left: str, right: str) -> str:
    return hashlib.sha256((left + right).encode("ascii")).hexdigest()


# ── The weakness, and its absence in v2 ──────────────────────────────────────


def test_v1_leaf_can_impersonate_an_interior_node():
    """The defect being fixed, pinned so the fix is not guarding a phantom."""
    left, right = _v1_leaf(b"honest A"), _v1_leaf(b"honest B")
    interior = _v1_node(left, right)

    # The adversary submits, as a leaf payload, the exact bytes v1 node hashing
    # consumes. Same digest, different semantic type.
    forged_payload = (left + right).encode("ascii")

    assert _v1_leaf(forged_payload) == interior


def test_v2_leaf_cannot_impersonate_an_interior_node():
    """The domain tag makes the two preimages disjoint."""
    left = v2_leaf_hash(b"honest A")
    right = v2_leaf_hash(b"honest B")
    interior = v2_node_hash(left, right)

    # Every shape of the same attack: the raw concatenation, and the hex text.
    assert v2_leaf_hash(left + right) != interior
    assert v2_leaf_hash((left.hex() + right.hex()).encode("ascii")) != interior


def test_domain_tags_are_distinct_across_the_three_positions():
    """Leaf, node and root hashing of identical bytes must not coincide."""
    a = b"\x11" * 32
    b = b"\x22" * 32
    assert v2_leaf_hash(a + b) != v2_node_hash(a, b)
    assert v2_node_hash(a, b) != v2_bagged_root([a, b])
    assert v2_bagged_root([a, b]) != v2_leaf_hash(a + b)


@pytest.mark.parametrize("bad", [b"", b"\x00" * 31, b"\x00" * 33])
def test_v2_node_and_root_reject_non_32_byte_digests(bad):
    """Interior hashing is defined over digests, so it refuses anything else."""
    with pytest.raises(ValueError):
        v2_node_hash(bad, b"\x00" * 32)
    with pytest.raises(ValueError):
        v2_bagged_root([b"\x00" * 32, bad])


# ── Scheme selection and isolation ───────────────────────────────────────────


def test_default_scheme_is_v1_so_existing_chains_keep_their_roots():
    """The default must not move: it decides every root a chain has recorded."""
    assert MerkleMountainRange().hash_scheme == HASH_SCHEME_V1


def test_unknown_scheme_is_refused():
    with pytest.raises(ValueError, match="hash_scheme"):
        MerkleMountainRange(hash_scheme="sha256-something-else")


def test_the_two_schemes_produce_different_roots_over_identical_leaves():
    payloads = [f"record {index}".encode() for index in range(7)]
    v1 = MerkleMountainRange()
    v2 = MerkleMountainRange(hash_scheme=HASH_SCHEME_V2)
    for payload in payloads:
        v1.add_leaf(payload)
        v2.add_leaf(payload)
    assert v1.get_root_hash() != v2.get_root_hash()
    assert v1.get_leaf_count() == v2.get_leaf_count() == len(payloads)


# ── Proofs ───────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("leaf_count", [1, 2, 3, 4, 7, 8, 15, 16, 21])
def test_v2_proofs_verify_for_every_leaf(leaf_count):
    """Inclusion holds across mountain shapes, not just the easy ones."""
    mmr = MerkleMountainRange(hash_scheme=HASH_SCHEME_V2)
    payloads = [f"record {index}".encode() for index in range(leaf_count)]
    for payload in payloads:
        mmr.add_leaf(payload)
    root = mmr.get_root_hash()
    for index, payload in enumerate(payloads):
        proof = mmr.get_portable_inclusion_proof(index)
        assert proof.version == MMR_PROOF_VERSION_V2
        assert proof.algorithm == MMR_ALGORITHM_V2
        assert MerkleMountainRange.verify_portable_inclusion(payload, proof, root)


def test_v1_proofs_still_verify_unchanged():
    """Backward compatibility: historical proofs keep verifying as they did."""
    mmr = MerkleMountainRange()
    payloads = [f"record {index}".encode() for index in range(7)]
    for payload in payloads:
        mmr.add_leaf(payload)
    root = mmr.get_root_hash()
    proof = mmr.get_portable_inclusion_proof(3)
    assert proof.version == MMR_PROOF_VERSION_V1
    assert proof.algorithm == MMR_ALGORITHM_V1
    assert MerkleMountainRange.verify_portable_inclusion(payloads[3], proof, root)


def test_a_proof_of_one_scheme_never_verifies_under_the_other():
    """Cross-scheme replay is refused in both directions."""
    payloads = [f"record {index}".encode() for index in range(7)]
    v1 = MerkleMountainRange()
    v2 = MerkleMountainRange(hash_scheme=HASH_SCHEME_V2)
    for payload in payloads:
        v1.add_leaf(payload)
        v2.add_leaf(payload)

    p1 = v1.get_portable_inclusion_proof(3)
    p2 = v2.get_portable_inclusion_proof(3)
    assert not MerkleMountainRange.verify_portable_inclusion(payloads[3], p1, v2.get_root_hash())
    assert not MerkleMountainRange.verify_portable_inclusion(payloads[3], p2, v1.get_root_hash())


def test_version_and_algorithm_must_agree():
    """A mismatched pair is rejected rather than resolved in the caller's favour."""
    mmr = MerkleMountainRange(hash_scheme=HASH_SCHEME_V2)
    for index in range(4):
        mmr.add_leaf(f"record {index}".encode())
    root = mmr.get_root_hash()
    proof = mmr.get_portable_inclusion_proof(1)

    from dataclasses import replace

    lying = replace(proof, algorithm=MMR_ALGORITHM_V1)
    assert not MerkleMountainRange.verify_portable_inclusion(b"record 1", lying, root)

    lying = replace(proof, version=MMR_PROOF_VERSION_V1)
    assert not MerkleMountainRange.verify_portable_inclusion(b"record 1", lying, root)


def test_v2_rejects_a_tampered_sibling():
    mmr = MerkleMountainRange(hash_scheme=HASH_SCHEME_V2)
    for index in range(8):
        mmr.add_leaf(f"record {index}".encode())
    root = mmr.get_root_hash()
    proof = mmr.get_portable_inclusion_proof(5)

    from dataclasses import replace

    from aegis.core.mmr import MMRProofStep

    corrupted = replace(
        proof,
        path=(MMRProofStep(sibling_hash="a" * 64, direction=proof.path[0].direction),)
        + proof.path[1:],
    )
    assert not MerkleMountainRange.verify_portable_inclusion(b"record 5", corrupted, root)


# ── Wire encoding ────────────────────────────────────────────────────────────


def test_v2_transmits_digests_as_unpadded_base64url():
    mmr = MerkleMountainRange(hash_scheme=HASH_SCHEME_V2)
    for index in range(4):
        mmr.add_leaf(f"record {index}".encode())
    document = mmr.get_portable_inclusion_proof(1).to_dict()

    assert len(document["root"]) == 43
    assert "=" not in document["root"]
    assert all(len(peak["hash"]) == 43 for peak in document["peaks"])
    assert all(len(step["sibling_hash"]) == 43 for step in document["path"])


def test_v1_still_transmits_hex():
    mmr = MerkleMountainRange()
    for index in range(4):
        mmr.add_leaf(f"record {index}".encode())
    document = mmr.get_portable_inclusion_proof(1).to_dict()
    assert len(document["root"]) == 64


@pytest.mark.parametrize("scheme", [HASH_SCHEME_V1, HASH_SCHEME_V2])
def test_serialisation_round_trip_preserves_verification(scheme):
    mmr = MerkleMountainRange(hash_scheme=scheme)
    payloads = [f"record {index}".encode() for index in range(9)]
    for payload in payloads:
        mmr.add_leaf(payload)
    root = mmr.get_root_hash()
    for index, payload in enumerate(payloads):
        parsed = MMRInclusionProofV1.from_dict(mmr.get_portable_inclusion_proof(index).to_dict())
        assert MerkleMountainRange.verify_portable_inclusion(payload, parsed, root)


@pytest.mark.parametrize(
    "bad_digest",
    ["short", "A" * 42, "A" * 44, "!" * 43, ""],
)
def test_v2_parsing_rejects_a_malformed_digest(bad_digest):
    """A digest that cannot be decoded is a malformed proof, and says so."""
    mmr = MerkleMountainRange(hash_scheme=HASH_SCHEME_V2)
    for index in range(4):
        mmr.add_leaf(f"record {index}".encode())
    document = mmr.get_portable_inclusion_proof(1).to_dict()
    document["root"] = bad_digest
    with pytest.raises(ValueError):
        MMRInclusionProofV1.from_dict(document)
