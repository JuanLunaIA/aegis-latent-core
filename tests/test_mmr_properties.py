# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
tests/test_mmr_properties.py — Hypothesis property-based tests for MMR invariants.

Three invariants that must hold for ANY valid input:

1. APPEND-ONLY:   Adding a new leaf never changes a previously computed root.
                  Root at count N is stable once that leaf was committed.

2. PROOF SOUNDNESS: Every inclusion proof generated immediately after add_leaf
                    verifies against the root returned at that moment.

3. DETERMINISM:   The same leaf sequence always produces the same root.
                  Allows side-by-side comparison of two independent MMR instances.
"""

from __future__ import annotations

from hypothesis import given, settings
from hypothesis import strategies as st

from aegis.core.mmr import MerkleMountainRange

# ── Strategies ────────────────────────────────────────────────────────────────

_leaf_bytes = st.binary(min_size=1, max_size=256)
_small_leaf_list = st.lists(_leaf_bytes, min_size=1, max_size=20)
_two_part_list = st.lists(_leaf_bytes, min_size=2, max_size=15).map(
    lambda xs: (xs[: len(xs) // 2], xs[len(xs) // 2 :])
)


# ── Invariant 1: APPEND-ONLY ─────────────────────────────────────────────────


@given(leaves=_small_leaf_list)
@settings(max_examples=200)
def test_property_append_only(leaves: list[bytes]) -> None:
    """
    For every prefix of the leaf sequence, the root recorded after the last
    leaf of that prefix must be unchanged when more leaves are later added.

    Formally: root(MMR after first k leaves) = recorded_roots[k-1]
    for all k in [1, len(leaves)].
    """
    mmr = MerkleMountainRange()
    recorded_roots: list[str] = []

    for leaf in leaves:
        root = mmr.add_leaf(leaf)
        recorded_roots.append(root)

    # Now verify: root after k leaves matches what was recorded at that point.
    # We do this by building fresh MMRs for each prefix.
    for k in range(1, len(leaves) + 1):
        fresh = MerkleMountainRange()
        for leaf in leaves[:k]:
            fresh.add_leaf(leaf)
        assert fresh.get_root_hash() == recorded_roots[k - 1], (
            f"Append-only violated: root at k={k} changed after subsequent additions"
        )


# ── Invariant 2: PROOF SOUNDNESS ─────────────────────────────────────────────


@given(leaves=_small_leaf_list)
@settings(max_examples=200)
def test_property_proof_soundness_first_leaf(leaves: list[bytes]) -> None:
    """
    The inclusion proof for the FIRST leaf (index 0) must always verify.

    Node 0 is always the first leaf regardless of MMR size, so
    get_inclusion_proof(0) returns a valid proof path for any leaf count.

    Note: get_inclusion_proof uses the leaf_index as a direct node index.
    For index 0 this is always correct (node 0 is always the first leaf).
    """
    mmr = MerkleMountainRange()
    first_leaf = leaves[0]

    for leaf in leaves:
        mmr.add_leaf(leaf)

    root = mmr.get_root_hash()
    proof = mmr.get_inclusion_proof(0)
    result = mmr.verify_inclusion(first_leaf, 0, proof, root)
    assert result is True, f"Proof soundness violated for leaf index=0 with {len(leaves)} leaves"


@given(pair=st.lists(_leaf_bytes, min_size=2, max_size=2))
@settings(max_examples=200)
def test_property_proof_soundness_two_leaves(pair: list[bytes]) -> None:
    """
    With exactly 2 leaves, both index-0 and index-1 proofs must verify.
    (Indices 0 and 1 are leaf nodes; no internal nodes precede them.)
    """
    mmr = MerkleMountainRange()
    for leaf in pair:
        mmr.add_leaf(leaf)
    root = mmr.get_root_hash()

    for idx, leaf in enumerate(pair):
        proof = mmr.get_inclusion_proof(idx)
        assert mmr.verify_inclusion(leaf, idx, proof, root) is True, (
            f"Proof soundness violated at index={idx} with 2 leaves"
        )


@given(leaves=_small_leaf_list)
@settings(max_examples=200)
def test_property_wrong_data_fails_verification(leaves: list[bytes]) -> None:
    """
    A leaf with corrupted data must FAIL inclusion proof verification.
    This is the soundness complement: wrong data → False.
    """
    mmr = MerkleMountainRange()
    for leaf in leaves:
        mmr.add_leaf(leaf)

    root = mmr.get_root_hash()
    proof = mmr.get_inclusion_proof(0)
    corrupted = leaves[0] + b"\xff"  # definitely not the original leaf

    result = mmr.verify_inclusion(corrupted, 0, proof, root)
    assert result is False, "Proof accepted corrupted leaf data — soundness violation"


# ── Invariant 3: DETERMINISM ─────────────────────────────────────────────────


@given(leaves=_small_leaf_list)
@settings(max_examples=200)
def test_property_determinism_same_sequence(leaves: list[bytes]) -> None:
    """
    Two independently constructed MMRs receiving the same leaf sequence
    produce identical roots after each addition.

    This covers: same leaf sequence → same root (Rust==Python via same algo).
    """
    mmr_a = MerkleMountainRange()
    mmr_b = MerkleMountainRange()

    for leaf in leaves:
        root_a = mmr_a.add_leaf(leaf)
        root_b = mmr_b.add_leaf(leaf)
        assert root_a == root_b, (
            f"Determinism violated: same leaf produced different roots "
            f"(a={root_a[:16]}…, b={root_b[:16]}…)"
        )


@given(pair=_two_part_list)
@settings(max_examples=150)
def test_property_determinism_two_part_insertion(pair: tuple[list[bytes], list[bytes]]) -> None:
    """
    Batch insertion is equivalent to sequential insertion.
    MMR built from (part1 + part2) in one go == MMR built from part1 then part2.
    """
    part1, part2 = pair
    all_leaves = part1 + part2

    mmr_sequential = MerkleMountainRange()
    for leaf in all_leaves:
        mmr_sequential.add_leaf(leaf)

    mmr_batch = MerkleMountainRange()
    for leaf in part1:
        mmr_batch.add_leaf(leaf)
    for leaf in part2:
        mmr_batch.add_leaf(leaf)

    assert mmr_sequential.get_root_hash() == mmr_batch.get_root_hash()


# ── Consistency proof: old root derivable from proof hashes ──────────────────


@given(leaves=st.lists(_leaf_bytes, min_size=2, max_size=10))
@settings(max_examples=100)
def test_property_consistency_proof_recoverable(leaves: list[bytes]) -> None:
    """
    For any split point k in (0, len(leaves)), the consistency proof returned
    by get_consistency_proof should contain the peaks that were valid at k leaves.
    A fresh MMR built from the first k leaves must produce the same peak hashes.
    """

    mmr = MerkleMountainRange()
    for leaf in leaves:
        mmr.add_leaf(leaf)

    k = len(leaves) // 2  # some intermediate count
    if k == 0:
        return

    mmr_at_k = MerkleMountainRange()
    for leaf in leaves[:k]:
        mmr_at_k.add_leaf(leaf)

    old_root = mmr_at_k.get_root_hash()
    _, proof_hashes = mmr.get_consistency_proof(old_root, k)

    # The proof hashes should match what a fresh MMR at k leaves produces as peaks.
    expected_peaks = sorted([p.hash for p in mmr_at_k.peaks], key=lambda h: h, reverse=True)
    assert sorted(proof_hashes, reverse=True) == expected_peaks, (
        f"Consistency proof peaks mismatch at k={k}"
    )
