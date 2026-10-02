# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
"""MMR scheme/index binding, strict prefix validation and checkpoint ownership."""
from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aegis.core.mmr import HASH_SCHEME_V1, HASH_SCHEME_V2, MerkleMountainRange, MMRPeak


@pytest.mark.parametrize("scheme", [HASH_SCHEME_V1, HASH_SCHEME_V2])
def test_in_memory_verifier_binds_scheme_and_position(scheme):
    tree = MerkleMountainRange(hash_scheme=scheme)
    for value in (b"a", b"b", b"c"):
        tree.add_leaf(value)
    proof = tree.get_inclusion_proof(0)
    assert tree.verify_inclusion(b"a", 0, proof, tree.get_root_hash())
    assert not tree.verify_inclusion(b"a", 1, proof, tree.get_root_hash())


@pytest.mark.parametrize("count", [0, 1, 3])
def test_inconsistent_old_root_is_an_error(count):
    tree = MerkleMountainRange()
    for value in (b"a", b"b", b"c"):
        tree.add_leaf(value)
    with pytest.raises(ValueError, match="old_root"):
        tree.get_consistency_proof("f" * 64, count)


def test_same_size_foreign_checkpoint_is_rejected_without_mutation():
    left, right = MerkleMountainRange(), MerkleMountainRange()
    left.add_leaf(b"left")
    right.add_leaf(b"right")
    before = right.get_root_hash()
    with pytest.raises(ValueError):
        right.rollback_to(left.checkpoint())
    assert right.get_root_hash() == before


def test_discarded_branch_checkpoint_is_rejected():
    tree = MerkleMountainRange()
    origin = tree.checkpoint()
    tree.add_leaf(b"discarded")
    stale = tree.checkpoint()
    tree.rollback_to(origin)
    tree.add_leaf(b"replacement")
    with pytest.raises(ValueError):
        tree.rollback_to(stale)


@settings(max_examples=50, deadline=None)
@given(st.lists(st.binary(max_size=32), min_size=2, max_size=32), st.sampled_from([HASH_SCHEME_V1, HASH_SCHEME_V2]))
def test_valid_prefix_and_restore_rollback(leaves, scheme):
    prefix = MerkleMountainRange(hash_scheme=scheme)
    for value in leaves[:-1]:
        prefix.add_leaf(value)
    root = prefix.get_root_hash()
    expected = [p.hash for p in prefix.peaks]
    restored = MerkleMountainRange(hash_scheme=scheme)
    restored.restore_from_peaks(leaf_count=len(leaves)-1, peaks=[MMRPeak(p.height, p.hash) for p in prefix.peaks])
    checkpoint = restored.checkpoint()
    restored.add_leaf(leaves[-1])
    restored.rollback_to(checkpoint)
    assert restored.get_root_hash() == root
    prefix.add_leaf(leaves[-1])
    assert prefix.get_consistency_proof(root, len(leaves)-1)[1] == expected
