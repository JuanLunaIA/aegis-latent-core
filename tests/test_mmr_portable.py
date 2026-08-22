# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

from dataclasses import replace

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from aegis.core.mmr import MerkleMountainRange, MMRInclusionProofV1, MMRProofStep


@pytest.mark.parametrize("leaf_count", [1, 2, 3, 4, 5, 7, 8, 15, 16, 33])
def test_portable_proof_verifies_every_leaf(leaf_count: int) -> None:
    leaves = [f"leaf-{index}".encode() for index in range(leaf_count)]
    mmr = MerkleMountainRange()
    for leaf in leaves:
        mmr.add_leaf(leaf)
    trusted_root = mmr.get_root_hash()

    for index, leaf in enumerate(leaves):
        proof = mmr.get_portable_inclusion_proof(index)
        serialized = proof.to_dict()
        parsed = MMRInclusionProofV1.from_dict(serialized)
        assert MerkleMountainRange.verify_portable_inclusion(leaf, parsed, trusted_root)
        assert mmr.verify_inclusion(leaf, index, mmr.get_inclusion_proof(index), trusted_root)


@given(leaves=st.lists(st.binary(min_size=0, max_size=64), min_size=1, max_size=24))
@settings(max_examples=100)
def test_property_portable_proof_sound_for_all_leaf_ordinals(leaves: list[bytes]) -> None:
    mmr = MerkleMountainRange()
    for leaf in leaves:
        mmr.add_leaf(leaf)
    root = mmr.get_root_hash()
    for index, leaf in enumerate(leaves):
        proof = mmr.get_portable_inclusion_proof(index)
        assert MerkleMountainRange.verify_portable_inclusion(leaf, proof, root)


def test_portable_proof_rejects_tampering_and_wrong_index() -> None:
    leaves = [b"a", b"b", b"c", b"d", b"e"]
    mmr = MerkleMountainRange()
    for leaf in leaves:
        mmr.add_leaf(leaf)
    proof = mmr.get_portable_inclusion_proof(2)
    root = mmr.get_root_hash()

    assert not MerkleMountainRange.verify_portable_inclusion(b"corrupt", proof, root)
    assert not MerkleMountainRange.verify_portable_inclusion(
        leaves[2], replace(proof, leaf_index=3), root
    )
    assert not MerkleMountainRange.verify_portable_inclusion(
        leaves[2], replace(proof, root="0" * 64), root
    )
    assert not MerkleMountainRange.verify_portable_inclusion(
        leaves[2], replace(proof, peaks=proof.peaks[:-1]), root
    )
    if proof.path:
        first = proof.path[0]
        opposite = "L" if first.direction == "R" else "R"
        changed_path = (replace(first, direction=opposite), *proof.path[1:])
        assert not MerkleMountainRange.verify_portable_inclusion(
            leaves[2], replace(proof, path=changed_path), root
        )
        corrupt_path = (
            MMRProofStep(sibling_hash="f" * 64, direction=first.direction),
            *proof.path[1:],
        )
        assert not MerkleMountainRange.verify_portable_inclusion(
            leaves[2], replace(proof, path=corrupt_path), root
        )


def test_portable_proof_schema_rejects_unknown_fields() -> None:
    mmr = MerkleMountainRange()
    mmr.add_leaf(b"leaf")
    value = mmr.get_portable_inclusion_proof(0).to_dict()
    value["unexpected"] = True
    with pytest.raises(ValueError, match="fields"):
        MMRInclusionProofV1.from_dict(value)
