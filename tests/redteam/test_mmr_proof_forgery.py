# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Forging an inclusion proof against a trusted root.

A portable inclusion proof is the one artifact that leaves the trust boundary.
A reviewer holds a root they trust from somewhere else and a proof supplied by
whoever is making the claim — which, in an adversarial setting, is the party
with a reason to lie. Everything in the proof is therefore attacker-chosen
except the root.

The attacks below take a genuine proof and change one thing each: the leaf, the
peak set, the declared position, the version/algorithm pairing, the structural
counts. Every one must verify `False`. A verifier that recomputes whatever the
proof tells it to and compares against the proof's own root proves nothing at
all; these tests are what separate that from real verification.

`peak_index` gets particular attention because it is the field that selects
which mountain the path is walked against. If it is not bounds-checked, a
crafted value indexes outside the peak list; if it is not *consistency*-checked
against `leaf_index`, a valid leaf can be replayed into the wrong mountain.
"""

from __future__ import annotations

import dataclasses
import hashlib

import pytest

from aegis.core.mmr import (
    MMR_ALGORITHM_V1,
    MMR_ALGORITHM_V2,
    MMR_PROOF_VERSION_V1,
    MMR_PROOF_VERSION_V2,
    MerkleMountainRange,
)

#: Sizes with different peak structures: a single perfect tree (8), two
#: mountains (5 -> 4+1), three (7 -> 4+2+1). Structure is where index
#: confusion hides, so the attacks run against several shapes.
LEAF_COUNTS = (1, 2, 5, 7, 8, 11)


def _build(leaf_count: int) -> tuple[MerkleMountainRange, list[bytes]]:
    mmr = MerkleMountainRange()
    leaves = [f"evidence-node-{index}".encode() for index in range(leaf_count)]
    for leaf in leaves:
        mmr.add_leaf(leaf)
    return mmr, leaves


def _genuine(leaf_count: int, leaf_index: int = 0):
    mmr, leaves = _build(leaf_count)
    proof = mmr.get_portable_inclusion_proof(leaf_index)
    return mmr, leaves, proof, mmr.get_root_hash()


def _flip_hex(digest: str) -> str:
    """One-character change, keeping it a well-formed SHA-256 hex string.

    Corrupting the *shape* would be caught by a format check and would not
    exercise the cryptographic comparison underneath it.
    """

    head = "0" if digest[0] != "0" else "1"
    return head + digest[1:]


class TestTheHonestProofVerifies:
    """Without this, every rejection below could be a false negative."""

    @pytest.mark.parametrize("leaf_count", LEAF_COUNTS)
    def test_every_leaf_verifies_against_the_real_root(self, leaf_count: int) -> None:
        mmr, leaves = _build(leaf_count)
        root = mmr.get_root_hash()
        for index, leaf in enumerate(leaves):
            proof = mmr.get_portable_inclusion_proof(index)
            assert MerkleMountainRange.verify_portable_inclusion(leaf, proof, root) is True


class TestLeafSubstitution:
    @pytest.mark.parametrize("leaf_count", LEAF_COUNTS)
    def test_a_different_leaf_does_not_verify(self, leaf_count: int) -> None:
        _, _, proof, root = _genuine(leaf_count)
        assert (
            MerkleMountainRange.verify_portable_inclusion(b"forged-evidence", proof, root) is False
        )

    def test_a_leaf_from_the_same_tree_at_another_index_does_not_verify(self) -> None:
        """The proof binds a leaf to a position, not merely to the tree."""

        mmr, leaves = _build(8)
        root = mmr.get_root_hash()
        proof_for_zero = mmr.get_portable_inclusion_proof(0)
        assert (
            MerkleMountainRange.verify_portable_inclusion(leaves[3], proof_for_zero, root) is False
        )


class TestRootSubstitution:
    @pytest.mark.parametrize("leaf_count", LEAF_COUNTS)
    def test_a_tampered_trusted_root_does_not_verify(self, leaf_count: int) -> None:
        _, leaves, proof, root = _genuine(leaf_count)
        assert (
            MerkleMountainRange.verify_portable_inclusion(leaves[0], proof, _flip_hex(root))
            is False
        )

    @pytest.mark.parametrize("leaf_count", LEAF_COUNTS)
    def test_a_proof_carrying_its_own_root_does_not_verify(self, leaf_count: int) -> None:
        """The whole point: the proof's root must equal the *trusted* root.

        A verifier that skipped this check would accept any internally
        consistent proof, which an attacker can always produce.
        """

        _, leaves, proof, root = _genuine(leaf_count)
        forged_root = _flip_hex(root)
        forged = dataclasses.replace(proof, root=forged_root)
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False
        # And the self-consistent pair must fail too, against the honest root.
        assert (
            MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, forged_root) is False
        )


class TestPeakIndexAttacks:
    """`peak_index` selects the mountain; unchecked, it is a type confusion."""

    @pytest.mark.parametrize("leaf_count", [5, 7, 11])
    @pytest.mark.parametrize("bogus", [-1, 99, 2**31, -(2**31)])
    def test_an_out_of_range_peak_index_is_refused(self, leaf_count: int, bogus: int) -> None:
        _, leaves, proof, root = _genuine(leaf_count)
        forged = dataclasses.replace(proof, peak_index=bogus)
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False

    @pytest.mark.parametrize("leaf_count", [5, 7, 11])
    def test_an_in_range_but_wrong_peak_index_is_refused(self, leaf_count: int) -> None:
        """In-range is the interesting case: no bounds check catches it.

        Rejection has to come from checking that `leaf_index` actually falls
        inside the mountain `peak_index` selects.
        """

        _, leaves, proof, root = _genuine(leaf_count, leaf_index=0)
        for candidate in range(len(proof.peaks)):
            if candidate == proof.peak_index:
                continue
            forged = dataclasses.replace(proof, peak_index=candidate)
            assert (
                MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False
            ), f"leaf 0 accepted against mountain {candidate}"


class TestStructuralCounts:
    @pytest.mark.parametrize("bogus", [0, -1, -(2**31)])
    def test_a_non_positive_leaf_count_is_refused(self, bogus: int) -> None:
        _, leaves, proof, root = _genuine(8)
        forged = dataclasses.replace(proof, leaf_count=bogus)
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False

    def test_a_leaf_index_outside_the_leaf_count_is_refused(self) -> None:
        _, leaves, proof, root = _genuine(8)
        for bogus in (-1, 8, 2**31):
            forged = dataclasses.replace(proof, leaf_index=bogus)
            assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False

    def test_an_inflated_leaf_count_is_refused(self) -> None:
        """Changing leaf_count changes the expected peak structure."""

        _, leaves, proof, root = _genuine(8)
        forged = dataclasses.replace(proof, leaf_count=9)
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False

    def test_a_truncated_peak_list_is_refused(self) -> None:
        _, leaves, proof, root = _genuine(11)
        assert len(proof.peaks) > 1
        forged = dataclasses.replace(proof, peaks=proof.peaks[:-1])
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False

    def test_an_extended_peak_list_is_refused(self) -> None:
        _, leaves, proof, root = _genuine(8)
        forged = dataclasses.replace(proof, peaks=proof.peaks + proof.peaks)
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False

    def test_a_tampered_peak_digest_is_refused(self) -> None:
        _, leaves, proof, root = _genuine(11)
        peaks = list(proof.peaks)
        peaks[0] = dataclasses.replace(peaks[0], hash=_flip_hex(peaks[0].hash))
        forged = dataclasses.replace(proof, peaks=tuple(peaks))
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False

    def test_a_malformed_peak_digest_is_refused_not_crashed(self) -> None:
        """Hostile encodings must return False, never raise into the caller."""

        _, leaves, proof, root = _genuine(11)
        for bogus in ("", "zz", "g" * 64, "0" * 63, "0" * 65, "../../etc/passwd"):
            peaks = list(proof.peaks)
            peaks[0] = dataclasses.replace(peaks[0], hash=bogus)
            forged = dataclasses.replace(proof, peaks=tuple(peaks))
            assert (
                MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False
            ), f"accepted peak digest {bogus!r}"

    def test_a_tampered_path_step_is_refused(self) -> None:
        _, leaves, proof, root = _genuine(8)
        assert proof.path, "leaf 0 of an 8-leaf tree has a non-empty path"
        path = list(proof.path)
        path[0] = dataclasses.replace(path[0], sibling_hash=_flip_hex(path[0].sibling_hash))
        forged = dataclasses.replace(proof, path=tuple(path))
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False

    def test_a_flipped_path_direction_is_refused(self) -> None:
        """Direction decides concatenation order, so flipping it changes the hash.

        A verifier that concatenated in a fixed order regardless of the
        declared direction would accept a sibling on the wrong side.
        """

        _, leaves, proof, root = _genuine(8)
        path = list(proof.path)
        flipped = "right" if path[0].direction == "left" else "left"
        path[0] = dataclasses.replace(path[0], direction=flipped)
        forged = dataclasses.replace(proof, path=tuple(path))
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False

    def test_an_emptied_path_is_refused(self) -> None:
        _, leaves, proof, root = _genuine(8)
        forged = dataclasses.replace(proof, path=())
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False


class TestVersionAndAlgorithmCrossover:
    """v1 is ASCII-hex; v2 is domain-separated binary. Mixing them must fail.

    The v2 domain tags exist to stop a second-preimage confusion between leaf
    and interior nodes. An attacker who can get a v1 digest accepted under a v2
    declaration, or vice versa, gets that confusion back.
    """

    def test_a_v2_version_with_the_v1_algorithm_is_refused(self) -> None:
        _, leaves, proof, root = _genuine(8)
        forged = dataclasses.replace(
            proof, version=MMR_PROOF_VERSION_V2, algorithm=MMR_ALGORITHM_V1
        )
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False

    def test_a_v1_version_with_the_v2_algorithm_is_refused(self) -> None:
        _, leaves, proof, root = _genuine(8)
        forged = dataclasses.replace(
            proof, version=MMR_PROOF_VERSION_V1, algorithm=MMR_ALGORITHM_V2
        )
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False

    @pytest.mark.parametrize(
        "bogus_version",
        ["", "aegis-mmr-inclusion-v3", "AEGIS-MMR-INCLUSION-V1", "v1", "../v1"],
    )
    def test_an_unrecognised_version_is_refused(self, bogus_version: str) -> None:
        _, leaves, proof, root = _genuine(8)
        forged = dataclasses.replace(proof, version=bogus_version)
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False


class TestDigestOnlyVerification:
    """`verify_portable_inclusion_hash` takes a digest, so it must validate it."""

    @pytest.mark.parametrize("bogus", ["", "zz", "g" * 64, "0" * 63, "0" * 65, "ABC", "\x00" * 64])
    def test_a_malformed_leaf_digest_is_refused(self, bogus: str) -> None:
        _, _, proof, root = _genuine(8)
        assert MerkleMountainRange.verify_portable_inclusion_hash(bogus, proof, root) is False

    def test_an_uppercase_digest_is_refused_rather_than_normalised(self) -> None:
        """Case-folding here would make two distinct strings one digest."""

        mmr, leaves = _build(8)
        root = mmr.get_root_hash()
        proof = mmr.get_portable_inclusion_proof(0)
        honest = hashlib.sha256(leaves[0]).hexdigest()
        assert MerkleMountainRange.verify_portable_inclusion_hash(honest, proof, root) is True
        assert (
            MerkleMountainRange.verify_portable_inclusion_hash(honest.upper(), proof, root) is False
        )

    @pytest.mark.parametrize("bogus_root", ["", "zz", "0" * 63, "g" * 64])
    def test_a_malformed_trusted_root_is_refused(self, bogus_root: str) -> None:
        _, leaves, proof, _ = _genuine(8)
        honest = hashlib.sha256(leaves[0]).hexdigest()
        assert (
            MerkleMountainRange.verify_portable_inclusion_hash(honest, proof, bogus_root) is False
        )


class TestTypeConfusionOnTheWire:
    """Regression: found by `tests/redteam/fuzz/fuzz_mmr_proof.py`.

    A proof arrives as JSON, where `"leaf_count": ""` is as easy to send as a
    number. The field-set check passed it through, and the range comparison in
    the verifier then raised `TypeError: '>' not supported between instances of
    'int' and 'str'` instead of returning `False`.

    A verifier that throws on hostile input is a denial of service against the
    auditor running it, and an exception caught one frame too broadly upstream
    turns into an accidental "valid". Both layers are pinned here: `from_dict`
    must refuse the document, and a proof assembled some other way must still
    verify `False` rather than raise.
    """

    @pytest.mark.parametrize("field", ["leaf_index", "leaf_count", "peak_index"])
    @pytest.mark.parametrize("bogus", ["", "0", "abc", None, 1.5, [], {}, True, False])
    def test_a_non_integer_count_is_refused_by_deserialisation(
        self, field: str, bogus: object
    ) -> None:
        _, _, proof, _ = _genuine(8)
        payload = proof.to_dict()
        payload[field] = bogus
        with pytest.raises((ValueError, TypeError)):
            type(proof).from_dict(payload)

    @pytest.mark.parametrize("field", ["leaf_index", "leaf_count", "peak_index"])
    @pytest.mark.parametrize("bogus", ["", "0", "abc", None, 1.5, True])
    def test_a_non_integer_count_verifies_false_rather_than_raising(
        self, field: str, bogus: object
    ) -> None:
        _, leaves, proof, root = _genuine(8)
        forged = dataclasses.replace(proof, **{field: bogus})
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False

    def test_the_exact_input_the_fuzzer_found(self) -> None:
        _, leaves, proof, root = _genuine(1)
        forged = dataclasses.replace(proof, leaf_count="")
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], forged, root) is False


class TestRoundTripThroughTheWireForm:
    """Proofs cross the boundary as dicts, so the dict path must reject too."""

    @pytest.mark.parametrize("leaf_count", LEAF_COUNTS)
    def test_an_honest_proof_survives_serialisation(self, leaf_count: int) -> None:
        mmr, leaves = _build(leaf_count)
        root = mmr.get_root_hash()
        proof = mmr.get_portable_inclusion_proof(0)
        restored = type(proof).from_dict(proof.to_dict())
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], restored, root) is True

    def test_a_proof_tampered_on_the_wire_is_refused(self) -> None:
        mmr, leaves = _build(8)
        root = mmr.get_root_hash()
        proof = mmr.get_portable_inclusion_proof(0)
        payload = proof.to_dict()
        payload["root"] = _flip_hex(str(payload["root"]))
        restored = type(proof).from_dict(payload)
        assert MerkleMountainRange.verify_portable_inclusion(leaves[0], restored, root) is False
