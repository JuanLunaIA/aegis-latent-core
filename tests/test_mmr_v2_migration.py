# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Selecting the MMR hash scheme on a production ledger, and refusing to mix them.

The v2 construction — RFC 6962 domain tags on leaf, node and root — has existed
in ``aegis/core/mmr.py`` and in both SDK verifiers since `4.3.0`. What did not
exist was the ability for :class:`~aegis.core.crypto_audit.CryptographicAuditLedger`
to use it, and the module comment recorded exactly why: the Rust accumulator
implemented v1 only, so an accelerated deployment would disagree with a
pure-Python one on every root. That is now closed, and this file covers the
ledger-side half.

The migration is not an upgrade
-------------------------------

The scheme decides every root a chain has ever recorded, so there is no
in-place conversion: a root cannot be recomputed under a different construction
without rewriting the history it commits to. A v1 WAL reopened as v2 would
replay every leaf to a different root and the integrity check would report the
chain corrupt — true about the roots, wrong about the evidence, and alarming
for a chain that is actually intact. The ledger recognises the mismatch by name
instead, before replay, so the diagnosis names the misconfiguration.

Calls with side effects are assigned before being asserted on, never called
inside the ``assert`` itself (``python -O`` strips asserts; CodeQL flags this as
py/side-effect-in-assert).
"""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.mmr import (
    HASH_SCHEME_V1,
    HASH_SCHEME_V2,
    MMR_PROOF_VERSION_V1,
    MMR_PROOF_VERSION_V2,
    MerkleMountainRange,
    v2_leaf_hash,
    v2_node_hash,
)

SIGNING_KEY = "k" * 32


def _ledger(path: Path, scheme: str) -> CryptographicAuditLedger:
    return CryptographicAuditLedger(
        persistence_path=str(path),
        signing_key=SIGNING_KEY,
        require_strong_signing=True,
        mmr_hash_scheme=scheme,
    )


def _commit(ledger: CryptographicAuditLedger, count: int = 3) -> None:
    for index in range(count):
        ledger.commit_state(
            state_id=f"req-{index}",
            entropy=0.5,
            payload=f"payload-{index}".encode(),
        )


class TestTypeConfusion:
    """The weakness v2 exists to remove, at the hashing layer."""

    def test_v1_hashes_a_crafted_leaf_identically_to_an_interior_node(self) -> None:
        # v1: leaf = SHA-256(payload), node = SHA-256(ascii(left_hex || right_hex)).
        # Neither input carries a tag, so a payload that *is* the concatenated
        # hex of two child digests collides with the node over those children.
        left = hashlib.sha256(b"left child").hexdigest()
        right = hashlib.sha256(b"right child").hexdigest()

        node_digest = hashlib.sha256((left + right).encode()).hexdigest()
        confusing_payload = (left + right).encode()
        leaf_digest = hashlib.sha256(confusing_payload).hexdigest()

        assert leaf_digest == node_digest

    def test_v2_separates_them_by_construction(self) -> None:
        left = hashlib.sha256(b"left child").digest()
        right = hashlib.sha256(b"right child").digest()

        node_digest = v2_node_hash(left, right)
        # Both encodings of the same confusing payload: the raw 64 bytes a v2
        # node actually hashes, and the 128-character hex a v1 node hashed.
        assert v2_leaf_hash(left + right) != node_digest
        assert v2_leaf_hash((left.hex() + right.hex()).encode()) != node_digest

    def test_the_domain_tags_are_the_declared_bytes(self) -> None:
        payload = b"anything"
        assert v2_leaf_hash(payload) == hashlib.sha256(b"\x00" + payload).digest()
        left = hashlib.sha256(b"l").digest()
        right = hashlib.sha256(b"r").digest()
        assert v2_node_hash(left, right) == hashlib.sha256(b"\x01" + left + right).digest()


class TestRustPythonParity:
    """The prerequisite that blocked this wiring: both must agree under both schemes."""

    @pytest.mark.parametrize("scheme", [HASH_SCHEME_V1, HASH_SCHEME_V2])
    def test_the_accumulators_agree_across_a_rollover(self, scheme: str) -> None:
        aegis_rust = pytest.importorskip("aegis_rust")

        python_mmr = MerkleMountainRange(hash_scheme=scheme)
        rust_mmr = aegis_rust.MmrAccumulator(scheme)
        # 37 leaves crosses several peak merges, so this exercises node hashing
        # and root bagging rather than only the leaf digest.
        for index in range(37):
            payload = f"leaf-{index}".encode()
            python_mmr.add_leaf(payload)
            rust_mmr.add_leaf(payload)
            assert python_mmr.get_root_hash() == rust_mmr.get_root_hash(), index

    def test_the_rust_accumulator_defaults_to_v1(self) -> None:
        aegis_rust = pytest.importorskip("aegis_rust")
        assert aegis_rust.MmrAccumulator().hash_scheme == HASH_SCHEME_V1

    def test_the_rust_accumulator_refuses_an_unknown_scheme(self) -> None:
        aegis_rust = pytest.importorskip("aegis_rust")
        with pytest.raises(ValueError, match="hash_scheme must be one of"):
            aegis_rust.MmrAccumulator("v3-imaginary")

    def test_the_two_schemes_disagree(self) -> None:
        # If they agreed, nothing above would be testing anything.
        v1 = MerkleMountainRange(hash_scheme=HASH_SCHEME_V1)
        v2 = MerkleMountainRange(hash_scheme=HASH_SCHEME_V2)
        for index in range(8):
            payload = f"leaf-{index}".encode()
            v1.add_leaf(payload)
            v2.add_leaf(payload)
        assert v1.get_root_hash() != v2.get_root_hash()


class TestLedgerSelection:
    def test_the_default_is_v1(self, tmp_path: Path) -> None:
        # Existing deployments must be unaffected by the option existing.
        ledger = _ledger(tmp_path / "default.wal", HASH_SCHEME_V1)
        try:
            assert ledger.mmr_hash_scheme == HASH_SCHEME_V1
        finally:
            ledger.close()

    def test_the_config_default_is_v1(self) -> None:
        from aegis.config import AegisSettings

        settings = AegisSettings(backend_api_key="k")
        assert settings.mmr_hash_scheme == HASH_SCHEME_V1

    def test_an_unknown_scheme_is_refused_at_construction(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="mmr_hash_scheme must be one of"):
            _ledger(tmp_path / "bad.wal", "v3-imaginary")

    @pytest.mark.parametrize("scheme", [HASH_SCHEME_V1, HASH_SCHEME_V2])
    def test_a_chain_commits_and_verifies_under_either_scheme(
        self, tmp_path: Path, scheme: str
    ) -> None:
        ledger = _ledger(tmp_path / f"{scheme}.wal", scheme)
        try:
            _commit(ledger, 5)
            valid, index = ledger.verify_integrity()
            assert valid is True
            assert index is None
        finally:
            ledger.close()

    @pytest.mark.parametrize(
        ("scheme", "expected_version"),
        [
            (HASH_SCHEME_V1, MMR_PROOF_VERSION_V1),
            (HASH_SCHEME_V2, MMR_PROOF_VERSION_V2),
        ],
    )
    def test_committed_proofs_carry_their_own_scheme(
        self, tmp_path: Path, scheme: str, expected_version: str
    ) -> None:
        # A verifier never has to guess which construction to check under.
        ledger = _ledger(tmp_path / f"{scheme}-proof.wal", scheme)
        try:
            _commit(ledger, 2)
            node = ledger.chain[-1]
            assert node.mmr_proof is not None
            assert node.mmr_proof["version"] == expected_version
        finally:
            ledger.close()

    def test_the_two_schemes_produce_different_roots_for_the_same_records(
        self, tmp_path: Path
    ) -> None:
        roots = []
        for scheme in (HASH_SCHEME_V1, HASH_SCHEME_V2):
            ledger = _ledger(tmp_path / f"roots-{scheme}.wal", scheme)
            try:
                _commit(ledger, 4)
                roots.append(ledger.chain[-1].merkle_root)
            finally:
                ledger.close()
        assert roots[0] != roots[1]


class TestNoInPlaceMigration:
    """Reopening a chain under the other scheme must fail closed, and say why."""

    @pytest.mark.parametrize(
        ("written", "reopened"),
        [(HASH_SCHEME_V1, HASH_SCHEME_V2), (HASH_SCHEME_V2, HASH_SCHEME_V1)],
    )
    def test_a_scheme_change_is_refused_by_name(
        self, tmp_path: Path, written: str, reopened: str
    ) -> None:
        wal = tmp_path / "chain.wal"
        first = _ledger(wal, written)
        try:
            _commit(first, 3)
        finally:
            first.close()

        second = _ledger(wal, reopened)
        try:
            # Not "wal_corrupt" and not "mmr_replay_mismatch": both would be
            # true statements about the roots and wrong about the evidence,
            # which is intact.
            assert second._fault_state == "mmr_scheme_mismatch"
        finally:
            second.close()

    @pytest.mark.parametrize("scheme", [HASH_SCHEME_V1, HASH_SCHEME_V2])
    def test_reopening_under_the_same_scheme_replays_cleanly(
        self, tmp_path: Path, scheme: str
    ) -> None:
        wal = tmp_path / "reopen.wal"
        first = _ledger(wal, scheme)
        try:
            _commit(first, 4)
            root_before = first.chain[-1].merkle_root
        finally:
            first.close()

        second = _ledger(wal, scheme)
        try:
            assert second._fault_state == "healthy"
            assert second.chain[-1].merkle_root == root_before
            valid, index = second.verify_integrity()
            assert valid is True
            assert index is None
        finally:
            second.close()

    def test_an_empty_wal_accepts_either_scheme(self, tmp_path: Path) -> None:
        # Nothing has been recorded, so no root is being contradicted.
        wal = tmp_path / "empty.wal"
        wal.touch()
        ledger = _ledger(wal, HASH_SCHEME_V2)
        try:
            assert ledger._fault_state == "healthy"
        finally:
            ledger.close()
