# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Causal-Merkle CRDT semilattice laws, exercised across the PyO3 boundary.

The Rust suite proves the laws inside the crate. These tests prove the same
properties through the binding actually shipped to Python, because a binding
can lose them: a getter that copies the wrong field, or a ``join`` that
returns the receiver, would pass every Rust test and still be wrong here.

Scope. ``CausalMmr`` is an accumulator, not a deployment. It is not wired into
``CryptographicAuditLedger`` — the ledger writes ``aegis-mmr-inclusion-v1``
roots — and there is no gossip transport. ``join`` reconciles replicas that
disagree about *ordering*, not replicas that lie: a replica contributing
fabricated leaves has them merged like any other. Cross-replica global
ordering remains open work; see ``docs/ROADMAP.md``.
"""

from __future__ import annotations

import itertools
import os

import pytest

# These tests need the compiled extension. Skipping when it is absent keeps the
# suite usable for contributors on a pure-Python checkout — but a skip that CI
# also honours would mean the binding is never exercised anywhere, and a silent
# skip reads exactly like a pass in the summary line. So CI sets
# AEGIS_REQUIRE_RUST=1 and a missing or incomplete extension becomes a failure
# there. See the "Rust Extension" job in .github/workflows/ci.yml.
_REQUIRED = os.environ.get("AEGIS_REQUIRE_RUST") == "1"

try:
    import aegis_rust
except ImportError as exc:  # pragma: no cover - depends on the build environment
    if _REQUIRED:
        raise AssertionError(
            "AEGIS_REQUIRE_RUST=1 but the aegis_rust extension is not importable; "
            "the CausalMmr binding tests would have skipped silently"
        ) from exc
    aegis_rust = None

CausalMmr = getattr(aegis_rust, "CausalMmr", None)

if _REQUIRED and CausalMmr is None:  # pragma: no cover - build-shape guard
    raise AssertionError(
        "AEGIS_REQUIRE_RUST=1 but aegis_rust exposes no CausalMmr; the extension "
        "was built without the binding these tests exist to cover"
    )

pytestmark = pytest.mark.skipif(
    CausalMmr is None, reason="aegis_rust built without the CausalMmr binding"
)


def _replica(replica_id: int, payloads: list[str]):
    mmr = CausalMmr(replica_id)
    for payload in payloads:
        mmr.append(payload.encode("utf-8"))
    return mmr


@pytest.fixture
def three_replicas():
    return (
        _replica(1, ["a1", "a2"]),
        _replica(2, ["b1"]),
        _replica(3, ["c1", "c2", "c3"]),
    )


class TestSemilatticeLaws:
    """Idempotence, commutativity, associativity — through the binding."""

    def test_join_is_idempotent(self, three_replicas):
        for replica in three_replicas:
            joined = replica.join(replica)
            assert joined.root == replica.root
            assert joined.leaf_count == replica.leaf_count

    def test_join_is_commutative(self, three_replicas):
        a, b, _ = three_replicas
        assert a.join(b).root == b.join(a).root

    def test_join_is_associative(self, three_replicas):
        a, b, c = three_replicas
        assert a.join(b).join(c).root == a.join(b.join(c)).root

    def test_every_merge_order_reaches_one_root(self, three_replicas):
        """The property the laws exist to deliver."""

        roots = set()
        for x, y, z in itertools.permutations(three_replicas):
            roots.add(x.join(y).join(z).root)
        assert len(roots) == 1, f"merge order changed the root: {roots}"


class TestConvergence:
    def test_disjoint_replicas_contribute_every_leaf(self, three_replicas):
        a, b, c = three_replicas
        assert a.join(b).join(c).leaf_count == 6

    def test_rejoining_a_merged_peer_is_a_no_op(self, three_replicas):
        a, b, _ = three_replicas
        merged = a.join(b)
        assert merged.join(b).root == merged.root
        assert merged.join(b).leaf_count == merged.leaf_count

    def test_a_replica_that_saw_nothing_changes_nothing(self, three_replicas):
        a, _, _ = three_replicas
        empty = CausalMmr(99)
        assert a.join(empty).root == a.root
        assert a.join(empty).leaf_count == a.leaf_count


class TestAccumulatorShape:
    def test_append_changes_the_root(self):
        mmr = CausalMmr(1)
        before = mmr.root
        mmr.append(b"payload")
        assert mmr.root != before

    def test_append_returns_the_new_root(self):
        mmr = CausalMmr(1)
        returned = mmr.append(b"payload")
        assert returned == mmr.root

    def test_root_is_lowercase_sha256_hex(self, three_replicas):
        root = three_replicas[0].root
        assert len(root) == 64
        assert root == root.lower()
        int(root, 16)

    def test_peak_count_is_the_population_count(self):
        mmr = CausalMmr(1)
        for i in range(1, 17):
            mmr.append(str(i).encode())
            assert len(mmr.peaks) == bin(mmr.leaf_count).count("1")

    def test_clock_advances_only_for_the_appending_replica(self):
        mmr = CausalMmr(7)
        mmr.append(b"one")
        mmr.append(b"two")
        assert mmr.clock == {7: 2}

    def test_join_merges_clocks_pointwise(self, three_replicas):
        a, b, _ = three_replicas
        merged = a.join(b)
        assert merged.clock[1] == a.clock[1]
        assert merged.clock[2] == b.clock[2]

    def test_replica_id_is_preserved(self):
        assert CausalMmr(42).replica_id == 42

    def test_join_does_not_mutate_either_operand(self, three_replicas):
        a, b, _ = three_replicas
        a_root, b_root, a_n, b_n = a.root, b.root, a.leaf_count, b.leaf_count
        a.join(b)
        assert (a.root, a.leaf_count) == (a_root, a_n)
        assert (b.root, b_root and b.leaf_count) == (b_root, b_n)


class TestBoundary:
    def test_the_crdt_root_is_not_the_ledger_root(self):
        """Pins that this is a separate accumulator, not the ledger's.

        The CRDT commits a leaf over ``0x00 || replica || clock || payload``,
        so its root cannot coincide with a v1 ledger root over the same
        payload. Asserting it here keeps a future reader from assuming the two
        are interchangeable.
        """

        from aegis.core.mmr import MerkleMountainRange

        payload = b"identical-payload"

        crdt = CausalMmr(1)
        crdt.append(payload)

        ledger = MerkleMountainRange()
        ledger.add_leaf(payload)

        assert crdt.root != ledger.get_root_hash()

    def test_empty_accumulator_has_a_defined_root(self):
        empty = CausalMmr(1)
        assert empty.leaf_count == 0
        assert len(empty.root) == 64
        assert empty.root != "0" * 64
