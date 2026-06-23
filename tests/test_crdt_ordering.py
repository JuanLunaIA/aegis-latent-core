# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.crdt_ordering — CRDT vector clock distributed ordering."""

from __future__ import annotations

from aegis.core.crdt_ordering import (
    CRDTAuditOrderer,
    OrderedAuditEntry,
    VectorClock,
)

# ── VectorClock.zero ──────────────────────────────────────────────────────────


def test_vector_clock_zero_is_empty():
    vc = VectorClock.zero()
    assert vc.clocks == {}


def test_vector_clock_zero_returns_new_instance():
    a = VectorClock.zero()
    b = VectorClock.zero()
    assert a is not b


# ── VectorClock.increment ─────────────────────────────────────────────────────


def test_increment_new_node():
    vc = VectorClock.zero()
    vc2 = vc.increment("A")
    assert vc2.clocks["A"] == 1


def test_increment_existing_node():
    vc = VectorClock(clocks={"A": 3})
    vc2 = vc.increment("A")
    assert vc2.clocks["A"] == 4


def test_increment_does_not_mutate_original():
    vc = VectorClock.zero()
    vc.increment("A")
    assert "A" not in vc.clocks


def test_increment_only_affects_target_node():
    vc = VectorClock(clocks={"A": 1, "B": 2})
    vc2 = vc.increment("A")
    assert vc2.clocks["B"] == 2


def test_increment_returns_vector_clock():
    vc = VectorClock.zero()
    assert isinstance(vc.increment("X"), VectorClock)


# ── VectorClock.merge ─────────────────────────────────────────────────────────


def test_merge_component_wise_max():
    a = VectorClock(clocks={"A": 3, "B": 1})
    b = VectorClock(clocks={"A": 1, "B": 4})
    merged = a.merge(b)
    assert merged.clocks["A"] == 3
    assert merged.clocks["B"] == 4


def test_merge_disjoint_keys():
    a = VectorClock(clocks={"A": 2})
    b = VectorClock(clocks={"B": 5})
    merged = a.merge(b)
    assert merged.clocks["A"] == 2
    assert merged.clocks["B"] == 5


def test_merge_with_zero():
    vc = VectorClock(clocks={"A": 7})
    merged = vc.merge(VectorClock.zero())
    assert merged.clocks["A"] == 7


def test_merge_commutative():
    a = VectorClock(clocks={"A": 3, "C": 1})
    b = VectorClock(clocks={"B": 2, "C": 5})
    assert a.merge(b).clocks == b.merge(a).clocks


def test_merge_returns_vector_clock():
    assert isinstance(VectorClock.zero().merge(VectorClock.zero()), VectorClock)


# ── VectorClock.happens_before ────────────────────────────────────────────────


def test_happens_before_simple():
    a = VectorClock(clocks={"A": 1})
    b = VectorClock(clocks={"A": 2})
    assert a.happens_before(b)


def test_happens_before_not_equal():
    vc = VectorClock(clocks={"A": 1})
    assert not vc.happens_before(vc)


def test_happens_before_false_when_greater():
    a = VectorClock(clocks={"A": 5})
    b = VectorClock(clocks={"A": 2})
    assert not a.happens_before(b)


def test_happens_before_with_multiple_components():
    a = VectorClock(clocks={"A": 1, "B": 2})
    b = VectorClock(clocks={"A": 2, "B": 3})
    assert a.happens_before(b)


def test_happens_before_false_concurrent():
    a = VectorClock(clocks={"A": 2, "B": 1})
    b = VectorClock(clocks={"A": 1, "B": 2})
    assert not a.happens_before(b)
    assert not b.happens_before(a)


def test_happens_before_zero_before_nonzero():
    z = VectorClock.zero()
    vc = VectorClock(clocks={"A": 1})
    assert z.happens_before(vc)


# ── VectorClock.concurrent_with ───────────────────────────────────────────────


def test_concurrent_when_neither_dominates():
    a = VectorClock(clocks={"A": 2, "B": 1})
    b = VectorClock(clocks={"A": 1, "B": 2})
    assert a.concurrent_with(b)
    assert b.concurrent_with(a)


def test_not_concurrent_when_one_dominates():
    a = VectorClock(clocks={"A": 1})
    b = VectorClock(clocks={"A": 2})
    assert not a.concurrent_with(b)
    assert not b.concurrent_with(a)


def test_not_concurrent_equal():
    vc = VectorClock(clocks={"A": 1})
    assert not vc.concurrent_with(vc)


# ── VectorClock serialization ─────────────────────────────────────────────────


def test_to_dict_roundtrip():
    vc = VectorClock(clocks={"A": 1, "B": 5})
    d = vc.to_dict()
    vc2 = VectorClock.from_dict(d)
    assert vc2.clocks == vc.clocks


def test_to_dict_returns_copy():
    vc = VectorClock(clocks={"A": 1})
    d = vc.to_dict()
    d["A"] = 99
    assert vc.clocks["A"] == 1


def test_from_dict_zero():
    vc = VectorClock.from_dict({})
    assert vc.clocks == {}


def test_from_dict_coerces_types():
    vc = VectorClock.from_dict({"X": "3"})
    assert vc.clocks["X"] == 3


# ── CRDTAuditOrderer construction ─────────────────────────────────────────────


def test_orderer_node_id():
    o = CRDTAuditOrderer(node_id="node-A")
    assert o.node_id == "node-A"


def test_orderer_initial_clock_is_zero():
    o = CRDTAuditOrderer(node_id="node-A")
    assert o._clock.clocks == {}


# ── CRDTAuditOrderer.next_clock ───────────────────────────────────────────────


def test_next_clock_increments():
    o = CRDTAuditOrderer(node_id="N")
    vc = o.next_clock()
    assert vc.clocks["N"] == 1


def test_next_clock_increments_twice():
    o = CRDTAuditOrderer(node_id="N")
    o.next_clock()
    vc = o.next_clock()
    assert vc.clocks["N"] == 2


def test_next_clock_updates_internal_state():
    o = CRDTAuditOrderer(node_id="N")
    o.next_clock()
    assert o._clock.clocks["N"] == 1


# ── CRDTAuditOrderer.receive_clock ────────────────────────────────────────────


def test_receive_clock_merges_and_increments():
    o = CRDTAuditOrderer(node_id="A")
    incoming = VectorClock(clocks={"B": 5})
    vc = o.receive_clock(incoming)
    assert vc.clocks["B"] == 5
    assert vc.clocks["A"] == 1  # own component incremented


def test_receive_clock_updates_internal():
    o = CRDTAuditOrderer(node_id="A")
    incoming = VectorClock(clocks={"B": 3})
    o.receive_clock(incoming)
    assert o._clock.clocks["B"] == 3


# ── CRDTAuditOrderer.tag_entry ────────────────────────────────────────────────


def test_tag_entry_returns_ordered_audit_entry():
    o = CRDTAuditOrderer(node_id="N")
    entry = o.tag_entry("state-1", "hash1", 1.0)
    assert isinstance(entry, OrderedAuditEntry)


def test_tag_entry_sets_state_id():
    o = CRDTAuditOrderer(node_id="N")
    entry = o.tag_entry("state-abc", "hash1", 1.0)
    assert entry.state_id == "state-abc"


def test_tag_entry_sets_node_hash():
    o = CRDTAuditOrderer(node_id="N")
    entry = o.tag_entry("state-1", "myhash", 2.5)
    assert entry.node_hash == "myhash"


def test_tag_entry_sets_origin_node_id():
    o = CRDTAuditOrderer(node_id="node-Q")
    entry = o.tag_entry("s", "h", 0.0)
    assert entry.origin_node_id == "node-Q"


def test_tag_entry_auto_assigns_clock():
    o = CRDTAuditOrderer(node_id="N")
    entry = o.tag_entry("s", "h", 0.0)
    assert entry.vector_clock.clocks["N"] == 1


def test_tag_entry_successive_clocks():
    o = CRDTAuditOrderer(node_id="N")
    e1 = o.tag_entry("s1", "h1", 1.0)
    e2 = o.tag_entry("s2", "h2", 2.0)
    assert e1.vector_clock.happens_before(e2.vector_clock)


# ── CRDTAuditOrderer.total_order ─────────────────────────────────────────────


def _make_entry(
    state_id: str, vc: VectorClock, ts: float = 0.0, origin: str = "N"
) -> OrderedAuditEntry:
    return OrderedAuditEntry(
        state_id=state_id,
        node_hash=state_id,
        timestamp=ts,
        vector_clock=vc,
        origin_node_id=origin,
    )


def test_total_order_causal_preserved():
    vc1 = VectorClock(clocks={"A": 1})
    vc2 = VectorClock(clocks={"A": 2})
    e1 = _make_entry("s1", vc1, ts=2.0)
    e2 = _make_entry("s2", vc2, ts=1.0)
    ordered = CRDTAuditOrderer.total_order([e2, e1])
    assert ordered[0].state_id == "s1"


def test_total_order_concurrent_sorted_by_timestamp():
    # Two concurrent clocks — sort by timestamp
    vc_a = VectorClock(clocks={"A": 1, "B": 0})
    vc_b = VectorClock(clocks={"A": 0, "B": 1})
    e_a = _make_entry("s-a", vc_a, ts=1.0, origin="A")
    e_b = _make_entry("s-b", vc_b, ts=2.0, origin="B")
    ordered = CRDTAuditOrderer.total_order([e_b, e_a])
    assert ordered[0].state_id == "s-a"


def test_total_order_concurrent_sorted_by_origin():
    vc_a = VectorClock(clocks={"A": 1, "B": 0})
    vc_b = VectorClock(clocks={"A": 0, "B": 1})
    e_a = _make_entry("s-z", vc_a, ts=1.0, origin="Z")
    e_b = _make_entry("s-a", vc_b, ts=1.0, origin="A")
    ordered = CRDTAuditOrderer.total_order([e_a, e_b])
    assert ordered[0].state_id == "s-a"


def test_total_order_empty():
    assert CRDTAuditOrderer.total_order([]) == []


def test_total_order_single_element():
    vc = VectorClock(clocks={"A": 1})
    e = _make_entry("s", vc)
    ordered = CRDTAuditOrderer.total_order([e])
    assert len(ordered) == 1


def test_total_order_deterministic():
    o = CRDTAuditOrderer("N")
    entries = [o.tag_entry(f"s{i}", f"h{i}", float(i)) for i in range(5)]
    import random

    shuffled = entries[:]
    random.shuffle(shuffled)
    r1 = CRDTAuditOrderer.total_order(shuffled)
    random.shuffle(shuffled)
    r2 = CRDTAuditOrderer.total_order(shuffled)
    assert [e.state_id for e in r1] == [e.state_id for e in r2]


# ── CRDTAuditOrderer.merge_from_peers ────────────────────────────────────────


def test_merge_from_peers_deduplicates():
    vc = VectorClock(clocks={"A": 1})
    e = _make_entry("dup-id", vc)
    merged = CRDTAuditOrderer.merge_from_peers([e], [e])
    assert len(merged) == 1


def test_merge_from_peers_combines_unique():
    vc1 = VectorClock(clocks={"A": 1})
    vc2 = VectorClock(clocks={"A": 2})
    e1 = _make_entry("s1", vc1, ts=1.0)
    e2 = _make_entry("s2", vc2, ts=2.0)
    merged = CRDTAuditOrderer.merge_from_peers([e1], [e2])
    assert len(merged) == 2


def test_merge_from_peers_local_wins_on_conflict():
    vc = VectorClock(clocks={"A": 1})
    local_e = OrderedAuditEntry(
        state_id="x",
        node_hash="local-hash",
        timestamp=1.0,
        vector_clock=vc,
        origin_node_id="L",
    )
    remote_e = OrderedAuditEntry(
        state_id="x",
        node_hash="remote-hash",
        timestamp=2.0,
        vector_clock=vc,
        origin_node_id="R",
    )
    merged = CRDTAuditOrderer.merge_from_peers([local_e], [remote_e])
    assert merged[0].node_hash == "local-hash"


def test_merge_from_peers_orders_result():
    vc1 = VectorClock(clocks={"A": 1})
    vc2 = VectorClock(clocks={"A": 2})
    e1 = _make_entry("s1", vc1, ts=1.0)
    e2 = _make_entry("s2", vc2, ts=2.0)
    merged = CRDTAuditOrderer.merge_from_peers([e2], [e1])
    assert merged[0].state_id == "s1"


def test_merge_from_peers_empty_inputs():
    merged = CRDTAuditOrderer.merge_from_peers([], [])
    assert merged == []
