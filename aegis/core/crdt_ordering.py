# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.crdt_ordering — Domain 3.3 CRDT for distributed audit node ordering.

Implements a Lamport-style vector clock CRDT that enables deterministic total
ordering of audit nodes across multiple Aegis instances without a central
coordinator.

Ordering rules (in priority):
  1. Causal order — if A happens-before B, A sorts first.
  2. Concurrent entries — broken deterministically by (timestamp, origin_node_id, state_id).

This module has no external dependencies beyond the standard library.
"""

from __future__ import annotations

import functools
import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ── VectorClock ───────────────────────────────────────────────────────────────


@dataclass
class VectorClock:
    """
    Lamport-style vector clock keyed by node_id.

    Each component tracks the logical time of one Aegis node.  The clock
    supports the standard vector-clock partial order (happens-before) and
    component-wise merge (join) for CRDT convergence.

    Usage::

        vc = VectorClock.zero()
        vc2 = vc.increment("node-A")
        vc3 = vc2.increment("node-A")
        assert vc2.happens_before(vc3)
    """

    clocks: dict[str, int] = field(default_factory=dict)

    # ── Mutating helpers return NEW instances (functional style) ──────────────

    def increment(self, node_id: str) -> VectorClock:
        """Return a new clock with *node_id*'s component incremented by 1."""
        updated = dict(self.clocks)
        updated[node_id] = updated.get(node_id, 0) + 1
        return VectorClock(clocks=updated)

    def merge(self, other: VectorClock) -> VectorClock:
        """Return a new clock that is the component-wise maximum of both clocks."""
        all_keys = set(self.clocks) | set(other.clocks)
        merged = {k: max(self.clocks.get(k, 0), other.clocks.get(k, 0)) for k in all_keys}
        return VectorClock(clocks=merged)

    # ── Partial-order predicates ──────────────────────────────────────────────

    def happens_before(self, other: VectorClock) -> bool:
        """
        Return True if *self* causally precedes *other*.

        self < other ⟺
          ∀k: self[k] ≤ other[k]  AND  ∃k: self[k] < other[k]
        """
        all_keys = set(self.clocks) | set(other.clocks)
        strictly_less = False
        for k in all_keys:
            s = self.clocks.get(k, 0)
            o = other.clocks.get(k, 0)
            if s > o:
                return False
            if s < o:
                strictly_less = True
        return strictly_less

    def concurrent_with(self, other: VectorClock) -> bool:
        """
        Return True if neither clock happens-before the other AND they are not equal.

        Two clocks are concurrent when they represent activity on diverged
        branches that have not yet been merged.  Equal clocks are considered
        identical, not concurrent.
        """
        if self.clocks == other.clocks:
            return False
        return not self.happens_before(other) and not other.happens_before(self)

    # ── Serialization ─────────────────────────────────────────────────────────

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable dict copy of the clock components."""
        return dict(self.clocks)

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> VectorClock:
        """Reconstruct a VectorClock from a dict produced by :meth:`to_dict`."""
        return cls(clocks={str(k): int(v) for k, v in d.items()})

    @classmethod
    def zero(cls) -> VectorClock:
        """Return the zero (empty) vector clock."""
        return cls(clocks={})


# ── OrderedAuditEntry ─────────────────────────────────────────────────────────


@dataclass
class OrderedAuditEntry:
    """An audit node annotated with a vector clock for distributed ordering."""

    state_id: str  # UUID from the audit node
    node_hash: str  # SHA-256 hash of the node
    timestamp: float  # wall-clock UTC epoch (advisory, not authoritative)
    vector_clock: VectorClock
    origin_node_id: str  # Which Aegis instance created this


# ── Exceptions ────────────────────────────────────────────────────────────────


class CRDTConflict(Exception):  # noqa: N818 — intentional domain name, not an error class
    """Raised when two entries are truly concurrent (neither happens-before the other)."""

    def __init__(self, a: OrderedAuditEntry, b: OrderedAuditEntry) -> None:
        self.a = a
        self.b = b
        super().__init__(f"CRDT conflict: entries {a.state_id!r} and {b.state_id!r} are concurrent")


# ── CRDTAuditOrderer ──────────────────────────────────────────────────────────


class CRDTAuditOrderer:
    """
    Assigns vector clocks to audit entries and produces a deterministic total order.

    Ordering rules (in priority):

    1. **Causal order**: if A happens-before B, A comes first.
    2. **Concurrent entries**: sort by ``(timestamp, origin_node_id, state_id)``
       for determinism across all nodes.

    Usage::

        orderer = CRDTAuditOrderer(node_id="node-A")
        entry = orderer.tag_entry(state_id="abc", node_hash="0x...", timestamp=1.0)
        ordered = CRDTAuditOrderer.total_order([entry, ...])
    """

    def __init__(self, node_id: str) -> None:
        self.node_id = node_id
        self._clock: VectorClock = VectorClock.zero()

    # ── Clock management ──────────────────────────────────────────────────────

    def next_clock(self) -> VectorClock:
        """Increment own clock component and return the updated clock."""
        self._clock = self._clock.increment(self.node_id)
        return self._clock

    def receive_clock(self, incoming: VectorClock) -> VectorClock:
        """
        Merge *incoming* with own clock, then increment own component.

        This implements the standard vector-clock receive rule:
            clock = merge(local, incoming).increment(self.node_id)
        """
        self._clock = self._clock.merge(incoming).increment(self.node_id)
        return self._clock

    def tag_entry(self, state_id: str, node_hash: str, timestamp: float) -> OrderedAuditEntry:
        """
        Assign the next clock tick to a new audit entry and return it.

        This is the primary way to register a locally generated audit node
        into the distributed ordering scheme.
        """
        clock = self.next_clock()
        return OrderedAuditEntry(
            state_id=state_id,
            node_hash=node_hash,
            timestamp=timestamp,
            vector_clock=clock,
            origin_node_id=self.node_id,
        )

    # ── Static ordering helpers ───────────────────────────────────────────────

    @staticmethod
    def total_order(entries: list[OrderedAuditEntry]) -> list[OrderedAuditEntry]:
        """
        Return a deterministic total ordering of *entries*.

        Uses a comparison that respects causal (happens-before) relationships
        and breaks ties between concurrent entries by
        ``(timestamp, origin_node_id, state_id)``.
        """

        def _cmp(a: OrderedAuditEntry, b: OrderedAuditEntry) -> int:
            if a.vector_clock.happens_before(b.vector_clock):
                return -1
            if b.vector_clock.happens_before(a.vector_clock):
                return 1
            # Concurrent: deterministic tiebreak
            a_key = (a.timestamp, a.origin_node_id, a.state_id)
            b_key = (b.timestamp, b.origin_node_id, b.state_id)
            if a_key < b_key:
                return -1
            if a_key > b_key:
                return 1
            return 0

        return sorted(entries, key=functools.cmp_to_key(_cmp))

    @staticmethod
    def merge_from_peers(
        local: list[OrderedAuditEntry],
        remote: list[OrderedAuditEntry],
    ) -> list[OrderedAuditEntry]:
        """
        Merge a remote peer's entry list with the local list.

        Deduplicates by ``state_id`` (local entry wins on conflict, which is
        idempotent since the vector clock encodes the same causal history),
        then applies :meth:`total_order`.
        """
        seen: dict[str, OrderedAuditEntry] = {}
        for entry in local:
            seen[entry.state_id] = entry
        for entry in remote:
            if entry.state_id not in seen:
                seen[entry.state_id] = entry
        return CRDTAuditOrderer.total_order(list(seen.values()))
