"""
tests/test_crypto_audit_rollover.py — chain integrity across memory-window rollover.

The in-memory chain is a ``deque(maxlen=max_memory_nodes)``. Once it is full,
every append silently evicts the oldest node. ``verify_integrity`` walks the
window checking ``node[i].prev_hash == node[i-1].node_hash``, so the very first
node in the window has no in-memory predecessor to link against: its
``prev_hash`` points at a node that was evicted.

``_append_memory_node`` closes that hole by recording the evicted node's hash in
``_window_anchor_hash`` *before* the eviction happens, and ``verify_integrity``
uses that anchor as the expected predecessor for index 0. These tests pin the
mechanism, in both directions — integrity holds across many rollovers, and a
break at the window boundary is still detected rather than absorbed by the
anchor.

The 100,000-node sweep is marked ``slow``; the boundary and detection tests run
in the default suite at small window sizes, where the same code path executes.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.mmr import MerkleMountainRange

GENESIS = "0" * 64
REQUEST = b'{"messages":[{"role":"user","content":"hello"}]}'
RESPONSE = b'{"choices":[{"message":{"content":"hi"}}]}'


def _ledger(path: Path, window: int, **kwargs: Any) -> CryptographicAuditLedger:
    """A ledger with fsync disabled — durability is covered by its own tests."""
    return CryptographicAuditLedger(
        persistence_path=str(path),
        signing_key="k" * 32,
        max_memory_nodes=window,
        fsync_fn=lambda fd: None,
        **kwargs,
    )


def _commit(ledger: CryptographicAuditLedger, index: int) -> str:
    node = ledger.commit_forensic(
        state_id=f"req-{index}",
        request_bytes=REQUEST,
        response_bytes=RESPONSE,
        model="m",
        endpoint="chat.completions",
    )
    return node.node_hash


# ── Anchor bookkeeping ───────────────────────────────────────────────────────


def test_anchor_is_genesis_until_the_window_fills(tmp_path: Path) -> None:
    """No eviction has happened, so index 0 must still link to genesis."""
    ledger = _ledger(tmp_path / "audit.jsonl", window=8)
    for i in range(8):
        _commit(ledger, i)

    assert len(ledger.chain) == 8
    assert ledger.window_anchor_hash == GENESIS
    assert ledger.chain[0].prev_hash == GENESIS
    assert ledger.verify_integrity() == (True, None)
    ledger.close()


def test_anchor_tracks_the_most_recently_evicted_node(tmp_path: Path) -> None:
    """After each eviction the anchor must equal the evicted node's hash.

    Checked on every commit past the boundary rather than only at the end, so
    an off-by-one that self-corrects on the next append cannot hide.
    """
    window = 8
    ledger = _ledger(tmp_path / "audit.jsonl", window=window)
    hashes = [_commit(ledger, i) for i in range(window)]

    for i in range(window, window + 25):
        hashes.append(_commit(ledger, i))
        evicted = len(hashes) - window - 1
        assert ledger.window_anchor_hash == hashes[evicted], (
            f"anchor should name node {evicted} after committing node {i}"
        )
        assert ledger.chain[0].prev_hash == ledger.window_anchor_hash
        assert ledger.verify_integrity() == (True, None)
    ledger.close()


@pytest.mark.parametrize("window", [1, 2, 3, 8, 64])
def test_integrity_holds_across_many_rollovers(tmp_path: Path, window: int) -> None:
    """Integrity must survive repeated full turnovers of the window.

    ``window=1`` is the degenerate case where every single append evicts the
    node committed immediately before it.
    """
    ledger = _ledger(tmp_path / "audit.jsonl", window=window)
    for i in range(window * 10 + 3):
        _commit(ledger, i)

    assert len(ledger.chain) == window
    assert ledger.verify_integrity() == (True, None)
    ledger.close()


# ── Detection is preserved, not absorbed ─────────────────────────────────────


def test_node_dropped_at_the_window_boundary_is_detected(tmp_path: Path) -> None:
    """Deleting the oldest in-window node must break verification.

    Every node left behind is still individually self-consistent — the deleted
    one is simply gone — so the per-node hash check cannot catch this. Only the
    ``prev_hash == anchor`` comparison at index 0 can, which makes this the
    sharpest available test of the anchor: an implementation that skipped index
    0, or that recomputed the expected predecessor from the node itself, would
    accept a silently truncated window.
    """
    ledger = _ledger(tmp_path / "audit.jsonl", window=8)
    for i in range(20):
        _commit(ledger, i)
    assert ledger.verify_integrity() == (True, None)

    ledger.chain.popleft()
    for index, node in enumerate(ledger.chain):
        assert node.node_hash == node.__creation_hash__, (
            f"node {index} was mutated; this test must exercise the link check alone"
        )

    ok, index = ledger.verify_integrity()
    assert ok is False
    assert index == 0
    ledger.close()


def test_prev_hash_rewritten_at_the_window_boundary_is_detected(tmp_path: Path) -> None:
    """Repointing the first node's predecessor must not verify."""
    ledger = _ledger(tmp_path / "audit.jsonl", window=8)
    for i in range(20):
        _commit(ledger, i)

    ledger.chain[0].prev_hash = "a" * 64
    ok, index = ledger.verify_integrity()
    assert ok is False
    assert index == 0
    ledger.close()


def test_tampered_anchor_is_detected(tmp_path: Path) -> None:
    """Rewriting the anchor must invalidate the window it anchors."""
    ledger = _ledger(tmp_path / "audit.jsonl", window=8)
    for i in range(20):
        _commit(ledger, i)

    ledger._window_anchor_hash = "b" * 64
    assert ledger.verify_integrity() == (False, 0)
    ledger.close()


def test_tampered_mid_window_node_is_detected(tmp_path: Path) -> None:
    """Rollover must not weaken detection anywhere else in the window."""
    ledger = _ledger(tmp_path / "audit.jsonl", window=8)
    for i in range(20):
        _commit(ledger, i)

    ledger.chain[4].entropy = 99.0
    ok, index = ledger.verify_integrity()
    assert ok is False
    assert index == 4
    ledger.close()


# ── Durable chain outlives the window ────────────────────────────────────────


def test_wal_retains_every_node_the_window_evicted(tmp_path: Path) -> None:
    """Eviction is a memory bound, not retention: the WAL keeps the full chain.

    Reopening with a window large enough to hold everything must reconstruct a
    chain that links back to genesis with no anchor in play.
    """
    path = tmp_path / "audit.jsonl"
    ledger = _ledger(path, window=8)
    for i in range(60):
        _commit(ledger, i)
    ledger.close()

    reopened = _ledger(path, window=1024)
    assert len(reopened.chain) == 60
    assert reopened.window_anchor_hash == GENESIS
    assert reopened.chain[0].prev_hash == GENESIS
    assert reopened.verify_integrity() == (True, None)
    assert reopened._mmr.get_leaf_count() == 60
    reopened.close()


def test_replay_into_a_small_window_reestablishes_the_anchor(tmp_path: Path) -> None:
    """Replay evicts through the same path, so it must rebuild the anchor too.

    A restart that left the anchor at genesis would report a false integrity
    violation on the first node of the reloaded window.
    """
    path = tmp_path / "audit.jsonl"
    ledger = _ledger(path, window=1024)
    hashes = [_commit(ledger, i) for i in range(60)]
    ledger.close()

    reopened = _ledger(path, window=8)
    assert len(reopened.chain) == 8
    assert reopened.window_anchor_hash == hashes[60 - 8 - 1]
    assert reopened.verify_integrity() == (True, None)
    reopened.close()


# ── Full-scale sweep ─────────────────────────────────────────────────────────


@pytest.mark.slow
def test_integrity_across_one_hundred_thousand_nodes(tmp_path: Path) -> None:
    """Commit 100,000 nodes through a 512-node window and verify the result.

    That is 194 complete turnovers of the in-memory window. Signature checking
    dominates a full ``verify_integrity`` sweep, so the sweep runs once at the
    end rather than per commit; anchor bookkeeping is checked on every eviction
    instead, which is the part rollover can break.

    The MMR is also asserted: the accumulator is unbounded and must still hold
    all 100,000 leaves, with proofs that verify against the live root long after
    the corresponding nodes left memory.
    """
    total = 100_000
    window = 512
    ledger = _ledger(tmp_path / "audit.jsonl", window=window)

    previous_hash = GENESIS
    anchor_checks = 0
    for i in range(total):
        node = ledger.commit_forensic(
            state_id=f"req-{i}",
            request_bytes=REQUEST,
            response_bytes=RESPONSE,
            model="m",
            endpoint="chat.completions",
        )
        assert node.prev_hash == previous_hash
        previous_hash = node.node_hash
        if i >= window:
            # Every append past the boundary evicts exactly one node, so the
            # anchor must equal the hash the current head links back to.
            assert ledger.window_anchor_hash == ledger.chain[0].prev_hash
            anchor_checks += 1

    assert anchor_checks == total - window
    assert len(ledger.chain) == window
    assert ledger.window_anchor_hash != GENESIS
    assert ledger.verify_integrity() == (True, None)

    mmr = ledger._mmr
    assert mmr.get_leaf_count() == total
    root = mmr.get_root_hash()
    for index in (0, 1, window, total // 2, total - window - 1, total - 1):
        leaf_hash = mmr.nodes[mmr._leaf_node_indices[index]].hash
        proof = mmr.get_portable_inclusion_proof(index)
        assert MerkleMountainRange.verify_portable_inclusion_hash(leaf_hash, proof, root), (
            f"leaf {index} does not prove inclusion in the {total}-leaf root"
        )
    ledger.close()
