"""
tests/test_mmr_state_continuity.py — the `.mmr.state` peak-set checkpoint.

Replaying every leaf to rebuild the accumulator is O(N log N) and holds O(N)
interior nodes. The checkpoint records the peak set so a restart can reseat the
accumulator in O(log N) instead.

The checkpoint is an optimisation over the WAL, never a substitute for it, and
these tests are written around that: the fast path is accepted only when it
lands on the root the WAL independently records, and every way of corrupting,
staling or removing the file must still produce the same accumulator by replay.
A checkpoint that could change the reconstructed chain would be a liability
rather than a speed-up.

The fast path is opt-in. `tests/test_mmr_restart.py` pins what full replay
gives that a peak restore does not — an in-memory inclusion proof for every
historical leaf — so the default must keep replaying.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis.core import mmr as mmr_module
from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.mmr import MerkleMountainRange, MMRInclusionProofV1, MMRPeak

SIGNING_KEY = "k" * 32


def _ledger(path: Path, *, fast: bool = False) -> CryptographicAuditLedger:
    return CryptographicAuditLedger(str(path), signing_key=SIGNING_KEY, mmr_fast_restore=fast)


def _commit(ledger: CryptographicAuditLedger, index: int) -> None:
    ledger.commit_forensic(
        state_id=f"s{index}",
        request_bytes=f"request-{index}".encode(),
        response_bytes=f"response-{index}".encode(),
    )


def _fill(path: Path, count: int) -> str:
    """Write `count` nodes, close cleanly, and return the final root."""
    ledger = _ledger(path)
    for index in range(count):
        _commit(ledger, index)
    root = ledger._mmr.get_root_hash()
    ledger.close()
    return root


def _state_path(path: Path) -> Path:
    return Path(str(path) + ".mmr.state")


# ── the checkpoint file itself ────────────────────────────────────────────────


def test_close_writes_a_checksummed_checkpoint(tmp_path: Path) -> None:
    path = tmp_path / "wal.jsonl"
    _fill(path, 7)

    document = json.loads(_state_path(path).read_text())
    assert document["version"] == 1
    assert document["leaf_count"] == 7
    # 7 = 0b111, so the peak set is three mountains of heights 2, 1, 0.
    assert [peak["height"] for peak in document["peaks"]] == [2, 1, 0]
    assert len(document["state_checksum"]) == 64


def test_checkpoint_is_owner_only(tmp_path: Path) -> None:
    """The checkpoint sits beside the WAL and must not widen its exposure."""
    path = tmp_path / "wal.jsonl"
    _fill(path, 3)
    assert _state_path(path).stat().st_mode & 0o777 == 0o600


def test_no_checkpoint_is_written_for_an_empty_ledger(tmp_path: Path) -> None:
    path = tmp_path / "wal.jsonl"
    _ledger(path).close()
    assert not _state_path(path).exists()


# ── the fast path ─────────────────────────────────────────────────────────────


def test_fast_restore_reproduces_the_root_and_holds_fewer_nodes(tmp_path: Path) -> None:
    path = tmp_path / "wal.jsonl"
    expected = _fill(path, 9)

    with _ledger(path, fast=True) as ledger:
        assert ledger._mmr.get_root_hash() == expected
        assert ledger._mmr.get_leaf_count() == 9
        assert ledger._fault_state == "healthy"
        # 9 = 0b1001 -> two peaks, against the 16 nodes a full replay holds.
        assert len(ledger._mmr.nodes) == 2


def test_appends_after_a_fast_restore_match_a_full_replay(tmp_path: Path) -> None:
    """The whole point: the two restore paths must be indistinguishable.

    Same next leaf index, same leaf count, same root — otherwise a restart
    would silently change the evidence a later commit publishes.
    """
    replayed = tmp_path / "replayed.jsonl"
    restored = tmp_path / "restored.jsonl"
    for path in (replayed, restored):
        _fill(path, 11)

    with _ledger(replayed, fast=False) as slow, _ledger(restored, fast=True) as fast:
        slow_node = slow.commit_forensic(state_id="next", request_bytes=b"a", response_bytes=b"b")
        fast_node = fast.commit_forensic(state_id="next", request_bytes=b"a", response_bytes=b"b")
        assert fast_node.mmr_leaf_index == slow_node.mmr_leaf_index == 11
        assert fast_node.mmr_leaf_count == slow_node.mmr_leaf_count == 12
        assert fast_node.merkle_root == slow_node.merkle_root


@pytest.mark.parametrize("count", [1, 2, 3, 4, 7, 8, 15, 16, 17, 31, 32])
def test_fast_restore_across_tree_shapes(tmp_path: Path, count: int) -> None:
    """Peak sets differ at every power of two; the restore must handle each."""
    path = tmp_path / f"wal-{count}.jsonl"
    expected = _fill(path, count)
    with _ledger(path, fast=True) as ledger:
        assert ledger._mmr.get_root_hash() == expected
        assert ledger._mmr.get_leaf_count() == count


def test_proofs_issued_after_a_fast_restore_verify(tmp_path: Path) -> None:
    path = tmp_path / "wal.jsonl"
    _fill(path, 6)

    with _ledger(path, fast=True) as ledger:
        node = ledger.commit_forensic(state_id="after", request_bytes=b"q", response_bytes=b"r")
        assert node.mmr_proof is not None
        proof = MMRInclusionProofV1.from_dict(node.mmr_proof)
        assert MerkleMountainRange.verify_portable_inclusion_hash(
            node.mmr_leaf_hash, proof, node.merkle_root
        )


def test_historical_leaves_refuse_rather_than_return_a_partial_path(tmp_path: Path) -> None:
    """A summarised leaf must raise, not produce a proof of nothing.

    The evidence is not lost: the committed node carries its own `mmr_proof`,
    and this test verifies that stored proof still checks out.
    """
    path = tmp_path / "wal.jsonl"
    ledger = _ledger(path)
    ledger.commit_forensic(state_id="first", request_bytes=b"a", response_bytes=b"b")
    for index in range(1, 5):
        _commit(ledger, index)
    stored = ledger.chain[0]
    ledger.close()

    with _ledger(path, fast=True) as reopened:
        # Resolved through the module rather than a from-import binding.
        # `tests/test_mmr_branch.py` calls `importlib.reload` on this module,
        # which rebuilds the exception class; a binding captured at import time
        # would then be a different object from the one actually raised, and
        # `pytest.raises` would not match it.
        with pytest.raises(mmr_module.MMRHistoricalLeafUnavailableError):
            reopened._mmr.get_portable_inclusion_proof(0)

        assert stored.mmr_proof is not None
        proof = MMRInclusionProofV1.from_dict(stored.mmr_proof)
        assert MerkleMountainRange.verify_portable_inclusion_hash(
            stored.mmr_leaf_hash, proof, stored.merkle_root
        )


# ── the default keeps full replay ─────────────────────────────────────────────


def test_default_still_replays_and_keeps_historical_proofs(tmp_path: Path) -> None:
    """Off by default: the checkpoint exists but is not consumed."""
    path = tmp_path / "wal.jsonl"
    expected = _fill(path, 9)
    assert _state_path(path).exists()

    # fast=False
    with _ledger(path) as ledger:
        assert ledger._mmr.get_root_hash() == expected
        assert ledger._mmr.leaf_index_base == 0
        for index in range(9):
            assert ledger._mmr.get_portable_inclusion_proof(index) is not None


# ── every failure mode falls back to replay ───────────────────────────────────


def _corrupt(path: Path, **overrides: object) -> None:
    document = json.loads(_state_path(path).read_text())
    document.update(overrides)
    _state_path(path).write_text(json.dumps(document))


@pytest.mark.parametrize(
    ("label", "mutate"),
    [
        ("absent", lambda p: _state_path(p).unlink()),
        ("unparseable", lambda p: _state_path(p).write_text("{not json")),
        ("empty", lambda p: _state_path(p).write_text("")),
        ("not an object", lambda p: _state_path(p).write_text("[1,2,3]")),
        ("root tampered", lambda p: _corrupt(p, bagged_root="0" * 64)),
        ("checksum stripped", lambda p: _corrupt(p, state_checksum="")),
        ("leaf_count inflated", lambda p: _corrupt(p, leaf_count=9999)),
        ("leaf_count deflated", lambda p: _corrupt(p, leaf_count=1)),
        ("unknown version", lambda p: _corrupt(p, version=99)),
        ("peaks emptied", lambda p: _corrupt(p, peaks=[])),
        ("peaks malformed", lambda p: _corrupt(p, peaks=[{"height": "x", "hash": 1}])),
    ],
)
def test_a_broken_checkpoint_falls_back_to_replay(
    tmp_path: Path, label: str, mutate: object
) -> None:
    """No corruption may change the reconstructed accumulator.

    A checkpoint the ledger cannot trust is discarded, not repaired: the WAL is
    authoritative and always sufficient on its own.
    """
    path = tmp_path / "wal.jsonl"
    expected = _fill(path, 5)
    mutate(path)  # type: ignore[operator]

    with _ledger(path, fast=True) as ledger:
        assert ledger._mmr.get_root_hash() == expected, label
        assert ledger._mmr.get_leaf_count() == 5, label
        assert ledger._fault_state == "healthy", label


def test_a_stale_checkpoint_replays_only_the_leaves_after_it(tmp_path: Path) -> None:
    """The crash case: commits landed in the WAL after the last checkpoint.

    The checkpoint covers the first four leaves; the remaining five are
    replayed on top of it, and the result must equal the live accumulator.
    """
    path = tmp_path / "wal.jsonl"
    _fill(path, 4)

    ledger = _ledger(path)
    for index in range(4, 9):
        _commit(ledger, index)
    live_root = ledger._mmr.get_root_hash()
    # Simulate a crash: drop the handle without close(), so no new checkpoint.
    assert ledger._wal_handle is not None
    ledger._wal_handle.close()
    ledger._wal_handle = None

    assert json.loads(_state_path(path).read_text())["leaf_count"] == 4

    with _ledger(path, fast=True) as recovered:
        assert recovered._mmr.get_root_hash() == live_root
        assert recovered._mmr.get_leaf_count() == 9
        assert recovered._fault_state == "healthy"


def test_rotation_checkpoints_and_survives_segments(tmp_path: Path) -> None:
    path = tmp_path / "wal.jsonl"
    ledger = CryptographicAuditLedger(str(path), signing_key=SIGNING_KEY, max_wal_bytes=2000)
    for index in range(30):
        _commit(ledger, index)
    live_root = ledger._mmr.get_root_hash()
    segments = len(ledger._segment_paths())
    ledger.close()
    assert segments > 0, "rotation did not occur; the test proves nothing"

    with _ledger(path, fast=True) as reopened:
        assert reopened._mmr.get_root_hash() == live_root
        assert reopened._mmr.get_leaf_count() == 30


# ── the accumulator primitive ─────────────────────────────────────────────────


def test_restore_from_peaks_rejects_structurally_invalid_input() -> None:
    """Fail closed: an unrepresentable peak set must not become an accumulator."""
    with pytest.raises(ValueError):
        # 3 = 0b11 requires heights [1, 0]; a single height-5 peak cannot cover it.
        MerkleMountainRange().restore_from_peaks(
            leaf_count=3, peaks=[MMRPeak(height=5, hash="a" * 64)]
        )
    with pytest.raises(ValueError):
        MerkleMountainRange().restore_from_peaks(
            leaf_count=1, peaks=[MMRPeak(height=0, hash="not-a-digest")]
        )
    with pytest.raises(ValueError):
        MerkleMountainRange().restore_from_peaks(leaf_count=0, peaks=[])

    populated = MerkleMountainRange()
    populated.add_leaf(b"leaf")
    with pytest.raises(ValueError):
        populated.restore_from_peaks(leaf_count=1, peaks=[MMRPeak(height=0, hash="a" * 64)])


@pytest.mark.parametrize("prefix", [1, 2, 3, 5, 8, 13, 21, 32, 33])
def test_restore_then_append_equals_uninterrupted_append(prefix: int) -> None:
    """Differential check against the accumulator that was never interrupted."""
    import hashlib

    def leaf(index: int) -> str:
        return hashlib.sha256(f"leaf-{index}".encode()).hexdigest()

    whole = MerkleMountainRange()
    for index in range(prefix + 3):
        whole.add_leaf_hash(leaf(index))

    partial = MerkleMountainRange()
    for index in range(prefix):
        partial.add_leaf_hash(leaf(index))
    peaks = [
        MMRPeak(height=peak.height, hash=peak.hash)
        for peak in sorted(partial.peaks, key=lambda p: p.height, reverse=True)
    ]

    restored = MerkleMountainRange()
    assert restored.restore_from_peaks(leaf_count=prefix, peaks=peaks) == (partial.get_root_hash())
    for index in range(prefix, prefix + 3):
        restored.add_leaf_hash(leaf(index))

    assert restored.get_root_hash() == whole.get_root_hash()
    assert restored.get_leaf_count() == whole.get_leaf_count()
    for index in range(prefix, prefix + 3):
        assert (
            restored.get_portable_inclusion_proof(index).to_dict()
            == whole.get_portable_inclusion_proof(index).to_dict()
        )
