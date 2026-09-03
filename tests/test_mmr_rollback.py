"""
tests/test_mmr_rollback.py — exact MMR append rollback and ledger fail-closed revert.

``CryptographicAuditLedger`` mutates its MMR before it knows whether the commit
will succeed, then reverts when signing or WAL persistence fails. That revert
used to be a ``copy.deepcopy`` of the whole accumulator taken on *every* commit,
which made commit cost grow with the length of the chain. It is now an O(log n)
checkpoint token.

The optimisation is only sound if the rollback is byte-for-byte exact, so these
tests pin two things that were previously unasserted:

1. ``rollback_to`` reproduces the state a deep copy would have restored — the
   node list, the peak list, peak/node object aliasing, the leaf bookkeeping,
   the root, and every subsequent inclusion proof.
2. The ledger actually reverts its MMR when signing or persistence fails, so a
   failed commit leaves no leaf behind and the next successful commit produces
   the same root it would have produced had the failure never happened.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import copy
import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.mmr import MerkleMountainRange

REQUEST = b'{"messages":[{"role":"user","content":"hello"}]}'
RESPONSE = b'{"choices":[{"message":{"content":"hi"}}]}'


def _state(mmr: MerkleMountainRange) -> tuple[Any, ...]:
    """Full observable state of an MMR, for equality comparison."""
    return (
        [dataclasses.astuple(node) for node in mmr.nodes],
        [dataclasses.astuple(peak) for peak in mmr.peaks],
        list(mmr._leaf_node_indices),
        mmr._leaf_count,
        mmr.get_root_hash(),
    )


def _build(leaf_count: int) -> MerkleMountainRange:
    mmr = MerkleMountainRange()
    for i in range(leaf_count):
        mmr.add_leaf(f"leaf-{i}".encode())
    return mmr


def _ledger(tmp_path: Path, **kwargs: Any) -> CryptographicAuditLedger:
    return CryptographicAuditLedger(
        persistence_path=str(tmp_path / "audit.jsonl"),
        signing_key="k" * 32,
        fsync_fn=lambda fd: None,
        **kwargs,
    )


# ── MMR checkpoint / rollback ────────────────────────────────────────────────


@pytest.mark.parametrize("leaf_count", [0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64])
def test_rollback_matches_deepcopy_restore(leaf_count: int) -> None:
    """Rollback must land on exactly the state a deep copy would have restored.

    Leaf counts straddle every power of two, because the number of peaks merged
    by a single append — and therefore the number of ``parent`` pointers the
    rollback has to clear — is determined by the trailing one-bits of the count.
    """
    mmr = _build(leaf_count)
    expected = _state(copy.deepcopy(mmr))

    checkpoint = mmr.checkpoint()
    mmr.add_leaf(b"leaf-that-must-not-survive")
    mmr.rollback_to(checkpoint)

    assert _state(mmr) == expected


@pytest.mark.parametrize("leaf_count", [1, 2, 3, 4, 7, 8, 15, 16, 31, 32])
def test_rollback_restores_peak_node_aliasing(leaf_count: int) -> None:
    """Peaks must remain the same objects as the nodes they name, with no parent.

    ``get_portable_inclusion_proof`` walks ``node.parent`` to find a leaf's peak
    and matches it by ``peak.index``. A rollback that left a stale parent
    pointer, or that replaced a peak with a copy, would produce proofs against
    a peak the root does not contain.
    """
    mmr = _build(leaf_count)
    checkpoint = mmr.checkpoint()
    mmr.add_leaf(b"transient")
    mmr.rollback_to(checkpoint)

    for peak in mmr.peaks:
        assert mmr.nodes[peak.index] is peak
        assert peak.parent is None


def test_rollback_undoes_many_appends() -> None:
    """One checkpoint covers an arbitrary run of appends, not just a single one."""
    mmr = _build(37)
    reference = _state(copy.deepcopy(mmr))

    checkpoint = mmr.checkpoint()
    for i in range(50):
        mmr.add_leaf(f"transient-{i}".encode())
    mmr.rollback_to(checkpoint)

    assert _state(mmr) == reference


def test_appends_after_rollback_match_a_clean_run() -> None:
    """A rolled-back MMR must be indistinguishable from one that never appended.

    Root equality alone would not catch a corrupted interior node, so every
    inclusion proof is compared as well.
    """
    rolled_back = _build(20)
    checkpoint = rolled_back.checkpoint()
    rolled_back.add_leaf(b"transient")
    rolled_back.rollback_to(checkpoint)
    for i in range(20, 60):
        rolled_back.add_leaf(f"leaf-{i}".encode())

    clean = _build(60)

    assert rolled_back.get_root_hash() == clean.get_root_hash()
    for index in range(60):
        assert (
            rolled_back.get_portable_inclusion_proof(index).to_dict()
            == clean.get_portable_inclusion_proof(index).to_dict()
        )


def test_checkpoint_is_cheap_relative_to_the_structure() -> None:
    """A checkpoint holds only the peaks, so it stays O(log n), not O(n).

    This is the property the optimisation rests on. Asserting the peak count
    rather than a wall-clock time keeps the test deterministic on shared CI.
    """
    mmr = _build(1024)
    checkpoint = mmr.checkpoint()

    assert len(checkpoint.peaks) == bin(1024).count("1")
    assert checkpoint.node_count == len(mmr.nodes)
    assert checkpoint.leaf_count == 1024


def test_rollback_rejects_a_checkpoint_from_another_mmr() -> None:
    """A checkpoint that is not a prefix of the current state must be refused.

    Silently accepting one would truncate a longer chain to a shorter one — an
    evidence-destroying outcome that must fail loudly instead.
    """
    ahead = _build(10)
    behind = _build(3)
    checkpoint = ahead.checkpoint()

    with pytest.raises(ValueError, match="prefix of the current state"):
        behind.rollback_to(checkpoint)


# ── Ledger fail-closed revert ────────────────────────────────────────────────


def _boom(*_args: Any, **_kwargs: Any) -> None:
    raise RuntimeError("induced failure")


def _attempt(ledger: CryptographicAuditLedger, commit: str, state_id: str) -> None:
    """Invoke one of the ledger's commit entry points."""
    if commit == "commit_forensic":
        ledger.commit_forensic(state_id=state_id, request_bytes=REQUEST, response_bytes=RESPONSE)
    elif commit == "commit_state":
        ledger.commit_state(state_id=state_id, entropy=0.0, payload=REQUEST)
    else:
        # The streaming terminal commit carries its own checkpoint site.
        ledger.commit_forensic_summary(
            state_id=state_id,
            request_bytes=REQUEST,
            response_hash="c" * 64,
            response_size=len(RESPONSE),
            response_preview=RESPONSE,
            terminal_outcome="complete",
            final_marker_included=True,
            token_count=3,
            elapsed_seconds=0.25,
        )


@pytest.mark.parametrize("failing_stage", ["_sign", "_persist_node"])
@pytest.mark.parametrize("commit", ["commit_forensic", "commit_state", "commit_forensic_summary"])
def test_failed_commit_leaves_no_leaf_in_the_mmr(
    tmp_path: Path, failing_stage: str, commit: str
) -> None:
    """A commit that fails after the leaf is appended must revert the MMR.

    Both failure points sit between the append and the WAL write, and both
    checkpoint sites — the request/response commit and the streaming terminal
    commit — must revert identically, so every combination is pinned.
    """
    ledger = _ledger(tmp_path)
    for i in range(5):
        ledger.commit_forensic(state_id=f"ok-{i}", request_bytes=REQUEST, response_bytes=RESPONSE)

    root_before = ledger._mmr.get_root_hash()
    count_before = ledger._mmr.get_leaf_count()

    setattr(ledger, failing_stage, _boom)
    with pytest.raises(RuntimeError, match="induced failure"):
        _attempt(ledger, commit, "doomed")

    assert ledger._mmr.get_root_hash() == root_before
    assert ledger._mmr.get_leaf_count() == count_before
    ledger.close()


@pytest.mark.parametrize("failing_stage", ["_sign", "_persist_node"])
def test_commit_after_a_failed_commit_matches_an_unbroken_run(
    tmp_path: Path, failing_stage: str
) -> None:
    """The chain must continue as if the failed commit had never been attempted.

    A rollback that merely restored the leaf *count* while leaving a stale
    interior node would pass the previous test and fail this one.
    """
    broken = _ledger(tmp_path / "broken")
    clean = _ledger(tmp_path / "clean")

    for i in range(8):
        for ledger in (broken, clean):
            ledger.commit_forensic(
                state_id=f"ok-{i}", request_bytes=REQUEST, response_bytes=RESPONSE
            )

    original = getattr(broken, failing_stage)
    setattr(broken, failing_stage, _boom)
    with pytest.raises(RuntimeError):
        broken.commit_forensic(state_id="doomed", request_bytes=REQUEST, response_bytes=RESPONSE)
    setattr(broken, failing_stage, original)

    for i in range(8, 20):
        for ledger in (broken, clean):
            ledger.commit_forensic(
                state_id=f"ok-{i}", request_bytes=REQUEST, response_bytes=RESPONSE
            )

    assert broken._mmr.get_root_hash() == clean._mmr.get_root_hash()
    assert _state(broken._mmr) == _state(clean._mmr)
    broken.close()
    clean.close()


def test_failed_commit_writes_no_wal_record(tmp_path: Path) -> None:
    """A reverted commit must leave no trace in the durable evidence log."""
    ledger = _ledger(tmp_path)
    for i in range(3):
        ledger.commit_forensic(state_id=f"ok-{i}", request_bytes=REQUEST, response_bytes=RESPONSE)

    ledger._sign = _boom  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        ledger.commit_forensic(state_id="doomed", request_bytes=REQUEST, response_bytes=RESPONSE)
    ledger.close()

    records = [
        json.loads(line)
        for line in (tmp_path / "audit.jsonl").read_text().splitlines()
        if line.strip()
    ]
    assert [record["state_id"] for record in records] == ["ok-0", "ok-1", "ok-2"]


def test_proofs_still_verify_after_a_failed_commit(tmp_path: Path) -> None:
    """Every committed leaf must still prove inclusion against the live root.

    This is the property a botched rollback would break in the field: the root
    keeps advancing, but proofs served from the corrupted structure no longer
    verify against it.
    """
    ledger = _ledger(tmp_path)
    for i in range(6):
        ledger.commit_forensic(state_id=f"ok-{i}", request_bytes=REQUEST, response_bytes=RESPONSE)

    ledger._persist_node = _boom  # type: ignore[method-assign]
    with pytest.raises(RuntimeError):
        ledger.commit_forensic(state_id="doomed", request_bytes=REQUEST, response_bytes=RESPONSE)
    del ledger._persist_node

    for i in range(6, 12):
        ledger.commit_forensic(state_id=f"ok-{i}", request_bytes=REQUEST, response_bytes=RESPONSE)

    mmr = ledger._mmr
    root = mmr.get_root_hash()
    for index in range(mmr.get_leaf_count()):
        leaf_hash = mmr.nodes[mmr._leaf_node_indices[index]].hash
        proof = mmr.get_portable_inclusion_proof(index)
        assert MerkleMountainRange.verify_portable_inclusion_hash(leaf_hash, proof, root)
    ledger.close()
