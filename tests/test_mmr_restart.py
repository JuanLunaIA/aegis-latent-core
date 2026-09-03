"""
tests/test_mmr_restart.py — MMR continuity across a process restart.

The MMR accumulator lives in memory. If a restart rebuilt only the node chain
and left the accumulator empty, the first commit after that restart would
publish a root for a one-leaf tree while claiming a leaf index far above it —
and every inclusion proof issued afterwards would verify against a root no
independent holder of the pre-restart root could reconcile.

`_load_from_wal` replays each record's leaf hash through `add_leaf_hash`, so the
accumulator is reconstructed before the ledger accepts new work. These tests pin
that continuity against the strongest available oracle: a ledger that never
restarted at all.
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

REQUEST = b'{"messages":[{"role":"user","content":"hello"}]}'
RESPONSE = b'{"choices":[{"message":{"content":"hi"}}]}'


def _ledger(path: Path, **kwargs: Any) -> CryptographicAuditLedger:
    return CryptographicAuditLedger(
        persistence_path=str(path),
        signing_key="k" * 32,
        fsync_fn=lambda fd: None,
        **kwargs,
    )


def _commit(ledger: CryptographicAuditLedger, index: int) -> Any:
    return ledger.commit_forensic(
        state_id=f"req-{index}",
        request_bytes=REQUEST,
        response_bytes=RESPONSE,
        model="m",
        endpoint="chat.completions",
    )


def test_root_after_restart_matches_an_uninterrupted_ledger(tmp_path: Path) -> None:
    """Five commits, a restart, a sixth — the root must equal six unbroken commits.

    The uninterrupted ledger is the oracle. Comparing against a hand-computed
    expectation would only prove the test agrees with itself.
    """
    restarted_path = tmp_path / "restarted.jsonl"
    first = _ledger(restarted_path)
    for i in range(5):
        _commit(first, i)
    root_before = first._mmr.get_root_hash()
    first.close()

    reopened = _ledger(restarted_path)
    assert reopened._mmr.get_leaf_count() == 5
    assert reopened._mmr.get_root_hash() == root_before
    node = _commit(reopened, 5)

    continuous = _ledger(tmp_path / "continuous.jsonl")
    for i in range(6):
        _commit(continuous, i)

    assert reopened._mmr.get_root_hash() == continuous._mmr.get_root_hash()
    assert reopened._mmr.get_leaf_count() == continuous._mmr.get_leaf_count() == 6
    assert node.mmr_leaf_index == 5
    assert node.mmr_leaf_count == 6

    reopened.close()
    continuous.close()


@pytest.mark.parametrize("before", [1, 2, 3, 7, 8, 9, 16])
def test_restart_at_every_shape_of_tree(tmp_path: Path, before: int) -> None:
    """Continuity must hold wherever the restart falls in the carry pattern.

    Peak merging is a binary increment, so a restart just below, at, and just
    above a power of two exercises different amounts of carry propagation on the
    next append.
    """
    path = tmp_path / f"restart-{before}.jsonl"
    first = _ledger(path)
    for i in range(before):
        _commit(first, i)
    first.close()

    reopened = _ledger(path)
    _commit(reopened, before)

    continuous = _ledger(tmp_path / f"continuous-{before}.jsonl")
    for i in range(before + 1):
        _commit(continuous, i)

    assert reopened._mmr.get_root_hash() == continuous._mmr.get_root_hash()
    reopened.close()
    continuous.close()


def test_proofs_issued_after_a_restart_verify_against_the_live_root(tmp_path: Path) -> None:
    """Every leaf, including pre-restart ones, must still prove inclusion.

    Root equality alone would not catch an accumulator rebuilt with the right
    peaks but the wrong interior structure, which is what proofs depend on.
    """
    path = tmp_path / "proofs.jsonl"
    first = _ledger(path)
    for i in range(9):
        _commit(first, i)
    first.close()

    reopened = _ledger(path)
    for i in range(9, 14):
        _commit(reopened, i)

    mmr = reopened._mmr
    root = mmr.get_root_hash()
    assert mmr.get_leaf_count() == 14
    for index in range(14):
        leaf_hash = mmr.nodes[mmr._leaf_node_indices[index]].hash
        proof = mmr.get_portable_inclusion_proof(index)
        assert MerkleMountainRange.verify_portable_inclusion_hash(leaf_hash, proof, root), (
            f"leaf {index} does not prove inclusion after restart"
        )
    reopened.close()


def test_repeated_restarts_do_not_drift(tmp_path: Path) -> None:
    """Continuity must survive many restarts, not just one.

    A rebuild that dropped or duplicated a single leaf per cycle would still
    pass a one-restart test.
    """
    path = tmp_path / "repeated.jsonl"
    index = 0
    for _ in range(6):
        ledger = _ledger(path)
        for _ in range(3):
            _commit(ledger, index)
            index += 1
        ledger.close()

    final = _ledger(path)
    continuous = _ledger(tmp_path / "continuous-repeated.jsonl")
    for i in range(index):
        _commit(continuous, i)

    assert final._mmr.get_leaf_count() == index == 18
    assert final._mmr.get_root_hash() == continuous._mmr.get_root_hash()
    final.close()
    continuous.close()
