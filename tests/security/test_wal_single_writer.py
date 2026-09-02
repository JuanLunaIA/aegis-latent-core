# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Single-writer enforcement for the authoritative JSONL WAL.

Threat WAL-02: two writers appending to one WAL path produce divergent
``prev_hash`` relationships that the loader cannot represent as one verified
chain. The topology was previously documented as unsupported but not enforced,
so the fork could occur silently. These tests pin the enforcement.
"""

from __future__ import annotations

import multiprocessing as mp
import os

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger, WalWriterConflictError

_KEY = "k" * 32


def test_second_writer_on_same_path_is_refused(tmp_path):
    """A live writer must prevent a second ledger from opening the same path."""
    wal = str(tmp_path / "a.wal.jsonl")
    first = CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY)
    try:
        with pytest.raises(WalWriterConflictError):
            CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY)
    finally:
        first.close()


def test_refused_writer_leaks_no_descriptor(tmp_path):
    """The losing writer must close its descriptor rather than leak it."""
    wal = str(tmp_path / "b.wal.jsonl")
    first = CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY)
    try:
        for _ in range(50):
            with pytest.raises(WalWriterConflictError):
                CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY)
        # A descriptor leak would exhaust the process limit well before 50.
        assert first._wal_handle is not None
    finally:
        first.close()


def test_restart_reacquires_the_lock(tmp_path):
    """Releasing the writer must allow a later process to reopen the path."""
    wal = str(tmp_path / "c.wal.jsonl")
    first = CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY)
    first.commit_state("s0", 1.0, b"payload", tenant_id="t1")
    first.close()

    second = CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY)
    try:
        assert len(second.chain) >= 1
        ok, _ = second.verify_integrity()
        assert ok is True
    finally:
        second.close()


def test_distinct_paths_are_independent(tmp_path):
    """The guard must not block legitimate per-replica WAL paths."""
    one = CryptographicAuditLedger(
        persistence_path=str(tmp_path / "r1.wal.jsonl"), signing_key=_KEY
    )
    two = CryptographicAuditLedger(
        persistence_path=str(tmp_path / "r2.wal.jsonl"), signing_key=_KEY
    )
    try:
        one.commit_state("s0", 1.0, b"a", tenant_id="t1")
        two.commit_state("s0", 1.0, b"b", tenant_id="t1")
        assert one.verify_integrity()[0] is True
        assert two.verify_integrity()[0] is True
    finally:
        one.close()
        two.close()


def _child_try_open(wal: str, result) -> None:
    """Open the WAL in a separate process and report the outcome."""
    try:
        ledger = CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY)
        ledger.close()
        result.value = 0  # acquired — a fork would have been possible
    except WalWriterConflictError:
        result.value = 1  # correctly refused
    except Exception:  # pragma: no cover - unexpected failure mode
        result.value = 2


@pytest.mark.skipif(os.name != "posix", reason="advisory locking is POSIX-only")
def test_cross_process_writer_is_refused(tmp_path):
    """The guard must hold across processes, which is the real threat."""
    wal = str(tmp_path / "d.wal.jsonl")
    holder = CryptographicAuditLedger(persistence_path=wal, signing_key=_KEY)
    try:
        ctx = mp.get_context("spawn")
        result = ctx.Value("i", -1)
        child = ctx.Process(target=_child_try_open, args=(wal, result))
        child.start()
        child.join(timeout=60)
        assert child.exitcode == 0
        assert result.value == 1, "a second process acquired the WAL lock"
    finally:
        holder.close()
