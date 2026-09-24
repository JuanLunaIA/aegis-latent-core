# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The sequencer follows a real ledger: every durable node, in chain order, once.

Drives a real ``CryptographicAuditLedger`` (fsynced JSONL WAL) and a real
SQLite sequence store. Checks that concurrent commits — whose durability
notifications arrive out of chain order — are sequenced in chain order; that a
restart sequences exactly what is missing; that a WAL which is not the one the
sequence was built from is refused rather than grafted on; and that admission
is refused while the sequence trails the chain by more than the bound.
"""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path
from typing import Any

import pytest

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.ha import (
    GlobalSequencer,
    SQLiteSequenceStore,
    verify_chain_references,
    verify_global_sequence,
)


def _ledger(path: Path) -> CryptographicAuditLedger:
    return CryptographicAuditLedger(persistence_path=str(path), signing_key="k" * 64)


def _commit(ledger: CryptographicAuditLedger, n: int) -> None:
    ledger.commit_state(state_id=f"s-{n}-{time.monotonic_ns()}", entropy=0.0, payload=b"x")


async def _wait_idle(sequencer: GlobalSequencer, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while sequencer.status()["backlog"]:
        if time.monotonic() > deadline:
            raise AssertionError(f"sequencer never caught up: {sequencer.status()}")
        await asyncio.sleep(0.05)


async def _entries(db: Path) -> list[Any]:
    store = SQLiteSequenceStore(str(db))
    await store.open()
    try:
        return await store.entries(limit=100_000)
    finally:
        await store.close()


def _references_hold(entries: list[Any], chain: str, ledger: CryptographicAuditLedger) -> None:
    ok, why = verify_chain_references(
        entries, chain, ((n.node_hash, n.prev_hash) for n in ledger.iter_wal_nodes())
    )
    assert ok, why


def test_concurrent_commits_are_sequenced_in_chain_order(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "a.wal.jsonl")
    for n in range(5):  # history that predates the sequencer: backfilled
        _commit(ledger, n)

    async def go() -> None:
        sequencer = GlobalSequencer(
            SQLiteSequenceStore(str(tmp_path / "seq.db")), "a", lambda: 1, max_lag_seconds=30
        )
        ledger.add_commit_listener(sequencer.notify)
        await sequencer.start(ledger.iter_wal_nodes)
        assert sequencer.admission_error() is None
        threads = [
            threading.Thread(target=lambda b=b: [_commit(ledger, 100 * b + i) for i in range(10)])
            for b in range(6)
        ]
        for thread in threads:
            thread.start()
        for thread in threads:
            await asyncio.to_thread(thread.join)
        await _wait_idle(sequencer)
        await sequencer.stop()

    asyncio.run(go())
    entries = asyncio.run(_entries(tmp_path / "seq.db"))
    report = verify_global_sequence(entries)
    assert report.valid, report.reason
    assert report.chains == {"a": 65}
    _references_hold(entries, "a", ledger)


def test_a_restart_sequences_exactly_what_is_missing(tmp_path: Path) -> None:
    wal, db = tmp_path / "a.wal.jsonl", tmp_path / "seq.db"
    ledger = _ledger(wal)

    async def run_once(extra: int) -> None:
        sequencer = GlobalSequencer(
            SQLiteSequenceStore(str(db)), "a", lambda: 1, max_lag_seconds=30
        )
        ledger.add_commit_listener(sequencer.notify)
        await sequencer.start(ledger.iter_wal_nodes)
        for n in range(extra):
            await asyncio.to_thread(_commit, ledger, n)
        await _wait_idle(sequencer)
        await sequencer.stop()

    asyncio.run(run_once(4))
    for n in range(3):  # committed while no sequencer was running
        _commit(ledger, 50 + n)
    asyncio.run(run_once(2))
    entries = asyncio.run(_entries(db))
    report = verify_global_sequence(entries)
    assert report.valid, report.reason
    assert report.chains == {"a": 9}, "every node exactly once: none skipped, none repeated"
    _references_hold(entries, "a", ledger)


def test_a_different_wal_under_the_same_chain_id_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "seq.db"
    original = _ledger(tmp_path / "one.wal.jsonl")
    for n in range(3):
        _commit(original, n)

    async def start(ledger: CryptographicAuditLedger) -> GlobalSequencer:
        sequencer = GlobalSequencer(
            SQLiteSequenceStore(str(db)), "a", lambda: 1, max_lag_seconds=30
        )
        await sequencer.start(ledger.iter_wal_nodes)
        return sequencer

    async def go() -> str | None:
        first = await start(original)
        await first.stop()
        impostor = _ledger(tmp_path / "two.wal.jsonl")  # e.g. the wrong volume mounted
        for n in range(5):
            _commit(impostor, n)
        second = await start(impostor)
        reason = second.admission_error()
        await second.stop()
        return reason

    reason = asyncio.run(go())
    assert reason is not None
    assert "diverged" in reason


def test_admission_is_refused_while_the_sequence_trails_too_far(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "a.wal.jsonl")
    now = [time.time()]

    class Down(SQLiteSequenceStore):
        broken = False

        async def append(self, *args: Any, **kwargs: Any) -> Any:
            if self.broken:
                raise ConnectionError("sequence store unreachable")
            return await super().append(*args, **kwargs)

    async def go() -> list[str | None]:
        store = Down(str(tmp_path / "seq.db"))
        sequencer = GlobalSequencer(
            store, "a", lambda: 1, max_lag_seconds=5, wall_clock=lambda: now[0]
        )
        ledger.add_commit_listener(sequencer.notify)
        await sequencer.start(ledger.iter_wal_nodes)
        store.broken = True
        await asyncio.to_thread(_commit, ledger, 1)
        await asyncio.sleep(0.3)
        within = sequencer.admission_error()
        now[0] += 60  # the store stays down past the bound
        beyond = sequencer.admission_error()
        store.broken = False
        now[0] = time.time()
        await _wait_idle(sequencer)
        recovered = sequencer.admission_error()
        await sequencer.stop()
        return [within, beyond, recovered]

    within, beyond, recovered = asyncio.run(go())
    assert within is None, "a lag inside the bound must not refuse traffic"
    assert beyond is not None
    assert "lag" in beyond
    assert "unreachable" in beyond
    assert recovered is None, "admission resumes once the backlog is sequenced"


@pytest.mark.parametrize("epoch", [None])
def test_no_lease_epoch_means_nothing_is_sequenced(tmp_path: Path, epoch: int | None) -> None:
    ledger = _ledger(tmp_path / "a.wal.jsonl")
    _commit(ledger, 1)

    async def go() -> dict[str, Any]:
        sequencer = GlobalSequencer(
            SQLiteSequenceStore(str(tmp_path / "seq.db")), "a", lambda: epoch, max_lag_seconds=30
        )
        await sequencer.start(ledger.iter_wal_nodes)
        status = sequencer.status()
        await sequencer.stop()
        return status

    status = asyncio.run(go())
    assert status["backlog"] == 1
    assert status["last_error"] == "no writer lease epoch"


def test_the_verify_command_passes_a_sound_record_and_fails_a_tampered_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    import json
    import sqlite3

    from aegis.core.ha import main as ha_main

    wal, db = tmp_path / "a.wal.jsonl", tmp_path / "seq.db"
    ledger = _ledger(wal)

    async def go() -> None:
        sequencer = GlobalSequencer(
            SQLiteSequenceStore(str(db)), "a", lambda: 1, max_lag_seconds=30
        )
        ledger.add_commit_listener(sequencer.notify)
        await sequencer.start(ledger.iter_wal_nodes)
        for n in range(4):
            await asyncio.to_thread(_commit, ledger, n)
        await _wait_idle(sequencer)
        await sequencer.stop()

    asyncio.run(go())
    args = ["verify", "--sequencer", f"sqlite:///{db}", "--wal", f"a={wal}"]
    assert ha_main(args) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["wal"]["a"]["fully_sequenced"] is True

    with sqlite3.connect(db) as conn:  # an operator with database access edits history
        conn.execute("UPDATE aegis_global_sequence SET node_hash = ? WHERE seq = 2", ("f" * 64,))
    assert ha_main(args) == 1
    report = json.loads(capsys.readouterr().out)
    assert report["valid"] is False
    assert report["reason"] == "entry altered"
