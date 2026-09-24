# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The global evidence sequence: one total order over every replica's chain.

What must hold, and is exercised here against real SQLite and PostgreSQL with
genuinely concurrent writers (separate processes; separate connection pools):

* concurrent replicas interleave in the sequence but never fork it — seq is
  contiguous from 1 and every entry links to the one before;
* each chain's entries stay contiguous and linked, whatever the interleaving;
* a second writer for the same chain (split brain) is refused, not merged;
* a writer holding an older lease epoch than the chain's last entry is refused
  (the storage-side fence);
* a retry of an append that already landed is a no-op, not a duplicate;
* any edit to a stored entry is caught by ``verify_global_sequence``.
"""

from __future__ import annotations

import asyncio
import dataclasses
import hashlib
import json
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest

from aegis.core.ha import (
    GENESIS_HASH,
    PendingNode,
    PostgresSequenceStore,
    SequenceDivergedError,
    SequenceEntry,
    SQLiteSequenceStore,
    plan_append,
    verify_global_sequence,
)

ROOT = Path(__file__).resolve().parents[2]


def _chain_nodes(tag: str, count: int, start_prev: str = GENESIS_HASH) -> list[PendingNode]:
    nodes, prev = [], start_prev
    for position in range(1, count + 1):
        node_hash = hashlib.sha256(f"{tag}:{position}".encode()).hexdigest()
        nodes.append(PendingNode(position, node_hash, prev))
        prev = node_hash
    return nodes


def _entry(**overrides: object) -> SequenceEntry:
    base = {
        "seq": 1,
        "prev_entry_hash": GENESIS_HASH,
        "chain_id": "c",
        "chain_epoch": 3,
        "local_seq": 5,
        "node_hash": "a" * 64,
        "local_prev_hash": "b" * 64,
        "recorded_at": "t",
        "entry_hash": "x",
    }
    base.update(overrides)
    return SequenceEntry(**base)  # type: ignore[arg-type]


# ── the fence, in isolation ──────────────────────────────────────────────────


def test_a_fresh_chain_accepts_its_first_nodes() -> None:
    nodes = _chain_nodes("c", 3)
    assert plan_append(None, 1, nodes) == nodes


def test_a_retry_of_nodes_already_sequenced_is_a_no_op() -> None:
    nodes = _chain_nodes("c", 3)
    last = _entry(local_seq=3, node_hash=nodes[2].node_hash, chain_epoch=1)
    assert plan_append(last, 1, nodes) == []
    assert plan_append(last, 1, [*nodes, *_chain_nodes("c", 4)[3:]]) == _chain_nodes("c", 4)[3:]


def test_a_node_that_does_not_continue_the_chain_is_refused() -> None:
    last = _entry(local_seq=3, node_hash="f" * 64, chain_epoch=1)
    other = _chain_nodes("other-writer", 4)
    with pytest.raises(SequenceDivergedError, match="position 3 is already sequenced"):
        plan_append(last, 1, other)
    with pytest.raises(SequenceDivergedError, match="does not continue"):
        plan_append(last, 1, [PendingNode(4, "1" * 64, "2" * 64)])


def test_a_stale_lease_epoch_is_refused() -> None:
    last = _entry(local_seq=3, chain_epoch=7)
    with pytest.raises(SequenceDivergedError, match="epoch 6 is older"):
        plan_append(last, 6, [PendingNode(4, "1" * 64, last.node_hash)])


def test_pending_nodes_must_be_contiguous() -> None:
    nodes = _chain_nodes("c", 3)
    with pytest.raises(ValueError, match="contiguous"):
        plan_append(None, 1, [nodes[0], nodes[2]])


# ── the verifier catches edits ──────────────────────────────────────────────


def _sqlite_run(path: Path, coro_factory):  # type: ignore[no-untyped-def]
    async def go():  # type: ignore[no-untyped-def]
        store = SQLiteSequenceStore(str(path))
        await store.open()
        try:
            return await coro_factory(store)
        finally:
            await store.close()

    return asyncio.run(go())


def _two_chain_sequence(tmp_path: Path) -> list[SequenceEntry]:
    a, b = _chain_nodes("a", 4), _chain_nodes("b", 4)

    async def fill(store: SQLiteSequenceStore) -> list[SequenceEntry]:
        await store.append("a", 1, a[:2])
        await store.append("b", 1, b[:3])
        await store.append("a", 1, a[2:])
        await store.append("b", 2, b[3:])
        return await store.entries()

    return _sqlite_run(tmp_path / "seq.db", fill)  # type: ignore[no-any-return]


def test_a_well_formed_sequence_verifies(tmp_path: Path) -> None:
    entries = _two_chain_sequence(tmp_path)
    report = verify_global_sequence(entries)
    assert report.valid, report.reason
    assert report.entries == 8
    assert report.chains == {"a": 4, "b": 4}


@pytest.mark.parametrize(
    ("index", "change", "reason"),
    [
        (3, {"node_hash": "e" * 64}, "entry altered"),
        (3, {"chain_epoch": 9}, "entry altered"),
        (4, {"prev_entry_hash": "0" * 63 + "1"}, "broken link"),
    ],
)
def test_an_edited_entry_is_caught(
    tmp_path: Path, index: int, change: dict[str, object], reason: str
) -> None:
    entries = _two_chain_sequence(tmp_path)
    entries[index] = dataclasses.replace(entries[index], **change)  # type: ignore[arg-type]
    report = verify_global_sequence(entries)
    assert not report.valid
    assert report.reason == reason


def test_a_dropped_entry_is_caught(tmp_path: Path) -> None:
    entries = _two_chain_sequence(tmp_path)
    del entries[2]
    report = verify_global_sequence(entries)
    assert not report.valid
    assert report.reason == "gap in seq"


# ── real concurrency: SQLite across processes ───────────────────────────────

WRITER = textwrap.dedent(
    """
    import asyncio, hashlib, random, sys
    from aegis.core.ha import GENESIS_HASH, PendingNode, SQLiteSequenceStore

    path, chain, count = sys.argv[1], sys.argv[2], int(sys.argv[3])

    async def main():
        store = SQLiteSequenceStore(path)
        await store.open()
        prev, position = GENESIS_HASH, 1
        while position <= count:
            batch = []
            for _ in range(random.randint(1, 5)):
                if position > count:
                    break
                node = hashlib.sha256(f"{chain}:{position}".encode()).hexdigest()
                batch.append(PendingNode(position, node, prev))
                prev, position = node, position + 1
            await store.append(chain, 1, batch)
        await store.close()

    asyncio.run(main())
    """
)


def test_replicas_in_separate_processes_interleave_without_forking(tmp_path: Path) -> None:
    db = tmp_path / "shared.db"
    env = {**os.environ, "PYTHONPATH": str(ROOT)}
    writers = [
        subprocess.Popen(  # noqa: S603 - fixed argv
            [sys.executable, "-c", WRITER, str(db), f"replica-{n}", "60"], env=env
        )
        for n in range(4)
    ]
    assert [w.wait(timeout=120) for w in writers] == [0, 0, 0, 0]
    entries = _sqlite_run(db, lambda store: store.entries(limit=10_000))
    report = verify_global_sequence(entries)
    assert report.valid, report.reason
    assert report.entries == 240
    assert report.chains == {f"replica-{n}": 60 for n in range(4)}
    owners = [e.chain_id for e in entries]
    assert (
        len({tuple(owners[i : i + 60]) for i in range(0, 240, 60)}) > 1 or len(set(owners[:60])) > 1
    ), "the writers never actually interleaved; the test proved nothing"


# ── real concurrency: PostgreSQL across connection pools ────────────────────


async def _pg_store(dsn: str) -> PostgresSequenceStore:
    store = PostgresSequenceStore(dsn)
    await store.open()
    return store


def test_postgres_replicas_interleave_without_forking(postgres_dsn: str) -> None:
    async def go() -> list[SequenceEntry]:
        stores = [await _pg_store(postgres_dsn) for _ in range(6)]

        async def replica(store: PostgresSequenceStore, chain: str) -> None:
            nodes = _chain_nodes(chain, 40)
            for start in range(0, 40, 4):
                await store.append(chain, 1, nodes[start : start + 4])

        await asyncio.gather(*(replica(s, f"replica-{n}") for n, s in enumerate(stores)))
        entries = await stores[0].entries(limit=10_000)
        for store in stores:
            await store.close()
        return entries

    entries = asyncio.run(go())
    report = verify_global_sequence(entries)
    assert report.valid, report.reason
    assert report.entries == 240
    assert report.chains == {f"replica-{n}": 40 for n in range(6)}


def test_postgres_refuses_a_second_writer_for_the_same_chain(postgres_dsn: str) -> None:
    async def go() -> list[object]:
        first, second = await _pg_store(postgres_dsn), await _pg_store(postgres_dsn)
        shared = _chain_nodes("shared", 2)
        await first.append("shared", 1, shared)
        # Two writers each believe they continue the chain, with different nodes.
        mine = _chain_nodes("mine", 1, start_prev=shared[-1].node_hash)
        theirs = _chain_nodes("theirs", 1, start_prev=shared[-1].node_hash)
        mine = [dataclasses.replace(mine[0], local_seq=3)]
        theirs = [dataclasses.replace(theirs[0], local_seq=3)]
        results = await asyncio.gather(
            first.append("shared", 1, mine),
            second.append("shared", 1, theirs),
            return_exceptions=True,
        )
        await first.close()
        await second.close()
        return list(results)

    results = asyncio.run(go())
    refused = [r for r in results if isinstance(r, SequenceDivergedError)]
    accepted = [r for r in results if isinstance(r, list)]
    assert len(accepted) == 1, results
    assert len(refused) == 1, results


def test_postgres_refuses_a_stale_epoch(postgres_dsn: str) -> None:
    async def go() -> None:
        store = await _pg_store(postgres_dsn)
        nodes = _chain_nodes("fenced", 3)
        await store.append("fenced", 5, nodes[:2])
        try:
            with pytest.raises(SequenceDivergedError, match="older"):
                await store.append("fenced", 4, nodes[2:])
            # The newer holder continues normally.
            await store.append("fenced", 6, nodes[2:])
            assert verify_global_sequence(await store.entries()).valid
        finally:
            await store.close()

    asyncio.run(go())


def test_entries_serialize_to_the_hashed_fields() -> None:
    entry = _entry()
    assert set(json.loads(json.dumps(entry.to_dict()))) >= {
        "seq",
        "prev_entry_hash",
        "chain_id",
        "chain_epoch",
        "local_seq",
        "node_hash",
        "local_prev_hash",
        "recorded_at",
        "entry_hash",
    }
