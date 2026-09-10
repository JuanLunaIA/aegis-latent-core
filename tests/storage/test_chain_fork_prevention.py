# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Concurrent appends must not fork the chain.

A hash chain earns its evidentiary value from having exactly one history. Two
nodes naming the same predecessor destroy that: afterwards nothing can say
which branch is the record, and an integrity sweep over either one passes. So a
fork is not a corruption to be detected later, it is a state the store must
never be able to reach.

The append path cannot be safe without help. A caller must read the tip to know
what to link to, and between that read and its write it builds and **signs** the
node — an await that may reach an HSM. Two concurrent appenders therefore read
the same tip and both write against it.

These tests drive that race directly rather than reasoning about it.

Calls with side effects are assigned before being asserted on, never called
inside the ``assert`` itself (``python -O`` strips asserts; CodeQL flags this as
py/side-effect-in-assert).
"""

from __future__ import annotations

import asyncio
import hashlib
import json
from typing import TYPE_CHECKING, Any

import pytest

if TYPE_CHECKING:  # pragma: no cover - typing only
    from pathlib import Path

pytest.importorskip("aiosqlite")

from aegis_server.storage.base import (  # noqa: E402
    GENESIS_PREV_HASH,
    ConcurrentChainMutationError,
)
from aegis_server.storage.sqlite_provider import SQLiteStorageProvider  # noqa: E402

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


async def _open(tmp_path: Path, name: str = "audit.db") -> SQLiteStorageProvider:
    provider = SQLiteStorageProvider(str(tmp_path / name))
    await provider.initialize()
    return provider


def _node(prev_hash: str, marker: str) -> dict[str, Any]:
    """A node that links to `prev_hash`, with an id nobody else will collide on."""
    node_id = hashlib.sha256(f"{prev_hash}:{marker}".encode()).hexdigest()
    return {
        "node_id": node_id,
        "timestamp": "2026-09-10T00:00:00.000000Z",
        "node_data": {"prev_hash": prev_hash, "marker": marker},
        "request_hash": hashlib.sha256(marker.encode()).hexdigest(),
        "response_hash": "",
        "merkle_root": hashlib.sha256(f"root:{marker}".encode()).hexdigest(),
        "signature": f"sig-{marker}",
        "client_id": "tenant-a",
    }


async def _chain(provider: SQLiteStorageProvider) -> list[dict[str, Any]]:
    return await provider.list_nodes(limit=10_000, offset=0)


def _is_linear(nodes: list[dict[str, Any]]) -> bool:
    """Every node links to its predecessor, and no predecessor is named twice."""
    seen_prev: set[str] = set()
    expected = GENESIS_PREV_HASH
    for node in nodes:
        data = node["node_data"]
        if isinstance(data, str):
            data = json.loads(data)
        prev = data.get("prev_hash", "")
        if prev != expected or prev in seen_prev:
            return False
        seen_prev.add(prev)
        expected = node["node_id"]
    return True


class TestConcurrentAppends:
    async def test_ten_concurrent_writers_produce_a_linear_chain(self, tmp_path: Path) -> None:
        """The order's headline case, driven for real.

        Ten tasks each read the tip, yield (standing in for the signing await
        the real caller makes), and append. Without the guard they all read the
        same tip and all write against it. With it, exactly one wins each round
        and the losers are told so.
        """
        provider = await _open(tmp_path)
        try:
            accepted = 0
            rejected = 0

            async def appender(marker: str) -> str:
                latest = await provider.get_latest_node()
                prev = latest["node_id"] if latest else GENESIS_PREV_HASH
                # The window the real caller has: build the node and sign it.
                await asyncio.sleep(0)
                try:
                    await provider.write_node_atomic(**_node(prev, marker), expected_prev_hash=prev)
                except ConcurrentChainMutationError:
                    return "rejected"
                return "accepted"

            results = await asyncio.gather(*(appender(f"n{i}") for i in range(10)))
            accepted = results.count("accepted")
            rejected = results.count("rejected")

            nodes = await _chain(provider)

            # Every write either landed or was refused; none forked.
            assert accepted + rejected == 10
            assert accepted >= 1
            assert len(nodes) == accepted
            assert _is_linear(nodes) is True
        finally:
            await provider.close()

    async def test_a_rejected_writer_succeeds_when_it_re_reads_the_tip(
        self, tmp_path: Path
    ) -> None:
        """Refusal has to be recoverable, or the guard just drops evidence."""
        provider = await _open(tmp_path)
        try:

            async def appender(marker: str) -> None:
                for _ in range(20):
                    latest = await provider.get_latest_node()
                    prev = latest["node_id"] if latest else GENESIS_PREV_HASH
                    await asyncio.sleep(0)
                    try:
                        await provider.write_node_atomic(
                            **_node(prev, marker), expected_prev_hash=prev
                        )
                    except ConcurrentChainMutationError:
                        continue
                    return
                raise AssertionError(f"{marker} never landed")

            await asyncio.gather(*(appender(f"r{i}") for i in range(10)))
            nodes = await _chain(provider)

            assert len(nodes) == 10
            assert _is_linear(nodes) is True
        finally:
            await provider.close()

    async def test_concurrent_genesis_writers_do_not_both_land(self, tmp_path: Path) -> None:
        """The case a compare-and-append alone misses.

        On an empty table there is no row to lock, so a check that only
        compares the tip lets two genesis writers through and the chain forks
        at node one. The uniqueness constraint is what actually closes this.
        """
        provider = await _open(tmp_path)
        try:
            outcomes = await asyncio.gather(
                *(_try_append(provider, GENESIS_PREV_HASH, f"g{i}") for i in range(8))
            )
            nodes = await _chain(provider)

            assert outcomes.count("accepted") == 1
            assert len(nodes) == 1
            assert _is_linear(nodes) is True
        finally:
            await provider.close()


async def _try_append(provider: SQLiteStorageProvider, prev: str, marker: str) -> str:
    await asyncio.sleep(0)
    try:
        await provider.write_node_atomic(**_node(prev, marker), expected_prev_hash=prev)
    except ConcurrentChainMutationError:
        return "rejected"
    return "accepted"


class TestTheGuardItself:
    async def test_a_stale_prev_hash_is_refused(self, tmp_path: Path) -> None:
        provider = await _open(tmp_path)
        try:
            first = _node(GENESIS_PREV_HASH, "one")
            await provider.write_node_atomic(**first, expected_prev_hash=GENESIS_PREV_HASH)

            # A writer that still believes the chain is empty.
            with pytest.raises(ConcurrentChainMutationError, match="chain tip moved"):
                await provider.write_node_atomic(
                    **_node(GENESIS_PREV_HASH, "stale"),
                    expected_prev_hash=GENESIS_PREV_HASH,
                )

            nodes = await _chain(provider)
            assert len(nodes) == 1
        finally:
            await provider.close()

    async def test_the_genesis_write_succeeds(self, tmp_path: Path) -> None:
        provider = await _open(tmp_path)
        try:
            await provider.write_node_atomic(
                **_node(GENESIS_PREV_HASH, "genesis"),
                expected_prev_hash=GENESIS_PREV_HASH,
            )
            nodes = await _chain(provider)

            assert len(nodes) == 1
            assert _is_linear(nodes) is True
        finally:
            await provider.close()

    async def test_a_refused_append_writes_nothing(self, tmp_path: Path) -> None:
        # Partial application would be worse than refusing: a node present in
        # the table but not linked is indistinguishable from tampering.
        provider = await _open(tmp_path)
        try:
            await provider.write_node_atomic(
                **_node(GENESIS_PREV_HASH, "one"), expected_prev_hash=GENESIS_PREV_HASH
            )
            before = await _chain(provider)
            with pytest.raises(ConcurrentChainMutationError):
                await provider.write_node_atomic(
                    **_node(GENESIS_PREV_HASH, "two"),
                    expected_prev_hash=GENESIS_PREV_HASH,
                )
            after = await _chain(provider)

            assert [n["node_id"] for n in before] == [n["node_id"] for n in after]
        finally:
            await provider.close()

    async def test_replaying_the_same_node_is_idempotent(self, tmp_path: Path) -> None:
        # A retry of the identical node must not be mistaken for a fork.
        provider = await _open(tmp_path)
        try:
            node = _node(GENESIS_PREV_HASH, "once")
            await provider.write_node_atomic(**node, expected_prev_hash=GENESIS_PREV_HASH)
            # The tip has moved to this node, so a replay is a stale append and
            # is refused — the record is already there either way.
            with pytest.raises(ConcurrentChainMutationError):
                await provider.write_node_atomic(**node, expected_prev_hash=GENESIS_PREV_HASH)
            nodes = await _chain(provider)

            assert len(nodes) == 1
        finally:
            await provider.close()


class TestAnAlreadyForkedStoreIsRefused:
    async def test_opening_a_forked_database_fails_loudly(self, tmp_path: Path) -> None:
        """A chain that forked before the guard existed must not be reopened.

        Appending to a history with two pasts produces evidence nobody can
        verify. There is no correct branch for this code to pick, so it refuses
        and names the duplicate for an operator to resolve.
        """
        import aiosqlite

        path = tmp_path / "forked.db"
        provider = SQLiteStorageProvider(str(path))
        await provider.initialize()
        await provider.close()

        # Forge the fork the old write_node path could produce: two nodes, one
        # predecessor, written straight past the guard.
        async with aiosqlite.connect(str(path)) as db:
            for marker in ("a", "b"):
                node = _node(GENESIS_PREV_HASH, marker)
                await db.execute(
                    "INSERT INTO audit_nodes (node_id, timestamp, request_hash, "
                    "response_hash, merkle_root, signature, client_id, node_data, "
                    "prev_hash) VALUES (?,?,?,?,?,?,?,?,?)",
                    (
                        node["node_id"],
                        node["timestamp"],
                        node["request_hash"],
                        node["response_hash"],
                        node["merkle_root"],
                        node["signature"],
                        node["client_id"],
                        json.dumps(node["node_data"]),
                        "",  # bypass the partial index while forging
                    ),
                )
            await db.execute("DROP INDEX IF EXISTS idx_audit_prev_hash;")
            await db.execute(
                "UPDATE audit_nodes SET prev_hash = json_extract(node_data, '$.prev_hash');"
            )
            await db.commit()

        reopened = SQLiteStorageProvider(str(path))
        with pytest.raises(RuntimeError, match="already forked"):
            await reopened.initialize()
