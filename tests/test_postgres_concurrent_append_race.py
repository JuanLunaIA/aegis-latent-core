"""
tests/test_postgres_concurrent_append_race.py — REG-011: does the guard hold
against a real server, not a mock?

`PostgreSQLStorageProvider.write_node_atomic` (`aegis_server/storage/postgres_provider.py`)
reads the chain tip under `FOR UPDATE` and makes the insert conditional on it,
backstopped by a unique index on `prev_hash`, so two concurrent appends racing
for the same predecessor should produce exactly one winner and N-1 refusals
(`ConcurrentChainMutationError`) rather than two nodes silently claiming the
same parent. Every existing test of this path (`tests/test_postgres_provider_new.py`)
mocks `asyncpg` entirely — the transaction semantics, the row lock, and the
unique-index backstop have never been exercised against a server that can
actually interleave two connections. `CLM-081` says exactly that: "PostgreSQL
and DynamoDB are tested" is a forbidden phrase because neither was executed
in this environment.

This file closes that gap for PostgreSQL by running the real race against a
real server. It is real network I/O against a live process, so it is marked
`slow` and skipped outright when `asyncpg` is not installed or the server is
not reachable — this is an integration test, not a substitute for the unit
suite, and CI environments without a Postgres service must still pass.

What these tests pin, against the actual database:

* N concurrent tasks appending to the same tip produce exactly one committed
  row and N-1 `ConcurrentChainMutationError`s — never two nodes linking to
  the same predecessor, and never a silent drop of the loser's identity;
* the refusal is real, not a mock's `side_effect`: a genuine second
  connection, in a genuine second transaction, was rejected by the server;
* a loser can legitimately retry — read the tip that actually won and append
  to *that* — and the retry succeeds, so the guard is a fence, not a dead end;
* the guard holds across repeated rounds on a growing chain, not only at the
  empty-table genesis race that the unique index's own comment calls out as
  a separate case from the tip-mismatch check.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import asyncio
import hashlib
import os
import uuid
from typing import Any

import pytest

asyncpg = pytest.importorskip("asyncpg", reason="asyncpg is an optional storage-postgres extra")

from aegis_server.storage.base import GENESIS_PREV_HASH, ConcurrentChainMutationError  # noqa: E402
from aegis_server.storage.postgres_provider import PostgreSQLStorageProvider  # noqa: E402

_DSN = os.environ.get(
    "AEGIS_TEST_POSTGRES_DSN",
    "postgresql://postgres:aegis_test@localhost:55432/aegis_audit",
)


async def _server_reachable() -> tuple[bool, str]:
    try:
        conn = await asyncpg.connect(dsn=_DSN, timeout=3.0)
    except Exception as exc:  # pragma: no cover - diagnostic path
        return False, f"{type(exc).__name__}: {exc}"
    await conn.close()
    return True, ""


def _node_id(label: str) -> str:
    """A plausible SHA-256-shaped node id; the race guard does not hash content."""
    return hashlib.sha256(f"{label}-{uuid.uuid4()}".encode()).hexdigest()


async def _write(
    provider: PostgreSQLStorageProvider, *, label: str, expected_prev_hash: str
) -> str:
    node_id = _node_id(label)
    await provider.write_node_atomic(
        node_id=node_id,
        timestamp="2026-09-17T00:00:00Z",
        node_data={"label": label},
        request_hash="r" * 64,
        response_hash="s" * 64,
        merkle_root="m" * 64,
        signature="sig",
        client_id="reg-011-race",
        expected_prev_hash=expected_prev_hash,
    )
    return node_id


@pytest.fixture
async def provider() -> Any:
    reachable, reason = await _server_reachable()
    if not reachable:
        pytest.skip(f"no reachable PostgreSQL at {_DSN!r} ({reason}) — this is an integration test")
    p = PostgreSQLStorageProvider(dsn=_DSN, min_size=2, max_size=25)
    await p.initialize()
    conn = await asyncpg.connect(dsn=_DSN)
    await conn.execute("TRUNCATE audit_nodes")
    await conn.close()
    yield p
    await p.close()


@pytest.mark.slow
@pytest.mark.asyncio
async def test_concurrent_genesis_writers_produce_exactly_one_winner(provider: Any) -> None:
    """Twenty real connections race for the empty table's genesis slot."""
    results = await asyncio.gather(
        *(
            _write(provider, label=f"racer-{i}", expected_prev_hash=GENESIS_PREV_HASH)
            for i in range(20)
        ),
        return_exceptions=True,
    )

    winners = [r for r in results if isinstance(r, str)]
    losers = [r for r in results if isinstance(r, ConcurrentChainMutationError)]
    other_errors = [
        r for r in results if isinstance(r, Exception) and not isinstance(r, ConcurrentChainMutationError)
    ]

    assert other_errors == [], f"unexpected exception types: {other_errors!r}"
    assert len(winners) == 1, f"expected exactly one winner, got {len(winners)}: {winners!r}"
    assert len(losers) == 19

    conn = await asyncpg.connect(dsn=_DSN)
    try:
        row_count = await conn.fetchval("SELECT COUNT(*) FROM audit_nodes")
    finally:
        await conn.close()
    assert row_count == 1, "the losing 19 must not have left any row behind"


@pytest.mark.slow
@pytest.mark.asyncio
async def test_a_loser_can_retry_against_the_real_new_tip(provider: Any) -> None:
    """The refusal is a fence to route around, not a dead end."""
    winner_id = await _write(provider, label="first", expected_prev_hash=GENESIS_PREV_HASH)

    with pytest.raises(ConcurrentChainMutationError):
        await _write(provider, label="stale-retry", expected_prev_hash=GENESIS_PREV_HASH)

    latest = await provider.get_latest_node()
    assert latest is not None
    assert latest["node_id"] == winner_id

    retried_id = await _write(provider, label="retry", expected_prev_hash=latest["node_id"])
    assert retried_id != winner_id

    conn = await asyncpg.connect(dsn=_DSN)
    try:
        row_count = await conn.fetchval("SELECT COUNT(*) FROM audit_nodes")
    finally:
        await conn.close()
    assert row_count == 2


@pytest.mark.slow
@pytest.mark.asyncio
async def test_the_guard_holds_on_a_grown_chain_not_only_at_genesis(provider: Any) -> None:
    """Repeat the race three links deep, each round against a real, moved tip."""
    tip = GENESIS_PREV_HASH
    for round_index in range(3):
        results = await asyncio.gather(
            *(
                _write(provider, label=f"round-{round_index}-racer-{i}", expected_prev_hash=tip)
                for i in range(8)
            ),
            return_exceptions=True,
        )
        winners = [r for r in results if isinstance(r, str)]
        losers = [r for r in results if isinstance(r, ConcurrentChainMutationError)]
        assert len(winners) == 1, f"round {round_index}: expected one winner, got {winners!r}"
        assert len(losers) == 7
        tip = winners[0]

    conn = await asyncpg.connect(dsn=_DSN)
    try:
        row_count = await conn.fetchval("SELECT COUNT(*) FROM audit_nodes")
        prev_hash_count = await conn.fetchval(
            "SELECT COUNT(DISTINCT prev_hash) FROM audit_nodes"
        )
    finally:
        await conn.close()
    assert row_count == 3, "three rounds, one committed winner each"
    assert prev_hash_count == 3, "no two committed nodes share a predecessor"
