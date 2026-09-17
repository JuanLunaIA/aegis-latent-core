"""
tests/test_dynamodb_concurrent_append_race.py — REG-011: does the DynamoDB
half of the guard hold against a real server, not a mock?

`DynamoDBStorageProvider.write_node_atomic` (`aegis_server/storage/dynamodb_provider.py`)
uses a `TransactWriteItems` with two halves — insert the node, advance a
separate tip item — conditioned so the whole transaction cancels if another
writer already moved the tip. Every existing test of this path
(`tests/test_dynamodb_provider_new.py`, `tests/test_zz_dynamodb_additional.py`)
stubs `aioboto3`/`botocore` entirely, so the transaction's actual atomicity —
whether DynamoDB really cancels the loser rather than committing two nodes
that both claim the same predecessor — has never been exercised against a
server that can actually interleave two clients. This is the DynamoDB half of
the gap `CLM-081`'s forbidden-phrase list already names: "PostgreSQL and
DynamoDB are tested" is disallowed because neither was executed in this
environment; `tests/test_postgres_concurrent_append_race.py` closed the
PostgreSQL half, and this file closes the other.

Real network I/O against a live process (DynamoDB Local), so `slow` and
skipped outright when `aioboto3` is not installed or the endpoint is not
reachable — an integration test, not a substitute for the unit suite.

What these tests pin, against the actual service:

* N concurrent tasks racing for the same tip produce exactly one committed
  node and N-1 `ConcurrentChainMutationError`s — the `TransactWriteItems`
  really is atomic across two real clients, not merely in the code's own
  reading of AWS's documentation;
* a loser can retry against the real new tip and succeed;
* the guard holds across repeated rounds on a growing chain.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import asyncio
import hashlib
import os
import uuid
from datetime import UTC, datetime
from typing import Any

import pytest

aioboto3 = pytest.importorskip("aioboto3", reason="aioboto3 is an optional storage-dynamodb extra")

from aegis_server.storage.base import GENESIS_PREV_HASH, ConcurrentChainMutationError  # noqa: E402
from aegis_server.storage.dynamodb_provider import DynamoDBStorageProvider  # noqa: E402

_ENDPOINT = os.environ.get("AEGIS_TEST_DYNAMODB_ENDPOINT", "http://localhost:58000")

# DynamoDB Local does not check these against a real account, but it does
# check the *shape* — an arbitrary string is rejected with
# UnrecognizedClientException — so use the well-known AWS documentation
# example pair, which is formatted like a real key/secret and used exactly
# this way (against local/mock endpoints) throughout AWS's own SDK examples.
# Deliberately overwritten, not `setdefault`: this sandbox pre-populates
# AWS_ACCESS_KEY_ID/AWS_SECRET_ACCESS_KEY with an unrelated placeholder for
# other tooling, which DynamoDB Local also rejects on shape. Every call in
# this file pins `endpoint_url` to the local Docker container, so overriding
# these for the test process never sends a credential anywhere but localhost.
os.environ["AWS_ACCESS_KEY_ID"] = "AKIAIOSFODNN7EXAMPLE"
os.environ["AWS_SECRET_ACCESS_KEY"] = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
os.environ.setdefault("AWS_DEFAULT_REGION", "us-east-1")


async def _server_reachable() -> tuple[bool, str]:
    try:
        session = aioboto3.Session()
        async with session.client(
            "dynamodb", region_name="us-east-1", endpoint_url=_ENDPOINT
        ) as client:
            await client.list_tables()
    except Exception as exc:  # pragma: no cover - diagnostic path
        return False, f"{type(exc).__name__}: {exc}"
    return True, ""


def _node_id(label: str) -> str:
    return hashlib.sha256(f"{label}-{uuid.uuid4()}".encode()).hexdigest()


_timestamp_counter = 0


def _fresh_timestamp() -> str:
    """A strictly increasing ISO-8601 timestamp, immune to clock-tick ties.

    Appends a zero-padded monotonic counter after the wall-clock timestamp so
    two writes issued within the same microsecond still sort distinctly under
    lexicographic (ISO-8601) ordering, which is what the GSI in
    ``get_latest_node`` relies on.
    """
    global _timestamp_counter
    _timestamp_counter += 1
    return f"{datetime.now(UTC).isoformat()}-{_timestamp_counter:012d}"


async def _write(provider: DynamoDBStorageProvider, *, label: str, expected_prev_hash: str) -> str:
    """Write one node with a genuinely fresh timestamp.

    ``get_latest_node`` orders the GSI by ``timestamp`` alone
    (``ScanIndexForward=False``, ``Limit=1``); two items sharing a timestamp
    have no defined order in that query. Real writers never share one, so the
    fixture must not either — an identical constant here would test a
    situation the production code never produces, and did, in an earlier
    draft of this file, produce exactly the flaky-looking failure this
    comment now prevents.
    """
    node_id = _node_id(label)
    await provider.write_node_atomic(
        node_id=node_id,
        timestamp=_fresh_timestamp(),
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
        pytest.skip(f"no reachable DynamoDB Local at {_ENDPOINT!r} ({reason})")
    table_name = f"aegis-reg011-{uuid.uuid4().hex[:12]}"
    p = DynamoDBStorageProvider(table_name=table_name, region="us-east-1", endpoint_url=_ENDPOINT)
    await p.initialize()
    yield p
    session = aioboto3.Session()
    async with session.client(
        "dynamodb", region_name="us-east-1", endpoint_url=_ENDPOINT
    ) as client:
        await client.delete_table(TableName=table_name)
    await p.close()


@pytest.mark.slow
@pytest.mark.asyncio
async def test_concurrent_genesis_writers_produce_exactly_one_winner(provider: Any) -> None:
    """Twenty real transactions race for the empty chain's genesis slot."""
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
        r
        for r in results
        if isinstance(r, Exception) and not isinstance(r, ConcurrentChainMutationError)
    ]

    assert other_errors == [], f"unexpected exception types: {other_errors!r}"
    assert len(winners) == 1, f"expected exactly one winner, got {len(winners)}: {winners!r}"
    assert len(losers) == 19

    latest = await provider.get_latest_node()
    assert latest is not None
    assert latest["node_id"] == winners[0]


@pytest.mark.slow
@pytest.mark.asyncio
async def test_a_loser_can_retry_against_the_real_new_tip(provider: Any) -> None:
    """The transaction cancellation is a fence to route around, not a dead end."""
    winner_id = await _write(provider, label="first", expected_prev_hash=GENESIS_PREV_HASH)

    with pytest.raises(ConcurrentChainMutationError):
        await _write(provider, label="stale-retry", expected_prev_hash=GENESIS_PREV_HASH)

    latest = await provider.get_latest_node()
    assert latest is not None
    assert latest["node_id"] == winner_id

    retried_id = await _write(provider, label="retry", expected_prev_hash=latest["node_id"])
    assert retried_id != winner_id

    latest_after_retry = await provider.get_latest_node()
    assert latest_after_retry is not None
    assert latest_after_retry["node_id"] == retried_id


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

    latest = await provider.get_latest_node()
    assert latest is not None
    assert latest["node_id"] == tip
