# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
"""Local regressions for atomic quota accounting and sequence transaction cleanup."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from aegis.core.ha import PendingNode, SQLiteSequenceStore
from aegis.proxy.rate_limiter import (
    BucketCharge,
    BucketSpec,
    DualRateLimiter,
    LocalRateLimitBackend,
    RateLimitBackendUnavailableError,
    RedisRateLimitBackend,
)


async def test_settlement_does_not_charge_streamed_overage_twice() -> None:
    limiter = DualRateLimiter(
        request_capacity=10,
        request_refill_per_second=0,
        token_capacity=100,
        token_refill_per_second=0,
        clock=lambda: 0.0,
    )
    reservation = (await limiter.reserve("tenant", "credential", 10)).reservation
    assert reservation is not None
    assert (await reservation.charge_stream(15)).token_remaining == 85
    settled = await reservation.finalize(17)
    assert settled.allowed
    assert settled.token_remaining == 83  # total charge is 17, not 22


async def test_cardinality_pressure_does_not_replenish_depleted_buckets() -> None:
    backend = LocalRateLimitBackend(max_buckets=2)
    spec = BucketSpec(1, 0)
    for key in ("a", "b"):
        assert (await backend.apply((BucketCharge(key, spec, 1),), 0))[0].allowed
    assert not (await backend.apply((BucketCharge("c", spec, 1),), 0))[0].allowed
    assert not (await backend.apply((BucketCharge("a", spec, 1),), 0))[0].allowed
    assert backend.bucket_count == 2


async def test_fully_replenished_buckets_can_be_reclaimed() -> None:
    backend = LocalRateLimitBackend(max_buckets=2)
    spec = BucketSpec(1, 1)
    for key in ("a", "b"):
        await backend.apply((BucketCharge(key, spec, 1),), 0)
    assert (await backend.apply((BucketCharge("c", spec, 1),), 1))[0].allowed
    assert backend.bucket_count == 2


async def test_backward_clock_does_not_create_extra_refill() -> None:
    backend = LocalRateLimitBackend()
    spec = BucketSpec(10, 1)
    await backend.apply((BucketCharge("a", spec, 10),), 10)
    assert not (await backend.apply((BucketCharge("a", spec, 1),), 5))[0].allowed
    assert not (await backend.apply((BucketCharge("a", spec, 1),), 10))[0].allowed


@pytest.mark.parametrize(
    "raw", [[2, 1, 0], [1, float("nan"), 0], [1, 11, 0], [1, 1, -2], [1, 1, "invalid"]]
)
async def test_malformed_redis_reply_raises_backend_unavailable(raw: list[object]) -> None:
    class Reply:
        async def eval(self, *args: object) -> list[object]:
            return raw

    backend = RedisRateLimitBackend("redis://127.0.0.1:1")
    await backend.close()
    backend._client = Reply()
    with pytest.raises(RateLimitBackendUnavailableError):
        await backend.apply((BucketCharge("a", BucketSpec(10, 1), 1),), 0)


async def test_cancelled_begin_does_not_leave_sqlite_transaction_open(tmp_path: Path) -> None:
    store = SQLiteSequenceStore(str(tmp_path / "sequence.db"))
    await store.open()
    db = store._db
    began = asyncio.Event()

    class PauseAfterBegin:
        async def execute(self, statement: str, *args: object) -> object:
            result = await db.execute(statement, *args)
            if statement == "BEGIN IMMEDIATE":
                began.set()
                await asyncio.Event().wait()
            return result

        def __getattr__(self, name: str) -> object:
            return getattr(db, name)

    store._db = PauseAfterBegin()
    task = asyncio.create_task(store.append("a", 1, [PendingNode(1, "n1", "g")]))
    try:
        await asyncio.wait_for(began.wait(), timeout=2)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        store._db = db
        assert not db.in_transaction
        entries = await store.append("a", 1, [PendingNode(1, "n1", "g")])
        assert len(entries) == 1
    finally:
        store._db = db
        await store.close()
