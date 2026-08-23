"""Deterministic tests for tenant/credential dual token buckets."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import asyncio

import pytest

from aegis.proxy.rate_limiter import (
    BucketCharge,
    BucketResult,
    DualRateLimiter,
    LocalRateLimitBackend,
)


class Clock:
    def __init__(self) -> None:
        self.value = 100.0

    def __call__(self) -> float:
        return self.value


@pytest.mark.asyncio
async def test_atomic_request_and_token_decision_has_accurate_remaining_and_retry() -> None:
    clock = Clock()
    limiter = DualRateLimiter(
        request_capacity=2,
        request_refill_per_second=1.0,
        token_capacity=10,
        token_refill_per_second=2.0,
        clock=clock,
    )
    first = await limiter.reserve("tenant", "credential", 8)
    assert first.allowed
    assert (first.request_remaining, first.token_remaining, first.retry_after) == (1, 2, 0.0)

    denied = await limiter.reserve("tenant", "credential", 4)
    assert not denied.allowed
    assert denied.request_remaining == 1  # request charge was rolled back atomically
    assert denied.token_remaining == 2
    assert denied.retry_after == 1.0

    clock.value += 1.0
    allowed = await limiter.reserve("tenant", "credential", 4)
    assert allowed.allowed
    assert (allowed.request_remaining, allowed.token_remaining) == (1, 0)


@pytest.mark.asyncio
async def test_buckets_are_scoped_only_by_tenant_and_credential() -> None:
    limiter = DualRateLimiter(
        request_capacity=1,
        request_refill_per_second=0,
        token_capacity=1,
        token_refill_per_second=0,
        clock=lambda: 0.0,
    )
    assert (await limiter.reserve("tenant-a", "same-credential", 1)).allowed
    assert not (await limiter.reserve("tenant-a", "same-credential", 1)).allowed
    assert (await limiter.reserve("tenant-b", "same-credential", 1)).allowed
    assert (await limiter.reserve("tenant-a", "different-credential", 1)).allowed


@pytest.mark.asyncio
async def test_reservation_stream_overage_and_refund_reconcile_once() -> None:
    limiter = DualRateLimiter(
        request_capacity=5,
        request_refill_per_second=0,
        token_capacity=10,
        token_refill_per_second=0,
        clock=lambda: 0.0,
    )
    admitted = await limiter.reserve("tenant", "credential", 6)
    reservation = admitted.reservation
    assert reservation is not None
    within = await reservation.charge_stream(4)
    assert within.allowed
    assert within.token_remaining == 4
    overage = await reservation.charge_stream(3)
    assert overage.allowed
    assert overage.token_remaining == 3
    settled = await reservation.refund()
    assert settled.allowed
    assert settled.token_remaining == 3
    with pytest.raises(RuntimeError, match="already closed"):
        await reservation.refund()


@pytest.mark.asyncio
async def test_finalize_refunds_unused_or_rejects_unavailable_overage() -> None:
    limiter = DualRateLimiter(
        request_capacity=5,
        request_refill_per_second=0,
        token_capacity=10,
        token_refill_per_second=0,
        clock=lambda: 0.0,
    )
    reservation = (await limiter.reserve("tenant", "credential", 6)).reservation
    assert reservation is not None
    refunded = await reservation.finalize(2)
    assert refunded.allowed
    assert refunded.token_remaining == 8

    reservation2 = (await limiter.reserve("tenant", "credential", 8)).reservation
    assert reservation2 is not None
    denied = await reservation2.finalize(9)
    assert not denied.allowed
    assert denied.retry_after == float("inf")


@pytest.mark.asyncio
async def test_local_backend_is_lock_protected_under_concurrency() -> None:
    limiter = DualRateLimiter(
        request_capacity=1,
        request_refill_per_second=0,
        token_capacity=100,
        token_refill_per_second=0,
        clock=lambda: 0.0,
    )
    decisions = await asyncio.gather(
        *(limiter.reserve("tenant", "credential", 0) for _ in range(20))
    )
    assert sum(decision.allowed for decision in decisions) == 1


@pytest.mark.asyncio
async def test_local_backend_cardinality_is_bounded() -> None:
    backend = LocalRateLimitBackend(max_buckets=4)
    limiter = DualRateLimiter(
        request_capacity=1,
        request_refill_per_second=0,
        token_capacity=1,
        token_refill_per_second=0,
        backend=backend,
        clock=lambda: 0.0,
    )
    for index in range(20):
        await limiter.reserve("tenant", f"credential-{index}", 1)
    assert backend.bucket_count == 4


class RecordingDistributedBackend:
    def __init__(self) -> None:
        self.calls: list[tuple[BucketCharge, ...]] = []

    async def apply(
        self, charges: tuple[BucketCharge, ...], now: float
    ) -> tuple[BucketResult, ...]:
        self.calls.append(charges)
        return tuple(
            BucketResult(True, charge.spec.capacity - charge.amount, 0.0) for charge in charges
        )


@pytest.mark.asyncio
async def test_injected_distributed_protocol_receives_derived_identity_keys() -> None:
    backend = RecordingDistributedBackend()
    limiter = DualRateLimiter(
        request_capacity=5,
        request_refill_per_second=1,
        token_capacity=20,
        token_refill_per_second=2,
        backend=backend,
        clock=lambda: 12.0,
    )
    assert (await limiter.reserve("tenant", "credential", 3)).allowed
    keys = [charge.key for charge in backend.calls[0]]
    assert len(keys) == 2
    assert keys[0].startswith("request:")
    assert keys[1].startswith("token:")
    assert all("tenant" not in key and "credential" not in key for key in keys)
    assert all("session" not in key for key in keys)
