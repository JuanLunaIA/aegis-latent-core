# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
"""Bounded empirical properties, not a refinement proof of distributed storage."""

from __future__ import annotations

import asyncio

from hypothesis import given, settings
from hypothesis import strategies as st

from aegis.proxy.rate_limiter import (
    BucketCharge,
    BucketSpec,
    DualRateLimiter,
    LocalRateLimitBackend,
)


@settings(max_examples=100, deadline=None)
@given(
    reserved=st.integers(min_value=0, max_value=100),
    parts=st.lists(st.integers(min_value=0, max_value=20), max_size=20),
    extra=st.integers(min_value=0, max_value=50),
)
def test_stream_and_finalize_conserve_debited_tokens(
    reserved: int, parts: list[int], extra: int
) -> None:
    async def scenario() -> None:
        limiter = DualRateLimiter(
            request_capacity=1,
            request_refill_per_second=0,
            token_capacity=1000,
            token_refill_per_second=0,
            clock=lambda: 0,
        )
        reservation = (await limiter.reserve("tenant", "credential", reserved)).reservation
        assert reservation is not None
        for part in parts:
            assert (await reservation.charge_stream(part)).allowed
        actual = sum(parts) + extra
        decision = await reservation.finalize(actual)
        assert decision.allowed
        assert decision.token_remaining == 1000 - actual
        await limiter.close()

    asyncio.run(scenario())


@settings(max_examples=100, deadline=None)
@given(keys=st.lists(st.integers(min_value=0, max_value=12), min_size=1, max_size=100))
def test_cardinality_pressure_never_reopens_depleted_identity(keys: list[int]) -> None:
    async def scenario() -> None:
        backend = LocalRateLimitBackend(max_buckets=4)
        admitted: set[int] = set()
        for key in keys:
            result = (await backend.apply((BucketCharge(str(key), BucketSpec(1, 0), 1),), 0))[0]
            if result.allowed:
                assert key not in admitted
                admitted.add(key)
            assert backend.bucket_count <= 4
        assert len(admitted) <= 4
        await backend.close()

    asyncio.run(scenario())
