# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
"""Exercise the real Redis/Valkey Lua contract, not a Python reply double."""

from __future__ import annotations

import uuid

import pytest

from aegis.proxy.rate_limiter import BucketCharge, BucketSpec, RedisRateLimitBackend


@pytest.fixture
async def backend(redis_url: str):
    instance = RedisRateLimitBackend(redis_url, namespace=f"hardening:{uuid.uuid4().hex}")
    try:
        yield instance
    finally:
        await instance.close()


async def test_lua_retains_fractional_quota(backend: RedisRateLimitBackend) -> None:
    result = await backend.apply((BucketCharge("a", BucketSpec(10, 0), 1.25),), 0)
    assert result[0].remaining == 8.75


async def test_lua_retains_fractional_retry(backend: RedisRateLimitBackend) -> None:
    result = await backend.apply((BucketCharge("a", BucketSpec(1, 4), 2),), 0)
    assert not result[0].allowed
    assert result[0].retry_after == 0.25


async def test_no_refill_bucket_never_expires(backend: RedisRateLimitBackend) -> None:
    await backend.apply((BucketCharge("a", BucketSpec(10, 0), 10),), 0)
    assert await backend._client.ttl(f"{backend._namespace}:a") == -1


async def test_clock_rollback_preserves_last_refill_time(backend: RedisRateLimitBackend) -> None:
    key = f"{backend._namespace}:a"
    seconds, micros = await backend._client.time()
    future = seconds + micros / 1_000_000 + 10
    await backend._client.hset(key, mapping={"tokens": 0, "updated_at": future})
    result = await backend.apply((BucketCharge("a", BucketSpec(10, 1), 1),), 0)
    assert not result[0].allowed
    assert float(await backend._client.hget(key, "updated_at")) >= future


async def test_tiny_refill_does_not_fail_after_debit(backend: RedisRateLimitBackend) -> None:
    result = await backend.apply((BucketCharge("a", BucketSpec(10, 1e-300), 1),), 0)
    assert result[0].allowed
    assert result[0].remaining == 9
    assert await backend._client.ttl(f"{backend._namespace}:a") == -1
