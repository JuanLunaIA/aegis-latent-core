# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.ratelimiter — InMemoryRateLimiter and DistributedRateLimiter."""

from __future__ import annotations

import logging
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis.core.ratelimiter import (
    DistributedRateLimiter,
    InMemoryRateLimiter,
    create_rate_limiter,
)

# ── InMemoryRateLimiter — basic token bucket ──────────────────────────────────


@pytest.mark.asyncio
async def test_in_memory_allows_first_request():
    limiter = InMemoryRateLimiter(requests_per_minute=60, burst=10)
    allowed = await limiter.check_limit("user-1")
    assert allowed is True
    await limiter.close()


@pytest.mark.asyncio
async def test_in_memory_blocks_after_burst_exhausted():
    # Very low burst (1 token)
    limiter = InMemoryRateLimiter(requests_per_minute=1, burst=1)
    result1 = await limiter.check_limit("user-x")
    result2 = await limiter.check_limit("user-x")
    assert result1 is True
    assert result2 is False  # burst exhausted
    await limiter.close()


@pytest.mark.asyncio
async def test_in_memory_different_keys_independent():
    limiter = InMemoryRateLimiter(requests_per_minute=1, burst=1)
    assert await limiter.check_limit("a") is True
    assert await limiter.check_limit("b") is True  # different key, still has tokens
    await limiter.close()


@pytest.mark.asyncio
async def test_in_memory_close_clears_buckets():
    limiter = InMemoryRateLimiter(requests_per_minute=60, burst=10)
    await limiter.check_limit("user-1")
    await limiter.close()
    # After close, buckets is empty
    assert len(limiter._buckets) == 0


@pytest.mark.asyncio
async def test_in_memory_cachetools_unavailable_falls_back_to_dict(caplog):
    InMemoryRateLimiter._WARN_ONCE = False  # Reset warning state
    with patch.dict("sys.modules", {"cachetools": None}):
        with caplog.at_level(logging.WARNING, logger="aegis.core.ratelimiter"):
            limiter = InMemoryRateLimiter(requests_per_minute=60, burst=10)
    # Should warn about cachetools not being installed
    assert any("cachetools" in m for m in caplog.messages)
    assert isinstance(limiter._buckets, dict)
    await limiter.close()


@pytest.mark.asyncio
async def test_in_memory_warn_once_not_repeated(caplog):
    InMemoryRateLimiter._WARN_ONCE = False
    with patch.dict("sys.modules", {"cachetools": None}):
        with caplog.at_level(logging.WARNING, logger="aegis.core.ratelimiter"):
            InMemoryRateLimiter(requests_per_minute=60, burst=10)
            initial_count = sum(1 for m in caplog.messages if "cachetools" in m)
            InMemoryRateLimiter(requests_per_minute=60, burst=10)
            second_count = sum(1 for m in caplog.messages if "cachetools" in m)
    # Warning should only appear once (WARN_ONCE flag)
    assert second_count == initial_count


# ── DistributedRateLimiter — construction ────────────────────────────────────


def test_distributed_warns_on_plaintext_remote(caplog):
    with caplog.at_level(logging.WARNING, logger="aegis.core.ratelimiter"):
        DistributedRateLimiter(redis_url="redis://10.0.0.5:6379")
    assert any("plaintext" in m or "TLS" in m for m in caplog.messages)


def test_distributed_no_warn_on_localhost(caplog):
    with caplog.at_level(logging.WARNING, logger="aegis.core.ratelimiter"):
        DistributedRateLimiter(redis_url="redis://localhost:6379")
    warns = [m for m in caplog.messages if "plaintext" in m]
    assert warns == []


def test_distributed_no_warn_on_rediss(caplog):
    with caplog.at_level(logging.WARNING, logger="aegis.core.ratelimiter"):
        DistributedRateLimiter(redis_url="rediss://10.0.0.5:6380")
    warns = [m for m in caplog.messages if "plaintext" in m]
    assert warns == []


# ── DistributedRateLimiter — check_limit ─────────────────────────────────────


@pytest.mark.asyncio
async def test_distributed_check_limit_allows_when_redis_returns_1():
    limiter = DistributedRateLimiter(redis_url="redis://localhost:6379")
    # Mock redis.eval to return 1 (allow)
    limiter.redis = MagicMock()
    limiter.redis.eval = AsyncMock(return_value=1)
    result = await limiter.check_limit("user-1")
    assert result is True


@pytest.mark.asyncio
async def test_distributed_check_limit_blocks_when_redis_returns_0():
    limiter = DistributedRateLimiter(redis_url="redis://localhost:6379")
    limiter.redis = MagicMock()
    limiter.redis.eval = AsyncMock(return_value=0)
    result = await limiter.check_limit("user-1")
    assert result is False


@pytest.mark.asyncio
async def test_distributed_check_limit_allows_on_redis_failure(caplog):
    limiter = DistributedRateLimiter(redis_url="redis://localhost:6379")
    limiter.redis = MagicMock()
    limiter.redis.eval = AsyncMock(side_effect=ConnectionError("Redis down"))
    with caplog.at_level(logging.WARNING, logger="aegis.core.ratelimiter"):
        result = await limiter.check_limit("user-fail")
    # Fail-open: allow the request when Redis is unavailable
    assert result is True
    assert any("Redis" in m or "rate limit" in m.lower() for m in caplog.messages)


@pytest.mark.asyncio
async def test_distributed_check_limit_zero_rate_returns_false():
    limiter = DistributedRateLimiter(redis_url="redis://localhost:6379", requests_per_minute=0)
    limiter.redis = MagicMock()
    result = await limiter.check_limit("user-1")
    assert result is False


@pytest.mark.asyncio
async def test_distributed_close():
    limiter = DistributedRateLimiter(redis_url="redis://localhost:6379")
    limiter.redis = MagicMock()
    limiter.redis.aclose = AsyncMock()
    await limiter.close()
    limiter.redis.aclose.assert_called_once()


# ── create_rate_limiter ───────────────────────────────────────────────────────


def test_create_rate_limiter_in_memory():
    from aegis.config import AegisSettings

    settings = AegisSettings(
        rate_limit_backend="memory",
        rate_limit_threshold=120,
        rate_limit_burst=20,
        backend_api_key="sk-test",
    )
    limiter = create_rate_limiter(settings)
    assert isinstance(limiter, InMemoryRateLimiter)


def test_create_rate_limiter_redis():
    from aegis.config import AegisSettings

    settings = AegisSettings(
        rate_limit_backend="redis",
        redis_url="redis://localhost:6379",
        rate_limit_threshold=60,
        rate_limit_burst=10,
        backend_api_key="sk-test",
    )
    limiter = create_rate_limiter(settings)
    assert isinstance(limiter, DistributedRateLimiter)


# ── except Exception audit: Redis failure must log at ERROR, not WARNING ──────


@pytest.mark.asyncio
async def test_redis_failure_logs_error_and_allows(caplog):
    """Redis unavailability bypasses rate limiting — must be logged at ERROR level."""
    redis_mock = AsyncMock()
    redis_mock.eval.side_effect = ConnectionError("Redis is down")

    limiter = DistributedRateLimiter(
        redis_url="redis://localhost:6379",
        requests_per_minute=60,
        burst=10,
    )
    limiter.redis = redis_mock

    with caplog.at_level(logging.ERROR, logger="aegis.core.ratelimiter"):
        result = await limiter.check_limit("session-x")

    # Fail-open: must allow the request
    assert result is True
    # But must log at ERROR (not silently swallow or only warn)
    error_msgs = [r.message for r in caplog.records if r.levelno >= logging.ERROR]
    assert any("bypass" in m.lower() or "bypassed" in m.lower() for m in error_msgs)
