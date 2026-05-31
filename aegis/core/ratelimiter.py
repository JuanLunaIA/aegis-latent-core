"""
aegis.core.ratelimiter — Rate limiting with Redis (distributed) or in-memory fallback.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Protocol

import redis.asyncio as redis

from aegis.config import AegisSettings

logger = logging.getLogger(__name__)


class RateLimiter(Protocol):
    async def check_limit(self, key: str) -> bool: ...
    async def close(self) -> None: ...


class InMemoryRateLimiter:
    """Token-bucket rate limiter for single-node / local development."""

    def __init__(self, requests_per_minute: int = 60, burst: int = 10) -> None:
        self._rate = requests_per_minute / 60.0
        self._burst = float(burst)
        self._buckets: dict[str, tuple[float, float]] = {}
        self._lock = asyncio.Lock()

    async def check_limit(self, key: str) -> bool:
        now = time.monotonic()
        async with self._lock:
            tokens, last = self._buckets.get(key, (self._burst, now))
            elapsed = max(0.0, now - last)
            tokens = min(self._burst, tokens + elapsed * self._rate)
            if tokens < 1.0:
                self._buckets[key] = (tokens, now)
                return False
            self._buckets[key] = (tokens - 1.0, now)
            return True

    async def close(self) -> None:
        self._buckets.clear()


class DistributedRateLimiter:
    """Redis-backed GCRA rate limiter for multi-node deployments."""

    def __init__(
        self,
        redis_url: str = "redis://localhost:6379",
        requests_per_minute: int = 60,
        burst: int = 10,
    ) -> None:
        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.rate = requests_per_minute / 60.0
        self.burst = float(burst)
        self.emission_interval = 1.0 / self.rate if self.rate > 0 else float("inf")

    async def check_limit(self, key: str) -> bool:
        now = time.time()
        lua_script = """
        local key = KEYS[1]
        local interval = tonumber(ARGV[1])
        local burst = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])

        local tat = redis.call('GET', key)
        if not tat then
            tat = now
        else
            tat = tonumber(tat)
        end

        local new_tat = math.max(tat, now) + interval
        local allow_at = new_tat - burst

        if allow_at > now then
            return 0
        end

        redis.call('SET', key, new_tat, 'EX', math.ceil(burst + interval))
        return 1
        """
        try:
            burst_tolerance = self.burst * self.emission_interval
            result = await self.redis.eval(
                lua_script,
                1,
                f"ratelimit:{key}",
                self.emission_interval,
                burst_tolerance,
                now,
            )
            return result == 1
        except Exception as e:
            logger.warning("Redis rate limit check failed (%s); allowing request", e)
            return True

    async def close(self) -> None:
        await self.redis.aclose()


def create_rate_limiter(settings: AegisSettings) -> RateLimiter:
    """Build the configured rate limiter backend."""
    rpm = settings.rate_limit_threshold
    burst = settings.rate_limit_burst
    if settings.rate_limit_backend == "redis":
        return DistributedRateLimiter(
            redis_url=settings.redis_url,
            requests_per_minute=rpm,
            burst=burst,
        )
    return InMemoryRateLimiter(requests_per_minute=rpm, burst=burst)
