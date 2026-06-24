"""
aegis.core.ratelimiter — Rate limiting with Redis (distributed) or in-memory fallback.

Tier-4 Rust acceleration (v3.0.0):
    When aegis_rust is compiled, `create_rate_limiter` returns a
    `RustBackedRateLimiter` for the "memory" backend.  It replaces
    `asyncio.Lock` with a lock-free atomic CAS token bucket implemented in
    Rust (~50 ns/check vs ~5 µs for the Python asyncio path).  The API is
    identical to `InMemoryRateLimiter` so no call-site changes are required.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any, Protocol

import redis.asyncio as redis

from aegis.config import AegisSettings
from aegis.core.rust_integration import new_rust_rate_limiter

logger = logging.getLogger(__name__)


class RateLimiter(Protocol):
    async def check_limit(self, key: str) -> bool: ...
    async def close(self) -> None: ...


class InMemoryRateLimiter:
    """
    Token-bucket rate limiter for single-node / local development.

    MEDIUM-01 fix: ``_buckets`` is now a bounded TTL dict.  Entries are
    automatically evicted after ``ttl`` seconds of inactivity, preventing
    unbounded memory growth under high client-ID cardinality (e.g. unique
    IPs during an enumeration attack).

    TTL is calculated as 2 × burst_window so a bucket survives long enough
    to replenish naturally but stale entries are cleaned up promptly.

    Falls back to a plain dict if ``cachetools`` is not installed (logs a
    one-time warning so operators can install it for production use).
    """

    _WARN_ONCE: bool = False

    def __init__(self, requests_per_minute: int = 60, burst: int = 10) -> None:
        self._rate = requests_per_minute / 60.0
        self._burst = float(burst)
        self._lock = asyncio.Lock()

        # Compute a sensible TTL: time to refill an empty bucket × 2 slack.
        ttl = (burst / self._rate) * 2.0 if self._rate > 0 else 300.0

        try:
            from cachetools import TTLCache  # type: ignore[import-untyped]

            self._buckets: dict[str, tuple[float, float]] = TTLCache(maxsize=200_000, ttl=ttl)
            logger.debug("InMemoryRateLimiter: cachetools TTLCache active (ttl=%.0fs)", ttl)
        except ImportError:
            if not InMemoryRateLimiter._WARN_ONCE:
                logger.warning(
                    "cachetools not installed — InMemoryRateLimiter will grow unbounded "
                    "under high client-ID cardinality. "
                    "Install with: pip install 'aegis-latent-core[ratelimit]'"
                )
                InMemoryRateLimiter._WARN_ONCE = True
            self._buckets = {}

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
        # Warn when using plaintext Redis against a remote host; use rediss:// for TLS.
        if redis_url.startswith("redis://") and not redis_url.startswith("redis://localhost"):
            logger.warning(
                "DistributedRateLimiter: Redis URL uses plaintext (redis://) with a "
                "non-localhost host. Use rediss:// to enable TLS for remote Redis connections."
            )
        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.rate = requests_per_minute / 60.0
        self.burst = float(burst)
        self.emission_interval = 1.0 / self.rate if self.rate > 0 else 0.0

    async def check_limit(self, key: str) -> bool:
        if self.rate <= 0:
            return False
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
            # Fail-open: Redis unavailability must not bring down the proxy.
            # This is a security-relevant event (rate limiting bypassed) — log as ERROR.
            logger.error(
                "Redis rate limit check failed — rate limiting BYPASSED for this request: %s", e
            )
            return True

    async def close(self) -> None:
        await self.redis.aclose()


class RustBackedRateLimiter(InMemoryRateLimiter):
    """Tier-4 lock-free rate limiter backed by aegis_rust.RustRateLimiter.

    The Rust implementation uses an atomic CAS token bucket per tenant stored
    in a DashMap (sharded RwLock).  Check latency: ~50 ns vs ~5 µs for the
    Python asyncio.Lock variant.

    Subclasses ``InMemoryRateLimiter`` so that it is a drop-in substitute
    (``isinstance(x, InMemoryRateLimiter)`` holds) and the parent's pure-Python
    token bucket serves as the automatic fallback when the Rust extension is
    not compiled or fails to initialise.
    """

    def __init__(self, requests_per_minute: int = 60, burst: int = 10) -> None:
        # Parent sets up the Python token bucket used as the fallback path.
        super().__init__(requests_per_minute=requests_per_minute, burst=burst)
        # Rust limiter: capacity = burst, refill_rate = rpm/60 tokens/sec.
        refill_per_sec = max(1, round(requests_per_minute / 60))
        self._rust: Any = new_rust_rate_limiter(burst, refill_per_sec)
        logger.debug(
            "RustBackedRateLimiter: burst=%d rpm=%d rust=%s",
            burst,
            requests_per_minute,
            self._rust is not None,
        )

    async def check_limit(self, key: str) -> bool:
        if self._rust is not None:
            return bool(self._rust.check_and_consume(key))
        # Fall back to the inherited pure-Python token bucket.
        return await super().check_limit(key)

    def evict_stale(self, max_age_secs: int = 3600) -> int:
        """Evict idle buckets — call from a background maintenance task."""
        if self._rust is not None:
            return int(self._rust.evict_stale(max_age_secs))
        return 0


def create_rate_limiter(settings: AegisSettings) -> RateLimiter:
    """Build the configured rate limiter backend."""
    from aegis.core.rust_integration import has_rust

    rpm = settings.rate_limit_threshold
    burst = settings.rate_limit_burst
    if settings.rate_limit_backend == "redis":
        return DistributedRateLimiter(
            redis_url=settings.redis_url,
            requests_per_minute=rpm,
            burst=burst,
        )
    # Use Rust lock-free path when the extension is compiled; fall back to Python.
    if has_rust():
        return RustBackedRateLimiter(requests_per_minute=rpm, burst=burst)
    return InMemoryRateLimiter(requests_per_minute=rpm, burst=burst)
