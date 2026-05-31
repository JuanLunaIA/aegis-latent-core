"""
aegis.core.ratelimiter — Distributed Redis-backed rate limiting.
Implements the Generic Cell Rate Algorithm (GCRA) for precise, distributed limiting.
"""
from __future__ import annotations
import time
import asyncio
import logging
from typing import Optional
import redis.asyncio as redis

logger = logging.getLogger(__name__)

class DistributedRateLimiter:
    """
    Redis-backed rate limiter implementing the Generic Cell Rate Algorithm (GCRA).
    This provides precise, atomic, and distributed rate limiting across multiple proxy nodes.
    """
    def __init__(
        self, 
        redis_url: str = "redis://localhost:6379", 
        requests_per_minute: int = 60, 
        burst: int = 10
    ) -> None:
        self.redis = redis.from_url(redis_url, decode_responses=True)
        self.rate = requests_per_minute / 60.0  # tokens per second
        self.burst = float(burst)
        self.emission_interval = 1.0 / self.rate if self.rate > 0 else float("inf")

    async def check_limit(self, key: str) -> bool:
        """
        Returns True if the request is allowed, False if rate-limited.
        Uses a Lua script to ensure atomicity of the GCRA operation.
        """
        now = time.time()
        
        # Lua script for GCRA (Generic Cell Rate Algorithm)
        # KEYS[1] = the rate limit key
        # ARGV[1] = emission interval (seconds)
        # ARGV[2] = burst tolerance (seconds)
        # ARGV[3] = current time (epoch)
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
            # The burst in GCRA is treated as a 'tolerance' in seconds
            burst_tolerance = self.burst * self.emission_interval
            
            result = await self.redis.eval(
                lua_script, 
                1, 
                f"ratelimit:{key}", 
                self.emission_interval, 
                burst_tolerance, 
                now
            )
            return result == 1
        except Exception as e:
            logger.error("Redis rate limit check failed: %s", e)
            # Fail-open to prevent total outage during Redis failure, 
            # but log as critical for security monitoring.
            return True

    async def close(self) -> None:
        await self.redis.close()
