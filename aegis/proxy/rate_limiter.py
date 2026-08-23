"""Tenant/credential-scoped request and generated-token rate limiting."""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

import asyncio
import hashlib
import math
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

import redis.asyncio as redis


@dataclass(frozen=True, slots=True)
class BucketSpec:
    """Capacity and continuous refill rate for one token bucket."""

    capacity: float
    refill_per_second: float

    def __post_init__(self) -> None:
        if not math.isfinite(self.capacity) or self.capacity <= 0:
            raise ValueError("bucket capacity must be finite and positive")
        if not math.isfinite(self.refill_per_second) or self.refill_per_second < 0:
            raise ValueError("bucket refill rate must be finite and non-negative")


@dataclass(frozen=True, slots=True)
class BucketCharge:
    """Atomic backend mutation and its result."""

    key: str
    spec: BucketSpec
    amount: float

    def __post_init__(self) -> None:
        if not self.key:
            raise ValueError("bucket key must not be empty")
        if not math.isfinite(self.amount):
            raise ValueError("bucket amount must be finite")


@dataclass(frozen=True, slots=True)
class BucketResult:
    """Backend decision for one bucket after applying a charge."""

    allowed: bool
    remaining: float
    retry_after: float


@runtime_checkable
class RateLimitBackend(Protocol):
    """Distributed backends implement the same atomic multi-bucket operation."""

    async def apply(
        self, charges: tuple[BucketCharge, ...], now: float
    ) -> tuple[BucketResult, ...]:
        """Atomically apply all charges or reject all positive charges."""

    async def close(self) -> None:
        """Release backend resources."""


@dataclass(slots=True)
class _BucketState:
    tokens: float
    updated_at: float


class LocalRateLimitBackend:
    """Deterministic lock-protected backend with bounded LRU cardinality."""

    def __init__(self, *, max_buckets: int = 10_000) -> None:
        if max_buckets < 2:
            raise ValueError("max_buckets must be at least two")
        self.max_buckets = max_buckets
        self._buckets: OrderedDict[str, _BucketState] = OrderedDict()
        self._lock = asyncio.Lock()

    async def apply(
        self, charges: tuple[BucketCharge, ...], now: float
    ) -> tuple[BucketResult, ...]:
        if not math.isfinite(now):
            raise ValueError("clock value must be finite")
        if len({charge.key for charge in charges}) != len(charges):
            raise ValueError("a backend transaction cannot charge a bucket twice")
        async with self._lock:
            missing = sum(charge.key not in self._buckets for charge in charges)
            protected = {charge.key for charge in charges}
            while len(self._buckets) + missing > self.max_buckets:
                evictable = next((key for key in self._buckets if key not in protected), None)
                if evictable is None:
                    return tuple(BucketResult(False, 0.0, math.inf) for _charge in charges)
                del self._buckets[evictable]
            available: list[float] = []
            for charge in charges:
                state = self._buckets.get(charge.key)
                if state is None:
                    tokens = charge.spec.capacity
                else:
                    elapsed = max(0.0, now - state.updated_at)
                    tokens = min(
                        charge.spec.capacity,
                        state.tokens + elapsed * charge.spec.refill_per_second,
                    )
                available.append(tokens)
            allowed = all(
                charge.amount <= 0 or tokens + 1e-12 >= charge.amount
                for charge, tokens in zip(charges, available, strict=True)
            )
            results: list[BucketResult] = []
            for charge, tokens in zip(charges, available, strict=True):
                if allowed:
                    new_tokens = min(charge.spec.capacity, max(0.0, tokens - charge.amount))
                else:
                    new_tokens = tokens
                self._buckets[charge.key] = _BucketState(new_tokens, now)
                self._buckets.move_to_end(charge.key)
                deficit = max(0.0, charge.amount - tokens) if charge.amount > 0 else 0.0
                retry_after = (
                    deficit / charge.spec.refill_per_second
                    if deficit and charge.spec.refill_per_second > 0
                    else (math.inf if deficit else 0.0)
                )
                results.append(
                    BucketResult(allowed, new_tokens if allowed else tokens, retry_after)
                )
            return tuple(results)

    async def close(self) -> None:
        """Clear local bucket state."""

        async with self._lock:
            self._buckets.clear()

    @property
    def bucket_count(self) -> int:
        """Current bounded state cardinality."""

        return len(self._buckets)


class RateLimitBackendUnavailableError(RuntimeError):
    """Raised when a distributed backend cannot produce an atomic decision."""


class RedisRateLimitBackend:
    """Redis-backed atomic multi-bucket limiter using Redis server time."""

    _SCRIPT = """
local now_parts = redis.call('TIME')
local now = tonumber(now_parts[1]) + tonumber(now_parts[2]) / 1000000
local count = #KEYS
local available = {}
local allowed = 1
for i = 1, count do
  local offset = (i - 1) * 3
  local capacity = tonumber(ARGV[offset + 1])
  local refill = tonumber(ARGV[offset + 2])
  local amount = tonumber(ARGV[offset + 3])
  local values = redis.call('HMGET', KEYS[i], 'tokens', 'updated_at')
  local tokens = capacity
  if values[1] and values[2] then
    local elapsed = math.max(0, now - tonumber(values[2]))
    tokens = math.min(capacity, tonumber(values[1]) + elapsed * refill)
  end
  available[i] = tokens
  if amount > 0 and tokens + 0.000000000001 < amount then allowed = 0 end
end
local result = {allowed}
for i = 1, count do
  local offset = (i - 1) * 3
  local capacity = tonumber(ARGV[offset + 1])
  local refill = tonumber(ARGV[offset + 2])
  local amount = tonumber(ARGV[offset + 3])
  local tokens = available[i]
  local updated = tokens
  if allowed == 1 then updated = math.min(capacity, math.max(0, tokens - amount)) end
  local deficit = 0
  if amount > tokens then deficit = amount - tokens end
  local retry = 0
  if deficit > 0 then
    if refill > 0 then retry = deficit / refill else retry = -1 end
  end
  redis.call('HSET', KEYS[i], 'tokens', updated, 'updated_at', now)
  local ttl = 3600
  if refill > 0 then ttl = math.max(1, math.ceil((capacity / refill) * 2)) end
  redis.call('EXPIRE', KEYS[i], ttl)
  table.insert(result, updated)
  table.insert(result, retry)
end
return result
"""

    def __init__(self, redis_url: str, *, namespace: str = "aegis:v4:ratelimit") -> None:
        if not redis_url:
            raise ValueError("redis_url must not be empty")
        if not namespace or any(character.isspace() for character in namespace):
            raise ValueError("namespace must be non-empty and contain no whitespace")
        self._client = redis.from_url(redis_url, decode_responses=False)
        self._namespace = namespace

    async def apply(
        self, charges: tuple[BucketCharge, ...], now: float
    ) -> tuple[BucketResult, ...]:
        del now
        if not charges:
            return ()
        if len({charge.key for charge in charges}) != len(charges):
            raise ValueError("a backend transaction cannot charge a bucket twice")
        keys = [f"{self._namespace}:{charge.key}" for charge in charges]
        arguments: list[str] = []
        for charge in charges:
            arguments.extend(
                (
                    format(charge.spec.capacity, ".17g"),
                    format(charge.spec.refill_per_second, ".17g"),
                    format(charge.amount, ".17g"),
                )
            )
        try:
            raw = await self._client.eval(self._SCRIPT, len(keys), *keys, *arguments)
        except Exception as exc:
            raise RateLimitBackendUnavailableError(
                "distributed rate-limit backend unavailable"
            ) from exc
        if not isinstance(raw, (list, tuple)) or len(raw) != 1 + 2 * len(charges):
            raise RateLimitBackendUnavailableError(
                "distributed rate-limit backend returned invalid data"
            )
        allowed = int(raw[0]) == 1
        results: list[BucketResult] = []
        for index in range(len(charges)):
            remaining = float(raw[1 + index * 2])
            retry_value = float(raw[2 + index * 2])
            retry_after = math.inf if retry_value < 0 else retry_value
            results.append(BucketResult(allowed, remaining, retry_after))
        return tuple(results)

    async def close(self) -> None:
        await self._client.aclose()


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    """Combined request/token admission decision."""

    allowed: bool
    request_remaining: int
    token_remaining: int
    retry_after: float
    reservation: TokenReservation | None = None

    @property
    def remaining(self) -> int:
        """Conservative remaining capacity across request and token dimensions."""

        return min(self.request_remaining, self.token_remaining)


class TokenReservation:
    """One-shot generated-token reservation with refund and streaming settlement."""

    __slots__ = (
        "_limiter",
        "tenant_id",
        "credential_id",
        "reserved",
        "_charged",
        "_closed",
        "_lock",
    )

    def __init__(
        self,
        limiter: DualRateLimiter,
        tenant_id: str,
        credential_id: str,
        reserved: int,
    ) -> None:
        self._limiter = limiter
        self.tenant_id = tenant_id
        self.credential_id = credential_id
        self.reserved = reserved
        self._charged = 0
        self._closed = False
        self._lock = asyncio.Lock()

    @property
    def charged(self) -> int:
        """Generated tokens settled against this reservation."""

        return self._charged

    async def charge_stream(self, token_count: int) -> RateLimitDecision:
        """Record streamed generated tokens, charging only usage above the reservation."""

        if token_count < 0:
            raise ValueError("stream token_count cannot be negative")
        async with self._lock:
            if self._closed:
                raise RuntimeError("token reservation is already closed")
            previous_overage = max(0, self._charged - self.reserved)
            new_total = self._charged + token_count
            new_overage = max(0, new_total - self.reserved)
            incremental = new_overage - previous_overage
            decision = await self._limiter._charge_tokens(
                self.tenant_id, self.credential_id, incremental
            )
            if decision.allowed:
                self._charged = new_total
            return decision

    async def refund(self, token_count: int | None = None) -> RateLimitDecision:
        """Close the reservation and refund unused reserved tokens exactly once."""

        async with self._lock:
            if self._closed:
                raise RuntimeError("token reservation is already closed")
            used = self._charged if token_count is None else token_count
            if used < 0:
                raise ValueError("used token count cannot be negative")
            if used < self._charged:
                raise ValueError("used token count cannot be below observed streamed usage")
            refund_amount = max(0, self.reserved - min(used, self.reserved))
            decision = await self._limiter._charge_tokens(
                self.tenant_id, self.credential_id, -refund_amount
            )
            self._closed = True
            return decision

    async def finalize(self, actual_tokens: int) -> RateLimitDecision:
        """Settle a non-streaming response and refund any unused reservation."""

        if actual_tokens < 0:
            raise ValueError("actual token count cannot be negative")
        async with self._lock:
            if self._closed:
                raise RuntimeError("token reservation is already closed")
            if actual_tokens < self._charged:
                raise ValueError("actual token count cannot be below observed streamed usage")
            overage = max(0, actual_tokens - self.reserved)
            refund = max(0, self.reserved - actual_tokens)
            decision = await self._limiter._charge_tokens(
                self.tenant_id, self.credential_id, overage - refund
            )
            if decision.allowed:
                self._charged = actual_tokens
                self._closed = True
            return decision


class DualRateLimiter:
    """Atomically gate requests and reserve generated-token budgets per credential.

    Keys are derived exclusively from validated tenant and credential identities; no caller-
    supplied session key participates in bucket selection.
    """

    def __init__(
        self,
        *,
        request_capacity: int,
        request_refill_per_second: float,
        token_capacity: int,
        token_refill_per_second: float,
        backend: RateLimitBackend | None = None,
        max_buckets: int = 10_000,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.request_spec = BucketSpec(float(request_capacity), request_refill_per_second)
        self.token_spec = BucketSpec(float(token_capacity), token_refill_per_second)
        self.backend: RateLimitBackend = backend or LocalRateLimitBackend(max_buckets=max_buckets)
        self._clock = clock

    async def reserve(
        self,
        tenant_id: str,
        credential_id: str,
        token_count: int,
    ) -> RateLimitDecision:
        """Consume one request and reserve up to *token_count* generated tokens."""

        _validate_identity(tenant_id, credential_id)
        if token_count < 0:
            raise ValueError("reserved token count cannot be negative")
        request_key, token_key = _bucket_keys(tenant_id, credential_id)
        results = await self.backend.apply(
            (
                BucketCharge(request_key, self.request_spec, 1.0),
                BucketCharge(token_key, self.token_spec, float(token_count)),
            ),
            self._clock(),
        )
        if len(results) != 2 or len({result.allowed for result in results}) != 1:
            raise RateLimitBackendUnavailableError(
                "rate-limit backend returned a non-atomic decision"
            )
        allowed = all(result.allowed for result in results)
        retry_after = max((result.retry_after for result in results), default=0.0)
        reservation = (
            TokenReservation(self, tenant_id, credential_id, token_count) if allowed else None
        )
        return RateLimitDecision(
            allowed=allowed,
            request_remaining=_whole_tokens(results[0].remaining),
            token_remaining=_whole_tokens(results[1].remaining),
            retry_after=retry_after,
            reservation=reservation,
        )

    async def check(
        self,
        tenant_id: str,
        credential_id: str,
        token_count: int = 0,
    ) -> RateLimitDecision:
        """Alias for :meth:`reserve` used by request middleware."""

        return await self.reserve(tenant_id, credential_id, token_count)

    async def charge_stream(
        self,
        reservation: TokenReservation,
        token_count: int,
    ) -> RateLimitDecision:
        """Charge incremental streamed output through an existing reservation."""

        if reservation._limiter is not self:
            raise ValueError("reservation belongs to a different rate limiter")
        return await reservation.charge_stream(token_count)

    async def refund(
        self,
        reservation: TokenReservation,
        token_count: int | None = None,
    ) -> RateLimitDecision:
        """Refund unused tokens through an existing reservation."""

        if reservation._limiter is not self:
            raise ValueError("reservation belongs to a different rate limiter")
        return await reservation.refund(token_count)

    async def _charge_tokens(
        self,
        tenant_id: str,
        credential_id: str,
        amount: int,
    ) -> RateLimitDecision:
        _, token_key = _bucket_keys(tenant_id, credential_id)
        results = await self.backend.apply(
            (BucketCharge(token_key, self.token_spec, float(amount)),), self._clock()
        )
        if len(results) != 1:
            raise RateLimitBackendUnavailableError(
                "rate-limit backend returned invalid cardinality"
            )
        (result,) = results
        return RateLimitDecision(
            allowed=result.allowed,
            request_remaining=_whole_tokens(self.request_spec.capacity),
            token_remaining=_whole_tokens(result.remaining),
            retry_after=result.retry_after,
        )

    async def close(self) -> None:
        """Release backend resources."""

        await self.backend.close()


TokenRateLimiter = DualRateLimiter
InMemoryRateLimitBackend = LocalRateLimitBackend
DistributedRateLimitBackend = RateLimitBackend


def _bucket_keys(tenant_id: str, credential_id: str) -> tuple[str, str]:
    # Length-prefixing prevents ambiguity; hashing keeps raw tenant/credential values
    # out of backend keys and operational key listings.
    identity = f"{len(tenant_id)}:{tenant_id}:{len(credential_id)}:{credential_id}"
    pseudonym = hashlib.sha256(identity.encode("utf-8")).hexdigest()
    return f"request:{pseudonym}", f"token:{pseudonym}"


def _validate_identity(tenant_id: str, credential_id: str) -> None:
    if not isinstance(tenant_id, str) or not tenant_id.strip():
        raise ValueError("tenant_id must be a non-empty authenticated identity")
    if not isinstance(credential_id, str) or not credential_id.strip():
        raise ValueError("credential_id must be a non-empty authenticated identity")


def _whole_tokens(value: float) -> int:
    if math.isinf(value):
        return 0
    return max(0, math.floor(value + 1e-12))


__all__ = [
    "BucketCharge",
    "BucketResult",
    "BucketSpec",
    "DistributedRateLimitBackend",
    "DualRateLimiter",
    "InMemoryRateLimitBackend",
    "LocalRateLimitBackend",
    "RateLimitBackend",
    "RateLimitBackendUnavailableError",
    "RateLimitDecision",
    "RedisRateLimitBackend",
    "TokenRateLimiter",
    "TokenReservation",
]
