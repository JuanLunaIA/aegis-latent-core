# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Admission control's refusals, and the token-reservation arithmetic.

`aegis/proxy/rate_limiter.py` decides whether a request is admitted and settles
how many generated tokens a response actually cost. Both halves fail closed, and
a reservation that settles wrongly is a silent budget leak rather than an error:
charge too little and a tenant spends tokens nobody counted, refund too much and
the budget is replenished from nothing.

So these tests pin the arithmetic exactly, and the refusals with it:

* the distributed backend refuses a malformed reply instead of guessing at a
  partial one, and reports an unreachable backend as such rather than as a
  denial (the caller distinguishes those two);
* a reservation charges only the *incremental overage* above what it reserved,
  never re-charging tokens already covered, and a refused charge leaves the
  observed total untouched;
* a reservation settles once: a second refund or finalize is an error, not a
  second refund;
* refunding or finalizing below what the stream already used is refused, because
  the two counters can only be reconciled in one direction.

Everything here drives the module's own seams (a fake Redis client, a fake
backend, a fake limiter) rather than a network or a clock.
"""

from __future__ import annotations

import math
from typing import Any

import pytest

from aegis.proxy.rate_limiter import (
    BucketCharge,
    BucketResult,
    BucketSpec,
    DualRateLimiter,
    LocalRateLimitBackend,
    RateLimitBackendUnavailableError,
    RateLimitDecision,
    RedisRateLimitBackend,
    TokenReservation,
    _bucket_keys,
    _validate_identity,
    _whole_tokens,
)

SPEC = BucketSpec(capacity=10.0, refill_per_second=1.0)


class _FakeRedis:
    def __init__(self, raw: Any = None, raises: BaseException | None = None) -> None:
        self.raw = raw
        self.raises = raises
        self.calls: list[tuple[int, tuple[Any, ...]]] = []
        self.closed = False

    async def eval(self, script: str, numkeys: int, *args: Any) -> Any:
        self.calls.append((numkeys, args))
        if self.raises is not None:
            raise self.raises
        return self.raw

    async def aclose(self) -> None:
        self.closed = True


def _redis_backend(raw: Any = None, raises: BaseException | None = None, **kwargs: Any) -> Any:
    backend = RedisRateLimitBackend("redis://localhost:6379/0", **kwargs)
    backend._client = _FakeRedis(raw, raises)
    return backend


class TestDistributedBackendRefusals:
    def test_an_empty_url_is_refused(self) -> None:
        with pytest.raises(ValueError, match="redis_url must not be empty"):
            RedisRateLimitBackend("")

    def test_a_whitespace_namespace_is_refused(self) -> None:
        with pytest.raises(ValueError, match="namespace must be non-empty"):
            RedisRateLimitBackend("redis://localhost:6379/0", namespace="has space")

    def test_an_empty_namespace_is_refused(self) -> None:
        with pytest.raises(ValueError, match="namespace must be non-empty"):
            RedisRateLimitBackend("redis://localhost:6379/0", namespace="")

    async def test_no_charges_means_no_backend_call(self) -> None:
        backend = _redis_backend(raw=[])
        assert await backend.apply((), 0.0) == ()
        assert backend._client.calls == []

    async def test_charging_the_same_bucket_twice_is_refused(self) -> None:
        """The script cannot express it, so the caller must not be able to ask."""
        backend = _redis_backend(raw=[1, 5.0, -1.0])
        charge = BucketCharge("k", SPEC, 1.0)
        with pytest.raises(ValueError, match="cannot charge a bucket twice"):
            await backend.apply((charge, charge), 0.0)

    async def test_an_unreachable_backend_is_reported_as_unavailable(self) -> None:
        backend = _redis_backend(raises=ConnectionError("down"))
        with pytest.raises(RateLimitBackendUnavailableError, match="backend unavailable"):
            await backend.apply((BucketCharge("k", SPEC, 1.0),), 0.0)

    async def test_a_reply_of_the_wrong_shape_is_refused_rather_than_guessed_at(self) -> None:
        backend = _redis_backend(raw=[1, 5.0])  # two buckets charged, one reported
        with pytest.raises(RateLimitBackendUnavailableError, match="returned invalid data"):
            await backend.apply((BucketCharge("k", SPEC, 1.0), BucketCharge("j", SPEC, 1.0)), 0.0)

    async def test_a_denied_charge_with_a_retry_is_reported_as_denied(self) -> None:
        backend = _redis_backend(raw=[0, 0.0, 2.5])
        (result,) = await backend.apply((BucketCharge("k", SPEC, 1.0),), 0.0)
        assert (result.allowed, result.remaining, result.retry_after) == (False, 0.0, 2.5)

    async def test_a_negative_retry_is_reported_as_infinite(self) -> None:
        """The script's sentinel for "no refill configured" is not a number."""
        backend = _redis_backend(raw=[0, 0.0, -1.0])
        (result,) = await backend.apply((BucketCharge("k", SPEC, 1.0),), 0.0)
        assert result.retry_after == math.inf

    async def test_close_releases_the_client(self) -> None:
        backend = _redis_backend(raw=[])
        await backend.close()
        assert backend._client.closed is True


class _FakeLimiter:
    """Just enough of ``DualRateLimiter`` for a reservation to settle against."""

    def __init__(self, allowed: bool = True) -> None:
        self.allowed = allowed
        self.deltas: list[int] = []

    async def _charge_tokens(self, tenant_id: str, credential_id: str, amount: int) -> Any:
        self.deltas.append(amount)
        return RateLimitDecision(
            allowed=self.allowed,
            request_remaining=9,
            token_remaining=9,
            retry_after=0.0,
        )


class _FakeBackend:
    def __init__(self, results: tuple[BucketResult, ...]) -> None:
        self.results = results
        self.charges: list[tuple[BucketCharge, ...]] = []

    async def apply(self, charges: tuple[BucketCharge, ...], now: float) -> tuple[Any, ...]:
        self.charges.append(charges)
        return self.results

    async def close(self) -> None:  # pragma: no cover - nothing to release
        return None


class TestReservationSettlement:
    async def test_a_negative_stream_charge_is_refused(self) -> None:
        reservation = TokenReservation(_FakeLimiter(), "t", "c", 10)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="cannot be negative"):
            await reservation.charge_stream(-1)

    async def test_only_the_overage_above_the_reservation_is_charged(self) -> None:
        """Reserved 10, used 4 then 8 more: 2 tokens are charged, once."""
        limiter = _FakeLimiter()
        reservation = TokenReservation(limiter, "t", "c", 10)  # type: ignore[arg-type]
        await reservation.charge_stream(4)
        assert limiter.deltas == [0]
        await reservation.charge_stream(8)
        assert limiter.deltas == [0, 2]
        assert reservation.charged == 12

    async def test_a_refused_charge_leaves_the_observed_total_alone(self) -> None:
        limiter = _FakeLimiter(allowed=False)
        reservation = TokenReservation(limiter, "t", "c", 0)  # type: ignore[arg-type]
        decision = await reservation.charge_stream(5)
        assert decision.allowed is False
        assert reservation.charged == 0

    async def test_refunding_unused_reservation_returns_what_was_not_used(self) -> None:
        limiter = _FakeLimiter()
        reservation = TokenReservation(limiter, "t", "c", 10)  # type: ignore[arg-type]
        await reservation.refund(4)
        assert limiter.deltas == [-6]  # 10 reserved − 4 used

    async def test_a_second_refund_is_refused(self) -> None:
        limiter = _FakeLimiter()
        reservation = TokenReservation(limiter, "t", "c", 10)  # type: ignore[arg-type]
        await reservation.refund(0)
        with pytest.raises(RuntimeError, match="already closed"):
            await reservation.refund(0)

    async def test_refunding_below_observed_usage_is_refused(self) -> None:
        limiter = _FakeLimiter()
        reservation = TokenReservation(limiter, "t", "c", 10)  # type: ignore[arg-type]
        await reservation.charge_stream(12)
        with pytest.raises(ValueError, match="below observed streamed usage"):
            await reservation.refund(5)

    async def test_a_negative_refund_count_is_refused(self) -> None:
        reservation = TokenReservation(_FakeLimiter(), "t", "c", 10)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="used token count cannot be negative"):
            await reservation.refund(-1)

    async def test_finalize_settles_the_difference_between_reserved_and_actual(self) -> None:
        limiter = _FakeLimiter()
        reservation = TokenReservation(limiter, "t", "c", 10)  # type: ignore[arg-type]
        await reservation.finalize(4)
        assert limiter.deltas == [-6]
        assert reservation.charged == 4

    async def test_finalize_charges_the_overage_when_the_response_ran_long(self) -> None:
        limiter = _FakeLimiter()
        reservation = TokenReservation(limiter, "t", "c", 10)  # type: ignore[arg-type]
        await reservation.finalize(13)
        assert limiter.deltas == [3]
        assert reservation.charged == 13

    async def test_a_refused_finalize_leaves_the_reservation_open(self) -> None:
        limiter = _FakeLimiter(allowed=False)
        reservation = TokenReservation(limiter, "t", "c", 10)  # type: ignore[arg-type]
        decision = await reservation.finalize(13)
        assert decision.allowed is False
        assert reservation._closed is False

    async def test_finalizing_below_observed_usage_is_refused(self) -> None:
        limiter = _FakeLimiter()
        reservation = TokenReservation(limiter, "t", "c", 10)  # type: ignore[arg-type]
        await reservation.charge_stream(12)
        with pytest.raises(ValueError, match="below observed streamed usage"):
            await reservation.finalize(11)

    async def test_a_negative_finalize_is_refused(self) -> None:
        reservation = TokenReservation(_FakeLimiter(), "t", "c", 10)  # type: ignore[arg-type]
        with pytest.raises(ValueError, match="cannot be negative"):
            await reservation.finalize(-1)


class TestLimiterDelegation:
    async def test_a_reservation_from_another_limiter_is_refused(self) -> None:
        first = DualRateLimiter(
            request_capacity=5,
            request_refill_per_second=1.0,
            token_capacity=5,
            token_refill_per_second=1.0,
        )
        second = DualRateLimiter(
            request_capacity=5,
            request_refill_per_second=1.0,
            token_capacity=5,
            token_refill_per_second=1.0,
        )
        decision = await first.reserve("tenant", "credential", 1)
        assert decision.reservation is not None
        with pytest.raises(ValueError, match="different rate limiter"):
            await second.charge_stream(decision.reservation, 1)
        with pytest.raises(ValueError, match="different rate limiter"):
            await second.refund(decision.reservation)

    async def test_check_is_the_reserve_path(self) -> None:
        limiter = DualRateLimiter(
            request_capacity=1,
            request_refill_per_second=1.0,
            token_capacity=1,
            token_refill_per_second=1.0,
        )
        granted = await limiter.check("tenant", "credential", 1)
        refused = await limiter.check("tenant", "credential", 1)
        assert granted.allowed is True
        assert refused.allowed is False

    async def test_a_negative_reservation_is_refused(self) -> None:
        limiter = DualRateLimiter(
            request_capacity=1,
            request_refill_per_second=1.0,
            token_capacity=1,
            token_refill_per_second=1.0,
        )
        with pytest.raises(ValueError, match="reserved token count cannot be negative"):
            await limiter.reserve("tenant", "credential", -1)

    async def test_a_non_atomic_backend_decision_is_refused(self) -> None:
        """Request and token halves must agree; a split decision is not a decision."""
        backend = _FakeBackend(
            (BucketResult(True, 1.0, 0.0), BucketResult(False, 0.0, 1.0)),
        )
        limiter = DualRateLimiter(
            request_capacity=5,
            request_refill_per_second=1.0,
            token_capacity=5,
            token_refill_per_second=1.0,
            backend=backend,  # type: ignore[arg-type]
        )
        with pytest.raises(RateLimitBackendUnavailableError, match="non-atomic decision"):
            await limiter.reserve("tenant", "credential", 1)

    async def test_an_allowed_reservation_records_the_decision(self) -> None:
        limiter = DualRateLimiter(
            request_capacity=3,
            request_refill_per_second=1.0,
            token_capacity=3,
            token_refill_per_second=1.0,
        )
        decision = await limiter.reserve("tenant", "credential", 2)
        assert decision.allowed is True
        assert decision.remaining == 1
        assert decision.reservation is not None
        assert decision.reservation.reserved == 2

    async def test_close_releases_the_backend(self) -> None:
        backend = LocalRateLimitBackend(max_buckets=4)
        limiter = DualRateLimiter(
            request_capacity=1,
            request_refill_per_second=1.0,
            token_capacity=1,
            token_refill_per_second=1.0,
            backend=backend,
        )
        await limiter.close()


class TestIdentityAndKeyDerivation:
    def test_a_blank_tenant_is_refused(self) -> None:
        with pytest.raises(ValueError, match="tenant_id must be a non-empty"):
            _validate_identity("   ", "credential")

    def test_a_non_string_credential_is_refused(self) -> None:
        with pytest.raises(ValueError, match="credential_id must be a non-empty"):
            _validate_identity("tenant", None)  # type: ignore[arg-type]

    def test_keys_are_pseudonymous_and_domain_separated(self) -> None:
        request_key, token_key = _bucket_keys("tenant", "credential")
        assert request_key.startswith("request:")
        assert token_key.startswith("token:")
        assert "tenant" not in request_key
        assert "credential" not in request_key

    def test_length_prefixing_keeps_pairs_unambiguous(self) -> None:
        """`("a", "bc")` and `("ab", "c")` must not collide on one pseudonym."""
        assert _bucket_keys("a", "bc") != _bucket_keys("ab", "c")

    def test_an_infinite_remaining_is_reported_as_zero_whole_tokens(self) -> None:
        assert _whole_tokens(math.inf) == 0

    def test_fractional_remaining_is_floored(self) -> None:
        assert _whole_tokens(3.99) == 3

    def test_negative_remaining_is_floored_at_zero(self) -> None:
        assert _whole_tokens(-1.5) == 0
