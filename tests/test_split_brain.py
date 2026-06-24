# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for Domain 4.1 split-brain fencing token prevention."""

from __future__ import annotations

import time

import pytest

from aegis.core.split_brain import (
    FencingToken,
    FencingTokenError,
    LeaseBasedLock,
    SplitBrainError,
    StaleLeaseError,
)

# ── FencingToken ──────────────────────────────────────────────────────────────


def test_fencing_token_is_valid_when_fresh():
    now = time.time()
    token = FencingToken(value=1, issued_at=now, node_id="n1", expires_at=now + 30)
    assert token.is_valid()


def test_fencing_token_invalid_when_expired():
    now = time.time()
    token = FencingToken(value=1, issued_at=now - 60, node_id="n1", expires_at=now - 1)
    assert not token.is_valid()


def test_fencing_token_supersedes_lower():
    now = time.time()
    t1 = FencingToken(value=2, issued_at=now, node_id="n1", expires_at=now + 30)
    t2 = FencingToken(value=1, issued_at=now, node_id="n2", expires_at=now + 30)
    assert t1.supersedes(t2)


def test_fencing_token_does_not_supersede_equal():
    now = time.time()
    t1 = FencingToken(value=1, issued_at=now, node_id="n1", expires_at=now + 30)
    t2 = FencingToken(value=1, issued_at=now, node_id="n2", expires_at=now + 30)
    assert not t1.supersedes(t2)


def test_fencing_token_does_not_supersede_higher():
    now = time.time()
    t1 = FencingToken(value=1, issued_at=now, node_id="n1", expires_at=now + 30)
    t2 = FencingToken(value=5, issued_at=now, node_id="n2", expires_at=now + 30)
    assert not t1.supersedes(t2)


def test_fencing_token_repr_contains_value():
    now = time.time()
    token = FencingToken(value=42, issued_at=now, node_id="n1", expires_at=now + 30)
    assert "42" in repr(token)


# ── Exception hierarchy ────────────────────────────────────────────────────────


def test_stale_lease_error_is_split_brain_error():
    assert issubclass(StaleLeaseError, SplitBrainError)


def test_fencing_token_error_is_split_brain_error():
    assert issubclass(FencingTokenError, SplitBrainError)


# ── LeaseBasedLock: acquire_lease ─────────────────────────────────────────────


def test_acquire_lease_with_first_token_succeeds():
    lock = LeaseBasedLock("n1")
    token = lock.acquire_lease(1)
    assert isinstance(token, FencingToken)
    assert token.value == 1
    assert token.node_id == "n1"
    assert token.is_valid()


def test_acquire_lease_with_higher_token_succeeds():
    lock = LeaseBasedLock("n1")
    lock.acquire_lease(1)
    token2 = lock.acquire_lease(5)
    assert token2.value == 5


def test_acquire_lease_stale_token_raises():
    lock = LeaseBasedLock("n1")
    lock.acquire_lease(5)
    with pytest.raises(FencingTokenError):
        lock.acquire_lease(1)


def test_acquire_lease_equal_token_raises():
    lock = LeaseBasedLock("n1")
    lock.acquire_lease(3)
    with pytest.raises(FencingTokenError):
        lock.acquire_lease(3)


def test_acquire_lease_zero_as_first_raises():
    """Token value 0 is not strictly greater than max_seen=0 (initial)."""
    lock = LeaseBasedLock("n1")
    with pytest.raises(FencingTokenError):
        lock.acquire_lease(0)


def test_acquire_lease_updates_max_seen():
    lock = LeaseBasedLock("n1")
    lock.acquire_lease(7)
    assert lock.max_seen_token == 7


def test_acquire_lease_token_has_ttl():
    lock = LeaseBasedLock("n1", lease_ttl_seconds=10.0)
    token = lock.acquire_lease(1)
    assert token.expires_at > token.issued_at
    assert abs((token.expires_at - token.issued_at) - 10.0) < 0.1


# ── LeaseBasedLock: check_fence ───────────────────────────────────────────────


def test_check_fence_valid_token_passes():
    lock = LeaseBasedLock("n1")
    token = lock.acquire_lease(1)
    lock.check_fence(token)  # should not raise


def test_check_fence_expired_token_raises():
    lock = LeaseBasedLock("n1", lease_ttl_seconds=30.0)
    now = time.time()
    expired_token = FencingToken(
        value=1,
        issued_at=now - 60,
        node_id="n1",
        expires_at=now - 1,  # expired 1 second ago
    )
    lock._max_seen_token_value = 1  # pretend we saw this token
    with pytest.raises(StaleLeaseError):
        lock.check_fence(expired_token)


def test_check_fence_stale_value_raises():
    lock = LeaseBasedLock("n1")
    lock.acquire_lease(5)
    now = time.time()
    # Create a valid-time token but with a stale value
    stale_token = FencingToken(
        value=3,
        issued_at=now,
        node_id="n1",
        expires_at=now + 30,
    )
    with pytest.raises(StaleLeaseError):
        lock.check_fence(stale_token)


# ── LeaseBasedLock: gate_wal_write ────────────────────────────────────────────


def test_gate_wal_write_calls_write_fn_on_valid_token():
    lock = LeaseBasedLock("n1")
    token = lock.acquire_lease(1)
    result = lock.gate_wal_write(token, lambda: "written")
    assert result == "written"


def test_gate_wal_write_raises_before_write_fn_on_expired():
    lock = LeaseBasedLock("n1")
    now = time.time()
    expired = FencingToken(value=1, issued_at=now - 60, node_id="n1", expires_at=now - 1)
    lock._max_seen_token_value = 1

    called = []

    def write_fn():
        called.append(True)
        return "should-not-reach"

    with pytest.raises(StaleLeaseError):
        lock.gate_wal_write(expired, write_fn)

    assert not called, "write_fn must not be called when fence check fails"


def test_gate_wal_write_raises_before_write_fn_on_stale_value():
    lock = LeaseBasedLock("n1")
    lock.acquire_lease(10)
    now = time.time()
    stale = FencingToken(value=5, issued_at=now, node_id="n1", expires_at=now + 30)

    called = []

    def write_fn():
        called.append(True)

    with pytest.raises(StaleLeaseError):
        lock.gate_wal_write(stale, write_fn)

    assert not called


def test_gate_wal_write_returns_write_fn_return_value():
    lock = LeaseBasedLock("n1")
    token = lock.acquire_lease(1)
    result = lock.gate_wal_write(token, lambda: {"status": "ok"})
    assert result == {"status": "ok"}


# ── LeaseBasedLock: properties ────────────────────────────────────────────────


def test_current_lease_valid_true_after_acquire():
    lock = LeaseBasedLock("n1")
    lock.acquire_lease(1)
    assert lock.current_lease_valid


def test_current_lease_valid_false_initially():
    lock = LeaseBasedLock("n1")
    assert not lock.current_lease_valid


def test_max_seen_token_starts_at_zero():
    lock = LeaseBasedLock("n1")
    assert lock.max_seen_token == 0


def test_max_seen_token_advances_correctly():
    lock = LeaseBasedLock("n1")
    lock.acquire_lease(1)
    assert lock.max_seen_token == 1
    lock.acquire_lease(3)
    assert lock.max_seen_token == 3
    lock.acquire_lease(100)
    assert lock.max_seen_token == 100


def test_current_lease_valid_false_after_expiry():
    lock = LeaseBasedLock("n1", lease_ttl_seconds=30.0)
    lock.acquire_lease(1)
    # Manually expire the current token
    lock._current_token = FencingToken(
        value=1,
        issued_at=time.time() - 60,
        node_id="n1",
        expires_at=time.time() - 1,
    )
    assert not lock.current_lease_valid
