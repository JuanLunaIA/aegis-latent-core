# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.circuit_breaker — thread-safe upstream circuit breaker."""

from __future__ import annotations

import threading
import time

import pytest

from aegis.core.circuit_breaker import CircuitBreaker, CircuitOpenError

# ── Helpers ───────────────────────────────────────────────────────────────────


def _closed_breaker(**kw) -> CircuitBreaker:
    return CircuitBreaker(name="test-upstream", **kw)


def _open_breaker(failure_threshold: int = 3, **kw) -> CircuitBreaker:
    cb = CircuitBreaker(name="test-upstream", failure_threshold=failure_threshold, **kw)
    for _ in range(failure_threshold):
        cb.record_failure()
    return cb


# ── Construction ──────────────────────────────────────────────────────────────


class TestConstruction:
    def test_default_state_is_closed(self):
        cb = CircuitBreaker()
        assert cb.state == "closed"

    def test_default_name(self):
        cb = CircuitBreaker()
        assert cb.name == "upstream"

    def test_custom_name(self):
        cb = CircuitBreaker(name="openai")
        assert cb.name == "openai"

    def test_allows_requests_initially(self):
        cb = CircuitBreaker()
        assert cb.allow_request() is True

    def test_check_passes_initially(self):
        cb = CircuitBreaker()
        cb.check()  # should not raise


# ── CLOSED state ──────────────────────────────────────────────────────────────


class TestClosedState:
    def test_failures_below_threshold_stays_closed(self):
        cb = _closed_breaker(failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        assert cb.state == "closed"

    def test_success_resets_failure_counter(self):
        cb = _closed_breaker(failure_threshold=5)
        for _ in range(4):
            cb.record_failure()
        cb.record_success()
        for _ in range(4):
            cb.record_failure()
        assert cb.state == "closed"

    def test_exact_threshold_opens(self):
        cb = _closed_breaker(failure_threshold=3)
        for _ in range(3):
            cb.record_failure()
        assert cb.state == "open"

    def test_allows_request_in_closed(self):
        cb = _closed_breaker()
        assert cb.allow_request() is True

    def test_check_does_not_raise_in_closed(self):
        cb = _closed_breaker()
        cb.check()  # must not raise


# ── OPEN state ────────────────────────────────────────────────────────────────


class TestOpenState:
    def test_state_is_open_after_threshold(self):
        cb = _open_breaker(failure_threshold=3)
        assert cb.state == "open"

    def test_allow_request_false_when_open(self):
        cb = _open_breaker(recovery_timeout=60.0)
        assert cb.allow_request() is False

    def test_check_raises_when_open(self):
        cb = _open_breaker(recovery_timeout=60.0)
        with pytest.raises(CircuitOpenError):
            cb.check()

    def test_circuit_open_error_message(self):
        cb = CircuitBreaker(name="my-provider", failure_threshold=1, recovery_timeout=30.0)
        cb.record_failure()
        with pytest.raises(CircuitOpenError, match="my-provider"):
            cb.check()

    def test_additional_failures_keep_open(self):
        cb = _open_breaker(failure_threshold=3, recovery_timeout=60.0)
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "open"

    def test_record_success_while_open_does_not_close(self):
        cb = _open_breaker(failure_threshold=3, recovery_timeout=60.0)
        cb.record_success()
        assert cb.state == "open"


# ── OPEN → HALF_OPEN transition ───────────────────────────────────────────────


class TestHalfOpenTransition:
    def test_transitions_to_half_open_after_timeout(self):
        cb = _open_breaker(failure_threshold=3, recovery_timeout=0.01)
        time.sleep(0.02)
        result = cb.allow_request()
        assert result is True
        assert cb.state == "half_open"

    def test_check_passes_after_recovery_timeout(self):
        cb = _open_breaker(failure_threshold=3, recovery_timeout=0.01)
        time.sleep(0.02)
        cb.check()  # should not raise; transitions to HALF_OPEN


# ── HALF_OPEN state ───────────────────────────────────────────────────────────


class TestHalfOpenState:
    def _half_open(self, success_threshold: int = 2) -> CircuitBreaker:
        cb = _open_breaker(failure_threshold=3, recovery_timeout=0.01, success_threshold=success_threshold)
        time.sleep(0.02)
        cb.allow_request()  # triggers OPEN → HALF_OPEN
        return cb

    def test_state_is_half_open(self):
        cb = self._half_open()
        assert cb.state == "half_open"

    def test_allow_request_true_in_half_open(self):
        cb = self._half_open()
        assert cb.allow_request() is True

    def test_failure_in_half_open_reopens(self):
        cb = self._half_open()
        cb.record_failure()
        assert cb.state == "open"

    def test_failure_in_half_open_resets_timer(self):
        cb = self._half_open(success_threshold=2)
        cb.record_failure()
        # The breaker re-entered OPEN; recovery_timeout restarts from now.
        assert cb.state == "open"
        assert cb.allow_request() is False  # timer not yet elapsed

    def test_success_below_threshold_stays_half_open(self):
        cb = self._half_open(success_threshold=3)
        cb.record_success()
        cb.record_success()
        assert cb.state == "half_open"

    def test_success_at_threshold_closes(self):
        cb = self._half_open(success_threshold=2)
        cb.record_success()
        cb.record_success()
        assert cb.state == "closed"

    def test_closed_after_recovery_allows_requests(self):
        cb = self._half_open(success_threshold=1)
        cb.record_success()
        assert cb.allow_request() is True

    def test_re_failure_after_half_open_success_threshold_not_met(self):
        cb = self._half_open(success_threshold=3)
        cb.record_success()
        cb.record_failure()  # threshold not met; failure reopens
        assert cb.state == "open"


# ── Full lifecycle ────────────────────────────────────────────────────────────


class TestFullLifecycle:
    def test_closed_to_open_to_half_open_to_closed(self):
        cb = CircuitBreaker(
            name="lifecycle",
            failure_threshold=3,
            recovery_timeout=0.01,
            success_threshold=2,
        )
        assert cb.state == "closed"

        # Trip the breaker
        cb.record_failure()
        cb.record_failure()
        cb.record_failure()
        assert cb.state == "open"

        # Recovery probe
        time.sleep(0.02)
        assert cb.allow_request() is True
        assert cb.state == "half_open"

        # Probe succeeds twice
        cb.record_success()
        cb.record_success()
        assert cb.state == "closed"

        # Now works normally
        cb.check()  # no raise

    def test_repeated_open_close_cycles(self):
        cb = CircuitBreaker(
            failure_threshold=1, recovery_timeout=0.01, success_threshold=1
        )
        for _ in range(3):
            cb.record_failure()
            assert cb.state == "open"
            time.sleep(0.02)
            cb.allow_request()
            cb.record_success()
            assert cb.state == "closed"


# ── check() vs allow_request() ────────────────────────────────────────────────


class TestCheckVsAllowRequest:
    def test_check_is_void_when_closed(self):
        cb = CircuitBreaker()
        result = cb.check()
        assert result is None

    def test_allow_request_returns_bool(self):
        cb = CircuitBreaker()
        result = cb.allow_request()
        assert isinstance(result, bool)

    def test_check_raises_circuit_open_error(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=60.0)
        cb.record_failure()
        with pytest.raises(CircuitOpenError):
            cb.check()

    def test_circuit_open_error_is_exception(self):
        assert issubclass(CircuitOpenError, Exception)


# ── Thread safety ─────────────────────────────────────────────────────────────


class TestThreadSafety:
    def test_concurrent_failures_trip_circuit(self):
        cb = CircuitBreaker(failure_threshold=10)
        errors: list[Exception] = []

        def fail():
            try:
                cb.record_failure()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=fail) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert cb.state == "open"

    def test_concurrent_successes_do_not_crash(self):
        cb = CircuitBreaker()
        errors: list[Exception] = []

        def succeed():
            try:
                cb.record_success()
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=succeed) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors
        assert cb.state == "closed"

    def test_concurrent_allow_request_consistent(self):
        cb = CircuitBreaker(failure_threshold=1, recovery_timeout=60.0)
        cb.record_failure()
        results: list[bool] = []
        lock = threading.Lock()

        def check():
            r = cb.allow_request()
            with lock:
                results.append(r)

        threads = [threading.Thread(target=check) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(r is False for r in results)


# ── Config integration (via aegis.config) ────────────────────────────────────


class TestConfigIntegration:
    def test_default_config_values_valid(self):
        from aegis.config import AegisSettings
        s = AegisSettings()
        assert s.circuit_breaker_failure_threshold > 0
        assert s.circuit_breaker_recovery_timeout > 0
        assert s.circuit_breaker_success_threshold > 0

    def test_circuit_breaker_from_config(self):
        from aegis.config import AegisSettings
        s = AegisSettings(
            circuit_breaker_failure_threshold=7,
            circuit_breaker_recovery_timeout=45.0,
            circuit_breaker_success_threshold=3,
        )
        cb = CircuitBreaker(
            name="from-config",
            failure_threshold=s.circuit_breaker_failure_threshold,
            recovery_timeout=s.circuit_breaker_recovery_timeout,
            success_threshold=s.circuit_breaker_success_threshold,
        )
        assert cb.state == "closed"
        for _ in range(7):
            cb.record_failure()
        assert cb.state == "open"
