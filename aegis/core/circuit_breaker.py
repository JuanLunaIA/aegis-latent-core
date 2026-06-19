# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.circuit_breaker — Thread-safe upstream circuit breaker.

States
------
CLOSED      Normal operation. Consecutive failure counter increments on each
            upstream error. On failure_threshold consecutive failures → OPEN.

OPEN        All calls rejected immediately (fail-fast; 503 to caller). After
            recovery_timeout seconds exactly one probe attempt is allowed
            (→ HALF_OPEN).

HALF_OPEN   One probe call allowed concurrently. On success: success counter
            increments; on success_threshold consecutive successes → CLOSED.
            On failure → OPEN (recovery timer resets).

Mechanism: consecutive_failures tracks "is the upstream currently broken?"
(Z). The recovery timer prevents thundering-herd on recovery: retries are
capped to one per recovery_timeout seconds rather than one per request.
Half-open limits blast radius from a flapping upstream.
"""
from __future__ import annotations

import logging
import threading
import time
from enum import Enum

logger = logging.getLogger(__name__)


class CircuitOpenError(Exception):
    """Raised by LLMForwarder when the circuit is OPEN.

    Callers should catch this and return HTTP 503 Service Unavailable.
    """


class _State(Enum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    """Thread-safe circuit breaker for upstream HTTP calls.

    Parameters
    ----------
    name : str
        Human-readable label (used in logs + metrics labels).
    failure_threshold : int
        Consecutive failures required to open the circuit.
    recovery_timeout : float
        Seconds to wait in OPEN state before allowing a probe (→ HALF_OPEN).
    success_threshold : int
        Consecutive probe successes in HALF_OPEN required to close the circuit.
    """

    def __init__(
        self,
        name: str = "upstream",
        failure_threshold: int = 5,
        recovery_timeout: float = 30.0,
        success_threshold: int = 2,
    ) -> None:
        self.name = name
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._success_threshold = success_threshold
        self._lock = threading.Lock()
        self._state = _State.CLOSED
        self._failures = 0
        self._successes = 0
        self._opened_at: float = 0.0

    @property
    def state(self) -> str:
        with self._lock:
            return self._state.value

    def allow_request(self) -> bool:
        """Return True if a request should be attempted now.

        Side-effect: may transition OPEN → HALF_OPEN when recovery_timeout
        has elapsed.
        """
        with self._lock:
            return self._allow_request_locked()

    def _allow_request_locked(self) -> bool:
        if self._state == _State.CLOSED:
            return True
        if self._state == _State.OPEN:
            if time.monotonic() - self._opened_at >= self._recovery_timeout:
                self._state = _State.HALF_OPEN
                self._successes = 0
                logger.info("CircuitBreaker[%s] → HALF_OPEN (recovery probe)", self.name)
                return True
            return False
        # HALF_OPEN: allow exactly one probe at a time (state is already HALF_OPEN
        # so we return True; the probe will call record_success/record_failure).
        return True

    def record_success(self) -> None:
        """Report a successful upstream call."""
        with self._lock:
            if self._state == _State.HALF_OPEN:
                self._successes += 1
                if self._successes >= self._success_threshold:
                    self._state = _State.CLOSED
                    self._failures = 0
                    logger.info("CircuitBreaker[%s] → CLOSED (upstream recovered)", self.name)
                    self._emit_state_metric(0)
            elif self._state == _State.CLOSED:
                self._failures = 0  # reset consecutive counter on any success

    def record_failure(self) -> None:
        """Report a failed upstream call."""
        with self._lock:
            self._failures += 1
            if self._state == _State.HALF_OPEN or self._failures >= self._failure_threshold:
                was_not_open = self._state != _State.OPEN
                self._state = _State.OPEN
                self._opened_at = time.monotonic()
                if was_not_open:
                    logger.error(
                        "CircuitBreaker[%s] → OPEN after %d consecutive failures",
                        self.name,
                        self._failures,
                    )
                    self._emit_open_metric()
                else:
                    logger.warning(
                        "CircuitBreaker[%s] probe failed → OPEN (back-off restarted)",
                        self.name,
                    )
                self._emit_state_metric(2)

    def _emit_open_metric(self) -> None:
        try:
            from aegis.core.observability import CIRCUIT_BREAKER_OPENS

            CIRCUIT_BREAKER_OPENS.labels(provider=self.name).inc()
        except Exception:
            pass

    def _emit_state_metric(self, value: int) -> None:
        # value: 0=CLOSED, 1=HALF_OPEN, 2=OPEN
        try:
            from aegis.core.observability import CIRCUIT_BREAKER_STATE

            CIRCUIT_BREAKER_STATE.labels(provider=self.name).set(value)
        except Exception:
            pass

    def check(self) -> None:
        """Raise CircuitOpenError if the circuit is OPEN.

        Call this at the start of any operation that talks to the upstream.
        On the OPEN→HALF_OPEN transition this returns normally (probe allowed).
        """
        if not self.allow_request():
            raise CircuitOpenError(
                f"Circuit breaker OPEN for {self.name!r}: upstream temporarily "
                f"unavailable. Retry after {self._recovery_timeout:.0f}s."
            )
