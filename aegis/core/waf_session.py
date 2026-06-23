# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.waf_session — Multi-turn behavioral WAF session state machine.

Tracks per-session WAF signal history to detect escalation patterns that
no single-turn check can catch:

  1. **Cumulative score escalation** — sum of per-turn WAF scores in a sliding
     window of N turns exceeds a configurable threshold.  Catches attacks
     distributed thinly across many turns (each below the per-turn block
     threshold, but collectively dangerous).

  2. **Crescendo pattern** — K or more *consecutive* turns each producing a
     non-zero WAF score.  Models the "gradual constraint erosion" attack where
     each message slightly probes limits until the model's guardrails erode.

Both checks operate only on requests that *passed* the per-turn WAF check
(score > 0, allowed = True).  Hard-blocked requests (allowed = False) are
not recorded because they already terminated the request.

Usage::

    tracker = WAFSessionTracker(max_sessions=4_096)

    # On each allowed request:
    result = tracker.record_and_check(
        session_id="abc",
        score=waf_result.score,
        allowed=waf_result.allowed,
        reason=waf_result.reason,
    )
    if result.escalated:
        raise HTTPException(429, detail=result.reason)
"""

from __future__ import annotations

import threading
from collections import OrderedDict, deque
from dataclasses import dataclass


@dataclass
class SessionEscalationResult:
    """Result of a multi-turn behavioral check."""

    escalated: bool
    reason: str = ""
    window_score: float = 0.0
    soft_hit_turns: int = 0


class _WAFTurnRecord:
    """Immutable snapshot of a single WAF turn result."""

    __slots__ = ("score", "allowed", "reason")

    def __init__(self, score: float, allowed: bool, reason: str) -> None:
        self.score = score
        self.allowed = allowed
        self.reason = reason


class WAFSessionState:
    """Per-session behavioral state machine.

    Parameters
    ----------
    window:
        Sliding-window size (number of recent turns examined for cumulative
        score).  Older turns are evicted automatically.
    cumulative_threshold:
        Sum of WAF scores in the window required to trigger escalation
        detection.  Each soft-hit turn contributes its ``score`` (0.0–1.0).
        Default 2.0 means ≥ 2 full-weight soft hits in the window escalate.
    crescendo_turns:
        Number of *consecutive* turns with score > 0 required to trigger
        crescendo detection.  Default 3.
    """

    def __init__(
        self,
        window: int = 10,
        cumulative_threshold: float = 2.0,
        crescendo_turns: int = 3,
    ) -> None:
        self._window = window
        self._cumulative_threshold = cumulative_threshold
        self._crescendo_turns = crescendo_turns
        self._history: deque[_WAFTurnRecord] = deque(maxlen=window)
        self._consecutive_soft: int = 0
        self._lock = threading.Lock()

    def record_and_check(
        self,
        score: float,
        allowed: bool,
        reason: str = "",
    ) -> SessionEscalationResult:
        """Record a WAF turn result and evaluate session-level escalation.

        Returns ``SessionEscalationResult(escalated=True, ...)`` when an
        escalation pattern is detected.  The caller should then block the
        request (HTTP 429) and optionally terminate the session.
        """
        with self._lock:
            self._history.append(_WAFTurnRecord(score=score, allowed=allowed, reason=reason))

            if score > 0.0 and allowed:
                self._consecutive_soft += 1
            else:
                self._consecutive_soft = 0

            window_score = sum(r.score for r in self._history)
            soft_turns = sum(1 for r in self._history if r.score > 0.0 and r.allowed)

            # Check 1: cumulative window score
            if window_score >= self._cumulative_threshold:
                return SessionEscalationResult(
                    escalated=True,
                    reason=(
                        f"Session behavioral escalation: cumulative WAF score "
                        f"{window_score:.2f} over {len(self._history)} turns "
                        f"(threshold {self._cumulative_threshold:.2f})"
                    ),
                    window_score=window_score,
                    soft_hit_turns=soft_turns,
                )

            # Check 2: crescendo pattern (consecutive suspicious turns)
            if self._consecutive_soft >= self._crescendo_turns:
                return SessionEscalationResult(
                    escalated=True,
                    reason=(
                        f"Session crescendo attack: {self._consecutive_soft} "
                        f"consecutive suspicious turns (threshold {self._crescendo_turns})"
                    ),
                    window_score=window_score,
                    soft_hit_turns=self._consecutive_soft,
                )

            return SessionEscalationResult(
                escalated=False,
                window_score=window_score,
                soft_hit_turns=soft_turns,
            )

    @property
    def turn_count(self) -> int:
        with self._lock:
            return len(self._history)


class WAFSessionTracker:
    """LRU-bounded registry of per-session :class:`WAFSessionState` instances.

    Thread-safe.  Sessions are silently evicted LRU when ``max_sessions``
    is reached, preventing unbounded memory growth under no-session-id
    traffic (UUID-per-request pattern).

    Parameters
    ----------
    max_sessions:
        Maximum concurrent sessions held in memory.
    window, cumulative_threshold, crescendo_turns:
        Forwarded to each newly-created :class:`WAFSessionState`.
    """

    def __init__(
        self,
        max_sessions: int = 4_096,
        window: int = 10,
        cumulative_threshold: float = 2.0,
        crescendo_turns: int = 3,
    ) -> None:
        self._max = max_sessions
        self._window = window
        self._cumulative_threshold = cumulative_threshold
        self._crescendo_turns = crescendo_turns
        self._sessions: OrderedDict[str, WAFSessionState] = OrderedDict()
        self._lock = threading.Lock()

    def record_and_check(
        self,
        session_id: str,
        score: float,
        allowed: bool,
        reason: str = "",
    ) -> SessionEscalationResult:
        """Record a WAF result for *session_id* and evaluate escalation."""
        session_state = self._get_or_create(session_id)
        return session_state.record_and_check(score=score, allowed=allowed, reason=reason)

    def _get_or_create(self, session_id: str) -> WAFSessionState:
        with self._lock:
            if session_id in self._sessions:
                self._sessions.move_to_end(session_id)
                return self._sessions[session_id]
            if len(self._sessions) >= self._max:
                self._sessions.popitem(last=False)
            state = WAFSessionState(
                window=self._window,
                cumulative_threshold=self._cumulative_threshold,
                crescendo_turns=self._crescendo_turns,
            )
            self._sessions[session_id] = state
            return state

    def terminate_session(self, session_id: str) -> None:
        """Explicitly remove a session's WAF state from memory."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def active_count(self) -> int:
        """Return the number of sessions currently tracked."""
        with self._lock:
            return len(self._sessions)
