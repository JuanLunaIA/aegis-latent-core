# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.conversation_graph — Conversation graph crescendo analysis.

Detects gradual constraint erosion across a multi-turn session by tracking
response-side entropy trends rather than (or in addition to) request-side
WAF scores.

The threat model is the "crescendo" attack: an adversary sends a sequence of
individually-benign requests that gradually normalise increasingly sensitive
content, causing the model's refusal guardrails to erode across turns.

This module provides two complementary signals:

  1. **Entropy trend decline** — response Shannon entropy decreases
     monotonically over a sliding window, indicating the model is becoming
     more predictable / less cautious (lower entropy → narrower output
     distribution → refusal hedging reduced).

  2. **Entropy baseline drift** — mean entropy in the recent window falls
     more than ``entropy_drop_threshold`` bits below the session baseline
     (established from the first ``baseline_turns`` turns), indicating a
     sustained shift in generation behaviour.

Usage::

    tracker = ConversationGraphTracker(max_sessions=4_096)

    # After each completed request/response pair:
    result = tracker.record_turn(
        session_id=session_id,
        waf_score=waf_result.score,
        response_entropy=analysis.mean_entropy,
    )
    if result.erosion_detected:
        raise HTTPException(429, detail=result.reason)
"""

from __future__ import annotations

import threading
from collections import OrderedDict, deque
from dataclasses import dataclass


@dataclass
class ErosionDetectionResult:
    """Result of a conversation-graph erosion analysis."""

    erosion_detected: bool
    reason: str = ""
    window_entropy_mean: float = 0.0
    baseline_entropy_mean: float = 0.0
    entropy_drop: float = 0.0
    monotone_decline_turns: int = 0


@dataclass
class _TurnRecord:
    waf_score: float
    response_entropy: float


class ConversationGraphState:
    """Per-session conversation graph state machine.

    Parameters
    ----------
    window:
        Sliding-window size (number of recent turns examined).
    baseline_turns:
        Number of initial turns used to establish the session entropy baseline.
    entropy_drop_threshold:
        Entropy drop (bits) below the session baseline that triggers a drift
        alert.  Default 0.8 bits — a meaningful shift without being too
        sensitive to natural response variance.
    monotone_decline_turns:
        Number of consecutive turns with strictly decreasing response entropy
        that triggers a monotone-decline alert.  Default 4.
    combined_score_boost:
        Additional WAF cumulative score threshold that, when combined with
        any entropy signal, lowers the entropy_drop_threshold by half.
        Set 0 to disable combined-signal detection.
    """

    def __init__(
        self,
        window: int = 10,
        baseline_turns: int = 3,
        entropy_drop_threshold: float = 0.8,
        monotone_decline_turns: int = 4,
        combined_score_boost: float = 0.5,
    ) -> None:
        self._window = window
        self._baseline_turns = baseline_turns
        self._entropy_drop_threshold = entropy_drop_threshold
        self._monotone_decline_turns = monotone_decline_turns
        self._combined_score_boost = combined_score_boost
        self._history: deque[_TurnRecord] = deque(maxlen=window)
        self._baseline_samples: list[float] = []
        self._baseline_mean: float | None = None
        self._all_turns: list[_TurnRecord] = []
        self._lock = threading.Lock()

    def record_and_check(
        self,
        waf_score: float,
        response_entropy: float,
    ) -> ErosionDetectionResult:
        """Record a completed turn and evaluate erosion signals.

        Parameters
        ----------
        waf_score:
            Per-turn WAF score for the *request* (0.0–1.0).
        response_entropy:
            Shannon entropy (bits) of the *response* logprob distribution.
            When logprobs are unavailable pass 0.0; drift detection is
            suppressed when the baseline entropy is 0.0.

        Returns
        -------
        ErosionDetectionResult
            ``erosion_detected=True`` when a crescendo erosion pattern is found.
        """
        with self._lock:
            turn = _TurnRecord(waf_score=waf_score, response_entropy=response_entropy)
            self._history.append(turn)
            self._all_turns.append(turn)

            # Accumulate baseline from first baseline_turns turns
            if self._baseline_mean is None:
                self._baseline_samples.append(response_entropy)
                if len(self._baseline_samples) >= self._baseline_turns:
                    self._baseline_mean = sum(self._baseline_samples) / len(self._baseline_samples)

            # Not enough data for detection yet
            if len(self._history) < 2:
                return ErosionDetectionResult(erosion_detected=False)

            history_list = list(self._history)
            window_entropies = [r.response_entropy for r in history_list]
            window_waf = [r.waf_score for r in history_list]
            window_mean = sum(window_entropies) / len(window_entropies)
            cumulative_waf = sum(window_waf)

            # ── Signal 1: monotone entropy decline ────────────────────────
            decline_streak = self._consecutive_decline(window_entropies)
            if decline_streak >= self._monotone_decline_turns:
                return ErosionDetectionResult(
                    erosion_detected=True,
                    reason=(
                        f"Conversation graph: monotone response-entropy decline "
                        f"over {decline_streak} consecutive turns — possible "
                        f"constraint erosion (crescendo attack)"
                    ),
                    window_entropy_mean=window_mean,
                    baseline_entropy_mean=self._baseline_mean or 0.0,
                    entropy_drop=0.0,
                    monotone_decline_turns=decline_streak,
                )

            # ── Signal 2: baseline drift ──────────────────────────────────
            # Compare the most recent baseline_turns against the session baseline
            # to avoid dilution from old high-entropy turns still in the window.
            if self._baseline_mean is not None and self._baseline_mean > 0.0:
                tail = history_list[-self._baseline_turns :]
                if len(tail) >= self._baseline_turns:
                    recent_mean = sum(r.response_entropy for r in tail) / len(tail)
                    drop = self._baseline_mean - recent_mean
                    # Combined signal: WAF activity lowers the drift threshold
                    effective_threshold = self._entropy_drop_threshold
                    if (
                        self._combined_score_boost > 0
                        and cumulative_waf >= self._combined_score_boost
                    ):
                        effective_threshold *= 0.5

                    if drop >= effective_threshold:
                        return ErosionDetectionResult(
                            erosion_detected=True,
                            reason=(
                                f"Conversation graph: response entropy drifted "
                                f"{drop:.3f} bits below session baseline "
                                f"(threshold {effective_threshold:.3f} bits) — "
                                f"possible model constraint erosion"
                            ),
                            window_entropy_mean=window_mean,
                            baseline_entropy_mean=self._baseline_mean,
                            entropy_drop=drop,
                            monotone_decline_turns=decline_streak,
                        )

            return ErosionDetectionResult(
                erosion_detected=False,
                window_entropy_mean=window_mean,
                baseline_entropy_mean=self._baseline_mean or 0.0,
                entropy_drop=max(0.0, (self._baseline_mean or 0.0) - window_mean),
                monotone_decline_turns=decline_streak,
            )

    @staticmethod
    def _consecutive_decline(values: list[float]) -> int:
        """Return the length of the longest consecutive strictly-declining suffix."""
        if len(values) < 2:
            return 0
        streak = 1
        for i in range(len(values) - 1, 0, -1):
            if values[i] < values[i - 1]:
                streak += 1
            else:
                break
        return streak if streak >= 2 else 0

    @property
    def turn_count(self) -> int:
        with self._lock:
            return len(self._all_turns)


class ConversationGraphTracker:
    """LRU-bounded registry of per-session :class:`ConversationGraphState` instances.

    Thread-safe.  Mirrors the design of :class:`~aegis.core.waf_session.WAFSessionTracker`
    so the two trackers can be composed by callers.

    Parameters
    ----------
    max_sessions:
        Maximum concurrent sessions held in memory.  Oldest session is evicted
        LRU when the cap is reached.
    window, baseline_turns, entropy_drop_threshold, monotone_decline_turns,
    combined_score_boost:
        Forwarded to each newly-created :class:`ConversationGraphState`.
    """

    def __init__(
        self,
        max_sessions: int = 4_096,
        window: int = 10,
        baseline_turns: int = 3,
        entropy_drop_threshold: float = 0.8,
        monotone_decline_turns: int = 4,
        combined_score_boost: float = 0.5,
    ) -> None:
        self._max = max_sessions
        self._window = window
        self._baseline_turns = baseline_turns
        self._entropy_drop_threshold = entropy_drop_threshold
        self._monotone_decline_turns = monotone_decline_turns
        self._combined_score_boost = combined_score_boost
        self._sessions: OrderedDict[str, ConversationGraphState] = OrderedDict()
        self._lock = threading.Lock()

    def record_turn(
        self,
        session_id: str,
        waf_score: float,
        response_entropy: float,
    ) -> ErosionDetectionResult:
        """Record a completed turn for *session_id* and evaluate erosion signals."""
        state = self._get_or_create(session_id)
        return state.record_and_check(waf_score=waf_score, response_entropy=response_entropy)

    def _get_or_create(self, session_id: str) -> ConversationGraphState:
        with self._lock:
            if session_id in self._sessions:
                self._sessions.move_to_end(session_id)
                return self._sessions[session_id]
            if len(self._sessions) >= self._max:
                self._sessions.popitem(last=False)
            state = ConversationGraphState(
                window=self._window,
                baseline_turns=self._baseline_turns,
                entropy_drop_threshold=self._entropy_drop_threshold,
                monotone_decline_turns=self._monotone_decline_turns,
                combined_score_boost=self._combined_score_boost,
            )
            self._sessions[session_id] = state
            return state

    def terminate_session(self, session_id: str) -> None:
        """Explicitly remove a session's graph state from memory."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def active_count(self) -> int:
        with self._lock:
            return len(self._sessions)
