# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Multi-turn behavioral WAF session state machine (ROADMAP Domain 5.1)."""
from __future__ import annotations

import threading

import pytest

from aegis.core.waf_session import SessionEscalationResult, WAFSessionState, WAFSessionTracker


class TestWAFSessionState:
    def _state(self, window=5, cumulative_threshold=2.0, crescendo_turns=3):
        return WAFSessionState(
            window=window,
            cumulative_threshold=cumulative_threshold,
            crescendo_turns=crescendo_turns,
        )

    def test_clean_turns_never_escalate(self):
        s = self._state()
        for _ in range(10):
            result = s.record_and_check(score=0.0, allowed=True)
            assert not result.escalated

    def test_cumulative_threshold_triggers(self):
        s = self._state(cumulative_threshold=1.0)
        # Two turns with score 0.6 each → window_score = 1.2 ≥ 1.0
        s.record_and_check(score=0.6, allowed=True)
        result = s.record_and_check(score=0.6, allowed=True)
        assert result.escalated
        assert "cumulative" in result.reason.lower()
        assert result.window_score >= 1.0

    def test_cumulative_below_threshold_no_escalation(self):
        # crescendo_turns=99 so only cumulative check is in play
        s = self._state(cumulative_threshold=2.0, crescendo_turns=99)
        # Three turns with score 0.3 each → window_score = 0.9 < 2.0
        for _ in range(3):
            result = s.record_and_check(score=0.3, allowed=True)
        assert not result.escalated

    def test_crescendo_triggers_on_consecutive_soft_hits(self):
        s = self._state(crescendo_turns=3, cumulative_threshold=99.0)
        s.record_and_check(score=0.1, allowed=True)
        s.record_and_check(score=0.1, allowed=True)
        result = s.record_and_check(score=0.1, allowed=True)
        assert result.escalated
        assert "crescendo" in result.reason.lower()
        assert result.soft_hit_turns >= 3

    def test_crescendo_resets_on_clean_turn(self):
        s = self._state(crescendo_turns=3, cumulative_threshold=99.0)
        s.record_and_check(score=0.2, allowed=True)
        s.record_and_check(score=0.2, allowed=True)
        # Clean turn resets consecutive counter
        s.record_and_check(score=0.0, allowed=True)
        s.record_and_check(score=0.2, allowed=True)
        result = s.record_and_check(score=0.2, allowed=True)
        # Only 2 consecutive after reset — should not escalate
        assert not result.escalated

    def test_blocked_turn_resets_crescendo(self):
        s = self._state(crescendo_turns=3, cumulative_threshold=99.0)
        s.record_and_check(score=0.2, allowed=True)
        s.record_and_check(score=0.2, allowed=True)
        # A blocked turn (allowed=False) resets consecutive counter
        s.record_and_check(score=1.0, allowed=False)
        s.record_and_check(score=0.2, allowed=True)
        result = s.record_and_check(score=0.2, allowed=True)
        assert not result.escalated

    def test_sliding_window_evicts_old_turns(self):
        # window=3, threshold=1.0: after 3 soft turns old ones roll out
        s = self._state(window=3, cumulative_threshold=1.0, crescendo_turns=99)
        # Fill window with score 0.4 turns — window_score = 1.2 → escalate
        s.record_and_check(score=0.4, allowed=True)
        s.record_and_check(score=0.4, allowed=True)
        result = s.record_and_check(score=0.4, allowed=True)
        assert result.escalated
        # Now add clean turns — old 0.4s roll out, window clears
        s.record_and_check(score=0.0, allowed=True)
        s.record_and_check(score=0.0, allowed=True)
        result = s.record_and_check(score=0.0, allowed=True)
        assert not result.escalated

    def test_turn_count_increments(self):
        s = self._state()
        assert s.turn_count == 0
        s.record_and_check(score=0.0, allowed=True)
        s.record_and_check(score=0.0, allowed=True)
        assert s.turn_count == 2

    def test_turn_count_bounded_by_window(self):
        s = self._state(window=3)
        for _ in range(10):
            s.record_and_check(score=0.0, allowed=True)
        assert s.turn_count == 3

    def test_result_is_dataclass(self):
        s = self._state()
        result = s.record_and_check(score=0.0, allowed=True)
        assert isinstance(result, SessionEscalationResult)
        assert result.escalated is False
        assert isinstance(result.window_score, float)
        assert isinstance(result.soft_hit_turns, int)

    def test_concurrent_access_is_safe(self):
        s = self._state(window=10, cumulative_threshold=99.0, crescendo_turns=99)
        errors = []

        def _worker():
            try:
                for _ in range(20):
                    s.record_and_check(score=0.1, allowed=True)
            except Exception as exc:
                errors.append(exc)

        threads = [threading.Thread(target=_worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors


class TestWAFSessionTracker:
    def _tracker(self, **kwargs):
        defaults = dict(
            max_sessions=100,
            window=5,
            cumulative_threshold=2.0,
            crescendo_turns=3,
        )
        defaults.update(kwargs)
        return WAFSessionTracker(**defaults)

    def test_separate_sessions_are_isolated(self):
        t = self._tracker(cumulative_threshold=1.0)
        # session A accumulates
        t.record_and_check("A", score=0.6, allowed=True)
        result_a = t.record_and_check("A", score=0.6, allowed=True)
        # session B is clean
        result_b = t.record_and_check("B", score=0.0, allowed=True)
        assert result_a.escalated
        assert not result_b.escalated

    def test_lru_eviction_when_at_capacity(self):
        t = self._tracker(max_sessions=2)
        t.record_and_check("s1", score=0.0, allowed=True)
        t.record_and_check("s2", score=0.0, allowed=True)
        assert t.active_count() == 2
        # Adding s3 evicts oldest (s1)
        t.record_and_check("s3", score=0.0, allowed=True)
        assert t.active_count() == 2

    def test_terminate_session_removes_state(self):
        t = self._tracker()
        t.record_and_check("sess", score=0.3, allowed=True)
        assert t.active_count() == 1
        t.terminate_session("sess")
        assert t.active_count() == 0

    def test_terminate_nonexistent_session_is_noop(self):
        t = self._tracker()
        t.terminate_session("ghost")  # must not raise

    def test_active_count_reflects_sessions(self):
        t = self._tracker()
        assert t.active_count() == 0
        t.record_and_check("a", score=0.0, allowed=True)
        t.record_and_check("b", score=0.0, allowed=True)
        assert t.active_count() == 2

    def test_session_state_reused_across_calls(self):
        t = self._tracker(cumulative_threshold=1.5, crescendo_turns=99)
        # Two calls for the same session accumulate
        t.record_and_check("x", score=0.8, allowed=True)
        result = t.record_and_check("x", score=0.8, allowed=True)
        assert result.escalated

    def test_clean_traffic_never_escalates(self):
        t = self._tracker()
        for i in range(50):
            result = t.record_and_check(f"user-{i % 10}", score=0.0, allowed=True)
            assert not result.escalated


class TestWAFSessionIntegration:
    """Integration tests with the proxy WAF flow (mock WAFResult-like objects)."""

    def test_gradual_escalation_detected(self):
        """Simulate an attack spread over 4 low-score turns."""
        tracker = WAFSessionTracker(
            max_sessions=10,
            window=5,
            cumulative_threshold=1.5,
            crescendo_turns=99,
        )
        session = "attacker-001"
        # 4 turns with score 0.4 each — cumulative = 1.6 after turn 4
        scores = [0.4, 0.4, 0.4, 0.4]
        results = [
            tracker.record_and_check(session, score=s, allowed=True) for s in scores
        ]
        # First 3: 0.4+0.4+0.4=1.2 < 1.5 → not escalated
        assert not results[0].escalated
        assert not results[1].escalated
        assert not results[2].escalated
        # Turn 4: 1.6 ≥ 1.5 → escalated
        assert results[3].escalated

    def test_crescendo_detected(self):
        """Simulate 3 consecutive suspicious turns (crescendo attack)."""
        tracker = WAFSessionTracker(
            max_sessions=10,
            window=5,
            cumulative_threshold=99.0,
            crescendo_turns=3,
        )
        session = "crescendo-attacker"
        r1 = tracker.record_and_check(session, score=0.3, allowed=True)
        r2 = tracker.record_and_check(session, score=0.3, allowed=True)
        r3 = tracker.record_and_check(session, score=0.3, allowed=True)
        assert not r1.escalated
        assert not r2.escalated
        assert r3.escalated
        assert "crescendo" in r3.reason.lower()

    def test_legitimate_session_not_flagged(self):
        """A session with a single soft hit and clean follow-up is not flagged."""
        tracker = WAFSessionTracker(
            max_sessions=10,
            window=5,
            cumulative_threshold=2.0,
            crescendo_turns=3,
        )
        session = "legit-user"
        tracker.record_and_check(session, score=0.5, allowed=True)
        result = tracker.record_and_check(session, score=0.0, allowed=True)
        assert not result.escalated
