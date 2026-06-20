# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.conversation_graph — conversation graph crescendo analysis."""
from __future__ import annotations

import threading

import pytest

from aegis.core.conversation_graph import (
    ConversationGraphState,
    ConversationGraphTracker,
    ErosionDetectionResult,
)


class TestConversationGraphState:
    def _state(self, **kwargs) -> ConversationGraphState:
        defaults = dict(
            window=10,
            baseline_turns=3,
            entropy_drop_threshold=0.8,
            monotone_decline_turns=4,
            combined_score_boost=0.5,
        )
        defaults.update(kwargs)
        return ConversationGraphState(**defaults)

    # ── Baseline / no-detection ──────────────────────────────────────────────

    def test_first_turn_never_escalates(self):
        state = self._state()
        result = state.record_and_check(waf_score=0.0, response_entropy=2.0)
        assert not result.erosion_detected

    def test_single_turn_never_escalates(self):
        state = self._state()
        state.record_and_check(waf_score=0.5, response_entropy=2.0)
        result = state.record_and_check(waf_score=0.5, response_entropy=1.0)
        assert not result.erosion_detected

    def test_stable_entropy_no_erosion(self):
        state = self._state(baseline_turns=3, entropy_drop_threshold=0.8)
        for _ in range(3):
            state.record_and_check(waf_score=0.0, response_entropy=3.0)
        for _ in range(7):
            result = state.record_and_check(waf_score=0.0, response_entropy=2.9)
        assert not result.erosion_detected

    def test_turn_count_increments(self):
        state = self._state()
        for _ in range(5):
            state.record_and_check(waf_score=0.0, response_entropy=2.0)
        assert state.turn_count == 5

    # ── Monotone decline detection ───────────────────────────────────────────

    def test_monotone_decline_detected(self):
        """Four strictly decreasing entropy values should trigger monotone signal."""
        state = self._state(monotone_decline_turns=4, baseline_turns=1)
        # Baseline turn
        state.record_and_check(waf_score=0.0, response_entropy=3.0)
        # Strictly decreasing sequence
        for entropy in [2.8, 2.5, 2.2, 1.9]:
            result = state.record_and_check(waf_score=0.0, response_entropy=entropy)
        assert result.erosion_detected
        assert "monotone" in result.reason.lower()
        assert result.monotone_decline_turns >= 4

    def test_monotone_decline_requires_consecutive(self):
        """A single increase resets the streak — no false positive."""
        state = self._state(monotone_decline_turns=4, baseline_turns=1)
        state.record_and_check(waf_score=0.0, response_entropy=3.0)
        for entropy in [2.8, 2.5, 2.7, 2.3]:  # bump at 2.7 resets streak
            result = state.record_and_check(waf_score=0.0, response_entropy=entropy)
        assert not result.erosion_detected

    def test_monotone_streak_reports_correct_length(self):
        state = self._state(monotone_decline_turns=3, baseline_turns=1)
        state.record_and_check(waf_score=0.0, response_entropy=3.0)
        for entropy in [2.9, 2.6, 2.2]:
            result = state.record_and_check(waf_score=0.0, response_entropy=entropy)
        assert result.erosion_detected
        assert result.monotone_decline_turns >= 3

    def test_monotone_equal_values_not_decline(self):
        """Equal values are not strictly decreasing — monotone signal stays silent."""
        # Use values near baseline so drift signal doesn't fire (drop < 0.8)
        state = self._state(monotone_decline_turns=3, baseline_turns=1)
        state.record_and_check(waf_score=0.0, response_entropy=3.0)
        for entropy in [2.9, 2.9, 2.9]:
            result = state.record_and_check(waf_score=0.0, response_entropy=entropy)
        assert not result.erosion_detected

    # ── Baseline drift detection ─────────────────────────────────────────────

    def test_baseline_drift_detected(self):
        """Response entropy dropping 1.0 bit below baseline triggers drift alert."""
        state = self._state(baseline_turns=3, entropy_drop_threshold=0.8)
        # Establish baseline at ~3.0 bits
        for _ in range(3):
            state.record_and_check(waf_score=0.0, response_entropy=3.0)
        # Recent turns drop to ~1.8 bits — 1.2 bit drop > 0.8 threshold
        for _ in range(5):
            result = state.record_and_check(waf_score=0.0, response_entropy=1.8)
        assert result.erosion_detected
        assert "baseline" in result.reason.lower()
        assert result.entropy_drop > 0.8

    def test_baseline_drift_not_detected_small_drop(self):
        """A drop smaller than the threshold should not trigger."""
        state = self._state(baseline_turns=3, entropy_drop_threshold=0.8)
        for _ in range(3):
            state.record_and_check(waf_score=0.0, response_entropy=3.0)
        for _ in range(5):
            result = state.record_and_check(waf_score=0.0, response_entropy=2.6)
        assert not result.erosion_detected

    def test_baseline_not_established_before_baseline_turns(self):
        """Before baseline_turns completes, drift detection is suppressed."""
        state = self._state(baseline_turns=5, entropy_drop_threshold=0.5)
        # Only 2 baseline turns recorded — drift can't fire yet
        state.record_and_check(waf_score=0.0, response_entropy=3.0)
        result = state.record_and_check(waf_score=0.0, response_entropy=1.0)
        assert not result.erosion_detected

    def test_result_reports_entropy_drop(self):
        state = self._state(baseline_turns=3, entropy_drop_threshold=0.5)
        for _ in range(3):
            state.record_and_check(waf_score=0.0, response_entropy=3.0)
        for _ in range(5):
            result = state.record_and_check(waf_score=0.0, response_entropy=2.0)
        assert result.baseline_entropy_mean == pytest.approx(3.0)
        assert result.window_entropy_mean == pytest.approx(2.0, abs=0.5)
        assert result.entropy_drop > 0.0

    # ── Combined signal boost ────────────────────────────────────────────────

    def test_combined_waf_plus_entropy_lowers_threshold(self):
        """With WAF cumulative score ≥ combined_score_boost, threshold halved."""
        state = self._state(
            baseline_turns=3,
            entropy_drop_threshold=0.8,
            combined_score_boost=0.3,
        )
        for _ in range(3):
            state.record_and_check(waf_score=0.0, response_entropy=3.0)
        # Drop 0.5 bits — normally below threshold (0.8) but above halved (0.4)
        for _ in range(5):
            result = state.record_and_check(waf_score=0.2, response_entropy=2.5)
        assert result.erosion_detected
        assert "baseline" in result.reason.lower()

    def test_combined_boost_disabled_when_zero(self):
        """combined_score_boost=0 disables the combined signal."""
        state = self._state(
            baseline_turns=3,
            entropy_drop_threshold=0.8,
            combined_score_boost=0.0,
        )
        for _ in range(3):
            state.record_and_check(waf_score=0.0, response_entropy=3.0)
        for _ in range(5):
            result = state.record_and_check(waf_score=1.0, response_entropy=2.5)
        assert not result.erosion_detected

    # ── Zero-entropy suppression ─────────────────────────────────────────────

    def test_zero_baseline_suppresses_drift(self):
        """When logprobs unavailable (entropy=0.0), drift detection suppressed."""
        state = self._state(baseline_turns=3, entropy_drop_threshold=0.1)
        for _ in range(5):
            result = state.record_and_check(waf_score=0.0, response_entropy=0.0)
        assert not result.erosion_detected

    # ── Thread safety ────────────────────────────────────────────────────────

    def test_concurrent_record_no_crash(self):
        state = self._state(window=50, monotone_decline_turns=100)
        errors = []

        def worker(entropy_start: float):
            try:
                for i in range(20):
                    state.record_and_check(waf_score=0.0, response_entropy=entropy_start + i * 0.01)
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(float(t),)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors


class TestConversationGraphTracker:
    def _tracker(self, **kwargs) -> ConversationGraphTracker:
        defaults = dict(
            max_sessions=8,
            window=10,
            baseline_turns=3,
            entropy_drop_threshold=0.8,
            monotone_decline_turns=4,
        )
        defaults.update(kwargs)
        return ConversationGraphTracker(**defaults)

    def test_new_session_created_on_first_call(self):
        tracker = self._tracker()
        assert tracker.active_count() == 0
        tracker.record_turn("s1", waf_score=0.0, response_entropy=2.0)
        assert tracker.active_count() == 1

    def test_separate_sessions_isolated(self):
        tracker = self._tracker(baseline_turns=2, entropy_drop_threshold=0.5)
        # s1 high baseline
        for _ in range(2):
            tracker.record_turn("s1", waf_score=0.0, response_entropy=4.0)
        # s2 has no baseline yet
        r = tracker.record_turn("s2", waf_score=0.0, response_entropy=1.0)
        assert not r.erosion_detected  # s2 has no baseline

    def test_erosion_detected_per_session(self):
        tracker = self._tracker(baseline_turns=3, entropy_drop_threshold=0.5)
        for _ in range(3):
            tracker.record_turn("s1", waf_score=0.0, response_entropy=3.0)
        for _ in range(6):
            result = tracker.record_turn("s1", waf_score=0.0, response_entropy=2.0)
        assert result.erosion_detected

    def test_lru_eviction_at_capacity(self):
        tracker = self._tracker(max_sessions=3)
        for i in range(3):
            tracker.record_turn(f"s{i}", waf_score=0.0, response_entropy=2.0)
        assert tracker.active_count() == 3
        tracker.record_turn("s_new", waf_score=0.0, response_entropy=2.0)
        assert tracker.active_count() == 3  # oldest evicted

    def test_terminate_session(self):
        tracker = self._tracker()
        tracker.record_turn("s1", waf_score=0.0, response_entropy=2.0)
        assert tracker.active_count() == 1
        tracker.terminate_session("s1")
        assert tracker.active_count() == 0

    def test_terminate_nonexistent_session_no_error(self):
        tracker = self._tracker()
        tracker.terminate_session("ghost")  # should not raise

    def test_returns_erosion_detection_result(self):
        tracker = self._tracker()
        result = tracker.record_turn("s1", waf_score=0.0, response_entropy=2.0)
        assert isinstance(result, ErosionDetectionResult)

    def test_multiple_sessions_independent_counts(self):
        tracker = self._tracker()
        for _ in range(5):
            tracker.record_turn("s1", waf_score=0.0, response_entropy=2.0)
        for _ in range(3):
            tracker.record_turn("s2", waf_score=0.0, response_entropy=2.0)
        # Access internal state directly via _get_or_create
        s1_state = tracker._get_or_create("s1")
        s2_state = tracker._get_or_create("s2")
        assert s1_state.turn_count == 5
        assert s2_state.turn_count == 3
