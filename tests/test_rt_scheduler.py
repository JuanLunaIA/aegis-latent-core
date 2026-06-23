# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.rt_scheduler — real-time scheduling policy manager."""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from aegis.core.rt_scheduler import (
    RTScheduler,
    RTSchedulerError,
    SchedulingConfig,
    SchedulingPolicy,
    SchedulingResult,
)

# ── get_current_policy() ──────────────────────────────────────────────────────


class TestGetCurrentPolicy:
    def test_returns_scheduling_config(self):
        result = RTScheduler.get_current_policy()
        assert isinstance(result, SchedulingConfig)

    def test_policy_is_valid_enum(self):
        result = RTScheduler.get_current_policy()
        assert result.policy in list(SchedulingPolicy)

    def test_priority_is_int(self):
        result = RTScheduler.get_current_policy()
        assert isinstance(result.priority, int)

    def test_non_linux_returns_normal(self):
        with patch.object(sys, "platform", "darwin"):
            result = RTScheduler.get_current_policy()
        assert result.policy == SchedulingPolicy.NORMAL
        assert result.priority == 0

    def test_no_libc_returns_normal(self):
        with patch("aegis.core.rt_scheduler.HAS_LIBC", False):
            result = RTScheduler.get_current_policy()
        assert result.policy == SchedulingPolicy.NORMAL


# ── set_fifo_priority() ───────────────────────────────────────────────────────


class TestSetFifoPriority:
    def test_returns_scheduling_result(self):
        result = RTScheduler.set_fifo_priority(50)
        assert isinstance(result, SchedulingResult)

    def test_result_policy_is_fifo(self):
        result = RTScheduler.set_fifo_priority(50)
        assert result.policy == SchedulingPolicy.FIFO

    def test_success_or_graceful_failure(self):
        result = RTScheduler.set_fifo_priority(50)
        assert isinstance(result.applied, bool)
        assert isinstance(result.reason, str)

    def test_priority_zero_raises(self):
        with pytest.raises(RTSchedulerError):
            RTScheduler.set_fifo_priority(0)

    def test_priority_100_raises(self):
        with pytest.raises(RTSchedulerError):
            RTScheduler.set_fifo_priority(100)

    def test_priority_negative_raises(self):
        with pytest.raises(RTSchedulerError):
            RTScheduler.set_fifo_priority(-1)

    def test_no_libc_returns_unapplied(self):
        with patch("aegis.core.rt_scheduler.HAS_LIBC", False):
            result = RTScheduler.set_fifo_priority(50)
        assert result.applied is False

    def test_non_linux_returns_unapplied(self):
        with patch.object(sys, "platform", "win32"):
            result = RTScheduler.set_fifo_priority(50)
        assert result.applied is False


# ── set_rr_priority() ─────────────────────────────────────────────────────────


class TestSetRRPriority:
    def test_returns_scheduling_result(self):
        result = RTScheduler.set_rr_priority(30)
        assert isinstance(result, SchedulingResult)

    def test_result_policy_is_rr(self):
        result = RTScheduler.set_rr_priority(30)
        assert result.policy == SchedulingPolicy.RR

    def test_priority_zero_raises(self):
        with pytest.raises(RTSchedulerError):
            RTScheduler.set_rr_priority(0)

    def test_priority_100_raises(self):
        with pytest.raises(RTSchedulerError):
            RTScheduler.set_rr_priority(100)

    def test_no_libc_returns_unapplied(self):
        with patch("aegis.core.rt_scheduler.HAS_LIBC", False):
            result = RTScheduler.set_rr_priority(30)
        assert result.applied is False


# ── reset_to_normal() ─────────────────────────────────────────────────────────


class TestResetToNormal:
    def test_does_not_raise(self):
        RTScheduler.reset_to_normal()

    def test_returns_scheduling_result(self):
        result = RTScheduler.reset_to_normal()
        assert isinstance(result, SchedulingResult)

    def test_policy_is_normal(self):
        result = RTScheduler.reset_to_normal()
        assert result.policy == SchedulingPolicy.NORMAL

    def test_priority_is_zero(self):
        result = RTScheduler.reset_to_normal()
        assert result.priority == 0


# ── from_env() ────────────────────────────────────────────────────────────────


class TestFromEnv:
    def test_default_is_normal(self, monkeypatch):
        monkeypatch.delenv("AEGIS_RT_POLICY", raising=False)
        monkeypatch.delenv("AEGIS_RT_PRIORITY", raising=False)
        sched = RTScheduler.from_env()
        assert sched._policy == SchedulingPolicy.NORMAL

    def test_fifo_policy_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_RT_POLICY", "fifo")
        monkeypatch.setenv("AEGIS_RT_PRIORITY", "60")
        sched = RTScheduler.from_env()
        assert sched._policy == SchedulingPolicy.FIFO
        assert sched._priority == 60

    def test_rr_policy_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_RT_POLICY", "rr")
        monkeypatch.setenv("AEGIS_RT_PRIORITY", "25")
        sched = RTScheduler.from_env()
        assert sched._policy == SchedulingPolicy.RR
        assert sched._priority == 25

    def test_none_policy_from_env(self, monkeypatch):
        monkeypatch.setenv("AEGIS_RT_POLICY", "none")
        sched = RTScheduler.from_env()
        assert sched._policy == SchedulingPolicy.NORMAL

    def test_invalid_priority_defaults_to_zero_for_normal(self, monkeypatch):
        monkeypatch.setenv("AEGIS_RT_POLICY", "none")
        monkeypatch.setenv("AEGIS_RT_PRIORITY", "bad_value")
        sched = RTScheduler.from_env()
        assert sched._policy == SchedulingPolicy.NORMAL
        assert sched._priority == 0


# ── SchedulingResult.to_dict() ────────────────────────────────────────────────


class TestSchedulingResultToDict:
    def test_has_required_keys(self):
        result = RTScheduler.reset_to_normal()
        d = result.to_dict()
        for key in ("applied", "policy", "priority", "reason"):
            assert key in d

    def test_policy_is_string_in_dict(self):
        result = SchedulingResult(
            applied=True,
            policy=SchedulingPolicy.FIFO,
            priority=50,
            reason="ok",
        )
        d = result.to_dict()
        assert d["policy"] == "SCHED_FIFO"

    def test_serialisable(self):
        import json

        result = RTScheduler.reset_to_normal()
        json.dumps(result.to_dict())


# ── apply() ───────────────────────────────────────────────────────────────────


class TestApply:
    def test_normal_policy_apply(self):
        sched = RTScheduler(policy=SchedulingPolicy.NORMAL, priority=0)
        result = sched.apply()
        assert isinstance(result, SchedulingResult)
        assert result.policy == SchedulingPolicy.NORMAL

    def test_fifo_apply_returns_result(self):
        sched = RTScheduler(policy=SchedulingPolicy.FIFO, priority=50)
        result = sched.apply()
        assert isinstance(result, SchedulingResult)
        assert result.policy == SchedulingPolicy.FIFO
