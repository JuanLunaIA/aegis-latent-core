# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.cpu_affinity — CPU core pinning."""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from aegis.core.cpu_affinity import AffinityResult, CPUAffinity, CPUAffinityError

# ── get_affinity() ────────────────────────────────────────────────────────────


class TestGetAffinity:
    def test_returns_frozenset(self):
        result = CPUAffinity.get_affinity()
        assert isinstance(result, frozenset)

    def test_all_elements_are_ints(self):
        result = CPUAffinity.get_affinity()
        assert all(isinstance(c, int) for c in result)

    def test_all_elements_non_negative(self):
        result = CPUAffinity.get_affinity()
        assert all(c >= 0 for c in result)

    def test_non_linux_falls_back_gracefully(self):
        with patch.object(sys, "platform", "darwin"):
            result = CPUAffinity.get_affinity()
        assert isinstance(result, frozenset)

    def test_no_libc_falls_back_gracefully(self):
        with patch("aegis.core.cpu_affinity.HAS_LIBC", False):
            result = CPUAffinity.get_affinity()
        assert isinstance(result, frozenset)


# ── available_cpus() ──────────────────────────────────────────────────────────


class TestAvailableCPUs:
    def test_returns_non_empty_frozenset(self):
        result = CPUAffinity.available_cpus()
        assert isinstance(result, frozenset)
        assert len(result) > 0

    def test_all_elements_non_negative_int(self):
        result = CPUAffinity.available_cpus()
        assert all(isinstance(c, int) and c >= 0 for c in result)

    def test_falls_back_when_os_sched_unavailable(self):
        with patch("os.sched_getaffinity", side_effect=AttributeError):
            result = CPUAffinity.available_cpus()
        assert len(result) > 0


# ── set_affinity() ────────────────────────────────────────────────────────────


class TestSetAffinity:
    def test_returns_affinity_result(self):
        result = CPUAffinity.set_affinity(frozenset({0}))
        assert isinstance(result, AffinityResult)

    def test_empty_cpu_set_raises(self):
        with pytest.raises(CPUAffinityError):
            CPUAffinity.set_affinity(frozenset())

    def test_applied_is_bool(self):
        result = CPUAffinity.set_affinity(frozenset({0}))
        assert isinstance(result.applied, bool)

    def test_reason_is_non_empty_string(self):
        result = CPUAffinity.set_affinity(frozenset({0}))
        assert isinstance(result.reason, str)
        assert len(result.reason) > 0

    def test_cpu_set_preserved_in_result(self):
        cpu_set = frozenset({0})
        result = CPUAffinity.set_affinity(cpu_set)
        assert result.cpu_set == cpu_set

    def test_non_linux_returns_unapplied(self):
        with patch.object(sys, "platform", "darwin"):
            result = CPUAffinity.set_affinity(frozenset({0}))
        assert result.applied is False

    def test_no_libc_returns_unapplied(self):
        with patch("aegis.core.cpu_affinity.HAS_LIBC", False):
            result = CPUAffinity.set_affinity(frozenset({0}))
        assert result.applied is False


# ── get_isolated_cpus() ───────────────────────────────────────────────────────


class TestGetIsolatedCPUs:
    def test_returns_frozenset(self):
        result = CPUAffinity.get_isolated_cpus()
        assert isinstance(result, frozenset)

    def test_all_elements_non_negative_int(self):
        result = CPUAffinity.get_isolated_cpus()
        assert all(isinstance(c, int) and c >= 0 for c in result)

    def test_non_linux_returns_empty(self):
        with patch.object(sys, "platform", "win32"):
            result = CPUAffinity.get_isolated_cpus()
        assert result == frozenset()

    def test_absent_file_returns_empty(self):
        with (
            patch("aegis.core.cpu_affinity._SYS_ISOLATED", "/nonexistent/isolated"),
            patch.object(sys, "platform", "linux"),
        ):
            result = CPUAffinity.get_isolated_cpus()
        assert result == frozenset()

    def test_parses_range_notation(self, tmp_path):
        isolated = tmp_path / "isolated"
        isolated.write_text("2-5\n")
        with (
            patch("aegis.core.cpu_affinity._SYS_ISOLATED", str(isolated)),
            patch.object(sys, "platform", "linux"),
        ):
            result = CPUAffinity.get_isolated_cpus()
        assert result == frozenset({2, 3, 4, 5})

    def test_parses_comma_notation(self, tmp_path):
        isolated = tmp_path / "isolated"
        isolated.write_text("0,2,4\n")
        with (
            patch("aegis.core.cpu_affinity._SYS_ISOLATED", str(isolated)),
            patch.object(sys, "platform", "linux"),
        ):
            result = CPUAffinity.get_isolated_cpus()
        assert result == frozenset({0, 2, 4})


# ── from_env() ────────────────────────────────────────────────────────────────


class TestFromEnv:
    def test_empty_env_returns_empty_set(self, monkeypatch):
        monkeypatch.delenv("AEGIS_CPU_AFFINITY", raising=False)
        aff = CPUAffinity.from_env()
        assert aff._cpu_set == frozenset()

    def test_comma_separated_parsed(self, monkeypatch):
        monkeypatch.setenv("AEGIS_CPU_AFFINITY", "2,3,4,5")
        aff = CPUAffinity.from_env()
        assert aff._cpu_set == frozenset({2, 3, 4, 5})

    def test_single_cpu_parsed(self, monkeypatch):
        monkeypatch.setenv("AEGIS_CPU_AFFINITY", "0")
        aff = CPUAffinity.from_env()
        assert aff._cpu_set == frozenset({0})

    def test_isolated_keyword_uses_isolated_cpus(self, monkeypatch, tmp_path):
        isolated = tmp_path / "isolated"
        isolated.write_text("6,7\n")
        monkeypatch.setenv("AEGIS_CPU_AFFINITY", "isolated")
        with (
            patch("aegis.core.cpu_affinity._SYS_ISOLATED", str(isolated)),
            patch.object(sys, "platform", "linux"),
        ):
            aff = CPUAffinity.from_env()
        assert aff._cpu_set == frozenset({6, 7})

    def test_invalid_env_ignored(self, monkeypatch):
        monkeypatch.setenv("AEGIS_CPU_AFFINITY", "not_a_number")
        aff = CPUAffinity.from_env()
        assert aff._cpu_set == frozenset()


# ── AffinityResult.to_dict() ──────────────────────────────────────────────────


class TestAffinityResultToDict:
    def test_has_required_keys(self):
        result = CPUAffinity.set_affinity(frozenset({0}))
        d = result.to_dict()
        for key in ("applied", "cpu_set", "pid", "reason"):
            assert key in d

    def test_cpu_set_is_sorted_list(self):
        result = AffinityResult(
            applied=True,
            cpu_set=frozenset({3, 1, 2}),
            pid=0,
            reason="ok",
        )
        d = result.to_dict()
        assert d["cpu_set"] == [1, 2, 3]

    def test_serialisable(self):
        import json

        result = CPUAffinity.set_affinity(frozenset({0}))
        json.dumps(result.to_dict())


# ── apply() ───────────────────────────────────────────────────────────────────


class TestApply:
    def test_returns_affinity_result(self):
        aff = CPUAffinity(cpu_set=frozenset({0}))
        result = aff.apply()
        assert isinstance(result, AffinityResult)

    def test_empty_set_returns_unapplied(self):
        aff = CPUAffinity(cpu_set=frozenset())
        result = aff.apply()
        assert result.applied is False
