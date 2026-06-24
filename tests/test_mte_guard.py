# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.mte_guard — real ARM MTE detection.

On non-ARM / non-MTE platforms (CI x86 hosts) the guard must report
False honestly rather than simulating a positive result.
"""

from __future__ import annotations

import os

import pytest

from aegis.core.mte_guard import (
    MTEGuard,
    _auxv_has_mte,
    _cpuinfo_has_mte,
    _prctl_enable_mte,
)

_IS_ARM_MTE = _cpuinfo_has_mte() or _auxv_has_mte()
requires_arm_mte = pytest.mark.skipif(
    not _IS_ARM_MTE,
    reason="ARM MTE hardware not present on this host",
)


class TestHardwareDetection:
    def test_cpuinfo_returns_bool(self):
        result = _cpuinfo_has_mte()
        assert isinstance(result, bool)

    def test_auxv_returns_bool(self):
        result = _auxv_has_mte()
        assert isinstance(result, bool)

    def test_prctl_returns_bool(self):
        result = _prctl_enable_mte()
        assert isinstance(result, bool)

    def test_no_mte_on_x86(self):
        machine = os.uname().machine
        if machine in ("x86_64", "i686", "i386"):
            assert not _cpuinfo_has_mte(), "cpuinfo must not report MTE on x86"
            assert not _auxv_has_mte(), "auxv must not report MTE on x86"


class TestMTEGuardInit:
    def test_not_protected_on_init(self):
        guard = MTEGuard()
        assert not guard.is_protected()

    def test_platform_report_returns_dict(self):
        report = MTEGuard.get_platform_report()
        assert isinstance(report, dict)
        assert "cpuinfo_mte" in report
        assert "auxv_hwcap2_mte" in report
        assert "arch" in report

    def test_platform_report_values_are_bool_or_str(self):
        report = MTEGuard.get_platform_report()
        assert isinstance(report["cpuinfo_mte"], bool)
        assert isinstance(report["auxv_hwcap2_mte"], bool)
        assert isinstance(report["arch"], str)


class TestMTEGuardNoHardware:
    """Verify honest behaviour on platforms without MTE (e.g. x86 CI)."""

    def _guard_without_mte(self, monkeypatch):
        monkeypatch.setattr("aegis.core.mte_guard._cpuinfo_has_mte", lambda: False)
        monkeypatch.setattr("aegis.core.mte_guard._auxv_has_mte", lambda: False)
        return MTEGuard()

    def test_check_hardware_returns_false(self, monkeypatch):
        guard = self._guard_without_mte(monkeypatch)
        assert guard.check_hardware_support() is False

    def test_enable_returns_false_without_hardware(self, monkeypatch):
        guard = self._guard_without_mte(monkeypatch)
        assert guard.enable_mte_protection() is False

    def test_is_protected_false_without_hardware(self, monkeypatch):
        guard = self._guard_without_mte(monkeypatch)
        guard.enable_mte_protection()  # should fail
        assert not guard.is_protected()

    def test_verify_tag_integrity_false_without_mte(self, monkeypatch):
        guard = self._guard_without_mte(monkeypatch)
        ok, msg = guard.verify_tag_integrity()
        assert not ok
        assert "not enabled" in msg.lower() or "absent" in msg.lower()


class TestMTEGuardWithHardware:
    """Verify behaviour when hardware detection is stubbed to succeed."""

    def _guard_with_mte(self, monkeypatch, prctl_succeeds=True):
        monkeypatch.setattr("aegis.core.mte_guard._cpuinfo_has_mte", lambda: True)
        monkeypatch.setattr("aegis.core.mte_guard._auxv_has_mte", lambda: True)
        monkeypatch.setattr("aegis.core.mte_guard._prctl_enable_mte", lambda: prctl_succeeds)
        return MTEGuard()

    def test_check_hardware_returns_true(self, monkeypatch):
        guard = self._guard_with_mte(monkeypatch)
        assert guard.check_hardware_support() is True

    def test_enable_succeeds_when_prctl_ok(self, monkeypatch):
        guard = self._guard_with_mte(monkeypatch, prctl_succeeds=True)
        assert guard.enable_mte_protection() is True
        assert guard.is_protected() is True

    def test_enable_fails_when_prctl_fails(self, monkeypatch):
        guard = self._guard_with_mte(monkeypatch, prctl_succeeds=False)
        assert guard.enable_mte_protection() is False
        assert not guard.is_protected()

    def test_verify_tag_integrity_true_when_enabled(self, monkeypatch):
        guard = self._guard_with_mte(monkeypatch, prctl_succeeds=True)
        guard.enable_mte_protection()
        ok, msg = guard.verify_tag_integrity()
        assert ok
        assert "confirmed" in msg.lower() or "active" in msg.lower()


@requires_arm_mte
class TestRealArmMTE:
    """Integration tests — only run on actual ARM MTE hardware."""

    def test_hardware_detected(self):
        guard = MTEGuard()
        assert guard.check_hardware_support() is True

    def test_enable_sets_protected(self):
        guard = MTEGuard()
        result = guard.enable_mte_protection()
        assert result is True
        assert guard.is_protected() is True
