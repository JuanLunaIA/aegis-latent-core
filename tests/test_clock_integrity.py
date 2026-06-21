# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for clock integrity assertion (aegis.core.clock_integrity)."""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.clock_integrity import (
    ClockDriftResult,
    ClockIntegrityAssertion,
    NTPSyncStatus,
)

# ── NTPSyncStatus ─────────────────────────────────────────────────────────────


class TestNTPSyncStatus:
    def test_defaults(self):
        s = NTPSyncStatus()
        assert s.ntp_synchronized is None
        assert s.source == "unavailable"
        assert s.warning == ""
        assert s.raw_output == ""

    def test_to_dict_synced(self):
        s = NTPSyncStatus(ntp_synchronized=True, source="timedatectl", warning="")
        d = s.to_dict()
        assert d["ntp_synchronized"] is True
        assert d["source"] == "timedatectl"
        assert d["warning"] == ""
        assert "reference_time" in d

    def test_to_dict_not_synced(self):
        s = NTPSyncStatus(ntp_synchronized=False, source="adjtimex", warning="not synced")
        d = s.to_dict()
        assert d["ntp_synchronized"] is False
        assert d["warning"] == "not synced"

    def test_to_dict_unknown(self):
        d = NTPSyncStatus(ntp_synchronized=None, source="unavailable").to_dict()
        assert d["ntp_synchronized"] is None


# ── ClockDriftResult ──────────────────────────────────────────────────────────


class TestClockDriftResult:
    def _make(self, drift: float, max_drift: float) -> ClockDriftResult:
        within = drift <= max_drift
        return ClockDriftResult(
            node_timestamp=1000.0,
            reference_time=1000.0 + drift,
            drift_seconds=drift,
            max_drift_seconds=max_drift,
            within_tolerance=within,
            warning="" if within else f"drift {drift}s exceeds {max_drift}s",
        )

    def test_within_tolerance_no_warning(self):
        r = self._make(0.5, 5.0)
        assert r.within_tolerance is True
        assert r.warning == ""

    def test_exceeded_tolerance_has_warning(self):
        r = self._make(10.0, 5.0)
        assert r.within_tolerance is False
        assert r.warning != ""

    def test_to_dict_structure(self):
        r = self._make(2.0, 5.0)
        d = r.to_dict()
        assert d["drift_seconds"] == 2.0
        assert d["max_drift_seconds"] == 5.0
        assert d["within_tolerance"] is True
        assert "node_timestamp" in d
        assert "reference_time" in d


# ── ClockIntegrityAssertion constructor ───────────────────────────────────────


class TestConstructor:
    def test_default_max_drift(self):
        cia = ClockIntegrityAssertion()
        assert cia._max_drift == 5.0

    def test_custom_max_drift(self):
        cia = ClockIntegrityAssertion(max_drift_seconds=1.0)
        assert cia._max_drift == 1.0

    def test_negative_max_drift_raises(self):
        with pytest.raises(ValueError, match="max_drift_seconds"):
            ClockIntegrityAssertion(max_drift_seconds=-1.0)

    def test_zero_max_drift_allowed(self):
        cia = ClockIntegrityAssertion(max_drift_seconds=0.0)
        assert cia._max_drift == 0.0


# ── check_node_drift ──────────────────────────────────────────────────────────


class TestCheckNodeDrift:
    def test_within_tolerance(self):
        cia = ClockIntegrityAssertion(max_drift_seconds=5.0)
        r = cia.check_node_drift(node_timestamp=1000.0, reference_time=1001.0)
        assert r.drift_seconds == pytest.approx(1.0)
        assert r.within_tolerance is True
        assert r.warning == ""

    def test_exceeds_tolerance(self):
        cia = ClockIntegrityAssertion(max_drift_seconds=5.0)
        r = cia.check_node_drift(node_timestamp=1000.0, reference_time=1010.0)
        assert r.drift_seconds == pytest.approx(10.0)
        assert r.within_tolerance is False
        assert "drift" in r.warning

    def test_exact_boundary_within(self):
        cia = ClockIntegrityAssertion(max_drift_seconds=5.0)
        r = cia.check_node_drift(node_timestamp=1000.0, reference_time=1005.0)
        assert r.within_tolerance is True

    def test_node_in_future(self):
        cia = ClockIntegrityAssertion(max_drift_seconds=5.0)
        r = cia.check_node_drift(node_timestamp=1010.0, reference_time=1000.0)
        assert r.drift_seconds == pytest.approx(10.0)
        assert r.within_tolerance is False

    def test_uses_current_time_when_no_reference(self):
        import time

        cia = ClockIntegrityAssertion(max_drift_seconds=60.0)
        now = time.time()
        r = cia.check_node_drift(node_timestamp=now)
        assert r.drift_seconds < 1.0
        assert r.within_tolerance is True

    def test_to_dict_has_all_fields(self):
        cia = ClockIntegrityAssertion(max_drift_seconds=5.0)
        r = cia.check_node_drift(node_timestamp=1000.0, reference_time=1002.0)
        d = r.to_dict()
        assert set(d.keys()) == {
            "node_timestamp",
            "reference_time",
            "drift_seconds",
            "max_drift_seconds",
            "within_tolerance",
            "warning",
        }

    def test_zero_drift_within(self):
        cia = ClockIntegrityAssertion(max_drift_seconds=0.0)
        r = cia.check_node_drift(node_timestamp=1000.0, reference_time=1000.0)
        assert r.within_tolerance is True
        assert r.drift_seconds == 0.0

    def test_zero_max_drift_any_drift_fails(self):
        cia = ClockIntegrityAssertion(max_drift_seconds=0.0)
        r = cia.check_node_drift(node_timestamp=1000.0, reference_time=1000.001)
        assert r.within_tolerance is False


# ── assert_startup: timedatectl path ─────────────────────────────────────────


class TestAssertStartupTimedatectl:
    def _timedatectl_result(self, output: str, returncode: int = 0) -> MagicMock:
        result = MagicMock()
        result.returncode = returncode
        result.stdout = output
        return result

    def test_synced_timedatectl(self):
        output = "NTPSynchronized=yes\nTimezone=UTC\n"
        with patch("subprocess.run", return_value=self._timedatectl_result(output)):
            cia = ClockIntegrityAssertion()
            status = cia.assert_startup()
        assert status.ntp_synchronized is True
        assert status.source == "timedatectl"
        assert status.warning == ""

    def test_not_synced_timedatectl(self):
        output = "NTPSynchronized=no\nTimezone=UTC\n"
        with patch("subprocess.run", return_value=self._timedatectl_result(output)):
            cia = ClockIntegrityAssertion()
            status = cia.assert_startup()
        assert status.ntp_synchronized is False
        assert status.source == "timedatectl"
        assert "not synchronized" in status.warning

    def test_timedatectl_missing_field(self):
        output = "Timezone=UTC\nLocalRTC=no\n"
        with patch("subprocess.run", return_value=self._timedatectl_result(output)):
            cia = ClockIntegrityAssertion()
            status = cia.assert_startup()
        assert status.source == "timedatectl"
        assert status.ntp_synchronized is None

    def test_timedatectl_nonzero_return_falls_through(self):
        with patch("subprocess.run", return_value=self._timedatectl_result("", returncode=1)):
            with patch.object(ClockIntegrityAssertion, "_check_adjtimex", return_value=None):
                cia = ClockIntegrityAssertion()
                status = cia.assert_startup()
        assert status.source == "unavailable"

    def test_timedatectl_not_found_falls_through(self):
        with patch("subprocess.run", side_effect=FileNotFoundError):
            with patch.object(ClockIntegrityAssertion, "_check_adjtimex", return_value=None):
                cia = ClockIntegrityAssertion()
                status = cia.assert_startup()
        assert status.source == "unavailable"

    def test_timedatectl_timeout_falls_through(self):
        with patch(
            "subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="timedatectl", timeout=3)
        ):
            with patch.object(ClockIntegrityAssertion, "_check_adjtimex", return_value=None):
                cia = ClockIntegrityAssertion()
                status = cia.assert_startup()
        assert status.source == "unavailable"


# ── assert_startup: adjtimex path ────────────────────────────────────────────


class TestAssertStartupAdjtimex:
    def _mock_adjtimex(self, ret_val: int) -> MagicMock:
        libc = MagicMock()
        libc.adjtimex.return_value = ret_val
        return libc

    def test_adjtimex_time_ok(self):
        with patch.object(ClockIntegrityAssertion, "_check_timedatectl", return_value=None):
            with patch("sys.platform", "linux"):
                with patch("ctypes.util.find_library", return_value="libc.so.6"):
                    with patch("ctypes.CDLL", return_value=self._mock_adjtimex(0)):
                        cia = ClockIntegrityAssertion()
                        status = cia.assert_startup()
        assert status.source == "adjtimex"
        assert status.ntp_synchronized is True

    def test_adjtimex_time_error(self):
        with patch.object(ClockIntegrityAssertion, "_check_timedatectl", return_value=None):
            with patch("sys.platform", "linux"):
                with patch("ctypes.util.find_library", return_value="libc.so.6"):
                    with patch("ctypes.CDLL", return_value=self._mock_adjtimex(5)):
                        cia = ClockIntegrityAssertion()
                        status = cia.assert_startup()
        assert status.source == "adjtimex"
        assert status.ntp_synchronized is False
        assert "TIME_ERROR" in status.warning

    def test_adjtimex_leap_second_insert_synced(self):
        with patch.object(ClockIntegrityAssertion, "_check_timedatectl", return_value=None):
            with patch("sys.platform", "linux"):
                with patch("ctypes.util.find_library", return_value="libc.so.6"):
                    with patch("ctypes.CDLL", return_value=self._mock_adjtimex(1)):
                        cia = ClockIntegrityAssertion()
                        status = cia.assert_startup()
        assert status.ntp_synchronized is True


# ── assert_startup: unavailable fallback ──────────────────────────────────────


class TestAssertStartupUnavailable:
    def test_both_probes_fail_returns_unavailable(self):
        with patch.object(ClockIntegrityAssertion, "_check_timedatectl", return_value=None):
            with patch.object(ClockIntegrityAssertion, "_check_adjtimex", return_value=None):
                status = ClockIntegrityAssertion().assert_startup()
        assert status.source == "unavailable"
        assert status.ntp_synchronized is None
        assert status.warning != ""

    def test_unavailable_warning_mentions_both(self):
        with patch.object(ClockIntegrityAssertion, "_check_timedatectl", return_value=None):
            with patch.object(ClockIntegrityAssertion, "_check_adjtimex", return_value=None):
                status = ClockIntegrityAssertion().assert_startup()
        assert "timedatectl" in status.warning
        assert "adjtimex" in status.warning


# ── Integration scenarios ─────────────────────────────────────────────────────


class TestIntegration:
    def test_per_node_drift_across_multiple_nodes(self):
        cia = ClockIntegrityAssertion(max_drift_seconds=2.0)
        base = 1_700_000_000.0
        results = [
            cia.check_node_drift(node_timestamp=base + i * 0.5, reference_time=base + 1.0)
            for i in range(6)
        ]
        within = [r.within_tolerance for r in results]
        # Timestamps at base, base+0.5, base+1.0 are within 2s of base+1.0
        # base+1.5 → drift=0.5; base+2.0 → drift=1.0; base+2.5 → drift=1.5 — all within
        assert all(within)

    def test_startup_then_node_check(self):
        output = "NTPSynchronized=yes\n"
        with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=output)):
            cia = ClockIntegrityAssertion(max_drift_seconds=5.0)
            startup = cia.assert_startup()
        assert startup.ntp_synchronized is True
        drift = cia.check_node_drift(
            node_timestamp=startup.reference_time + 0.1,
            reference_time=startup.reference_time + 0.2,
        )
        assert drift.within_tolerance is True

    def test_startup_result_to_dict_serializable(self):
        output = "NTPSynchronized=yes\n"
        with patch("subprocess.run", return_value=MagicMock(returncode=0, stdout=output)):
            status = ClockIntegrityAssertion().assert_startup()
        d = status.to_dict()
        import json

        json.dumps(d)  # must be JSON-serializable

    def test_drift_result_to_dict_serializable(self):
        r = ClockIntegrityAssertion().check_node_drift(node_timestamp=1000.0, reference_time=1001.5)
        import json

        json.dumps(r.to_dict())
