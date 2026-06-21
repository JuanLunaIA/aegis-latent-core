# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for prctl-based process hardening (aegis.core.process_hardening)."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

from aegis.core.process_hardening import (
    ProcessHardening,
    ProcessHardeningResult,
    apply_process_hardening,
    verify_process_hardening,
)

# ── ProcessHardeningResult ────────────────────────────────────────────────────


class TestProcessHardeningResult:
    def test_defaults_all_false(self):
        r = ProcessHardeningResult()
        assert r.no_new_privs_applied is False
        assert r.dumpable_disabled is False
        assert r.errors == []

    def test_fully_hardened_when_both_true(self):
        r = ProcessHardeningResult(no_new_privs_applied=True, dumpable_disabled=True)
        assert r.fully_hardened is True

    def test_fully_hardened_false_when_one_missing(self):
        assert not ProcessHardeningResult(no_new_privs_applied=True).fully_hardened
        assert not ProcessHardeningResult(dumpable_disabled=True).fully_hardened

    def test_to_dict_structure(self):
        r = ProcessHardeningResult(
            no_new_privs_applied=True,
            dumpable_disabled=True,
            platform="linux",
            errors=[],
        )
        d = r.to_dict()
        assert d["no_new_privs_applied"] is True
        assert d["dumpable_disabled"] is True
        assert d["fully_hardened"] is True
        assert d["platform"] == "linux"
        assert d["errors"] == []

    def test_to_dict_with_errors(self):
        r = ProcessHardeningResult(errors=["prctl failed"])
        d = r.to_dict()
        assert "prctl failed" in d["errors"]

    def test_platform_recorded(self):
        r = ProcessHardeningResult(platform="linux")
        assert r.platform == "linux"


# ── Non-Linux platform ────────────────────────────────────────────────────────


class TestNonLinuxPlatform:
    def test_non_linux_returns_without_applying(self):
        with patch.object(sys, "platform", "darwin"):
            r = ProcessHardening().apply()
        assert r.no_new_privs_applied is False
        assert r.dumpable_disabled is False
        assert r.errors == []
        assert r.platform == "darwin"

    def test_windows_platform_skips(self):
        with patch.object(sys, "platform", "win32"):
            r = ProcessHardening().apply()
        assert not r.fully_hardened

    def test_non_linux_verify_returns_empty(self):
        with patch.object(sys, "platform", "darwin"):
            out = ProcessHardening().verify()
        assert out == {}


# ── Linux with successful prctl calls ────────────────────────────────────────


class TestLinuxSuccess:
    def _make_libc(self, return_value: int = 0) -> MagicMock:
        libc = MagicMock()
        libc.prctl.return_value = return_value
        return libc

    def test_apply_sets_both_flags_on_linux(self):
        with patch.object(sys, "platform", "linux"):
            with patch.object(ProcessHardening, "_load_libc", return_value=self._make_libc(0)):
                r = ProcessHardening().apply()
        assert r.no_new_privs_applied is True
        assert r.dumpable_disabled is True
        assert r.fully_hardened is True
        assert r.errors == []

    def test_apply_calls_no_new_privs_prctl(self):
        libc = self._make_libc(0)
        with patch.object(sys, "platform", "linux"):
            with patch.object(ProcessHardening, "_load_libc", return_value=libc):
                ProcessHardening().apply()
        calls = libc.prctl.call_args_list
        # First call should be PR_SET_NO_NEW_PRIVS=38 with value=1
        assert calls[0][0][0] == 38
        assert calls[0][0][1] == 1

    def test_apply_calls_set_dumpable_prctl(self):
        libc = self._make_libc(0)
        with patch.object(sys, "platform", "linux"):
            with patch.object(ProcessHardening, "_load_libc", return_value=libc):
                ProcessHardening().apply()
        calls = libc.prctl.call_args_list
        # Second call should be PR_SET_DUMPABLE=4 with value=0
        assert calls[1][0][0] == 4
        assert calls[1][0][1] == 0

    def test_apply_records_linux_platform(self):
        with patch.object(sys, "platform", "linux"):
            with patch.object(ProcessHardening, "_load_libc", return_value=self._make_libc(0)):
                r = ProcessHardening().apply()
        assert r.platform == "linux"


# ── libc load failure ─────────────────────────────────────────────────────────


class TestLibcLoadFailure:
    def test_missing_libc_returns_errors(self):
        with patch.object(sys, "platform", "linux"):
            with patch.object(ProcessHardening, "_load_libc", return_value=None):
                r = ProcessHardening().apply()
        assert not r.fully_hardened
        assert len(r.errors) > 0

    def test_missing_libc_both_flags_false(self):
        with patch.object(sys, "platform", "linux"):
            with patch.object(ProcessHardening, "_load_libc", return_value=None):
                r = ProcessHardening().apply()
        assert r.no_new_privs_applied is False
        assert r.dumpable_disabled is False


# ── prctl call failures ───────────────────────────────────────────────────────


class TestPrctlFailures:
    def test_no_new_privs_failure_recorded(self):
        libc = MagicMock()
        libc.prctl.side_effect = [1, 0]  # first call fails, second succeeds
        with patch.object(sys, "platform", "linux"):
            with patch.object(ProcessHardening, "_load_libc", return_value=libc):
                r = ProcessHardening().apply()
        assert r.no_new_privs_applied is False
        assert len(r.errors) >= 1

    def test_dumpable_failure_recorded(self):
        libc = MagicMock()
        libc.prctl.side_effect = [0, 1]  # first succeeds, second fails
        with patch.object(sys, "platform", "linux"):
            with patch.object(ProcessHardening, "_load_libc", return_value=libc):
                r = ProcessHardening().apply()
        assert r.dumpable_disabled is False
        assert len(r.errors) >= 1

    def test_exception_in_prctl_recorded(self):
        libc = MagicMock()
        libc.prctl.side_effect = OSError("mock error")
        with patch.object(sys, "platform", "linux"):
            with patch.object(ProcessHardening, "_load_libc", return_value=libc):
                r = ProcessHardening().apply()
        assert not r.fully_hardened
        assert any("exception" in e.lower() for e in r.errors)

    def test_both_failures_both_errors_recorded(self):
        libc = MagicMock()
        libc.prctl.return_value = 1  # always fail
        with patch.object(sys, "platform", "linux"):
            with patch.object(ProcessHardening, "_load_libc", return_value=libc):
                r = ProcessHardening().apply()
        assert not r.no_new_privs_applied
        assert not r.dumpable_disabled
        assert len(r.errors) == 2


# ── idempotency ───────────────────────────────────────────────────────────────


class TestIdempotency:
    def test_apply_twice_does_not_raise(self):
        libc = MagicMock()
        libc.prctl.return_value = 0
        with patch.object(sys, "platform", "linux"):
            with patch.object(ProcessHardening, "_load_libc", return_value=libc):
                h = ProcessHardening()
                r1 = h.apply()
                r2 = h.apply()
        assert r1.fully_hardened
        assert r2.fully_hardened


# ── verify() method ───────────────────────────────────────────────────────────


class TestVerify:
    def test_verify_on_linux_reads_proc(self):
        proc_status = (
            "Name:\tpython3\n"
            "NoNewPrivs:\t1\n"
            "CoreDumping:\t0\n"
        )
        import io
        with patch.object(sys, "platform", "linux"):
            with patch("builtins.open", return_value=io.StringIO(proc_status)):
                out = ProcessHardening().verify()
        assert out.get("no_new_privs") == 1
        assert out.get("core_dumping") == 0

    def test_verify_non_linux_returns_empty(self):
        with patch.object(sys, "platform", "darwin"):
            out = ProcessHardening().verify()
        assert out == {}

    def test_verify_handles_missing_proc(self):
        with patch.object(sys, "platform", "linux"):
            with patch("builtins.open", side_effect=OSError("no proc")):
                out = ProcessHardening().verify()
        assert isinstance(out, dict)


# ── module-level helpers ──────────────────────────────────────────────────────


class TestModuleLevelHelpers:
    def test_apply_process_hardening_returns_result(self):
        with patch.object(sys, "platform", "linux"):
            with patch.object(ProcessHardening, "_load_libc", return_value=MagicMock(prctl=MagicMock(return_value=0))):
                r = apply_process_hardening()
        assert isinstance(r, ProcessHardeningResult)

    def test_verify_process_hardening_returns_dict(self):
        with patch.object(sys, "platform", "darwin"):
            out = verify_process_hardening()
        assert isinstance(out, dict)


# ── Integration: full Linux apply + to_dict ───────────────────────────────────


class TestIntegration:
    def test_full_apply_to_dict_round_trip(self):
        libc = MagicMock()
        libc.prctl.return_value = 0
        with patch.object(sys, "platform", "linux"):
            with patch.object(ProcessHardening, "_load_libc", return_value=libc):
                r = ProcessHardening().apply()
        d = r.to_dict()
        assert d["fully_hardened"] is True
        assert d["errors"] == []
        assert d["platform"] == "linux"

    def test_partial_hardening_dict_shows_partial(self):
        libc = MagicMock()
        libc.prctl.side_effect = [0, 1]  # no_new_privs ok, dumpable fails
        with patch.object(sys, "platform", "linux"):
            with patch.object(ProcessHardening, "_load_libc", return_value=libc):
                r = ProcessHardening().apply()
        d = r.to_dict()
        assert d["fully_hardened"] is False
        assert d["no_new_privs_applied"] is True
        assert d["dumpable_disabled"] is False
