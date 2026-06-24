# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.fuzzing_harness — AegisFuzzingEngine."""

from __future__ import annotations

from subprocess import CompletedProcess
from unittest.mock import MagicMock, patch

import pytest

from aegis.core.fuzzing_harness import AegisFuzzingEngine, FuzzTarget


class TestAegisFuzzingEngineInit:
    def test_has_three_targets(self):
        engine = AegisFuzzingEngine()
        assert len(engine.targets) == 3

    def test_target_names(self):
        engine = AegisFuzzingEngine()
        names = {t.name for t in engine.targets}
        assert names == {"ledger_commit", "mmr_append", "pqc_sign_verify"}

    def test_default_status_not_run(self):
        engine = AegisFuzzingEngine()
        for t in engine.targets:
            assert t.last_run_status == "NOT_RUN"


class TestRunTargetUnknown:
    def test_unknown_target_returns_false(self):
        engine = AegisFuzzingEngine()
        result = engine.run_target("does_not_exist")
        assert result is False

    def test_unknown_target_does_not_touch_statuses(self):
        engine = AegisFuzzingEngine()
        engine.run_target("nonexistent")
        for t in engine.targets:
            assert t.last_run_status == "NOT_RUN"


class TestRunTargetCargoAbsent:
    def test_returns_false_when_cargo_missing(self):
        engine = AegisFuzzingEngine()
        with patch("aegis.core.fuzzing_harness.shutil.which", return_value=None):
            result = engine.run_target("ledger_commit")
        assert result is False

    def test_status_unavailable_when_cargo_missing(self):
        engine = AegisFuzzingEngine()
        with patch("aegis.core.fuzzing_harness.shutil.which", return_value=None):
            engine.run_target("ledger_commit")
        target = next(t for t in engine.targets if t.name == "ledger_commit")
        assert target.last_run_status == "UNAVAILABLE"

    def test_file_not_found_from_subprocess_sets_unavailable(self):
        engine = AegisFuzzingEngine()
        with (
            patch("aegis.core.fuzzing_harness.shutil.which", return_value="/usr/bin/cargo"),
            patch(
                "aegis.core.fuzzing_harness.subprocess.run",
                side_effect=FileNotFoundError("cargo fuzz not found"),
            ),
        ):
            result = engine.run_target("ledger_commit")
        assert result is False
        target = next(t for t in engine.targets if t.name == "ledger_commit")
        assert target.last_run_status == "UNAVAILABLE"


class TestRunTargetCleanRun:
    def _make_completed(self, returncode: int) -> CompletedProcess:
        cp = MagicMock(spec=CompletedProcess)
        cp.returncode = returncode
        cp.stdout = ""
        cp.stderr = ""
        return cp

    def test_clean_run_returns_true(self):
        engine = AegisFuzzingEngine()
        with (
            patch("aegis.core.fuzzing_harness.shutil.which", return_value="/usr/bin/cargo"),
            patch(
                "aegis.core.fuzzing_harness.subprocess.run",
                return_value=self._make_completed(0),
            ),
        ):
            result = engine.run_target("mmr_append")
        assert result is True

    def test_clean_run_sets_clean_status(self):
        engine = AegisFuzzingEngine()
        with (
            patch("aegis.core.fuzzing_harness.shutil.which", return_value="/usr/bin/cargo"),
            patch(
                "aegis.core.fuzzing_harness.subprocess.run",
                return_value=self._make_completed(0),
            ),
        ):
            engine.run_target("mmr_append")
        target = next(t for t in engine.targets if t.name == "mmr_append")
        assert target.last_run_status == "CLEAN"

    def test_crash_returncode_sets_crash_found(self):
        engine = AegisFuzzingEngine()
        with (
            patch("aegis.core.fuzzing_harness.shutil.which", return_value="/usr/bin/cargo"),
            patch(
                "aegis.core.fuzzing_harness.subprocess.run",
                return_value=self._make_completed(77),
            ),
        ):
            result = engine.run_target("pqc_sign_verify")
        assert result is True
        target = next(t for t in engine.targets if t.name == "pqc_sign_verify")
        assert target.last_run_status == "CRASH_FOUND"

    def test_subprocess_called_with_cargo_fuzz(self):
        engine = AegisFuzzingEngine()
        captured: list = []

        def fake_run(cmd, **kwargs):
            captured.append(cmd)
            return self._make_completed(0)

        with (
            patch("aegis.core.fuzzing_harness.shutil.which", return_value="/usr/bin/cargo"),
            patch("aegis.core.fuzzing_harness.subprocess.run", side_effect=fake_run),
        ):
            engine.run_target("ledger_commit", duration_seconds=60)

        assert captured, "subprocess.run was not called"
        cmd = captured[0]
        assert cmd[0] == "cargo"
        assert cmd[1] == "fuzz"
        assert cmd[2] == "run"
        assert cmd[3] == "ledger_commit"

    def test_duration_passed_as_flag(self):
        engine = AegisFuzzingEngine()
        captured: list = []

        def fake_run(cmd, **kwargs):
            captured.append(cmd)
            return self._make_completed(0)

        with (
            patch("aegis.core.fuzzing_harness.shutil.which", return_value="/usr/bin/cargo"),
            patch("aegis.core.fuzzing_harness.subprocess.run", side_effect=fake_run),
        ):
            engine.run_target("ledger_commit", duration_seconds=120)

        cmd = captured[0]
        assert "-max_total_time=120" in cmd

    def test_unexpected_exception_returns_false(self):
        engine = AegisFuzzingEngine()
        with (
            patch("aegis.core.fuzzing_harness.shutil.which", return_value="/usr/bin/cargo"),
            patch(
                "aegis.core.fuzzing_harness.subprocess.run",
                side_effect=OSError("unexpected"),
            ),
        ):
            result = engine.run_target("ledger_commit")
        assert result is False


class TestGetCoverageReport:
    def test_returns_dict(self):
        engine = AegisFuzzingEngine()
        report = engine.get_coverage_report()
        assert isinstance(report, dict)

    def test_has_status_key(self):
        engine = AegisFuzzingEngine()
        report = engine.get_coverage_report()
        assert "status" in report
