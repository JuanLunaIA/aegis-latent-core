# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.sandbox — SeccompFilter and LandlockManager."""

from __future__ import annotations

import subprocess
import sys
from unittest.mock import MagicMock, patch

from aegis.core.sandbox import LandlockManager, SandboxState, SeccompFilter


class TestSeccompFilterInit:
    def test_initial_state(self):
        sf = SeccompFilter([0, 1, 2])
        assert sf.current_allowed == {0, 1, 2}
        assert sf._phase == "INIT"
        assert sf._filter_applied is False

    def test_libc_loaded(self):
        sf = SeccompFilter([])
        assert sf._libc is not None


class TestSeccompFilterTransitionToPhase:
    def test_phase_update(self):
        sf = SeccompFilter([0, 1, 2, 3])
        sf.transition_to_phase("RUNNING", [0, 1])
        assert sf._phase == "RUNNING"
        assert sf.current_allowed == {0, 1}

    def test_narrowing_removes_syscalls(self):
        sf = SeccompFilter([0, 1, 2, 3, 4])
        sf.transition_to_phase("SHUTDOWN", [0])
        assert sf.current_allowed == {0}

    def test_no_simulation_marker_in_docstring(self):
        doc = SeccompFilter.transition_to_phase.__doc__ or ""
        assert "In a real" not in doc
        assert "Simulation" not in doc


class TestSeccompFilterApplyPrctl:
    """apply() calls prctl(PR_SET_NO_NEW_PRIVS) and delegates to SeccompSandbox."""

    def _make_sf(self):
        sf = SeccompFilter([0, 1, 2])
        sf._libc = MagicMock()
        sf._libc.prctl.return_value = 0
        return sf

    def test_prctl_called_with_correct_args(self):
        sf = self._make_sf()
        mock_sb = MagicMock()
        mock_sb.apply_filter.return_value = True
        with patch("aegis.core.sandbox.SeccompSandbox", return_value=mock_sb):
            sf.apply()
        sf._libc.prctl.assert_called_once_with(38, 1, 0, 0, 0)

    def test_apply_filter_delegated_to_sandbox_l1(self):
        sf = self._make_sf()
        mock_sb = MagicMock()
        mock_sb.apply_filter.return_value = True
        with patch("aegis.core.sandbox.SeccompSandbox", return_value=mock_sb):
            sf.apply()
        mock_sb.apply_filter.assert_called_once()
        assert sf._filter_applied is True

    def test_prctl_failure_raises_runtime_error(self):
        sf = self._make_sf()
        sf._libc.prctl.return_value = -1
        with patch("ctypes.get_errno", return_value=1):
            try:
                sf.apply()
            except RuntimeError as exc:
                assert "PR_SET_NO_NEW_PRIVS" in str(exc)
            else:
                raise AssertionError("expected RuntimeError")

    def test_libseccomp_unavailable_warns_but_does_not_raise(self, caplog):
        import logging

        sf = self._make_sf()
        mock_sb = MagicMock()
        mock_sb.apply_filter.return_value = False
        with patch("aegis.core.sandbox.SeccompSandbox", return_value=mock_sb):
            with caplog.at_level(logging.WARNING, logger="aegis.core.sandbox"):
                sf.apply()
        assert "libseccomp" in caplog.text
        assert sf._filter_applied is False

    def test_unexpected_exception_raises_runtime_error(self):
        sf = self._make_sf()
        sf._libc.prctl.side_effect = OSError("libc exploded")
        try:
            sf.apply()
        except RuntimeError as exc:
            assert "Security invariant violation" in str(exc)
        else:
            raise AssertionError("expected RuntimeError")


class TestSeccompFilterApplySubprocess:
    """Run apply() in a subprocess so the test process is unaffected."""

    def test_apply_in_subprocess_succeeds(self, tmp_path):
        script = tmp_path / "run_apply.py"
        # Include PYTHONPATH setup in the subprocess to ensure aegis module is found
        script.write_text(
            "import sys\n"
            "sys.path.insert(0, '/workspace')\n"
            "from unittest.mock import MagicMock, patch\n"
            "from aegis.core.sandbox import SeccompFilter\n"
            "sf = SeccompFilter([0, 1])\n"
            "sf._libc = MagicMock()\n"
            "sf._libc.prctl.return_value = 0\n"
            "mock_sb = MagicMock()\n"
            "mock_sb.apply_filter.return_value = True\n"
            "with patch('aegis.core.sandbox.SeccompSandbox', return_value=mock_sb):\n"
            "    sf.apply()\n"
            "assert sf._filter_applied is True\n"
        )
        result = subprocess.run(  # noqa: S603
            [sys.executable, str(script)],
            capture_output=True,
            text=True,
            timeout=15,
        )
        assert result.returncode == 0, result.stderr


class TestSandboxState:
    def test_dataclass_fields(self):
        state = SandboxState(
            phase="INIT",
            allowed_syscalls={0, 1, 2},
            fs_restrictions={"/tmp": "rw"},
        )
        assert state.phase == "INIT"
        assert 0 in state.allowed_syscalls
        assert state.fs_restrictions["/tmp"] == "rw"


class TestLandlockManager:
    def test_not_restricted_initially(self):
        lm = LandlockManager()
        assert lm.is_restricted is False

    def test_restrict_filesystem_sets_flag(self):
        lm = LandlockManager()
        lm.restrict_filesystem({"/etc/config": "ro"})
        assert lm.is_restricted is True

    def test_restrict_filesystem_logs_each_path(self, caplog):
        import logging

        lm = LandlockManager()
        with caplog.at_level(logging.INFO, logger="aegis.core.sandbox"):
            lm.restrict_filesystem({"/data": "rw", "/config": "ro"})
        assert "/data" in caplog.text
        assert "/config" in caplog.text

    def test_restrict_filesystem_warns_not_enforced(self, caplog):
        import logging

        lm = LandlockManager()
        with caplog.at_level(logging.WARNING, logger="aegis.core.sandbox"):
            lm.restrict_filesystem({"/tmp": "rw"})
        assert "NOT active" in caplog.text or "not yet wired" in caplog.text
