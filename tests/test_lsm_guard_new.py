# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.lsm_guard — LSM confinement verification."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from aegis.core.lsm_guard import LSMGuard

# ── _detect_sandbox ───────────────────────────────────────────────────────────


def test_detect_sandbox_no_markers(tmp_path):
    with patch("os.path.exists", return_value=False):
        guard = LSMGuard.__new__(LSMGuard)
        result = guard._detect_sandbox()
    assert result is False


def test_detect_sandbox_dockerenv_present():
    def _exists(path: str) -> bool:
        return path == "/.dockerenv"

    with patch("os.path.exists", side_effect=_exists):
        guard = LSMGuard.__new__(LSMGuard)
        result = guard._detect_sandbox()
    assert result is True


def test_detect_sandbox_hermes_marker_present():
    def _exists(path: str) -> bool:
        return path == "/.hermes_sandbox_marker"

    with patch("os.path.exists", side_effect=_exists):
        guard = LSMGuard.__new__(LSMGuard)
        result = guard._detect_sandbox()
    assert result is True


def test_is_sandbox_property_false():
    with (
        patch.object(LSMGuard, "_detect_sandbox", return_value=False),
        patch.object(LSMGuard, "verify_confinement", return_value=False),
    ):
        guard = LSMGuard()
    assert guard.is_sandbox is False


def test_is_sandbox_property_true():
    with (
        patch.object(LSMGuard, "_detect_sandbox", return_value=True),
        patch.object(LSMGuard, "verify_confinement", return_value=False),
    ):
        guard = LSMGuard()
    assert guard.is_sandbox is True


# ── _check_selinux ────────────────────────────────────────────────────────────


def test_check_selinux_enforcing():
    guard = LSMGuard.__new__(LSMGuard)
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "Enforcing\n"
    with patch("subprocess.run", return_value=mock_result):
        assert guard._check_selinux() is True


def test_check_selinux_permissive():
    guard = LSMGuard.__new__(LSMGuard)
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "Permissive\n"
    with patch("subprocess.run", return_value=mock_result):
        assert guard._check_selinux() is False


def test_check_selinux_disabled():
    guard = LSMGuard.__new__(LSMGuard)
    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "Disabled\n"
    with patch("subprocess.run", return_value=mock_result):
        assert guard._check_selinux() is False


def test_check_selinux_file_not_found():
    guard = LSMGuard.__new__(LSMGuard)
    with patch("subprocess.run", side_effect=FileNotFoundError("getenforce not found")):
        assert guard._check_selinux() is False


def test_check_selinux_nonzero_returncode():
    guard = LSMGuard.__new__(LSMGuard)
    mock_result = MagicMock()
    mock_result.returncode = 1
    mock_result.stdout = ""
    with patch("subprocess.run", return_value=mock_result):
        assert guard._check_selinux() is False


# ── _check_apparmor ───────────────────────────────────────────────────────────


def test_check_apparmor_module_present():
    guard = LSMGuard.__new__(LSMGuard)
    with patch("os.path.exists", return_value=True):
        assert guard._check_apparmor() is True


def test_check_apparmor_module_absent():
    guard = LSMGuard.__new__(LSMGuard)
    with patch("os.path.exists", return_value=False):
        assert guard._check_apparmor() is False


def test_check_apparmor_exception_returns_false():
    guard = LSMGuard.__new__(LSMGuard)
    with patch("os.path.exists", side_effect=OSError("permission denied")):
        assert guard._check_apparmor() is False


# ── strict enforcement ────────────────────────────────────────────────────────


def test_assert_enforcing_fails_when_unconfined():
    status = type(
        "Status",
        (),
        {
            "active": False,
            "mode": "unknown",
            "lsm_type": type("Type", (), {"value": "none"})(),
        },
    )()
    with patch.object(LSMGuard, "detect", staticmethod(lambda: status)):
        with pytest.raises(RuntimeError, match="LSM enforcement required"):
            LSMGuard.assert_enforcing()


# ── verify_confinement ────────────────────────────────────────────────────────


def test_verify_confinement_selinux_active():
    with (
        patch.object(LSMGuard, "_detect_sandbox", return_value=False),
        patch.object(LSMGuard, "_check_selinux", return_value=True),
        patch.object(LSMGuard, "_check_apparmor", return_value=False),
    ):
        guard = LSMGuard()
        # verify_confinement() was called in __init__; _is_confined is set
        assert guard._is_confined is True
        # Calling again within patch scope also returns True
        assert guard.verify_confinement() is True


def test_verify_confinement_apparmor_active():
    with (
        patch.object(LSMGuard, "_detect_sandbox", return_value=False),
        patch.object(LSMGuard, "_check_selinux", return_value=False),
        patch.object(LSMGuard, "_check_apparmor", return_value=True),
    ):
        guard = LSMGuard()
        assert guard._is_confined is True
        assert guard.verify_confinement() is True


def test_verify_confinement_no_lsm():
    with (
        patch.object(LSMGuard, "_detect_sandbox", return_value=False),
        patch.object(LSMGuard, "_check_selinux", return_value=False),
        patch.object(LSMGuard, "_check_apparmor", return_value=False),
    ):
        guard = LSMGuard()
        assert guard._is_confined is False
        assert guard.verify_confinement() is False


def test_verify_confinement_exception_returns_false():
    with (
        patch.object(LSMGuard, "_detect_sandbox", return_value=False),
        patch.object(LSMGuard, "_check_selinux", side_effect=Exception("kaboom")),
    ):
        guard = LSMGuard()
        assert guard._is_confined is False


# ── get_confinement_status ────────────────────────────────────────────────────


def test_get_confinement_status_confined():
    with (
        patch.object(LSMGuard, "_detect_sandbox", return_value=False),
        patch.object(LSMGuard, "_check_selinux", return_value=True),
        patch.object(LSMGuard, "_check_apparmor", return_value=False),
    ):
        guard = LSMGuard()
    assert guard.get_confinement_status() == "CONFINED"


def test_get_confinement_status_unconfined():
    with (
        patch.object(LSMGuard, "_detect_sandbox", return_value=False),
        patch.object(LSMGuard, "_check_selinux", return_value=False),
        patch.object(LSMGuard, "_check_apparmor", return_value=False),
    ):
        guard = LSMGuard()
    assert guard.get_confinement_status() == "UNCONFINED"
