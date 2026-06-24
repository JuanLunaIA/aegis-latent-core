# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Extended seccomp_guard tests — non-sandbox apply_filter paths.

SeccompGuard.apply_filter() now delegates ctypes work to
aegis.core.sandbox_l1.SeccompSandbox.  Tests here patch SeccompSandbox and
the prctl/libc path rather than the removed _libseccomp/_libseccomp_loaded
module globals.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from aegis.core.seccomp_guard import SeccompGuard

# ── _detect_sandbox — return False ────────────────────────────────────────────


def test_detect_sandbox_returns_false_when_no_markers():
    import importlib.util as _ilu

    guard = SeccompGuard.__new__(SeccompGuard)
    with (
        patch.dict("os.environ", {}, clear=True),
        patch("os.path.exists", return_value=False),
        patch.object(_ilu, "find_spec", return_value=None),
    ):
        result = guard._detect_sandbox()
    assert result is False


def test_detect_sandbox_importerror_path():
    guard = SeccompGuard.__new__(SeccompGuard)
    with patch.dict("os.environ", {}, clear=True), patch("os.path.exists", return_value=False):
        import builtins

        _real_import = builtins.__import__

        def _fake_import(name, *args, **kwargs):
            if name == "importlib.util":
                raise ImportError("no importlib")
            return _real_import(name, *args, **kwargs)

        with patch("builtins.__import__", side_effect=_fake_import):
            result = guard._detect_sandbox()
    assert isinstance(result, bool)


# ── apply_filter — non-sandbox, libc not found ───────────────────────────────


def test_apply_filter_non_sandbox_libc_not_found():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False
    guard._is_enforced = False
    guard._degraded_mode = False
    guard.profile = SeccompGuard.DEFAULT_PROFILE

    import ctypes.util as _ctu

    with patch.object(_ctu, "find_library", return_value=None):
        result = guard.apply_filter()

    assert result is False
    assert guard._degraded_mode is True


# ── apply_filter — non-sandbox, prctl fails ──────────────────────────────────


def test_apply_filter_non_sandbox_prctl_fails():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False
    guard._is_enforced = False
    guard._degraded_mode = False
    guard.profile = SeccompGuard.DEFAULT_PROFILE

    mock_libc = MagicMock()
    mock_libc.prctl.return_value = -1

    import ctypes.util as _ctu

    with (
        patch.object(_ctu, "find_library", return_value="/lib/libc.so"),
        patch("ctypes.CDLL", return_value=mock_libc),
    ):
        result = guard.apply_filter()

    assert result is False
    assert guard._degraded_mode is True


# ── apply_filter — non-sandbox, SeccompSandbox unavailable ───────────────────


def test_apply_filter_non_sandbox_libseccomp_unavailable():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False
    guard._is_enforced = False
    guard._degraded_mode = False
    guard.profile = SeccompGuard.DEFAULT_PROFILE

    mock_libc = MagicMock()
    mock_libc.prctl.return_value = 0

    mock_sb = MagicMock()
    mock_sb.enabled = False  # libseccomp not available

    import ctypes.util as _ctu

    with (
        patch.object(_ctu, "find_library", return_value="/lib/libc.so"),
        patch("ctypes.CDLL", return_value=mock_libc),
        patch("aegis.core.sandbox_l1.SeccompSandbox", return_value=mock_sb),
    ):
        result = guard.apply_filter()

    assert result is False
    assert guard._degraded_mode is True
    assert guard._is_enforced is False


# ── apply_filter — non-sandbox, full success path ────────────────────────────


def test_apply_filter_non_sandbox_success():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False
    guard._is_enforced = False
    guard._degraded_mode = False
    guard.profile = SeccompGuard.DEFAULT_PROFILE

    mock_libc = MagicMock()
    mock_libc.prctl.return_value = 0

    mock_sb = MagicMock()
    mock_sb.enabled = True
    mock_sb.apply_filter.return_value = True

    import ctypes.util as _ctu

    with (
        patch.object(_ctu, "find_library", return_value="/lib/libc.so"),
        patch("ctypes.CDLL", return_value=mock_libc),
        patch("aegis.core.sandbox_l1.SeccompSandbox", return_value=mock_sb),
    ):
        result = guard.apply_filter()

    assert result is True
    assert guard._is_enforced is True
    mock_sb.apply_filter.assert_called_once()


# ── apply_filter — non-sandbox, SeccompSandbox.apply_filter returns False ────


def test_apply_filter_non_sandbox_filter_load_fails():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False
    guard._is_enforced = False
    guard._degraded_mode = False
    guard.profile = SeccompGuard.DEFAULT_PROFILE

    mock_libc = MagicMock()
    mock_libc.prctl.return_value = 0

    mock_sb = MagicMock()
    mock_sb.enabled = True
    mock_sb.apply_filter.return_value = False  # load failed

    import ctypes.util as _ctu

    with (
        patch.object(_ctu, "find_library", return_value="/lib/libc.so"),
        patch("ctypes.CDLL", return_value=mock_libc),
        patch("aegis.core.sandbox_l1.SeccompSandbox", return_value=mock_sb),
    ):
        result = guard.apply_filter()

    assert result is False
    assert guard._degraded_mode is True
    assert guard._is_enforced is False


# ── apply_filter — non-sandbox, SeccompSandbox constructed with KILL action ──


def test_apply_filter_passes_kill_action_to_sandbox():
    """SeccompGuard must request SCMP_ACT_KILL (0x0) as the default action."""
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False
    guard._is_enforced = False
    guard._degraded_mode = False
    guard.profile = SeccompGuard.DEFAULT_PROFILE

    mock_libc = MagicMock()
    mock_libc.prctl.return_value = 0

    mock_sb = MagicMock()
    mock_sb.enabled = True
    mock_sb.apply_filter.return_value = True

    import ctypes.util as _ctu

    constructor_kwargs: dict = {}

    def _capture_sb(*args, **kwargs):
        constructor_kwargs.update(kwargs)
        return mock_sb

    with (
        patch.object(_ctu, "find_library", return_value="/lib/libc.so"),
        patch("ctypes.CDLL", return_value=mock_libc),
        patch("aegis.core.sandbox_l1.SeccompSandbox", side_effect=_capture_sb),
    ):
        guard.apply_filter()

    assert constructor_kwargs.get("default_action") == 0x00000000  # SCMP_ACT_KILL


# ── apply_filter — non-sandbox, syscall list passed to SeccompSandbox ─────────


def test_apply_filter_passes_profile_syscalls_to_sandbox():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False
    guard._is_enforced = False
    guard._degraded_mode = False
    guard.profile = SeccompGuard.DEFAULT_PROFILE

    mock_libc = MagicMock()
    mock_libc.prctl.return_value = 0

    mock_sb = MagicMock()
    mock_sb.enabled = True
    mock_sb.apply_filter.return_value = True

    import ctypes.util as _ctu

    captured_syscalls: list = []

    def _capture_sb(*args, **kwargs):
        captured_syscalls.extend(kwargs.get("allowed_syscalls", ()))
        return mock_sb

    with (
        patch.object(_ctu, "find_library", return_value="/lib/libc.so"),
        patch("ctypes.CDLL", return_value=mock_libc),
        patch("aegis.core.sandbox_l1.SeccompSandbox", side_effect=_capture_sb),
    ):
        guard.apply_filter()

    assert "read" in captured_syscalls
    assert "write" in captured_syscalls
    assert "getrandom" in captured_syscalls  # Tokio-specific entry
