# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Extended seccomp_guard tests — non-sandbox (libseccomp) paths."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import aegis.core.seccomp_guard as _sg_mod
from aegis.core.seccomp_guard import SeccompGuard

# ── _detect_sandbox — return False (line 120) ─────────────────────────────────


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


# ── _load_libseccomp — already loaded (line 126) ─────────────────────────────


def test_load_libseccomp_returns_true_when_already_loaded():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False

    original = _sg_mod._libseccomp_loaded
    try:
        _sg_mod._libseccomp_loaded = True
        result = guard._load_libseccomp()
    finally:
        _sg_mod._libseccomp_loaded = original

    assert result is True


# ── _load_libseccomp — non-sandbox, library not found ────────────────────────


def test_load_libseccomp_library_not_found():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False

    import ctypes.util as _ctu

    original_loaded = _sg_mod._libseccomp_loaded
    try:
        _sg_mod._libseccomp_loaded = False
        with patch.object(_ctu, "find_library", return_value=None):
            result = guard._load_libseccomp()
    finally:
        _sg_mod._libseccomp_loaded = original_loaded

    assert result is False


# ── _load_libseccomp — non-sandbox, ctypes CDLL exception ────────────────────


def test_load_libseccomp_cdll_exception():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False

    import ctypes.util as _ctu

    original_loaded = _sg_mod._libseccomp_loaded
    original_lib = _sg_mod._libseccomp
    try:
        _sg_mod._libseccomp_loaded = False
        with (
            patch.object(_ctu, "find_library", return_value="/lib/libseccomp.so"),
            patch("ctypes.CDLL", side_effect=OSError("cannot load")),
        ):
            result = guard._load_libseccomp()
    finally:
        _sg_mod._libseccomp_loaded = original_loaded
        _sg_mod._libseccomp = original_lib

    assert result is False


# ── _load_libseccomp — non-sandbox, success path (lines 132-162) ─────────────


def test_load_libseccomp_success_sets_global():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False

    mock_lib = MagicMock()
    import ctypes.util as _ctu

    original_loaded = _sg_mod._libseccomp_loaded
    original_lib = _sg_mod._libseccomp
    try:
        _sg_mod._libseccomp_loaded = False
        _sg_mod._libseccomp = None
        with (
            patch.object(_ctu, "find_library", return_value="/lib/libseccomp.so"),
            patch("ctypes.CDLL", return_value=mock_lib),
        ):
            result = guard._load_libseccomp()
    finally:
        _sg_mod._libseccomp_loaded = original_loaded
        _sg_mod._libseccomp = original_lib

    assert result is True


# ── apply_filter — non-sandbox, _load_libseccomp returns False (lines 173-176)


def test_apply_filter_non_sandbox_no_libseccomp():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False
    guard._is_enforced = False
    guard._degraded_mode = False

    with patch.object(guard, "_load_libseccomp", return_value=False):
        result = guard.apply_filter()

    assert result is False
    assert guard._degraded_mode is True
    assert guard._is_enforced is False


# ── apply_filter — non-sandbox, full path mocked (lines 178-210) ─────────────


def test_apply_filter_non_sandbox_libc_not_found():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False
    guard._is_enforced = False
    guard._degraded_mode = False

    mock_lib = MagicMock()
    import ctypes.util as _ctu

    with (
        patch.object(guard, "_load_libseccomp", return_value=True),
        patch.object(_ctu, "find_library", return_value=None),
    ):
        result = guard.apply_filter()

    assert result is False
    assert guard._degraded_mode is True


def test_apply_filter_non_sandbox_prctl_fails():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False
    guard._is_enforced = False
    guard._degraded_mode = False

    mock_libc = MagicMock()
    mock_libc.prctl.return_value = -1  # failure

    mock_libseccomp = MagicMock()
    _sg_mod._libseccomp = mock_libseccomp

    import ctypes.util as _ctu

    try:
        with (
            patch.object(guard, "_load_libseccomp", return_value=True),
            patch.object(_ctu, "find_library", return_value="/lib/libc.so"),
            patch("ctypes.CDLL", return_value=mock_libc),
        ):
            result = guard.apply_filter()
    finally:
        _sg_mod._libseccomp = None

    assert result is False
    assert guard._degraded_mode is True


def test_apply_filter_non_sandbox_success():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False
    guard._is_enforced = False
    guard._degraded_mode = False
    guard.profile = SeccompGuard.DEFAULT_PROFILE

    mock_libc = MagicMock()
    mock_libc.prctl.return_value = 0  # success

    mock_seccomp = MagicMock()
    mock_seccomp.seccomp_init.return_value = 1  # non-null ctx
    mock_seccomp.seccomp_syscall_resolve_name.return_value = 1  # valid nr
    mock_seccomp.seccomp_load.return_value = 0  # success

    _sg_mod._libseccomp = mock_seccomp

    import ctypes.util as _ctu

    try:
        with (
            patch.object(guard, "_load_libseccomp", return_value=True),
            patch.object(_ctu, "find_library", return_value="/lib/libc.so"),
            patch("ctypes.CDLL", return_value=mock_libc),
        ):
            result = guard.apply_filter()
    finally:
        _sg_mod._libseccomp = None

    assert result is True
    assert guard._is_enforced is True


def test_apply_filter_non_sandbox_seccomp_load_fails():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False
    guard._is_enforced = False
    guard._degraded_mode = False
    guard.profile = SeccompGuard.DEFAULT_PROFILE

    mock_libc = MagicMock()
    mock_libc.prctl.return_value = 0

    mock_seccomp = MagicMock()
    mock_seccomp.seccomp_init.return_value = 1
    mock_seccomp.seccomp_syscall_resolve_name.return_value = 1
    mock_seccomp.seccomp_load.return_value = -1  # failure

    _sg_mod._libseccomp = mock_seccomp

    import ctypes.util as _ctu

    try:
        with (
            patch.object(guard, "_load_libseccomp", return_value=True),
            patch.object(_ctu, "find_library", return_value="/lib/libc.so"),
            patch("ctypes.CDLL", return_value=mock_libc),
        ):
            result = guard.apply_filter()
    finally:
        _sg_mod._libseccomp = None

    assert result is False
    assert guard._degraded_mode is True


def test_apply_filter_non_sandbox_null_ctx():
    guard = SeccompGuard.__new__(SeccompGuard)
    guard._is_sandbox = False
    guard._is_enforced = False
    guard._degraded_mode = False
    guard.profile = SeccompGuard.DEFAULT_PROFILE

    mock_libc = MagicMock()
    mock_libc.prctl.return_value = 0

    mock_seccomp = MagicMock()
    mock_seccomp.seccomp_init.return_value = None  # null ctx

    _sg_mod._libseccomp = mock_seccomp

    import ctypes.util as _ctu

    try:
        with (
            patch.object(guard, "_load_libseccomp", return_value=True),
            patch.object(_ctu, "find_library", return_value="/lib/libc.so"),
            patch("ctypes.CDLL", return_value=mock_libc),
        ):
            result = guard.apply_filter()
    finally:
        _sg_mod._libseccomp = None

    assert result is False
    assert guard._degraded_mode is True
