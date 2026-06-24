# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.core.sandbox_l1 — real libseccomp syscall filtering.

Verifies that SeccompSandbox uses the real libseccomp C API: syscall names
resolved via seccomp_syscall_resolve_name, rules added via seccomp_rule_add,
and the filter loadable into a kernel.  apply_filter() is tested in a
subprocess so the test runner's process is never constrained.
"""

from __future__ import annotations

import subprocess
import sys
from unittest.mock import MagicMock, patch

from aegis.core.sandbox_l1 import (
    _ALLOWED_SYSCALLS,
    SeccompSandbox,
    _load_libseccomp,
    sandbox_l1,
)

# ── _load_libseccomp ──────────────────────────────────────────────────────────


class TestLoadLibseccomp:
    def test_returns_cdll_when_available(self):
        lib = _load_libseccomp()
        assert lib is not None

    def test_sets_function_prototypes(self):
        import ctypes

        lib = _load_libseccomp()
        assert lib is not None
        assert lib.seccomp_init.restype == ctypes.c_void_p
        assert lib.seccomp_load.restype == ctypes.c_int

    def test_returns_none_when_absent(self):
        with patch("ctypes.CDLL", side_effect=OSError("not found")):
            assert _load_libseccomp() is None


# ── SeccompSandbox (with libseccomp available) ────────────────────────────────


class TestSeccompSandboxEnabled:
    def test_enabled_when_libseccomp_present(self):
        sb = SeccompSandbox()
        assert sb.enabled is True

    def test_build_filter_without_loading_returns_true(self):
        sb = SeccompSandbox()
        assert sb.build_filter_without_loading() is True

    def test_module_singleton_is_enabled(self):
        assert sandbox_l1.enabled is True

    def test_allowed_syscalls_not_empty(self):
        assert len(_ALLOWED_SYSCALLS) > 10

    def test_build_filter_resolves_core_syscalls(self):

        lib = _load_libseccomp()
        assert lib is not None
        for name in ("read", "write", "exit_group", "rt_sigaction"):
            nr = lib.seccomp_syscall_resolve_name(name.encode())
            assert nr >= 0, f"syscall '{name}' not resolved"

    def test_build_context_adds_rules(self):

        sb = SeccompSandbox()
        mock_lib = MagicMock()
        mock_lib.seccomp_init.return_value = 0xDEAD
        mock_lib.seccomp_syscall_resolve_name.return_value = 1
        mock_lib.seccomp_rule_add.return_value = 0
        sb._lib = mock_lib

        ctx = sb._build_context()

        assert ctx == 0xDEAD
        assert mock_lib.seccomp_rule_add.call_count == len(_ALLOWED_SYSCALLS)

    def test_build_context_skips_unresolved_syscalls(self):
        sb = SeccompSandbox()
        mock_lib = MagicMock()
        mock_lib.seccomp_init.return_value = 0xDEAD
        mock_lib.seccomp_syscall_resolve_name.return_value = -1  # all unresolved
        mock_lib.seccomp_rule_add.return_value = 0
        sb._lib = mock_lib

        ctx = sb._build_context()
        assert ctx == 0xDEAD
        mock_lib.seccomp_rule_add.assert_not_called()

    def test_build_context_returns_none_on_null_ctx(self):
        sb = SeccompSandbox()
        mock_lib = MagicMock()
        mock_lib.seccomp_init.return_value = None  # NULL
        sb._lib = mock_lib
        assert sb._build_context() is None

    def test_build_filter_without_loading_releases_context(self):
        sb = SeccompSandbox()
        mock_lib = MagicMock()
        mock_lib.seccomp_init.return_value = 0xCAFE
        mock_lib.seccomp_syscall_resolve_name.return_value = 1
        mock_lib.seccomp_rule_add.return_value = 0
        sb._lib = mock_lib
        sb.enabled = True

        result = sb.build_filter_without_loading()

        assert result is True
        mock_lib.seccomp_release.assert_called_once_with(0xCAFE)

    def test_apply_filter_returns_false_on_seccomp_load_failure(self):
        sb = SeccompSandbox()
        mock_lib = MagicMock()
        mock_lib.seccomp_init.return_value = 0xDEAD
        mock_lib.seccomp_syscall_resolve_name.return_value = 1
        mock_lib.seccomp_rule_add.return_value = 0
        mock_lib.seccomp_load.return_value = -1  # load failure
        sb._lib = mock_lib
        sb.enabled = True

        result = sb.apply_filter()
        assert result is False
        mock_lib.seccomp_release.assert_called_once_with(0xDEAD)

    def test_apply_filter_returns_true_on_success(self):
        sb = SeccompSandbox()
        mock_lib = MagicMock()
        mock_lib.seccomp_init.return_value = 0xDEAD
        mock_lib.seccomp_syscall_resolve_name.return_value = 1
        mock_lib.seccomp_rule_add.return_value = 0
        mock_lib.seccomp_load.return_value = 0  # success
        sb._lib = mock_lib
        sb.enabled = True

        result = sb.apply_filter()
        assert result is True
        mock_lib.seccomp_load.assert_called_once_with(0xDEAD)
        mock_lib.seccomp_release.assert_called_once_with(0xDEAD)


# ── SeccompSandbox (libseccomp absent) ───────────────────────────────────────


class TestSeccompSandboxDisabled:
    def test_disabled_when_libseccomp_absent(self):
        with patch("aegis.core.sandbox_l1._load_libseccomp", return_value=None):
            sb = SeccompSandbox()
        assert sb.enabled is False

    def test_build_filter_returns_false_when_disabled(self):
        with patch("aegis.core.sandbox_l1._load_libseccomp", return_value=None):
            sb = SeccompSandbox()
        assert sb.build_filter_without_loading() is False

    def test_apply_filter_returns_false_when_disabled(self):
        with patch("aegis.core.sandbox_l1._load_libseccomp", return_value=None):
            sb = SeccompSandbox()
        assert sb.apply_filter() is False


# ── apply_filter() in a subprocess (safe — does not constrain this process) ──


class TestApplyFilterSubprocess:
    def test_apply_filter_in_subprocess_succeeds(self):
        """Load the seccomp filter in an isolated subprocess; verify exit code 0."""
        code = (
            "from aegis.core.sandbox_l1 import SeccompSandbox; "
            "sb = SeccompSandbox(); "
            "assert sb.apply_filter() is True, 'apply_filter returned False'"
        )
        result = subprocess.run(  # noqa: S603
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result.returncode == 0, (
            f"subprocess failed:\nstdout: {result.stdout}\nstderr: {result.stderr}"
        )


# ── Custom allowed_syscalls and default_action parameters ─────────────────────


class TestSeccompSandboxCustomParams:
    def test_custom_allowed_syscalls_used_in_build_context(self):
        custom = ("read", "write", "exit_group")
        sb = SeccompSandbox(allowed_syscalls=custom)
        assert sb._allowed_syscalls == custom
        mock_lib = MagicMock()
        mock_lib.seccomp_init.return_value = 0xABCD
        mock_lib.seccomp_syscall_resolve_name.return_value = 1
        mock_lib.seccomp_rule_add.return_value = 0
        sb._lib = mock_lib

        sb._build_context()
        assert mock_lib.seccomp_rule_add.call_count == len(custom)

    def test_default_action_passed_to_seccomp_init(self):
        from aegis.core.sandbox_l1 import SCMP_ACT_KILL

        sb = SeccompSandbox(default_action=SCMP_ACT_KILL)
        assert sb._default_action == SCMP_ACT_KILL
        mock_lib = MagicMock()
        mock_lib.seccomp_init.return_value = 0xABCD
        mock_lib.seccomp_syscall_resolve_name.return_value = 1
        mock_lib.seccomp_rule_add.return_value = 0
        sb._lib = mock_lib

        sb._build_context()
        mock_lib.seccomp_init.assert_called_once_with(SCMP_ACT_KILL)

    def test_default_constructor_uses_module_allowlist(self):
        sb = SeccompSandbox()
        assert sb._allowed_syscalls is _ALLOWED_SYSCALLS

    def test_scmp_act_kill_constant_value(self):
        from aegis.core.sandbox_l1 import SCMP_ACT_KILL

        assert SCMP_ACT_KILL == 0x00000000

    def test_scmp_act_allow_constant_value(self):
        from aegis.core.sandbox_l1 import SCMP_ACT_ALLOW

        assert SCMP_ACT_ALLOW == 0x7FFF0000
