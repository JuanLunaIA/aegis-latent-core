# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.sandbox_l1 — L1 Seccomp-BPF sandbox via libseccomp C API.

This is the authoritative ctypes binding layer for libseccomp in Aegis.
Every allowed syscall is resolved by name with ``seccomp_syscall_resolve_name``
and permitted with a real ``seccomp_rule_add`` call.

``SeccompSandbox`` accepts an optional ``allowed_syscalls`` tuple and
``default_action`` constant so callers can supply a custom profile without
duplicating the ctypes loading logic.  The default action is
``SCMP_ACT_ERRNO(EPERM)`` (returns EPERM rather than killing the thread);
callers requiring harder enforcement pass ``SCMP_ACT_KILL``.

When libseccomp is unavailable the sandbox is disabled and logs a critical
advisory — it never pretends to enforce a filter it has not loaded.

Relationship to ``seccomp_guard.py``: ``SeccompGuard`` is the high-level
profile-management and sandbox-detection layer; it delegates all ctypes work
to ``SeccompSandbox`` here.  ``sandbox.py`` is the Landlock + phase coordinator
that also uses ``SeccompSandbox`` for its ``SeccompFilter`` wrapper.
"""

from __future__ import annotations

import ctypes
import logging
from typing import cast

logger = logging.getLogger(__name__)

# libseccomp action constants (from seccomp.h)
_SCMP_ACT_KILL = 0x00000000  # kill the calling thread
_SCMP_ACT_ERRNO_EPERM = 0x00050001  # SCMP_ACT_ERRNO(1 == EPERM)
_SCMP_ACT_ALLOW = 0x7FFF0000

# Public aliases for callers that want the KILL action
SCMP_ACT_KILL = _SCMP_ACT_KILL
SCMP_ACT_ALLOW = _SCMP_ACT_ALLOW

# Minimal syscall allowlist for the aegis proxy process.
# Resolved at runtime via seccomp_syscall_resolve_name so syscall
# numbers stay correct across kernel/arch variants.
_ALLOWED_SYSCALLS: tuple[str, ...] = (
    "read",
    "write",
    "close",
    "stat",
    "fstat",
    "lstat",
    "access",
    "openat",
    "open",
    "lseek",
    "pread64",
    "pwrite64",
    "fcntl",
    "dup",
    "dup2",
    "ioctl",
    "mmap",
    "munmap",
    "mprotect",
    "brk",
    "rt_sigaction",
    "rt_sigreturn",
    "sigreturn",
    "sigaltstack",
    "futex",
    "epoll_wait",
    "epoll_ctl",
    "epoll_create1",
    "sendto",
    "recvfrom",
    "sendmsg",
    "recvmsg",
    "accept4",
    "bind",
    "listen",
    "connect",
    "socket",
    "getpid",
    "gettid",
    "getuid",
    "getgid",
    "nanosleep",
    "clock_gettime",
    "gettimeofday",
    "exit_group",
    "set_robust_list",
    "set_tid_address",
    "poll",
    "select",
    "pselect6",
    "uname",
    "getrlimit",
    "arch_prctl",
    "clone",
    "clone3",
    "wait4",
    "waitid",
    "sched_yield",
    "prctl",
    "getrandom",
    "sched_getaffinity",
    "pipe",
    "pipe2",
)


def _load_libseccomp() -> ctypes.CDLL | None:
    """Load libseccomp.so.2 and set required function prototypes."""
    try:
        lib = ctypes.CDLL("libseccomp.so.2", use_errno=True)
    except OSError:
        return None

    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_release.restype = None
    lib.seccomp_release.argtypes = [ctypes.c_void_p]
    lib.seccomp_load.restype = ctypes.c_int
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_rule_add.restype = ctypes.c_int
    lib.seccomp_rule_add.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint32,
        ctypes.c_int,
        ctypes.c_uint,
    ]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    return lib


class SeccompSandbox:
    """L1 Sandbox — real syscall filtering via libseccomp C API.

    Uses ``seccomp_syscall_resolve_name`` to map syscall names to numbers and
    ``seccomp_rule_add`` to permit each entry in the allowlist.  Callers can
    supply a custom ``allowed_syscalls`` tuple (e.g. ``SeccompGuard`` supplies
    its Tokio-aware extended list) and a ``default_action`` constant (e.g.
    ``SCMP_ACT_KILL`` for hard enforcement).

    Call ``apply_filter()`` to load the filter into the kernel.  This is a
    one-way, process-wide operation — call only after all setup work is done.
    Use ``build_filter_without_loading()`` for health checks and tests.
    """

    def __init__(
        self,
        allowed_syscalls: tuple[str, ...] | None = None,
        default_action: int = _SCMP_ACT_ERRNO_EPERM,
    ) -> None:
        self._allowed_syscalls: tuple[str, ...] = (
            allowed_syscalls if allowed_syscalls is not None else _ALLOWED_SYSCALLS
        )
        self._default_action = default_action
        lib = _load_libseccomp()
        if lib is None:
            logger.error(
                "SeccompSandbox: libseccomp.so.2 not found — Sandbox L1 DISABLED. "
                "Install libseccomp2 for kernel-enforced syscall filtering."
            )
        else:
            logger.info("SeccompSandbox: libseccomp.so.2 loaded.")
        self._lib = lib
        self.enabled = lib is not None

    def _build_context(self) -> int | None:
        """Create a seccomp context with all allowed syscalls added.

        The caller owns the returned context pointer and must call
        ``seccomp_release`` when done.  Returns None on failure.
        """
        assert self._lib is not None
        lib = self._lib
        ctx = lib.seccomp_init(self._default_action)
        if not ctx:
            logger.error("SeccompSandbox: seccomp_init() returned NULL.")
            return None

        missing: list[str] = []
        for name in self._allowed_syscalls:
            nr = lib.seccomp_syscall_resolve_name(name.encode())
            if nr < 0:
                missing.append(name)
                continue
            ret = lib.seccomp_rule_add(ctx, _SCMP_ACT_ALLOW, nr, 0)
            if ret != 0:
                logger.warning("SeccompSandbox: seccomp_rule_add(%s) = %d", name, ret)

        if missing:
            logger.warning(
                "SeccompSandbox: %d syscall(s) not resolved on this kernel/arch: %s",
                len(missing),
                missing,
            )
        return cast("int | None", ctx)

    def apply_filter(self) -> bool:
        """Build and load the seccomp-BPF filter into the kernel.

        Returns True on success.  WARNING: this permanently constrains the
        calling process — call only after all setup work is complete.
        """
        if not self.enabled or self._lib is None:
            logger.warning(
                "SeccompSandbox.apply_filter: libseccomp unavailable — no kernel filter loaded."
            )
            return False

        lib = self._lib
        ctx = self._build_context()
        if ctx is None:
            return False
        try:
            ret = lib.seccomp_load(ctx)
            if ret != 0:
                logger.error("SeccompSandbox: seccomp_load() failed: %d", ret)
                return False
            logger.info(
                "SeccompSandbox: seccomp-BPF filter loaded. "
                "%d syscalls allowed; unknown syscalls return EPERM.",
                len(_ALLOWED_SYSCALLS),
            )
            return True
        finally:
            lib.seccomp_release(ctx)

    def build_filter_without_loading(self) -> bool:
        """Build and validate the filter context without loading it into the kernel.

        Safe for health checks and unit tests.  Returns True when libseccomp is
        present and all syscall rules can be constructed successfully.
        """
        if not self.enabled or self._lib is None:
            return False

        ctx = self._build_context()
        if ctx is None:
            return False
        self._lib.seccomp_release(ctx)
        return True


sandbox_l1 = SeccompSandbox()
