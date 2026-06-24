"""
aegis.core.seccomp_guard — Secure Computing (Seccomp-BPF) Enforcement.
High-level profile management and sandbox detection; delegates all ctypes
work to ``aegis.core.sandbox_l1.SeccompSandbox``.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
import logging
import os
import sys
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Constants re-exported for callers that import them from this module.
SCMP_ACT_KILL = 0x00000000
SCMP_ACT_ALLOW = 0x7FFF0000
PR_SET_NO_NEW_PRIVS = 38


@dataclass
class SyscallProfile:
    name: str
    allowed_syscalls: set[str]
    forbidden_syscalls: set[str]


class SeccompGuard:
    """
    Enforces a strict Seccomp-BPF filter.

    Performs sandbox detection to avoid crashing test runners and restricted
    CI environments.  In non-sandbox environments, delegates the actual filter
    build and load to ``aegis.core.sandbox_l1.SeccompSandbox`` so there is
    exactly one ctypes-libseccomp implementation in the tree.
    """

    DEFAULT_PROFILE = SyscallProfile(
        name="AEGIS_PROXY_STRICT",
        allowed_syscalls={
            "read",
            "write",
            "close",
            "stat",
            "fstat",
            "lstat",
            "access",
            "mmap",
            "munmap",
            "mprotect",
            "brk",
            "rt_sigaction",
            "rt_sigreturn",
            "sigreturn",
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
            "getpeername",
            # ── Async Rust forwarder (Tokio runtime) steady-state syscalls ──
            # Thread creation (clone/clone3) is deliberately NOT allowed: the
            # Tokio worker pool is warmed before this filter is installed (see
            # app.py lifespan + forwarder::warmup_runtime), and the async
            # hickory DNS resolver removes the per-request blocking-pool spawn.
            # These cover the request hot path only — socket option tuning,
            # non-blocking fd flags, TLS entropy, the epoll/eventfd reactor,
            # allocator hints, and CPU-topology probing.
            "getrandom",  # native-tls / OpenSSL handshake entropy
            "setsockopt",  # TCP_NODELAY, SO_KEEPALIVE on new sockets
            "getsockopt",  # connect() error retrieval (SO_ERROR)
            "getsockname",  # local socket introspection
            "fcntl",  # set O_NONBLOCK on async sockets
            "eventfd2",  # Tokio I/O driver wakeups
            "epoll_create",  # reactor (older libc path; create1 also allowed)
            "madvise",  # allocator / mmap region hints
            "mremap",  # allocator growth
            "sched_getaffinity",  # available_parallelism() CPU probe
            "sched_yield",  # Tokio cooperative scheduling
            "rseq",  # glibc restartable sequences (thread init)
            "prctl",  # Tokio worker thread naming (PR_SET_NAME)
            "rt_sigprocmask",  # per-thread signal mask setup
            "sigaltstack",  # Rust thread signal-stack setup
            "clock_nanosleep",  # Tokio timer driver
            "restart_syscall",  # kernel-resumed syscalls after signal
        },
        forbidden_syscalls={
            "execve",
            "execveat",
            "ptrace",
            "process_vm_readv",
            "process_vm_writev",
            "mount",
            "umount2",
            "reboot",
        },
    )

    def __init__(self, profile: SyscallProfile = DEFAULT_PROFILE):
        self.profile = profile
        self._is_enforced = False
        self._degraded_mode = False
        self._is_sandbox = self._detect_sandbox()
        logger.info("SeccompGuard initialized. Sandbox detected: %s", self._is_sandbox)

    def _detect_sandbox(self) -> bool:
        """Detects if we are running in a highly restricted sandbox or test environment."""
        if os.environ.get("HERMES_SANDBOX") == "true":
            return True

        # Check for presence of pytest to prevent killing the test runner
        try:
            import importlib.util

            if importlib.util.find_spec("pytest") is not None and "pytest" in sys.modules:
                return True
        except ImportError:
            pass

        # Check for existence of common sandbox markers
        for marker in ["/.hermes_sandbox_marker", "/.dockerenv"]:
            if os.path.exists(marker):
                return True
        return False

    def apply_filter(self) -> bool:
        """Apply the Seccomp-BPF filter for this guard's profile.

        Skipped when a sandbox/test environment is detected (returns False,
        sets degraded mode).  In production, sets PR_SET_NO_NEW_PRIVS then
        delegates filter construction and loading to
        ``aegis.core.sandbox_l1.SeccompSandbox``.
        """
        if self._is_sandbox:
            logger.warning("System is in SANDBOX mode. Skipping real Seccomp enforcement.")
            self._degraded_mode = True
            return False

        try:
            # 1. Set PR_SET_NO_NEW_PRIVS (required before the seccomp filter).
            import ctypes.util

            libc_path = ctypes.util.find_library("c")
            if not libc_path:
                raise RuntimeError("libc not found via ctypes.util.find_library")
            libc = ctypes.CDLL(libc_path)
            res = libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            if res != 0:
                raise PermissionError("Failed to set PR_SET_NO_NEW_PRIVS")

            # 2. Build and load the filter via sandbox_l1 (single ctypes layer).
            from aegis.core.sandbox_l1 import SeccompSandbox

            sb = SeccompSandbox(
                allowed_syscalls=tuple(self.profile.allowed_syscalls),
                default_action=SCMP_ACT_KILL,
            )
            if not sb.enabled:
                logger.error("libseccomp not available. Entering degraded mode.")
                self._degraded_mode = True
                return False
            if not sb.apply_filter():
                raise RuntimeError("SeccompSandbox.apply_filter() returned False")

            self._is_enforced = True
            return True

        except Exception as e:
            logger.error("Seccomp application failed: %s. Entering degraded mode.", e)
            self._degraded_mode = True
            return False

    @property
    def is_sandbox(self) -> bool:
        return self._is_sandbox

    def is_enforced(self) -> bool:
        return self._is_enforced

    def is_degraded(self) -> bool:
        return self._degraded_mode
