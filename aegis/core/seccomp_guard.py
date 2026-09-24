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
SCMP_ACT_KILL = 0x00000000  # kills only the calling thread: a miss hangs the process silently
SCMP_ACT_KILL_PROCESS = 0x80000000  # a miss exits with SIGSYS, visibly and restartably
SCMP_ACT_ALLOW = 0x7FFF0000
PR_SET_NO_NEW_PRIVS = 38

# REG-D67: io_uring is not allowlisted — its submitted operations run in the
# kernel without passing through this filter, so permitting it would hollow the
# control out. A ring that already exists when the filter loads is fatal, though:
# libuv (under uvloop) calls io_uring_enter on it later and the process dies with
# SIGSYS. New rings are refused with EPERM after lockdown (libuv falls back to
# epoll when io_uring_setup fails); an existing ring is detected before lockdown.
IO_URING_ERRNO_SYSCALLS: tuple[str, ...] = ("io_uring_setup",)
_IO_URING_FD_TARGET = "anon_inode:[io_uring]"


class IoUringActiveError(RuntimeError):
    """An io_uring instance is open, so loading the filter would kill the process."""


def open_io_uring_fds(fd_dir: str = "/proc/self/fd") -> list[int]:
    """Return this process's open io_uring file descriptors (empty off Linux)."""
    try:
        entries = os.listdir(fd_dir)
    except OSError:
        return []
    found: list[int] = []
    for entry in entries:
        try:
            if os.readlink(os.path.join(fd_dir, entry)) == _IO_URING_FD_TARGET:
                found.append(int(entry))
        except (OSError, ValueError):
            continue  # closed between listdir and readlink, or not an fd entry
    return sorted(found)


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
            # The Tokio worker pool is warmed before this filter is installed
            # (see app.py lifespan + forwarder::warmup_runtime), and the async
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
            # ── Observed after lockdown (strace -f of startup, /health, /ready,
            # authenticated completions, WAF block, 401, SIGTERM; uvicorn 0.46 +
            # uvloop 0.22). Missing any one of these killed the event-loop thread.
            "epoll_pwait",  # libuv / uvloop event loop (glibc epoll_wait on arm64)
            "epoll_pwait2",  # newer libuv poll path
            "ioctl",  # FIONBIO on accepted sockets (asyncio setblocking)
            "newfstatat",  # glibc stat()/fstat() on 64-bit
            "statx",  # glibc stat path on newer builds
            "openat",  # WAL segment and config reads
            "lseek",  # WAL append positioning
            "fsync",  # durable evidence commit
            "fdatasync",  # durable evidence commit (data-only variant)
            "flock",  # WAL single-writer advisory lock
            "rename",  # WAL segment finalization
            "renameat",  # rename() on archs without the legacy syscall
            "renameat2",  # rename() on glibc builds that use it
            "getdents64",  # WAL directory scan
            "getcwd",  # import system resolving a "" sys.path entry for lazy imports
            "unlink",  # WAL MMR state removal on shutdown
            "unlinkat",  # unlink() on archs without the legacy syscall
            "writev",  # uvloop/libuv scatter-gather response writes
            "shutdown",  # HTTP connection close
            "tgkill",  # thread-directed signal during shutdown
            "exit",  # a single thread ending (exit_group ends the process)
            # ── Hostname resolution (REG-D78). The list above came from a
            # loopback-only run, so no name was ever resolved; the shipped image
            # talking to a named upstream or Redis was killed on its first request.
            # Found by running the image's whole request flow under SCMP_ACT_LOG
            # (scripts/container_smoke_test.py): these two were the only misses.
            "uname",  # glibc res_init -> gethostname() for the resolver's default domain
            "sendmmsg",  # glibc getaddrinfo sends the A and AAAA queries in one call
            # clone is added separately and only with CLONE_THREAD: the ASGI
            # threadpool (sync endpoints, to_thread) spawns threads per request;
            # process creation stays impossible.
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

        # An explicit test-harness marker only. "/.dockerenv" used to be listed
        # here too, which switched the filter off in every Docker container —
        # and with the image's strict AEGIS_REQUIRE_SECCOMP=true the gateway
        # then refused to start (REG-D68). A container is not a reason to drop
        # the control: this filter stacks on the runtime's profile, and the
        # stricter action of the two wins.
        return os.path.exists("/.hermes_sandbox_marker")

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
            # 0. Refuse to lock down over a live io_uring (REG-D67): checked before
            #    PR_SET_NO_NEW_PRIVS, so a refusal leaves the process unchanged.
            rings = open_io_uring_fds()
            if rings:
                raise IoUringActiveError(
                    f"io_uring instance(s) open on fd {rings}: loading the seccomp filter "
                    "would kill the process on its next io_uring_enter. Start the gateway "
                    "with the `aegis` entry point (it sets UV_USE_IO_URING=0), export "
                    "UV_USE_IO_URING=0 before launching uvicorn, or use --loop asyncio."
                )

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
                default_action=SCMP_ACT_KILL_PROCESS,
                thread_clone_only=True,
                errno_syscalls=IO_URING_ERRNO_SYSCALLS,
            )
            if not sb.enabled:
                logger.error("libseccomp not available. Entering degraded mode.")
                self._degraded_mode = True
                return False
            if not sb.apply_filter():
                raise RuntimeError("SeccompSandbox.apply_filter() returned False")

            self._is_enforced = True
            return True

        except IoUringActiveError as exc:
            # Re-raised as itself so the lifespan reports the actionable message.
            logger.error("Seccomp not applied: %s", exc)
            self._degraded_mode = True
            raise
        except Exception as exc:
            logger.error("Seccomp application failed: %s", exc)
            self._degraded_mode = True
            if not self._is_sandbox:
                raise RuntimeError("Seccomp enforcement failed outside sandbox") from exc
            return False

    @property
    def is_sandbox(self) -> bool:
        return self._is_sandbox

    def is_enforced(self) -> bool:
        return self._is_enforced

    def is_degraded(self) -> bool:
        return self._degraded_mode
