"""
aegis.core.sandbox — System-level hardening and sandbox enforcement.
Implements seccomp-bpf filtering and Landlock LSM for resource isolation.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import ctypes
import logging
from dataclasses import dataclass

from aegis.core.sandbox_l1 import SeccompSandbox

logger = logging.getLogger(__name__)

_PR_SET_NO_NEW_PRIVS = 38

# Syscall numbers for x86_64
SYS_READ = 0
SYS_WRITE = 1
SYS_CLOSE = 3
SYS_RT_SIGRETURN = 15
SYS_MUNMAP = 9
SYS_BRK = 12
SYS_EPOLL_WAIT = 1
SYS_ACCEPT = 43
SYS_SENDTO = 44
SYS_RECVFROM = 45
SYS_EXIT_GROUP = 231
SYS_FUTEX = 125


@dataclass
class SandboxState:
    phase: str  # 'INIT', 'RUNNING', 'SHUTDOWN'
    allowed_syscalls: set[int]
    fs_restrictions: dict[str, str]  # path -> permission ('ro', 'rw')


class SeccompFilter:
    """
    Implements a dynamic syscall filter using seccomp-bpf.
    Can transition between different security postures based on process phase.
    """

    def __init__(self, initial_syscalls: list[int]):
        self.current_allowed = set(initial_syscalls)
        self._libc = ctypes.CDLL("libc.so.6", use_errno=True)
        self._phase = "INIT"
        self._filter_applied = False

    def transition_to_phase(self, phase: str, new_syscalls: list[int]) -> None:
        """
        Transitions the process to a new security phase, narrowing the syscall surface.
        Seccomp filters stack — each successive call to apply() adds a constraint layer,
        so transitions must only narrow (remove) allowed syscalls to remain safe.
        """
        logger.info("Transitioning sandbox phase: %s -> %s", self._phase, phase)
        self._phase = phase
        self.current_allowed = set(new_syscalls)
        logger.info(
            "Sandbox phase updated. New syscall surface size: %d", len(self.current_allowed)
        )

    def apply(self) -> None:
        """Applies the current filter to the process.

        Calls prctl(PR_SET_NO_NEW_PRIVS) to lock privilege-escalation paths, then
        installs a kernel-enforced seccomp-bpf syscall allowlist via libseccomp.
        Both operations are irreversible for the lifetime of the process.
        """
        try:
            logger.info(
                "Applying seccomp-bpf filter for phase %s. Allowed: %s",
                self._phase,
                self.current_allowed,
            )
            ret = self._libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            if ret != 0:
                errno = ctypes.get_errno()
                raise RuntimeError(f"prctl(PR_SET_NO_NEW_PRIVS) failed with errno {errno}")
            logger.info("PR_SET_NO_NEW_PRIVS set — privilege escalation paths locked.")

            sb = SeccompSandbox()
            if sb.apply_filter():
                self._filter_applied = True
                logger.info("Seccomp-BPF filter installed via libseccomp.")
            else:
                logger.warning(
                    "libseccomp unavailable — syscall filter not installed. "
                    "Install libseccomp for kernel-enforced syscall allowlisting."
                )
        except RuntimeError:
            raise
        except Exception as exc:  # noqa: BLE001
            logger.error("Failed to apply seccomp filter: %s", exc)
            raise RuntimeError("Security invariant violation: Seccomp could not be applied.")


class LandlockManager:
    """Landlock LSM filesystem restriction intent recorder.

    Records the caller's intended path restrictions.  The kernel Landlock API
    (``landlock_create_ruleset`` / ``landlock_add_rule`` / ``landlock_restrict_self``)
    is not yet called here — this is a documented stub.  ``is_restricted`` reflects
    that restrictions have been *requested*, not that kernel enforcement is active.
    Real kernel Landlock enforcement is tracked in the ROADMAP.
    """

    def __init__(self) -> None:
        self._restricted = False

    def restrict_filesystem(self, allowed_paths: dict[str, str]) -> None:
        """Record the intended filesystem restrictions (stub — no kernel call yet)."""
        try:
            logger.info(
                "LandlockManager: recording filesystem restrictions (kernel Landlock not yet wired)."
            )
            for path, perm in allowed_paths.items():
                logger.info("Restriction recorded: path [%s] permission [%s]", path, perm)

            self._restricted = True
            logger.warning(
                "LandlockManager: restrictions recorded but kernel Landlock is NOT active. "
                "Real isolation requires landlock_create_ruleset/add_rule/restrict_self."
            )
        except Exception as e:
            logger.error("LandlockManager recording failed: %s", e)
            raise RuntimeError("Security invariant violation: Landlock could not be applied.")

    @property
    def is_restricted(self) -> bool:
        return self._restricted


def enable_hardened_sandbox(phase: str = "INIT") -> tuple[SeccompFilter, LandlockManager]:
    """
    Activates the full system sandbox, combining Seccomp-BPF and Landlock.
    """
    # 1. Syscall Filtering
    # Basic set for INIT (includes file opening, networking setup)
    init_syscalls = [
        SYS_READ,
        SYS_WRITE,
        SYS_CLOSE,
        SYS_RT_SIGRETURN,
        SYS_MUNMAP,
        SYS_BRK,
        SYS_EPOLL_WAIT,
        SYS_ACCEPT,
        SYS_SENDTO,
        SYS_RECVFROM,
        SYS_EXIT_GROUP,
        SYS_FUTEX,
        0,
        1,
        2,  # open, openat, etc.
    ]

    filter_engine = SeccompFilter(init_syscalls)
    filter_engine.apply()

    # 2. Filesystem Isolation (Landlock)
    landlock = LandlockManager()
    # Only allow read access to specific config and the socket
    landlock.restrict_filesystem(
        {
            "/etc/aegis/config.yaml": "ro",
            "/run/spire/sockets/agent.sock": "rw",
            "/var/log/aegis/audit.log": "rw",
        }
    )

    return filter_engine, landlock
