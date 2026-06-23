# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.rt_scheduler — Domain 3.2 real-time scheduling policy manager.

Wraps Linux ``sched_setscheduler`` / ``sched_getscheduler`` via ctypes to
apply SCHED_FIFO or SCHED_RR real-time priorities to the current process.
Requires ``CAP_SYS_NICE`` (or equivalent); degrades gracefully when the
capability is absent or the platform is not Linux.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import sys
from dataclasses import dataclass
from enum import StrEnum

logger = logging.getLogger(__name__)

# ── Optional libc import ──────────────────────────────────────────────────────

try:
    _libc_name = ctypes.util.find_library("c")
    if _libc_name is None:
        raise OSError("libc not found")
    _libc = ctypes.CDLL(_libc_name, use_errno=True)
    HAS_LIBC: bool = True
except OSError:
    _libc = None  # type: ignore[assignment]
    HAS_LIBC = False

# ── Linux scheduling constants ────────────────────────────────────────────────

_SCHED_OTHER = 0
_SCHED_FIFO = 1
_SCHED_RR = 2
_SCHED_BATCH = 3
_SCHED_IDLE = 5
_SCHED_DEADLINE = 6

_POLICY_MAP: dict[int, SchedulingPolicy] = {}


# ── Enumerations ──────────────────────────────────────────────────────────────


class SchedulingPolicy(StrEnum):
    NORMAL = "SCHED_OTHER"
    FIFO = "SCHED_FIFO"
    RR = "SCHED_RR"
    DEADLINE = "SCHED_DEADLINE"
    BATCH = "SCHED_BATCH"
    IDLE = "SCHED_IDLE"


_POLICY_TO_INT: dict[SchedulingPolicy, int] = {
    SchedulingPolicy.NORMAL: _SCHED_OTHER,
    SchedulingPolicy.FIFO: _SCHED_FIFO,
    SchedulingPolicy.RR: _SCHED_RR,
    SchedulingPolicy.DEADLINE: _SCHED_DEADLINE,
    SchedulingPolicy.BATCH: _SCHED_BATCH,
    SchedulingPolicy.IDLE: _SCHED_IDLE,
}

_INT_TO_POLICY: dict[int, SchedulingPolicy] = {v: k for k, v in _POLICY_TO_INT.items()}

# ── Exceptions ────────────────────────────────────────────────────────────────


class RTSchedulerError(Exception):
    """Raised for invalid scheduling parameters."""


# ── ctypes structures ─────────────────────────────────────────────────────────


class _SchedParam(ctypes.Structure):
    _fields_ = [("sched_priority", ctypes.c_int)]


# ── Data types ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class SchedulingConfig:
    """Snapshot of a process scheduling configuration."""

    policy: SchedulingPolicy
    priority: int
    deadline_runtime_ns: int = 0
    deadline_deadline_ns: int = 0
    deadline_period_ns: int = 0


@dataclass(frozen=True)
class SchedulingResult:
    """Result of a scheduling policy change attempt."""

    applied: bool
    policy: SchedulingPolicy
    priority: int
    reason: str

    def to_dict(self) -> dict:
        return {
            "applied": self.applied,
            "policy": self.policy.value,
            "priority": self.priority,
            "reason": self.reason,
        }


# ── Core class ────────────────────────────────────────────────────────────────


class RTScheduler:
    """
    Real-time scheduling policy manager.

    Wraps ``sched_setscheduler`` and ``sched_getscheduler`` from libc via
    ctypes.  All set-* methods return a :class:`SchedulingResult` rather than
    raising on privilege or platform errors.
    """

    def __init__(
        self,
        policy: SchedulingPolicy = SchedulingPolicy.NORMAL,
        priority: int = 0,
    ) -> None:
        self._policy = policy
        self._priority = priority

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _set_scheduler(
        pid: int,
        policy_int: int,
        priority: int,
        policy_enum: SchedulingPolicy,
    ) -> SchedulingResult:
        if not HAS_LIBC:
            return SchedulingResult(
                applied=False,
                policy=policy_enum,
                priority=priority,
                reason="libc not available",
            )
        if sys.platform != "linux":
            return SchedulingResult(
                applied=False,
                policy=policy_enum,
                priority=priority,
                reason="not Linux",
            )
        param = _SchedParam(sched_priority=priority)
        ret = _libc.sched_setscheduler(pid, policy_int, ctypes.byref(param))
        if ret == 0:
            return SchedulingResult(
                applied=True,
                policy=policy_enum,
                priority=priority,
                reason="ok",
            )
        errno_val = ctypes.get_errno()
        import errno as _errno

        if errno_val == _errno.EPERM:
            reason = "permission denied (CAP_SYS_NICE required)"
        else:
            reason = f"sched_setscheduler errno={errno_val}"
        logger.warning("RTScheduler: %s", reason)
        return SchedulingResult(
            applied=False,
            policy=policy_enum,
            priority=priority,
            reason=reason,
        )

    # ── Public API ────────────────────────────────────────────────────────────

    @staticmethod
    def set_fifo_priority(priority: int = 50, pid: int = 0) -> SchedulingResult:
        """
        Apply ``SCHED_FIFO`` with *priority* (1–99) to *pid*.

        *pid* ``0`` targets the calling process.  Raises
        :class:`RTSchedulerError` for out-of-range priorities.
        """
        if not (1 <= priority <= 99):
            raise RTSchedulerError(f"FIFO priority must be 1–99, got {priority}")
        return RTScheduler._set_scheduler(pid, _SCHED_FIFO, priority, SchedulingPolicy.FIFO)

    @staticmethod
    def set_rr_priority(priority: int = 50, pid: int = 0) -> SchedulingResult:
        """
        Apply ``SCHED_RR`` with *priority* (1–99) to *pid*.

        Raises :class:`RTSchedulerError` for out-of-range priorities.
        """
        if not (1 <= priority <= 99):
            raise RTSchedulerError(f"RR priority must be 1–99, got {priority}")
        return RTScheduler._set_scheduler(pid, _SCHED_RR, priority, SchedulingPolicy.RR)

    @staticmethod
    def reset_to_normal(pid: int = 0) -> SchedulingResult:
        """Reset *pid* to ``SCHED_OTHER`` (normal CFS scheduling)."""
        return RTScheduler._set_scheduler(pid, _SCHED_OTHER, 0, SchedulingPolicy.NORMAL)

    @staticmethod
    def get_current_policy(pid: int = 0) -> SchedulingConfig:
        """
        Query the current scheduling policy and priority for *pid*.

        Falls back to a ``SCHED_OTHER / priority=0`` config when libc or the
        syscall is unavailable.
        """
        if not HAS_LIBC or sys.platform != "linux":
            return SchedulingConfig(policy=SchedulingPolicy.NORMAL, priority=0)
        policy_int = _libc.sched_getscheduler(pid)
        if policy_int < 0:
            errno_val = ctypes.get_errno()
            logger.debug("sched_getscheduler errno=%d", errno_val)
            return SchedulingConfig(policy=SchedulingPolicy.NORMAL, priority=0)
        param = _SchedParam()
        ret = _libc.sched_getparam(pid, ctypes.byref(param))
        priority = param.sched_priority if ret == 0 else 0
        policy_enum = _INT_TO_POLICY.get(policy_int, SchedulingPolicy.NORMAL)
        return SchedulingConfig(policy=policy_enum, priority=priority)

    @classmethod
    def from_env(cls) -> RTScheduler:
        """
        Construct an :class:`RTScheduler` from environment variables.

        ``AEGIS_RT_POLICY`` — ``"fifo"``, ``"rr"``, or ``"none"`` (default ``"none"``).
        ``AEGIS_RT_PRIORITY`` — integer 1–99 (default ``50``).
        """
        raw_policy = os.environ.get("AEGIS_RT_POLICY", "none").lower().strip()
        raw_priority = os.environ.get("AEGIS_RT_PRIORITY", "50").strip()

        try:
            priority = int(raw_priority)
        except ValueError:
            logger.warning("AEGIS_RT_PRIORITY invalid (%r), defaulting to 50", raw_priority)
            priority = 50

        if raw_policy == "fifo":
            policy = SchedulingPolicy.FIFO
        elif raw_policy == "rr":
            policy = SchedulingPolicy.RR
        else:
            policy = SchedulingPolicy.NORMAL
            priority = 0

        return cls(policy=policy, priority=priority)

    def apply(self) -> SchedulingResult:
        """Apply the configured scheduling policy."""
        if self._policy == SchedulingPolicy.FIFO:
            return self.set_fifo_priority(self._priority)
        if self._policy == SchedulingPolicy.RR:
            return self.set_rr_priority(self._priority)
        return self.reset_to_normal()
