# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.cpu_affinity — Domain 3.2 CPU pinning via sched_setaffinity.

Pins the calling process (or any pid) to a subset of CPU cores using the
Linux ``sched_setaffinity`` syscall via ctypes.  Degrades gracefully on
non-Linux platforms and when the process lacks ``CAP_SYS_NICE``.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import sys
from dataclasses import dataclass

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

# ── Constants ─────────────────────────────────────────────────────────────────

_CPU_SETSIZE = 1024
_CPU_SET_BYTES = _CPU_SET_BYTES = _CPU_SETSIZE // 8  # 128 bytes

_SYS_ISOLATED = "/sys/devices/system/cpu/isolated"

# ── Exceptions ────────────────────────────────────────────────────────────────


class CPUAffinityError(Exception):
    """Raised for invalid CPU affinity parameters."""


# ── Data types ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class AffinityResult:
    """Result of a CPU affinity change attempt."""

    applied: bool
    cpu_set: frozenset[int]
    pid: int
    reason: str

    def to_dict(self) -> dict:
        return {
            "applied": self.applied,
            "cpu_set": sorted(self.cpu_set),
            "pid": self.pid,
            "reason": self.reason,
        }


# ── Internal helpers ──────────────────────────────────────────────────────────


def _cpu_set_to_mask(cpu_set: frozenset[int]) -> bytearray:
    """Convert a set of CPU indices to a 128-byte cpu_set_t bitmask."""
    mask = bytearray(_CPU_SET_BYTES)
    for cpu in cpu_set:
        if 0 <= cpu < _CPU_SETSIZE:
            mask[cpu // 8] |= 1 << (cpu % 8)
    return mask


def _mask_to_cpu_set(mask: bytes) -> frozenset[int]:
    """Convert a 128-byte cpu_set_t bitmask to a frozenset of CPU indices."""
    cpus: list[int] = []
    for byte_idx, byte_val in enumerate(mask):
        for bit in range(8):
            if byte_val & (1 << bit):
                cpus.append(byte_idx * 8 + bit)
    return frozenset(cpus)


def _parse_cpu_range(token: str) -> list[int]:
    """Parse a single CPU range token like ``"2"`` or ``"2-5"``."""
    token = token.strip()
    if "-" in token:
        parts = token.split("-", 1)
        lo, hi = int(parts[0]), int(parts[1])
        return list(range(lo, hi + 1))
    return [int(token)]


# ── Core class ────────────────────────────────────────────────────────────────


class CPUAffinity:
    """
    CPU core affinity manager.

    Wraps ``sched_setaffinity`` and ``sched_getaffinity`` from libc.  All
    methods that change affinity return an :class:`AffinityResult` rather than
    raising on platform or privilege errors (except for invalid parameters).
    """

    def __init__(self, cpu_set: frozenset[int] | None = None) -> None:
        self._cpu_set = cpu_set or frozenset()

    # ── Static API ────────────────────────────────────────────────────────────

    @staticmethod
    def set_affinity(cpu_set: frozenset[int], pid: int = 0) -> AffinityResult:
        """
        Pin *pid* to the CPUs in *cpu_set*.

        *pid* ``0`` targets the calling process.  Raises
        :class:`CPUAffinityError` when *cpu_set* is empty.
        """
        if not cpu_set:
            raise CPUAffinityError("cpu_set must not be empty")

        if not HAS_LIBC or sys.platform != "linux":
            return AffinityResult(
                applied=False,
                cpu_set=cpu_set,
                pid=pid,
                reason="libc not available" if not HAS_LIBC else "not Linux",
            )

        mask = _cpu_set_to_mask(cpu_set)
        c_mask = (ctypes.c_uint8 * _CPU_SET_BYTES)(*mask)
        ret = _libc.sched_setaffinity(pid, ctypes.c_size_t(_CPU_SET_BYTES), ctypes.byref(c_mask))
        if ret == 0:
            return AffinityResult(applied=True, cpu_set=cpu_set, pid=pid, reason="ok")

        errno_val = ctypes.get_errno()
        import errno as _errno

        if errno_val == _errno.EPERM:
            reason = "permission denied (CAP_SYS_NICE required)"
        else:
            reason = f"sched_setaffinity errno={errno_val}"
        logger.warning("CPUAffinity: %s", reason)
        return AffinityResult(applied=False, cpu_set=cpu_set, pid=pid, reason=reason)

    @staticmethod
    def get_affinity(pid: int = 0) -> frozenset[int]:
        """
        Return the set of CPU indices the process is allowed to run on.

        Falls back to :meth:`available_cpus` when libc or the syscall is
        unavailable.
        """
        if not HAS_LIBC or sys.platform != "linux":
            return CPUAffinity.available_cpus()

        c_mask = (ctypes.c_uint8 * _CPU_SET_BYTES)()
        ret = _libc.sched_getaffinity(pid, ctypes.c_size_t(_CPU_SET_BYTES), ctypes.byref(c_mask))
        if ret != 0:
            errno_val = ctypes.get_errno()
            logger.debug("sched_getaffinity errno=%d", errno_val)
            return CPUAffinity.available_cpus()
        return _mask_to_cpu_set(bytes(c_mask))

    @staticmethod
    def available_cpus() -> frozenset[int]:
        """
        Return all CPU indices available to the process.

        Uses ``os.sched_getaffinity(0)`` when available, otherwise parses
        ``/proc/cpuinfo`` for ``processor`` lines, and finally falls back to
        ``os.cpu_count()``.
        """
        try:
            return frozenset(os.sched_getaffinity(0))
        except (AttributeError, OSError):
            pass

        try:
            cpus: list[int] = []
            with open("/proc/cpuinfo") as fh:
                for line in fh:
                    if line.startswith("processor"):
                        parts = line.split(":", 1)
                        if len(parts) == 2:
                            cpus.append(int(parts[1].strip()))
            if cpus:
                return frozenset(cpus)
        except OSError:
            pass

        count = os.cpu_count() or 1
        return frozenset(range(count))

    @staticmethod
    def get_isolated_cpus() -> frozenset[int]:
        """
        Return CPU indices listed in ``/sys/devices/system/cpu/isolated``.

        Returns an empty frozenset when the file is absent, empty, or the
        platform is not Linux.
        """
        if sys.platform != "linux":
            return frozenset()
        try:
            with open(_SYS_ISOLATED) as fh:
                content = fh.read().strip()
            if not content:
                return frozenset()
            cpus: list[int] = []
            for token in content.split(","):
                cpus.extend(_parse_cpu_range(token))
            return frozenset(cpus)
        except OSError:
            return frozenset()

    @classmethod
    def from_env(cls) -> CPUAffinity:
        """
        Construct a :class:`CPUAffinity` from environment variables.

        ``AEGIS_CPU_AFFINITY`` — comma-separated CPU indices (e.g. ``"2,3,4"``)
        or the literal ``"isolated"`` to use isolated CPUs from
        ``/sys/devices/system/cpu/isolated``.
        """
        raw = os.environ.get("AEGIS_CPU_AFFINITY", "").strip()
        if not raw:
            return cls(cpu_set=None)

        if raw.lower() == "isolated":
            isolated = cls.get_isolated_cpus()
            if not isolated:
                logger.warning("AEGIS_CPU_AFFINITY=isolated but no isolated CPUs found")
            return cls(cpu_set=isolated)

        try:
            cpu_set: list[int] = []
            for token in raw.split(","):
                cpu_set.extend(_parse_cpu_range(token))
            return cls(cpu_set=frozenset(cpu_set))
        except ValueError:
            logger.warning("AEGIS_CPU_AFFINITY invalid (%r), ignoring", raw)
            return cls(cpu_set=None)

    def apply(self) -> AffinityResult:
        """Apply the configured CPU affinity to the calling process."""
        if not self._cpu_set:
            return AffinityResult(
                applied=False,
                cpu_set=frozenset(),
                pid=0,
                reason="no cpu_set configured",
            )
        return self.set_affinity(self._cpu_set, pid=0)
