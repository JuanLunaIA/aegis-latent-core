# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.mte_guard — Memory Tagging Extension (MTE) Guard.

Detects and (where the kernel permits) enables ARM MTE via real system-call
interfaces.  On x86 / non-ARM platforms, reports honestly rather than
manufacturing a positive result.

Detection strategy (in order):

1. Parse ``/proc/cpuinfo`` for the ``mte`` CPU feature flag (ARM Linux,
   visible as ``Features: … mte …``).
2. Parse ``/proc/self/auxv`` for ``AT_HWCAP2`` bit 18
   (``HWCAP2_MTE = 1 << 18``).
3. Attempt ``prctl(PR_SET_TAGGED_ADDR_CTRL, PR_TAGGED_ADDR_ENABLE)`` via
   ``ctypes.CDLL("libc.so.6")`` for real kernel-level enablement.

None of these steps simulate a result — if MTE is unavailable the guard
returns ``False`` and logs a clear advisory.
"""

from __future__ import annotations

import ctypes
import logging
import os
import struct

logger = logging.getLogger(__name__)

# ARM Linux kernel constants (linux/prctl.h)
_PR_SET_TAGGED_ADDR_CTRL = 55
_PR_TAGGED_ADDR_ENABLE = 1 << 0  # bit 0 of the control word
_HWCAP2_MTE = 1 << 18  # AT_HWCAP2 bit for ARM MTE
_AT_HWCAP2 = 26  # ELF auxiliary vector type
_AT_NULL = 0


def _cpuinfo_has_mte() -> bool:
    """Return True if /proc/cpuinfo lists the 'mte' CPU feature."""
    try:
        with open("/proc/cpuinfo", encoding="ascii", errors="ignore") as f:
            for line in f:
                if line.startswith("Features") and " mte" in line:
                    return True
    except OSError:
        pass
    return False


def _auxv_has_mte() -> bool:
    """Return True if AT_HWCAP2 in /proc/self/auxv has HWCAP2_MTE set."""
    try:
        # auxv entries are pairs of (type, value), each pointer-sized
        ptr_size = 8 if struct.calcsize("P") == 8 else 4
        fmt = "<QQ" if ptr_size == 8 else "<II"
        entry_size = struct.calcsize(fmt)
        with open("/proc/self/auxv", "rb") as f:
            data = f.read()
        for i in range(0, len(data) - entry_size + 1, entry_size):
            a_type, a_val = struct.unpack_from(fmt, data, i)
            if a_type == _AT_NULL:
                break
            if a_type == _AT_HWCAP2:
                return bool(a_val & _HWCAP2_MTE)
    except OSError:
        pass
    return False


def _prctl_enable_mte() -> bool:
    """Attempt to enable MTE via prctl(PR_SET_TAGGED_ADDR_CTRL).

    Returns True only if the kernel syscall succeeds (ret == 0).
    """
    try:
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        ret = libc.prctl(
            ctypes.c_int(_PR_SET_TAGGED_ADDR_CTRL),
            ctypes.c_ulong(_PR_TAGGED_ADDR_ENABLE),
            ctypes.c_ulong(0),
            ctypes.c_ulong(0),
            ctypes.c_ulong(0),
        )
        return bool(ret == 0)
    except OSError:
        return False


class MTEGuard:
    """Interfaces with ARM Memory Tagging Extension (MTE) via real kernel APIs.

    ``check_hardware_support()`` inspects ``/proc/cpuinfo`` and the ELF
    auxiliary vector; it never reports ``True`` on hardware that lacks MTE.
    ``enable_mte_protection()`` issues the real ``prctl`` syscall — it does
    not simulate success.
    """

    def __init__(self) -> None:
        self._hardware_support: bool = False
        self._mte_enabled: bool = False
        logger.info("MTEGuard initialised; checking hardware support…")

    def check_hardware_support(self) -> bool:
        """Return True only if the running CPU supports ARM MTE.

        Checks ``/proc/cpuinfo`` and ``AT_HWCAP2``; returns False and logs
        a clear advisory on non-ARM or pre-ARMv8.5 hosts.
        """
        via_cpuinfo = _cpuinfo_has_mte()
        via_auxv = _auxv_has_mte()
        self._hardware_support = via_cpuinfo or via_auxv
        if self._hardware_support:
            logger.info(
                "MTE hardware support detected (cpuinfo=%s, auxv=%s)",
                via_cpuinfo,
                via_auxv,
            )
        else:
            logger.warning(
                "MTE hardware NOT available on this platform "
                "(cpuinfo=%s, auxv=%s); UAF protection is absent.",
                via_cpuinfo,
                via_auxv,
            )
        return self._hardware_support

    def enable_mte_protection(self) -> bool:
        """Enable MTE for the current process via prctl.

        Returns True only after the kernel syscall confirms success.
        Does not set ``_mte_enabled`` if hardware support is absent.
        """
        if not self.check_hardware_support():
            logger.critical("MTE cannot be enabled: hardware support missing.")
            return False

        if _prctl_enable_mte():
            self._mte_enabled = True
            logger.info("MTE protection enabled (PR_TAGGED_ADDR_ENABLE set).")
            return True

        errno_val = ctypes.get_errno()
        logger.error(
            "prctl(PR_SET_TAGGED_ADDR_CTRL) failed (errno=%d). "
            "Kernel MTE support requires CONFIG_ARM64_MTE=y and kernel ≥ 5.10.",
            errno_val,
        )
        return False

    def is_protected(self) -> bool:
        """Return True only if MTE is both available and actively enabled."""
        return self._hardware_support and self._mte_enabled

    def verify_tag_integrity(self) -> tuple[bool, str]:
        """Report MTE enablement status.

        This does NOT perform a synthetic fault test (that would require
        an MTE-aware allocator and inline assembly).  Returns the honest
        activation state so callers can decide whether to abort or downgrade.
        """
        if not self._mte_enabled:
            return False, "MTE not enabled"
        if not self._hardware_support:
            return False, "MTE hardware absent"
        return True, "MTE active (PR_TAGGED_ADDR_ENABLE confirmed via prctl)"

    @staticmethod
    def get_platform_report() -> dict[str, bool | str]:
        """Return a snapshot of MTE availability on the current host."""
        return {
            "cpuinfo_mte": _cpuinfo_has_mte(),
            "auxv_hwcap2_mte": _auxv_has_mte(),
            "arch": os.uname().machine,
        }
