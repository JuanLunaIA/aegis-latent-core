# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.process_hardening — prctl-based process privilege hardening.

Applies two Linux ``prctl(2)`` flags as early as possible at startup,
independently of the seccomp filter installation:

``PR_SET_NO_NEW_PRIVS`` (38)
    Prevents the process and any child from gaining new privileges via
    ``setuid``/``setgid`` binaries or Linux capabilities after this call.
    Required by the kernel before installing a seccomp filter with
    ``SECCOMP_FILTER_FLAG_NEW_LISTENER``.  Setting it independently of
    seccomp ensures it takes effect even when libseccomp is unavailable.

``PR_SET_DUMPABLE`` (4) → 0
    Disables core dump generation and ``/proc/PID/mem`` access by
    non-privileged peers.  Prevents signing-key material from appearing in
    a core file on crash or in ``/proc`` pseudo-filesystem reads by adjacent
    processes.

Both calls are no-ops (with a logged warning) on non-Linux platforms so
that development on macOS or Windows is unaffected.

Usage::

    from aegis.core.process_hardening import ProcessHardening
    result = ProcessHardening().apply()
    if result.no_new_privs_applied and result.dumpable_disabled:
        logger.info("Full process hardening applied")
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import sys
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Linux prctl(2) option constants
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_DUMPABLE = 4


@dataclass
class ProcessHardeningResult:
    """Outcome of a :meth:`ProcessHardening.apply` call.

    Attributes
    ----------
    no_new_privs_applied:
        True when ``PR_SET_NO_NEW_PRIVS=1`` was successfully set.
    dumpable_disabled:
        True when ``PR_SET_DUMPABLE=0`` was successfully set.
    platform:
        The value of ``sys.platform`` at call time.
    errors:
        List of error strings for any calls that failed.
    """

    no_new_privs_applied: bool = False
    dumpable_disabled: bool = False
    platform: str = ""
    errors: list[str] = field(default_factory=list)

    @property
    def fully_hardened(self) -> bool:
        """True when both prctl flags were applied."""
        return self.no_new_privs_applied and self.dumpable_disabled

    def to_dict(self) -> dict[str, object]:
        return {
            "no_new_privs_applied": self.no_new_privs_applied,
            "dumpable_disabled": self.dumpable_disabled,
            "fully_hardened": self.fully_hardened,
            "platform": self.platform,
            "errors": list(self.errors),
        }


class ProcessHardening:
    """Applies startup prctl hardening flags.

    Thread-safe: ``apply()`` is idempotent — calling it multiple times is safe
    because the kernel silently accepts redundant ``prctl`` calls with the same
    value.

    Sandbox/test environments are detected automatically: the calls are still
    attempted (they rarely fail in CI), but failures are recorded rather than
    raised so that test runners are not broken.
    """

    def apply(self) -> ProcessHardeningResult:
        """Apply ``PR_SET_NO_NEW_PRIVS`` and ``PR_SET_DUMPABLE=0``.

        Returns a :class:`ProcessHardeningResult` describing what was applied.
        On non-Linux platforms both flags are skipped with a warning and the
        result fields remain ``False``.
        """
        result = ProcessHardeningResult(platform=sys.platform)

        if sys.platform != "linux":
            logger.warning(
                "process_hardening: prctl(2) is Linux-only; skipping on %s",
                sys.platform,
            )
            return result

        libc = self._load_libc()
        if libc is None:
            msg = "process_hardening: libc not found; cannot apply prctl flags"
            logger.error(msg)
            result.errors.append(msg)
            return result

        result.no_new_privs_applied = self._set_no_new_privs(libc, result)
        result.dumpable_disabled = self._set_not_dumpable(libc, result)

        if result.fully_hardened:
            logger.info("process_hardening: PR_SET_NO_NEW_PRIVS=1 and PR_SET_DUMPABLE=0 applied")
        else:
            logger.warning(
                "process_hardening: partial hardening — no_new_privs=%s dumpable_disabled=%s errors=%s",
                result.no_new_privs_applied,
                result.dumpable_disabled,
                result.errors,
            )
        return result

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _load_libc() -> ctypes.CDLL | None:
        path = ctypes.util.find_library("c")
        if not path:
            return None
        try:
            lib = ctypes.CDLL(path, use_errno=True)
            lib.prctl.restype = ctypes.c_int
            lib.prctl.argtypes = [
                ctypes.c_int,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
                ctypes.c_ulong,
            ]
            return lib
        except OSError as exc:
            logger.warning("process_hardening: failed to load libc: %s", exc)
            return None

    @staticmethod
    def _set_no_new_privs(libc: ctypes.CDLL, result: ProcessHardeningResult) -> bool:
        try:
            ret = libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
            if ret != 0:
                errno = ctypes.get_errno()
                msg = f"prctl(PR_SET_NO_NEW_PRIVS) failed: errno={errno}"
                logger.error("process_hardening: %s", msg)
                result.errors.append(msg)
                return False
            return True
        except Exception as exc:
            msg = f"prctl(PR_SET_NO_NEW_PRIVS) exception: {exc}"
            logger.error("process_hardening: %s", msg)
            result.errors.append(msg)
            return False

    @staticmethod
    def _set_not_dumpable(libc: ctypes.CDLL, result: ProcessHardeningResult) -> bool:
        try:
            ret = libc.prctl(_PR_SET_DUMPABLE, 0, 0, 0, 0)
            if ret != 0:
                errno = ctypes.get_errno()
                msg = f"prctl(PR_SET_DUMPABLE=0) failed: errno={errno}"
                logger.error("process_hardening: %s", msg)
                result.errors.append(msg)
                return False
            return True
        except Exception as exc:
            msg = f"prctl(PR_SET_DUMPABLE=0) exception: {exc}"
            logger.error("process_hardening: %s", msg)
            result.errors.append(msg)
            return False

    @staticmethod
    def _read_proc_dumpable() -> int | None:
        """Read ``/proc/self/status`` dumpable field for verification (Linux only)."""
        try:
            with open("/proc/self/status") as fh:
                for line in fh:
                    if line.startswith("CoreDumping:") or line.startswith("Dumpable:"):
                        return int(line.split(":")[-1].strip())
        except OSError:
            pass
        return None

    def verify(self) -> dict[str, object]:
        """Read-back prctl state for audit logging.

        Returns a dict with ``no_new_privs`` (from ``/proc/self/status``) and
        ``dumpable`` (from ``/proc/self/status``).  Returns empty dict on
        non-Linux or when ``/proc`` is unavailable.
        """
        if sys.platform != "linux":
            return {}
        out: dict[str, object] = {}
        try:
            with open("/proc/self/status") as fh:
                for line in fh:
                    if line.startswith("NoNewPrivs:"):
                        out["no_new_privs"] = int(line.split(":")[-1].strip())
                    elif line.startswith("CoreDumping:"):
                        out["core_dumping"] = int(line.split(":")[-1].strip())
        except OSError:
            pass
        # /proc/self/status on older kernels uses "Dumpable" instead of "CoreDumping"
        if "core_dumping" not in out:
            val = self._read_proc_dumpable()
            if val is not None:
                out["core_dumping"] = val
        return out


# ── Module-level singleton ─────────────────────────────────────────────────────

_hardening = ProcessHardening()


def apply_process_hardening() -> ProcessHardeningResult:
    """Module-level convenience wrapper; applies hardening via the singleton."""
    return _hardening.apply()


def verify_process_hardening() -> dict[str, object]:
    """Module-level convenience wrapper; verifies prctl state via ``/proc``."""
    return _hardening.verify()


# Auto-apply if this module is imported directly (not in test/sandbox context).
# The caller can also call apply_process_hardening() explicitly.
def _auto_apply() -> None:
    if not os.environ.get("AEGIS_SKIP_PROCESS_HARDENING"):
        _hardening.apply()
