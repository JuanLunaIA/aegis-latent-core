# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.cgroups_quota — cgroups v2 memory and CPU quota enforcement.

Enforces per-process memory and CPU quotas by writing directly to the
cgroups v2 (unified hierarchy) filesystem at ``/sys/fs/cgroup``.

This is distinct from container-level quotas (OCI runtime, Kubernetes):
process-level enforcement provides defence-in-depth when the container
runtime quota is absent, misconfigured, or bypassed.

Cgroups v2 API
--------------
``memory.max``
    Maximum resident memory in bytes.  Write "``N``" to set; write
    "``max``" to remove the limit.  Writes to the process's own cgroup
    path, derived from ``/proc/self/cgroup`` (``0::<path>`` format).

``cpu.max``
    Maximum CPU bandwidth: "``<quota_us> <period_us>``".
    ``200000 100000`` → 2 CPUs; ``50000 100000`` → 0.5 CPUs.
    Write "``max 100000``" to remove the quota.

Configuration
-------------
``AEGIS_CGROUP_MEMORY_MAX``
    Maximum resident memory for the proxy process (bytes).
    Default: ``2147483648`` (2 GiB).  Set to ``0`` to disable.

``AEGIS_CGROUP_CPU_MAX``
    Maximum CPU cores (fractional).  Default: ``2.0``.
    Converted to ``cpu.max`` as ``int(cpu_max × period) period``.
    Set to ``0`` to disable.

``AEGIS_SKIP_CGROUPS_QUOTA``
    Set to any non-empty value to skip cgroup quota enforcement (CI, macOS).

Usage::

    from aegis.core.cgroups_quota import CgroupsQuota
    result = CgroupsQuota().apply(memory_max_bytes=2 * 1024**3, cpu_max_cores=2.0)
    if result.applied:
        logger.info("cgroups v2 quotas applied: %s", result.to_dict())
"""

from __future__ import annotations

import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_CGROUP_MOUNT = Path("/sys/fs/cgroup")
_PROC_SELF_CGROUP = Path("/proc/self/cgroup")
_CPU_PERIOD_US = 100_000  # 100ms scheduling period


@dataclass
class CgroupsQuotaResult:
    """Outcome of a :meth:`CgroupsQuota.apply` call.

    Attributes
    ----------
    cgroups_v2_detected:
        True when ``/sys/fs/cgroup`` is present and using the unified hierarchy.
    cgroup_path:
        The process's own cgroup path (relative to ``/sys/fs/cgroup``),
        or empty string if detection failed.
    memory_max_applied:
        True when the memory limit was written successfully.
    cpu_max_applied:
        True when the CPU quota was written successfully.
    memory_max_bytes:
        The requested memory limit in bytes (0 = no limit applied).
    cpu_max_cores:
        The requested CPU limit in fractional cores (0 = no limit applied).
    platform:
        ``sys.platform`` at call time.
    errors:
        List of error strings from failed operations.
    skipped:
        True when enforcement was intentionally skipped (env var override,
        non-Linux, or no cgroups v2).
    """

    cgroups_v2_detected: bool = False
    cgroup_path: str = ""
    memory_max_applied: bool = False
    cpu_max_applied: bool = False
    memory_max_bytes: int = 0
    cpu_max_cores: float = 0.0
    platform: str = ""
    errors: list[str] = field(default_factory=list)
    skipped: bool = False

    @property
    def applied(self) -> bool:
        """True when at least one quota was applied."""
        return self.memory_max_applied or self.cpu_max_applied

    @property
    def fully_applied(self) -> bool:
        """True when both requested quotas were applied."""
        requested_memory = self.memory_max_bytes > 0
        requested_cpu = self.cpu_max_cores > 0.0
        mem_ok = (not requested_memory) or self.memory_max_applied
        cpu_ok = (not requested_cpu) or self.cpu_max_applied
        return mem_ok and cpu_ok

    def to_dict(self) -> dict[str, object]:
        return {
            "cgroups_v2_detected": self.cgroups_v2_detected,
            "cgroup_path": self.cgroup_path,
            "memory_max_applied": self.memory_max_applied,
            "cpu_max_applied": self.cpu_max_applied,
            "memory_max_bytes": self.memory_max_bytes,
            "cpu_max_cores": self.cpu_max_cores,
            "applied": self.applied,
            "fully_applied": self.fully_applied,
            "platform": self.platform,
            "errors": list(self.errors),
            "skipped": self.skipped,
        }


class CgroupsQuota:
    """Applies cgroups v2 memory and CPU quotas to the current process.

    All operations gracefully fall back on errors so proxy startup is
    never blocked by a missing cgroup or permission issue.
    """

    def apply(
        self,
        memory_max_bytes: int = 2 * 1024**3,
        cpu_max_cores: float = 2.0,
    ) -> CgroupsQuotaResult:
        """Write memory and CPU quotas to the current process's cgroup.

        Parameters
        ----------
        memory_max_bytes:
            Memory limit in bytes.  Pass ``0`` to skip.
        cpu_max_cores:
            CPU limit in fractional cores (e.g. ``2.0`` = 2 CPUs).
            Pass ``0.0`` to skip.

        Returns
        -------
        CgroupsQuotaResult
            Detailed outcome of every operation.
        """
        result = CgroupsQuotaResult(
            platform=sys.platform,
            memory_max_bytes=memory_max_bytes,
            cpu_max_cores=cpu_max_cores,
        )

        if os.environ.get("AEGIS_SKIP_CGROUPS_QUOTA"):
            result.skipped = True
            logger.debug("cgroups_quota: skipped via AEGIS_SKIP_CGROUPS_QUOTA")
            return result

        if sys.platform != "linux":
            result.skipped = True
            logger.debug("cgroups_quota: cgroups v2 is Linux-only; skipping on %s", sys.platform)
            return result

        cgroup_dir = self._detect_cgroup_dir(result)
        if cgroup_dir is None:
            result.skipped = True
            return result

        if memory_max_bytes > 0:
            result.memory_max_applied = self._write_memory_max(cgroup_dir, memory_max_bytes, result)

        if cpu_max_cores > 0.0:
            result.cpu_max_applied = self._write_cpu_max(cgroup_dir, cpu_max_cores, result)

        if result.applied:
            logger.info(
                "cgroups_quota: applied — memory_max=%d bytes cpu_max=%.2f cores cgroup=%s",
                memory_max_bytes,
                cpu_max_cores,
                result.cgroup_path,
            )
        elif result.errors:
            logger.warning(
                "cgroups_quota: no quotas applied — errors: %s",
                result.errors,
            )
        return result

    # ── Quota readers (non-destructive) ──────────────────────────────────────

    @staticmethod
    def read_memory_current(cgroup_path: str = "") -> int | None:
        """Read the current memory usage from ``memory.current`` (bytes).

        Parameters
        ----------
        cgroup_path:
            Relative cgroup path (e.g. ``"/system.slice/aegis.service"``).
            Auto-detected from ``/proc/self/cgroup`` when empty.

        Returns ``None`` when unavailable.
        """
        if not cgroup_path:
            cgroup_path = CgroupsQuota._read_proc_self_cgroup()
        if not cgroup_path:
            return None
        p = _CGROUP_MOUNT / cgroup_path.lstrip("/") / "memory.current"
        try:
            return int(p.read_text().strip())
        except (OSError, ValueError):
            return None

    @staticmethod
    def read_cpu_stat(cgroup_path: str = "") -> dict[str, int]:
        """Read ``cpu.stat`` counters as a dict (``usage_usec``, ``user_usec``, etc.).

        Returns an empty dict when unavailable.
        """
        if not cgroup_path:
            cgroup_path = CgroupsQuota._read_proc_self_cgroup()
        if not cgroup_path:
            return {}
        p = _CGROUP_MOUNT / cgroup_path.lstrip("/") / "cpu.stat"
        try:
            out: dict[str, int] = {}
            for line in p.read_text().splitlines():
                parts = line.split()
                if len(parts) == 2:
                    out[parts[0]] = int(parts[1])
            return out
        except (OSError, ValueError):
            return {}

    # ── Detection ─────────────────────────────────────────────────────────────

    def _detect_cgroup_dir(self, result: CgroupsQuotaResult) -> Path | None:
        """Return the absolute path to the process's cgroup dir, or None."""
        if not _CGROUP_MOUNT.exists():
            msg = "cgroups_quota: /sys/fs/cgroup not found (cgroups v2 not mounted)"
            logger.debug(msg)
            result.errors.append(msg)
            return None

        # Verify unified hierarchy (v2): root cgroup has cgroup.controllers
        if not (_CGROUP_MOUNT / "cgroup.controllers").exists():
            msg = "cgroups_quota: cgroup.controllers not found — may be cgroups v1 or hybrid mode"
            logger.debug(msg)
            result.errors.append(msg)
            return None

        result.cgroups_v2_detected = True

        cgroup_rel = self._read_proc_self_cgroup()
        if not cgroup_rel:
            msg = "cgroups_quota: could not determine process cgroup from /proc/self/cgroup"
            logger.warning(msg)
            result.errors.append(msg)
            return None

        result.cgroup_path = cgroup_rel
        cgroup_dir = _CGROUP_MOUNT / cgroup_rel.lstrip("/")
        if not cgroup_dir.exists():
            msg = f"cgroups_quota: cgroup directory not found: {cgroup_dir}"
            logger.warning(msg)
            result.errors.append(msg)
            return None

        return cgroup_dir

    @staticmethod
    def _read_proc_self_cgroup() -> str:
        """Parse ``/proc/self/cgroup`` and return the cgroup path for the unified hierarchy."""
        try:
            for line in _PROC_SELF_CGROUP.read_text().splitlines():
                parts = line.split(":", 2)
                if len(parts) == 3 and parts[0] == "0":
                    return parts[2]  # unified hierarchy path (e.g. "/system.slice/aegis")
        except OSError:
            pass
        return ""

    # ── Writers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _write_memory_max(
        cgroup_dir: Path, memory_max_bytes: int, result: CgroupsQuotaResult
    ) -> bool:
        memory_max_file = cgroup_dir / "memory.max"
        try:
            memory_max_file.write_text(str(memory_max_bytes))
            logger.debug("cgroups_quota: memory.max set to %d bytes", memory_max_bytes)
            return True
        except PermissionError:
            msg = (
                f"cgroups_quota: permission denied writing memory.max "
                f"(need write access to {memory_max_file})"
            )
            logger.debug(msg)
            result.errors.append(msg)
            return False
        except OSError as exc:
            msg = f"cgroups_quota: failed to write memory.max: {exc}"
            logger.warning(msg)
            result.errors.append(msg)
            return False

    @staticmethod
    def _write_cpu_max(cgroup_dir: Path, cpu_max_cores: float, result: CgroupsQuotaResult) -> bool:
        cpu_max_file = cgroup_dir / "cpu.max"
        quota_us = int(cpu_max_cores * _CPU_PERIOD_US)
        value = f"{quota_us} {_CPU_PERIOD_US}"
        try:
            cpu_max_file.write_text(value)
            logger.debug("cgroups_quota: cpu.max set to %s (%.2f cores)", value, cpu_max_cores)
            return True
        except PermissionError:
            msg = (
                f"cgroups_quota: permission denied writing cpu.max "
                f"(need write access to {cpu_max_file})"
            )
            logger.debug(msg)
            result.errors.append(msg)
            return False
        except OSError as exc:
            msg = f"cgroups_quota: failed to write cpu.max: {exc}"
            logger.warning(msg)
            result.errors.append(msg)
            return False


# ── Module-level singleton ────────────────────────────────────────────────────

_quota = CgroupsQuota()


def apply_cgroups_quota(
    memory_max_bytes: int | None = None,
    cpu_max_cores: float | None = None,
) -> CgroupsQuotaResult:
    """Apply cgroups v2 quotas from environment variables or explicit parameters.

    Environment variables override explicit parameters when present:

    ``AEGIS_CGROUP_MEMORY_MAX``
        Memory limit in bytes (``0`` = disabled).
    ``AEGIS_CGROUP_CPU_MAX``
        CPU limit in fractional cores (``0`` = disabled).

    Parameters take effect when the environment variable is unset.
    Defaults: 2 GiB memory, 2.0 CPU cores.
    """
    env_mem = os.environ.get("AEGIS_CGROUP_MEMORY_MAX")
    env_cpu = os.environ.get("AEGIS_CGROUP_CPU_MAX")

    if env_mem is not None:
        try:
            memory_max_bytes = int(env_mem)
        except ValueError:
            logger.warning(
                "cgroups_quota: invalid AEGIS_CGROUP_MEMORY_MAX=%r; using default", env_mem
            )

    if env_cpu is not None:
        try:
            cpu_max_cores = float(env_cpu)
        except ValueError:
            logger.warning("cgroups_quota: invalid AEGIS_CGROUP_CPU_MAX=%r; using default", env_cpu)

    if memory_max_bytes is None:
        memory_max_bytes = 2 * 1024**3
    if cpu_max_cores is None:
        cpu_max_cores = 2.0

    return _quota.apply(memory_max_bytes=memory_max_bytes, cpu_max_cores=cpu_max_cores)


def is_cgroups_v2_available() -> bool:
    """Return True when cgroups v2 is mounted at ``/sys/fs/cgroup``."""
    return sys.platform == "linux" and (_CGROUP_MOUNT / "cgroup.controllers").exists()
