# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.core.lsm_guard — Domain 1.5 Linux Security Module confinement guard.

Detects and reports AppArmor / SELinux status for the current process.
Provides helpers to load AppArmor profiles and assert enforcing mode at
startup.  All operations degrade gracefully on non-Linux systems or when
kernel interfaces are inaccessible due to permission restrictions.
"""

from __future__ import annotations

import logging
import os
import subprocess
import sys
from dataclasses import dataclass
from enum import StrEnum

logger = logging.getLogger(__name__)

# ── Constants ─────────────────────────────────────────────────────────────────

_APPARMOR_PROFILES = "/sys/kernel/security/apparmor/profiles"
_SELINUX_ENFORCE = "/sys/fs/selinux/enforce"
_PROC_SELF_ATTR = "/proc/self/attr/current"

# ── Enumerations ──────────────────────────────────────────────────────────────


class LSMType(StrEnum):
    APPARMOR = "apparmor"
    SELINUX = "selinux"
    NONE = "none"


# ── Data types ────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class LSMStatus:
    """Immutable snapshot of the system LSM state."""

    lsm_type: LSMType
    active: bool
    mode: str
    profile: str | None
    context: str | None

    def to_dict(self) -> dict:
        return {
            "lsm_type": self.lsm_type.value,
            "active": self.active,
            "mode": self.mode,
            "profile": self.profile,
            "context": self.context,
        }


# ── Core class ────────────────────────────────────────────────────────────────


class LSMGuard:
    """
    Linux Security Module confinement guard.

    All methods are static and never raise — callers receive a safe default
    value or a degraded :class:`LSMStatus` on any error.
    """

    @staticmethod
    def detect() -> LSMStatus:
        """
        Probe the running kernel for active LSM confinement.

        Checks AppArmor first (via ``/sys/kernel/security/apparmor/profiles``),
        then SELinux (via ``/sys/fs/selinux/enforce``).  Returns an
        :class:`LSMStatus` with ``lsm_type=LSMType.NONE`` when neither is
        detected or on non-Linux platforms.
        """
        if sys.platform != "linux":
            return LSMStatus(
                lsm_type=LSMType.NONE,
                active=False,
                mode="disabled",
                profile=None,
                context=None,
            )

        try:
            if os.path.exists(_APPARMOR_PROFILES):
                profile = LSMGuard.get_apparmor_profile_name()
                mode = "enforcing"
                try:
                    if os.path.exists("/sys/module/apparmor/parameters/enabled"):
                        with open("/sys/module/apparmor/parameters/enabled") as fh:
                            enabled = fh.read().strip()
                        mode = "enforcing" if enabled == "Y" else "permissive"
                except OSError:
                    mode = "unknown"
                return LSMStatus(
                    lsm_type=LSMType.APPARMOR,
                    active=True,
                    mode=mode,
                    profile=profile,
                    context=None,
                )
        except OSError:
            pass

        try:
            if os.path.exists(_SELINUX_ENFORCE):
                with open(_SELINUX_ENFORCE) as fh:
                    enforce_val = fh.read().strip()
                if enforce_val == "1":
                    selinux_mode = "enforcing"
                    selinux_active = True
                elif enforce_val == "0":
                    selinux_mode = "permissive"
                    selinux_active = True
                else:
                    selinux_mode = "disabled"
                    selinux_active = False
                return LSMStatus(
                    lsm_type=LSMType.SELINUX,
                    active=selinux_active,
                    mode=selinux_mode,
                    profile=None,
                    context=LSMGuard.get_selinux_context(),
                )
        except OSError:
            pass

        return LSMStatus(
            lsm_type=LSMType.NONE,
            active=False,
            mode="disabled",
            profile=None,
            context=None,
        )

    @staticmethod
    def is_apparmor_active() -> bool:
        """Return ``True`` when AppArmor profiles directory is present."""
        try:
            return sys.platform == "linux" and os.path.exists(_APPARMOR_PROFILES)
        except OSError:
            return False

    @staticmethod
    def is_selinux_enforcing() -> bool:
        """Return ``True`` when SELinux enforce file reports ``1``."""
        try:
            if sys.platform != "linux":
                return False
            if not os.path.exists(_SELINUX_ENFORCE):
                return False
            with open(_SELINUX_ENFORCE) as fh:
                return fh.read().strip() == "1"
        except OSError:
            return False

    @staticmethod
    def load_apparmor_profile(profile_path: str) -> bool:
        """
        Reload an AppArmor profile via ``apparmor_parser -r``.

        Returns ``True`` on success, ``False`` when ``apparmor_parser`` is not
        found or the reload fails.  Never raises.
        """
        try:
            result = subprocess.run(  # nosec B603 B607 — trusted system binary, not user input
                ["apparmor_parser", "-r", profile_path],
                capture_output=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info("AppArmor profile reloaded: %s", profile_path)
                return True
            logger.warning(
                "apparmor_parser returned %d for %s: %s",
                result.returncode,
                profile_path,
                result.stderr.decode(errors="replace").strip(),
            )
            return False
        except FileNotFoundError:
            logger.debug("apparmor_parser not found — profile reload skipped")
            return False
        except Exception as exc:
            logger.warning("AppArmor profile load failed: %s", exc)
            return False

    @staticmethod
    def get_apparmor_profile_name() -> str | None:
        """
        Read the AppArmor label of the current process from
        ``/proc/self/attr/current``.

        Returns ``None`` when the file is absent, unreadable, or the label
        indicates an unconfined process.
        """
        try:
            with open(_PROC_SELF_ATTR, "rb") as fh:
                raw = fh.read().rstrip(b"\x00\n")
            label = raw.decode(errors="replace")
            if label.lower().startswith("unconfined"):
                return None
            return label if label else None
        except OSError:
            return None

    @staticmethod
    def get_selinux_context() -> str | None:
        """
        Read the SELinux context of the current process from
        ``/proc/self/attr/current``.

        Returns ``None`` when the file is absent or unreadable.  On an
        AppArmor-only system the attribute file may contain an AppArmor label
        instead; callers should only trust this value after confirming SELinux
        is active.
        """
        try:
            with open(_PROC_SELF_ATTR, "rb") as fh:
                raw = fh.read().rstrip(b"\x00\n")
            label = raw.decode(errors="replace")
            return label if label else None
        except OSError:
            return None

    @staticmethod
    def assert_enforcing_or_warn() -> None:
        """
        Emit a ``WARNING`` log when no enforcing LSM is detected.

        Intended to be called once at application startup so operators are
        alerted when the process runs without mandatory access control.
        """
        status = LSMGuard.detect()
        if not status.active or status.mode not in ("enforcing",):
            logger.warning(
                "LSM confinement not enforcing — lsm_type=%s mode=%s; "
                "process is running in DAC-only mode",
                status.lsm_type.value,
                status.mode,
            )
        else:
            logger.info(
                "LSM confinement active — lsm_type=%s mode=%s",
                status.lsm_type.value,
                status.mode,
            )
