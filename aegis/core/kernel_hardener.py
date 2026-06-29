"""
aegis.core.kernel_hardener — Kernel-Level Security Enforcement.
Verifies and enforces Secure Boot and Kernel Lockdown states.

This module provides production-grade kernel security verification including:
- Secure Boot status detection via multiple methods
- Kernel lockdown mode verification
- Fail-secure behavior when hardware security features are unavailable
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
import os
import subprocess
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LockdownState:
    enabled: bool
    mode: str  # 'none', 'integrity', 'confidentiality'
    policy: str


class KernelHardenerError(Exception):
    """Exception raised when kernel hardening requirements are not met."""

    pass


class KernelHardener:
    """
    Enforces Kernel Lockdown and Secure Boot requirements for the Aegis runtime.

    This class provides comprehensive kernel security verification:
    - Secure Boot status via mokutil, bootctl, or direct EFI variable reading
    - Kernel lockdown mode via /sys/kernel/security/lockdown
    - Fail-secure behavior when required security features are absent

    The system will fail closed (raise exceptions) if required security
    features are not present and fail_secure=True.
    """

    LOCKDOWN_PATH = "/sys/kernel/security/lockdown"
    SECURE_BOOT_PATH = "/sys/firmware/efi/efivars"
    MokutilPath = "/usr/bin/mokutil"

    def __init__(self, required_mode: str = "integrity", fail_secure: bool = True):
        """
        Initialize the Kernel Hardener.

        Args:
            required_mode: Required lockdown mode ('integrity' or 'confidentiality').
            fail_secure: If True, raise exception when security requirements aren't met.
                        If False, log warnings and return False.
        """
        self.required_mode = required_mode
        self.fail_secure = fail_secure

    def _read_efi_variable(self, var_name: str, guid: str) -> bytes | None:
        """
        Read an EFI variable from sysfs.

        Args:
            var_name: Name of the EFI variable.
            guid: GUID of the EFI variable namespace.

        Returns:
            Raw bytes of the variable content, or None if unreadable.
        """
        try:
            # EFI variables have a 4-byte header before the actual data
            path = f"{self.SECURE_BOOT_PATH}/{var_name}-{guid}"
            with open(path, "rb") as f:
                data = f.read()
                # Skip the first 4 bytes (attributes header)
                return data[4:] if len(data) > 4 else data
        except (FileNotFoundError, PermissionError, OSError):
            return None

    def check_secure_boot(self) -> tuple[bool, str]:
        """
        Checks if Secure Boot is enabled using multiple detection methods.

        Detection methods tried in order:
        1. mokutil --sb-state (if available)
        2. bootctl status (systemd-boot)
        3. Direct EFI variable reading

        Returns:
            Tuple of (is_enabled: bool, message: str)

        Raises:
            KernelHardenerError: If Secure Boot is not detected and fail_secure=True.
        """
        # Method 1: Try mokutil (most reliable on most distros)
        if os.path.exists(self.MokutilPath):
            try:
                result = subprocess.run(
                    [self.MokutilPath, "--sb-state"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    if "SecureBoot enabled" in result.stdout:
                        return True, "Secure Boot enabled (verified via mokutil)"
                    elif "SecureBoot disabled" in result.stdout:
                        msg = "Secure Boot is disabled"
                        if self.fail_secure:
                            raise KernelHardenerError(msg)
                        return False, msg
            except (subprocess.TimeoutExpired, Exception) as e:
                logger.warning("mokutil check failed: %s", e)

        # Method 2: Try bootctl (systemd-boot)
        try:
            result = subprocess.run(
                ["bootctl", "status"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                if "Secure Boot: enabled" in result.stdout:
                    return True, "Secure Boot enabled (verified via bootctl)"
                elif "Secure Boot: disabled" in result.stdout:
                    msg = "Secure Boot is disabled"
                    if self.fail_secure:
                        raise KernelHardenerError(msg)
                    return False, msg
        except (subprocess.TimeoutExpired, FileNotFoundError, Exception) as e:
            logger.debug("bootctl check failed or unavailable: %s", e)

        # Method 3: Direct EFI variable reading
        # SecureBoot EFI variable: GUID 8be4df61-93ca-11d2-aa0d-00e098032b8c
        secure_boot_guid = "8be4df61-93ca-11d2-aa0d-00e098032b8c"
        sb_data = self._read_efi_variable("SecureBoot", secure_boot_guid)

        if sb_data is not None:
            # SecureBoot=1 means enabled, SecureBoot=0 means disabled
            is_enabled = sb_data[-1] == 1 if len(sb_data) >= 1 else False
            if is_enabled:
                return True, "Secure Boot enabled (verified via EFI variable)"
            else:
                msg = "Secure Boot is disabled (EFI variable reads 0)"
                if self.fail_secure:
                    raise KernelHardenerError(msg)
                return False, msg

        # Method 4: Check for EFI vars directory existence as fallback
        if not os.path.exists(self.SECURE_BOOT_PATH):
            msg = "UEFI firmware not detected (no EFI variables found)"
            if self.fail_secure:
                raise KernelHardenerError(msg)
            return False, msg

        # If we reach here, EFI vars exist but we couldn't determine Secure Boot state
        logger.warning(
            "Could not definitively determine Secure Boot state. Assuming disabled for safety."
        )
        msg = "Secure Boot state undetermined; failing closed"
        if self.fail_secure:
            raise KernelHardenerError(msg)
        return False, msg

    def check_kernel_lockdown(self) -> LockdownState:
        """
        Reads the current kernel lockdown state from sysfs.

        Returns:
            LockdownState dataclass with enabled status, mode, and policy.
        """
        try:
            if not os.path.exists(self.LOCKDOWN_PATH):
                return LockdownState(enabled=False, mode="none", policy="Not Supported")

            with open(self.LOCKDOWN_PATH) as f:
                content = f.read().strip()
                # Format is usually: "[none] integrity confidentiality"
                # The one in brackets is the active one.
                if "[integrity]" in content:
                    return LockdownState(enabled=True, mode="integrity", policy="Integrity")
                elif "[confidentiality]" in content:
                    return LockdownState(
                        enabled=True, mode="confidentiality", policy="Confidentiality"
                    )
                else:
                    return LockdownState(enabled=False, mode="none", policy="None")
        except Exception as e:
            logger.error("Failed to read kernel lockdown state: %s", e)
            return LockdownState(enabled=False, mode="none", policy="Error")

    def enforce_hardening(self) -> bool:
        """
        Strictly validates that the system meets the minimum security baseline.

        Verifies:
        1. Secure Boot is enabled
        2. Kernel lockdown is in the required mode or stricter

        Returns:
            True if all checks pass, False otherwise.

        Raises:
            KernelHardenerError: If any check fails and fail_secure=True.
        """
        sb_ok, sb_msg = self.check_secure_boot()
        lockdown = self.check_kernel_lockdown()

        logger.info("Secure Boot: %s", sb_msg)
        logger.info("Kernel Lockdown: %s (%s)", lockdown.mode, lockdown.policy)

        # Validate lockdown mode meets requirements
        mode_hierarchy = {"none": 0, "integrity": 1, "confidentiality": 2}
        required_level = mode_hierarchy.get(self.required_mode, 1)
        current_level = mode_hierarchy.get(lockdown.mode, 0)

        if current_level < required_level:
            msg = (
                f"Kernel lockdown mode '{lockdown.mode}' does not meet "
                f"required level '{self.required_mode}'"
            )
            logger.critical(msg)
            if self.fail_secure:
                raise KernelHardenerError(msg)
            return False

        if not sb_ok:
            msg = f"Secure Boot requirement not met: {sb_msg}"
            logger.critical(msg)
            if self.fail_secure:
                raise KernelHardenerError(msg)
            return False

        logger.info(
            "Kernel hardening validation PASSED. "
            "System meets security baseline: Secure Boot=%s, Lockdown=%s",
            sb_ok,
            lockdown.mode,
        )
        return True

    def get_security_status(self) -> dict:
        """
        Get comprehensive kernel security status.

        Returns:
            Dictionary with detailed security posture information.
        """
        sb_ok, sb_msg = self.check_secure_boot()
        lockdown = self.check_kernel_lockdown()

        return {
            "secure_boot": {
                "enabled": sb_ok,
                "message": sb_msg,
            },
            "kernel_lockdown": {
                "enabled": lockdown.enabled,
                "mode": lockdown.mode,
                "policy": lockdown.policy,
                "required_mode": self.required_mode,
                "meets_requirement": lockdown.enabled
                and (
                    lockdown.mode == self.required_mode
                    or (lockdown.mode == "confidentiality" and self.required_mode == "integrity")
                ),
            },
            "fail_secure_mode": self.fail_secure,
        }

        logger.info("--- Kernel Hardening Audit ---")
        logger.info("Secure Boot: %s (%s)", "OK" if sb_ok else "FAIL", sb_msg)
        logger.info("Lockdown Mode: %s", lockdown.mode)

        if not sb_ok:
            logger.warning("System is NOT running with Secure Boot. Risk of bootkit persistence.")
            # For high-security mode, this should return False and halt the app.

        if lockdown.mode == "none" and self.required_mode != "none":
            logger.error(
                "CRITICAL: Kernel Lockdown is DISABLED. Root user can modify kernel memory."
            )
            return False

        if lockdown.mode == "integrity" and self.required_mode == "confidentiality":
            logger.error(
                "CRITICAL: Lockdown mode 'integrity' is insufficient. 'confidentiality' required."
            )
            return False

        logger.info("Kernel Hardening verified. Baseline met.")
        return True


# Singleton instance for the system
hardener = KernelHardener(required_mode="integrity")
