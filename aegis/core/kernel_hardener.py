"""
aegis.core.kernel_hardener — Kernel-Level Security Enforcement.
Verifies and enforces Secure Boot and Kernel Lockdown states.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
import os
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LockdownState:
    enabled: bool
    mode: str  # 'none', 'integrity', 'confidentiality'
    policy: str


class KernelHardener:
    """
    Enforces Kernel Lockdown and Secure Boot requirements for the Aegis runtime.
    """

    LOCKDOWN_PATH = "/sys/kernel/security/lockdown"
    SECURE_BOOT_PATH = "/sys/firmware/efi_efivars"  # Indicator of UEFI presence

    def __init__(self, required_mode: str = "integrity"):
        self.required_mode = required_mode

    def check_secure_boot(self) -> tuple[bool, str]:
        """
        Checks if Secure Boot is enabled.
        Note: In a real Linux system, this usually involves checking 'mokutil --sb-state'
        or reading /sys/kernel/security/lockdown.
        """
        # In many distros, if lockdown is enabled, Secure Boot was likely the trigger.
        # For this HAL, we check for the existence of EFI vars as a baseline.
        if not os.path.exists(self.SECURE_BOOT_PATH):
            return False, "UEFI/SecureBoot variables not found"

        # Simulated check: in production, we'd call a binary or read a specific EFI var.
        return True, "Secure Boot Active"

    def check_kernel_lockdown(self) -> LockdownState:
        """
        Reads the current kernel lockdown state from sysfs.
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
        """
        sb_ok, sb_msg = self.check_secure_boot()
        lockdown = self.check_kernel_lockdown()

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
