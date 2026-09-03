"""
aegis.core.build_hardener — Binary Hardening Orchestrator.
Ensures that all binaries are compiled with a strict security profile.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
import shutil

from aegis.core.cfi_manager import CFIManager

logger = logging.getLogger(__name__)


class BuildHardenerError(Exception):
    """Exception raised when binary hardening validation fails."""

    pass


class BuildHardener:
    """
    Validates that the production binaries meet the 'Inexpugnable' hardening standards.

    This class performs comprehensive binary security audits including:
    - Control Flow Integrity (CFI) verification
    - Full RELRO (RELocation Read-Only) verification
    - Stack canary protection verification
    - PIE (Position Independent Executable) verification
    """

    def __init__(self, fail_secure: bool = True):
        """
        Initialize the Build Hardener.

        Args:
            fail_secure: If True, raise exception on validation failure.
                        If False, log warnings and return False.
        """
        self.cfi = CFIManager()
        self.fail_secure = fail_secure

    def validate_binary_integrity(self, binary_path: str) -> bool:
        """
        Performs a full hardening audit of the binary.

        Args:
            binary_path: Path to the binary to audit.

        Returns:
            True if binary passes all hardening checks, False otherwise.

        Raises:
            BuildHardenerError: If validation fails and fail_secure=True.
        """
        logger.info("Starting binary hardening audit for: %s", binary_path)

        # 1. Verify CFI
        cfi_ok, msg = self.cfi.verify_binary_cfi(binary_path)
        if not cfi_ok:
            error_msg = f"Binary Hardening FAILURE: CFI check failed - {msg}"
            logger.critical(error_msg)
            if self.fail_secure:
                raise BuildHardenerError(error_msg)
            return False

        # 2. Verify Full RELRO (RELocation Read-Only)
        logger.info("Verifying Full RELRO (RELocation Read-Only)...")
        relro_ok, relro_msg = self._verify_relro(binary_path)
        if not relro_ok:
            error_msg = f"Binary Hardening FAILURE: RELRO check failed - {relro_msg}"
            logger.critical(error_msg)
            if self.fail_secure:
                raise BuildHardenerError(error_msg)
            return False

        # 3. Verify Stack Canary Protection
        logger.info("Verifying Stack Canary protection...")
        canary_ok, canary_msg = self._verify_stack_canary(binary_path)
        if not canary_ok:
            error_msg = f"Binary Hardening FAILURE: Stack canary check failed - {canary_msg}"
            logger.critical(error_msg)
            if self.fail_secure:
                raise BuildHardenerError(error_msg)
            return False

        # 4. Verify PIE (Position Independent Executable)
        logger.info("Verifying PIE (Position Independent Executable)...")
        pie_ok, pie_msg = self._verify_pie(binary_path)
        if not pie_ok:
            error_msg = f"Binary Hardening FAILURE: PIE check failed - {pie_msg}"
            logger.critical(error_msg)
            if self.fail_secure:
                raise BuildHardenerError(error_msg)
            return False

        logger.info(
            "Binary hardening audit PASSED. Binary is resistant to ROP/JOP/GOT overwrite attacks."
        )
        return True

    def _verify_relro(self, binary_path: str) -> tuple[bool, str]:
        """
        Verify that the binary has Full RELRO enabled.

        Full RELRO makes the GOT (Global Offset Table) read-only after relocation,
        preventing GOT overwrite attacks.

        Args:
            binary_path: Path to the binary to check.

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            import subprocess  # nosec B404 - subprocess is required to probe host hardening state; every call site uses a fixed argv list, never a shell

            # Check for GNU_RELRO segment and BIND_NOW flag
            result = subprocess.run(  # nosec B603 - argv list built from literals and configuration, never from request data; shell=False throughout
                [shutil.which("readelf") or "readelf", "-l", binary_path],
                capture_output=True,
                text=True,
                timeout=10,
            )

            has_relro = "GNU_RELRO" in result.stdout

            # Check for BIND_NOW in dynamic section
            result_dyn = subprocess.run(  # nosec B603 - argv list built from literals and configuration, never from request data; shell=False throughout
                [shutil.which("readelf") or "readelf", "-d", binary_path],
                capture_output=True,
                text=True,
                timeout=10,
            )
            has_bind_now = (
                "BIND_NOW" in result_dyn.stdout
                or "(FLAGS)" in result_dyn.stdout
                and "NOW" in result_dyn.stdout
            )

            if has_relro and has_bind_now:
                return True, "Full RELRO enabled (GNU_RELRO + BIND_NOW)"
            elif has_relro:
                return False, "Partial RELRO only (missing BIND_NOW flag)"
            else:
                return False, "No RELRO protection found"

        except FileNotFoundError:
            logger.warning("readelf not found; cannot verify RELRO. Install binutils.")
            return False, "readelf tool not available"
        except subprocess.TimeoutExpired:
            return False, "RELRO verification timed out"
        except Exception as e:
            logger.error("RELRO verification error: %s", e)
            return False, str(e)

    def _verify_stack_canary(self, binary_path: str) -> tuple[bool, str]:
        """
        Verify that the binary has stack canary protection enabled.

        Stack canaries detect buffer overflows before they can corrupt the return address.

        Args:
            binary_path: Path to the binary to check.

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            import subprocess  # nosec B404 - subprocess is required to probe host hardening state; every call site uses a fixed argv list, never a shell

            # Check for __stack_chk_fail symbol which indicates stack canary usage
            result = subprocess.run(  # nosec B603 - argv list built from literals and configuration, never from request data; shell=False throughout
                [shutil.which("nm") or "nm", "-D", binary_path],
                capture_output=True,
                text=True,
                timeout=10,
            )

            has_canary = "__stack_chk_fail" in result.stdout

            if has_canary:
                return True, "Stack canary protection enabled (__stack_chk_fail present)"
            else:
                return False, "No stack canary protection detected (__stack_chk_fail missing)"

        except FileNotFoundError:
            logger.warning("nm not found; cannot verify stack canary. Install binutils.")
            return False, "nm tool not available"
        except subprocess.TimeoutExpired:
            return False, "Stack canary verification timed out"
        except Exception as e:
            logger.error("Stack canary verification error: %s", e)
            return False, str(e)

    def _verify_pie(self, binary_path: str) -> tuple[bool, str]:
        """
        Verify that the binary is a Position Independent Executable (PIE).

        PIE enables ASLR for the entire binary, making memory addresses unpredictable.

        Args:
            binary_path: Path to the binary to check.

        Returns:
            Tuple of (success: bool, message: str)
        """
        try:
            import subprocess  # nosec B404 - subprocess is required to probe host hardening state; every call site uses a fixed argv list, never a shell

            # Check if binary type is DYN (shared object / PIE)
            result = subprocess.run(  # nosec B603 - argv list built from literals and configuration, never from request data; shell=False throughout
                [shutil.which("file") or "file", binary_path],
                capture_output=True,
                text=True,
                timeout=10,
            )

            is_pie = "pie" in result.stdout.lower() or "shared object" in result.stdout.lower()

            # Also verify with readelf header
            result_header = subprocess.run(  # nosec B603 - argv list built from literals and configuration, never from request data; shell=False throughout
                [shutil.which("readelf") or "readelf", "-h", binary_path],
                capture_output=True,
                text=True,
                timeout=10,
            )

            # Type should be DYN for PIE
            has_dyn_type = "Type:" in result_header.stdout and "DYN" in result_header.stdout

            if is_pie or has_dyn_type:
                return True, "PIE enabled (Position Independent Executable)"
            else:
                return False, "PIE not enabled (binary is not position independent)"

        except FileNotFoundError:
            logger.warning("file/readelf not found; cannot verify PIE. Install file/binutils.")
            return False, "file/readelf tools not available"
        except subprocess.TimeoutExpired:
            return False, "PIE verification timed out"
        except Exception as e:
            logger.error("PIE verification error: %s", e)
            return False, str(e)
