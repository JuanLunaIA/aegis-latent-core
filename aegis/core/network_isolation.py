"""
aegis.core.network_isolation — XDP/eBPF Network Hardening.
Implements high-performance packet filtering at the driver level to isolate the proxy.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


class XDPNetworkIsolationError(Exception):
    """Exception raised when XDP network isolation operations fail."""

    pass


class XDPBinaryNotFoundError(XDPNetworkIsolationError):
    """Exception raised when required XDP binary is not found."""

    pass


class XDPNetworkIsolator:
    """
    Controls the XDP (eXpress Data Path) filter to block unauthorized traffic
    before it reaches the Linux TCP/IP stack.

    This class provides production-grade network isolation using eBPF/XDP.
    If XDP is unavailable, the system fails securely by denying operation
    rather than operating in a degraded simulation mode.
    """

    DEFAULT_XDP_BINARY_PATH = "/app/aegis/core/xdp_filter.o"

    def __init__(
        self,
        interface: str = "enp0s25",
        xdp_binary_path: str | None = None,
        fail_secure: bool = True,
    ):
        """
        Initialize the XDP Network Isolator.

        Args:
            interface: Network interface to attach XDP program to.
            xdp_binary_path: Path to the compiled XDP binary (.o file).
            fail_secure: If True, raise exception when XDP binary is missing.
                        If False, operate in degraded mode with logging.
        """
        self.interface = interface
        self.xdp_binary_path = xdp_binary_path or self.DEFAULT_XDP_BINARY_PATH
        self.fail_secure = fail_secure
        self._is_active = False
        self._xdp_program_id: int | None = None

    def _execute_bpftool(self, cmd: list[str], timeout: int = 10) -> tuple[int, str, str]:
        """
        Helper to run bpftool commands with enhanced error handling.

        Returns:
            Tuple of (return_code, stdout, stderr)
        """
        try:
            result = subprocess.run(
                ["sudo", "bpftool"] + cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
            return result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired:
            logger.error("bpftool command timed out after %ds: %s", timeout, cmd)
            return -1, "", "Command timeout"
        except FileNotFoundError:
            logger.error("bpftool binary not found in PATH")
            return -1, "", "bpftool not found"
        except Exception as e:
            logger.error("bpftool execution error: %s", e)
            return -1, "", str(e)

    def _verify_xdp_binary(self) -> bool:
        """Verify that the XDP binary exists and is readable."""
        binary_path = Path(self.xdp_binary_path)
        if not binary_path.exists():
            logger.error("XDP binary not found at: %s", self.xdp_binary_path)
            return False
        if not os.access(self.xdp_binary_path, os.R_OK):
            logger.error("XDP binary not readable: %s", self.xdp_binary_path)
            return False
        return True

    def apply_isolation(self, allowed_ips: list[str]) -> bool:
        """
        Loads the XDP program and configures the allowlist map.

        Args:
            allowed_ips: List of IP addresses to allow through the XDP filter.

        Returns:
            True if isolation was successfully applied, False otherwise.

        Raises:
            XDPBinaryNotFoundError: If XDP binary is missing and fail_secure=True.
            XDPNetworkIsolationError: If XDP program fails to load or attach.
        """
        logger.info("Applying XDP Network Isolation on %s...", self.interface)

        # Verify XDP binary exists
        if not self._verify_xdp_binary():
            if self.fail_secure:
                raise XDPBinaryNotFoundError(
                    f"XDP binary '{self.xdp_binary_path}' not found. "
                    "Network isolation cannot be applied. Ensure eBPF tools are installed "
                    "and XDP program is compiled."
                )
            else:
                logger.warning(
                    "XDP binary not found. Operating without hardware-level network isolation. "
                    "This is a security risk - ensure alternative controls are in place."
                )
                self._is_active = False
                return False

        # 1. Load XDP program
        # Production: bpftool prog load xdp_filter.o /sys/fs/bpf/xdp_filter type drv
        rc, stdout, stderr = self._execute_bpftool(
            ["prog", "load", self.xdp_binary_path, "/sys/fs/bpf/xdp_filter", "type", "drv"]
        )

        if rc != 0:
            error_msg = stderr.strip() or stdout.strip() or "Unknown error"
            logger.error("Failed to load XDP program: %s", error_msg)
            raise XDPNetworkIsolationError(
                f"XDP program load failed: {error_msg}. "
                "Ensure kernel supports eBPF/XDP and capabilities are set correctly."
            )

        # Extract program ID from output (format: "id 123")
        try:
            self._xdp_program_id = int(stdout.split()[1]) if stdout else None
        except (IndexError, ValueError):
            logger.warning("Could not extract XDP program ID from output")
            self._xdp_program_id = None

        # 2. Attach XDP program to interface in DRV mode (highest performance)
        # bpftool net attach xdp id <id> dev <iface>
        rc, stdout, stderr = self._execute_bpftool(
            ["net", "attach", "xdp", "id", str(self._xdp_program_id), "dev", self.interface]
        )

        if rc != 0:
            error_msg = stderr.strip() or stdout.strip() or "Unknown error"
            logger.error("Failed to attach XDP program: %s", error_msg)
            # Attempt cleanup
            self._cleanup_xdp_program()
            raise XDPNetworkIsolationError(f"XDP program attach failed: {error_msg}")

        # 3. Populate the allowlist map with validated IPs
        if not self._populate_allowlist_map(allowed_ips):
            logger.error("Failed to populate allowlist map")
            self.remove_isolation()
            raise XDPNetworkIsolationError("Failed to configure IP allowlist")

        self._is_active = True
        logger.info(
            "XDP Network Isolation active on %s. Allowed IPs: %d entries. "
            "Only allowed IPs can reach the proxy.",
            self.interface,
            len(allowed_ips),
        )
        return True

    def _populate_allowlist_map(self, allowed_ips: list[str]) -> bool:
        """
        Populate the XDP allowlist map with IP addresses.

        Args:
            allowed_ips: List of IP addresses to allow.

        Returns:
            True if all IPs were added successfully, False otherwise.
        """
        for ip in allowed_ips:
            # Validate IP format before adding
            if not self._validate_ip(ip):
                logger.warning("Skipping invalid IP address: %s", ip)
                continue

            # Convert IP to hex format for BPF map
            ip_hex = self._ip_to_hex(ip)
            rc, _, stderr = self._execute_bpftool(
                ["map", "update", "name", "allowlist", "key", ip_hex, "value", "1"]
            )
            if rc != 0:
                logger.error("Failed to add IP %s to allowlist: %s", ip, stderr)
                return False
        return True

    @staticmethod
    def _validate_ip(ip: str) -> bool:
        """Validate IPv4 address format."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False

    @staticmethod
    def _ip_to_hex(ip: str) -> str:
        """Convert IPv4 address to hex format for BPF map."""
        parts = [int(p) for p in ip.split(".")]
        # Little-endian format for x86_64
        return "".join(f"{p:02x}" for p in reversed(parts))

    def _cleanup_xdp_program(self):
        """Clean up partially loaded XDP program."""
        if self._xdp_program_id:
            try:
                subprocess.run(
                    ["sudo", "bpftool", "prog", "unload", "id", str(self._xdp_program_id)],
                    capture_output=True,
                    timeout=5,
                )
            except Exception as e:
                logger.warning("Failed to cleanup XDP program: %s", e)
            self._xdp_program_id = None

    def remove_isolation(self) -> bool:
        """
        Detaches the XDP program from the interface and cleans up resources.

        Returns:
            True if isolation was successfully removed, False otherwise.
        """
        if not self._is_active:
            logger.debug("XDP isolation not active, nothing to remove")
            return True

        rc, stdout, stderr = self._execute_bpftool(
            ["net", "detach", "xdp", "dev", self.interface]
        )

        if rc == 0:
            self._is_active = False
            self._xdp_program_id = None
            logger.info("XDP Network Isolation removed from %s.", self.interface)
            return True
        else:
            error_msg = stderr.strip() or stdout.strip() or "Unknown error"
            logger.error("Failed to detach XDP program: %s", error_msg)
            return False

    def get_status(self) -> dict:
        """
        Get current XDP isolation status.

        Returns:
            Dictionary with interface, active status, driver mode, and program ID.
        """
        return {
            "interface": self.interface,
            "active": self._is_active,
            "driver": "XDP_DRV" if self._is_active else "NONE",
            "program_id": self._xdp_program_id,
            "binary_path": self.xdp_binary_path,
            "fail_secure_mode": self.fail_secure,
        }

    def __del__(self):
        """Destructor to ensure XDP program is detached on object destruction."""
        if getattr(self, "_is_active", False):
            try:
                self.remove_isolation()
            except Exception as e:
                logger.warning("Error during XDP cleanup in destructor: %s", e)
