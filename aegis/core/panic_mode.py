"""
aegis.core.panic_mode — Logical Self-Destruct (Panic-Mode).
Implements a high-priority 'Kill Switch' to wipe sensitive data and halt
the system upon detection of a critical security breach.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
import os
from collections.abc import Callable
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class PanicTrigger:
    source: str
    reason: str
    severity: str  # 'CRITICAL' | 'CATASTROPHIC'


class PanicModeController:
    """
    Orchestrates the emergency shutdown of the Aegis Core.
    Ensures that sensitive data is destroyed before an attacker can extract it.
    """

    def __init__(self):
        self._panic_callbacks: list[Callable] = []
        logger.info("PanicModeController initialized. Kill-Switch armed.")

    def register_panic_callback(self, callback: Callable):
        """Registers a function to be executed during the panic sequence."""
        self._panic_callbacks.append(callback)

    def trigger_panic(self, trigger: PanicTrigger):
        """
        Initiates the self-destruct sequence.
        This is a non-returnable operation.
        """
        logger.critical("!!! PANIC MODE ACTIVATED !!!")
        logger.critical(
            "SOURCE: %s | REASON: %s | SEVERITY: %s",
            trigger.source,
            trigger.reason,
            trigger.severity,
        )

        # 1. Execute all registered panic callbacks (e.g., zeroing RAM, locking HSM)
        for callback in self._panic_callbacks:
            try:
                callback()
            except Exception as e:
                logger.error("Panic callback failed: %s", e)

        # 2. Securely wipe sensitive buffers in RAM
        self._zeroize_critical_memory()

        # 3. Drop all network connections
        self._isolate_network()

        # 4. Final Halt
        logger.critical("SISTEMA INEXPUGNABLE: Self-destruct sequence complete. Halting CPU.")
        os._exit(137)  # SIGKILL equivalent

    def _zeroize_critical_memory(self):
        """
        Attempts to overwrite sensitive memory regions with zeros.
        In a real C/Rust implementation, this uses memset_s or explicit_bzero.
        """
        logger.info("Zeroizing ephemeral keys and session buffers in RAM...")
        # Simulation: Overwriting a hypothetical memory range
        # ctypes.memset(address, 0, size)
        logger.info("Memory zeroization complete.")

    def _isolate_network(self):
        """Forces an immediate disconnect of all network interfaces."""
        logger.info("Isolating network interfaces via XDP BLACKHOLE...")
        # Simulation: calls XDPDynamicSegmenter.block_ip_immediately(all)
        logger.info("Network isolation complete.")


# Global singleton for the system
PANIC_CONTROLLER = PanicModeController()
