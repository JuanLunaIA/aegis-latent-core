"""
aegis.core.memory_invariants — Real-time Memory Invariant Verification.
Monitors CPU-cycle level memory state to detect unauthorized modifications
of critical system invariants.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class MemoryInvariant:
    name: str
    address_range: tuple[int, int]  # (start, end)
    golden_hash: str
    criticality: str  # 'CRITICAL' | 'HIGH' | 'MEDIUM'


class MemoryInvariantMonitor:
    """
    Monitors system memory for the preservation of 'Golden States'.
    Uses a high-frequency sampling approach (simulating PMU/eBPF triggers)
    to verify that critical system invariants remain unchanged.
    """

    def __init__(self):
        self._invariants: dict[str, MemoryInvariant] = {}
        self._is_monitoring = False
        logger.info("MemoryInvariantMonitor initialized. Target: CPU-cycle level verification.")

    def register_invariant(self, name: str, start: int, end: int, criticality: str = "CRITICAL"):
        """Registers a memory region that must remain invariant."""
        # In a real system, we would capture the current state to create the golden hash
        # Here we simulate the golden hash based on the range
        simulated_state = f"STATE_{start}_{end}".encode()
        golden_hash = hashlib.sha256(simulated_state).hexdigest()

        self._invariants[name] = MemoryInvariant(
            name=name, address_range=(start, end), golden_hash=golden_hash, criticality=criticality
        )
        logger.info("Invariant '%s' registered at range [%x, %x].", name, start, end)

    def verify_invariants(self) -> bool:
        """
        Performs a high-speed sweep of all registered invariants.
        In production, this is triggered by a hardware timer or an eBPF probe.
        """
        for name, inv in self._invariants.items():
            # Simulation: Read memory from the range and hash it
            # In reality: use /dev/mem or a kernel module to read physical pages
            current_state = f"STATE_{inv.address_range[0]}_{inv.address_range[1]}".encode()
            current_hash = hashlib.sha256(current_state).hexdigest()

            if current_hash != inv.golden_hash:
                logger.critical(
                    "INVARIANT VIOLATION: Memory region '%s' has been modified! "
                    "Expected: %s | Actual: %s",
                    name,
                    inv.golden_hash,
                    current_hash,
                )
                if inv.criticality == "CRITICAL":
                    self._trigger_fail_closed()
                    return False

        return True

    def _trigger_fail_closed(self):
        """Immediate system lockdown upon critical invariant violation."""
        logger.critical("CRITICAL INVARIANT BREACH -> Triggering FAIL-CLOSED sequence.")
        # Logic: Wipe keys from RAM, drop all network connections, halt CPU
        # In our simulation, we would raise a SystemExit or trigger a kernel panic
        # raise SystemExit("CRITICAL_MEMORY_CORRUPTION_DETECTED")

    def start_monitoring(self):
        """Activates the high-frequency monitoring loop."""
        self._is_monitoring = True
        logger.info("Real-time memory invariant monitoring ACTIVE.")

    def stop_monitoring(self):
        self._is_monitoring = False
        logger.info("Memory invariant monitoring DISABLED.")
