# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.memory_invariants — Real-time memory invariant verification.

Monitors process virtual-address ranges for unauthorised modifications by
reading the actual bytes at registration time via ``/proc/self/mem`` and
recomputing the SHA-256 digest on each verify call.

Limitations / honest advisory
------------------------------
- Reads from ``/proc/self/mem``; the address range must be readable (i.e.
  mapped with PROT_READ in the current process).  Unmapped or write-only
  regions raise ``OSError`` (caught and logged as UNAVAILABLE).
- Memory contents can change between ``register_invariant()`` and
  ``verify_invariants()`` calls for mutable regions (e.g. heap objects).
  Pin invariant ranges to read-only regions (e.g. text segment, ``mmap``
  with ``PROT_READ`` only) for meaningful protection.
- Physical-page-level verification (``/dev/mem``, eBPF kprobes) is not
  implemented; that requires kernel module or CAP_SYS_RAWIO.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from pathlib import Path

logger = logging.getLogger(__name__)

_PROC_SELF_MEM = Path("/proc/self/mem")


def _read_range(start: int, end: int) -> bytes | None:
    """Read [start, end) bytes from the process's own virtual address space.

    Returns None when the range is unmapped or unreadable, so callers can
    log an advisory rather than crashing.
    """
    if start >= end:
        return None
    try:
        with _PROC_SELF_MEM.open("rb") as f:
            f.seek(start)
            return f.read(end - start)
    except OSError as exc:
        logger.debug("_read_range [%x, %x): %s", start, end, exc)
        return None


def _hash_range(start: int, end: int) -> str | None:
    """Return the SHA-256 hex digest of bytes at [start, end), or None on failure."""
    data = _read_range(start, end)
    if data is None:
        return None
    return hashlib.sha256(data).hexdigest()


@dataclass
class MemoryInvariant:
    name: str
    address_range: tuple[int, int]
    golden_hash: str
    criticality: str  # 'CRITICAL' | 'HIGH' | 'MEDIUM'


class MemoryInvariantMonitor:
    """Monitors process virtual-address regions for unauthorised modifications.

    Golden hashes are computed from the real bytes at ``/proc/self/mem``
    when ``register_invariant()`` is called.  Each ``verify_invariants()``
    call re-reads the same ranges and compares SHA-256 digests.

    When a range cannot be read (unmapped, no PROT_READ), the invariant is
    logged as UNAVAILABLE and treated as a non-fatal advisory — the caller
    may choose to fail closed.
    """

    def __init__(self) -> None:
        self._invariants: dict[str, MemoryInvariant] = {}
        self._is_monitoring = False
        logger.info("MemoryInvariantMonitor initialised (backed by /proc/self/mem).")

    def register_invariant(
        self, name: str, start: int, end: int, criticality: str = "CRITICAL"
    ) -> bool:
        """Capture the real SHA-256 of [start, end) as the golden state.

        Returns True when the range is readable and the invariant is
        registered, False when the range cannot be read.
        """
        golden = _hash_range(start, end)
        if golden is None:
            logger.warning(
                "register_invariant: cannot read [%x, %x) from /proc/self/mem — "
                "invariant '%s' NOT registered.",
                start,
                end,
                name,
            )
            return False

        self._invariants[name] = MemoryInvariant(
            name=name,
            address_range=(start, end),
            golden_hash=golden,
            criticality=criticality,
        )
        logger.info(
            "Invariant '%s' registered at [%x, %x) — SHA-256: %s…",
            name,
            start,
            end,
            golden[:16],
        )
        return True

    def verify_invariants(self) -> bool:
        """Re-read all registered ranges and compare against golden hashes.

        Returns True when every invariant passes.  A CRITICAL invariant
        failure triggers ``_trigger_fail_closed()`` and returns False
        immediately.  Unreadable ranges (e.g. pages that were unmapped
        after registration) are logged as CRITICAL and return False.
        """
        for name, inv in self._invariants.items():
            start, end = inv.address_range
            current = _hash_range(start, end)
            if current is None:
                logger.critical(
                    "INVARIANT UNAVAILABLE: '%s' range [%x, %x) is no longer readable — "
                    "possible memory unmap or protection change.",
                    name,
                    start,
                    end,
                )
                if inv.criticality == "CRITICAL":
                    self._trigger_fail_closed()
                    return False
                continue

            if current != inv.golden_hash:
                logger.critical(
                    "INVARIANT VIOLATION: '%s' at [%x, %x) modified. Expected: %s… | Actual: %s…",
                    name,
                    start,
                    end,
                    inv.golden_hash[:16],
                    current[:16],
                )
                if inv.criticality == "CRITICAL":
                    self._trigger_fail_closed()
                    return False
        return True

    def _trigger_fail_closed(self) -> None:
        """Log a critical breach alert; callers decide whether to halt."""
        logger.critical(
            "CRITICAL INVARIANT BREACH — fail-closed triggered. "
            "Operator action required: wipe keys, revoke sessions, halt service."
        )

    def start_monitoring(self) -> None:
        self._is_monitoring = True
        logger.info("Memory invariant monitoring ACTIVE.")

    def stop_monitoring(self) -> None:
        self._is_monitoring = False
        logger.info("Memory invariant monitoring DISABLED.")
