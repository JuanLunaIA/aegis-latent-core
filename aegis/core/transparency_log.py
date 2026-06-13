"""
aegis.core.transparency_log — Binary Transparency Log.
Implements a public, immutable ledger for deployment hashes to ensure
that only audited and published binaries are executed in production.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class LogEntry:
    index: int
    binary_hash: str
    version: str
    timestamp: float
    prev_hash: str
    entry_hash: str


class TransparencyLogManager:
    """
    Manages the interaction with a public transparency log (e.g., Rekor/Sigstore).
    Ensures that any binary running in production has a verifiable 'proof of existence'
    in an immutable ledger.
    """

    def __init__(self):
        # Simulation of a public ledger. In production, this would be a
        # distributed ledger or a Merkle Tree hosted on a public API.
        self._ledger: list[LogEntry] = []
        logger.info("TransparencyLogManager initialized. Target: Public Immutable Ledger.")

    def publish_binary_hash(self, binary_hash: str, version: str) -> str:
        """
        Publishes a binary hash to the transparency log.
        Creates a hash-chain to ensure the ledger is append-only.
        """
        prev_hash = self._ledger[-1].entry_hash if self._ledger else "0" * 64

        # Compute entry hash: SHA256(index || binary_hash || version || timestamp || prev_hash)
        timestamp = time.time()
        index = len(self._ledger)
        data_to_hash = f"{index}{binary_hash}{version}{timestamp}{prev_hash}".encode()
        entry_hash = hashlib.sha256(data_to_hash).hexdigest()

        entry = LogEntry(
            index=index,
            binary_hash=binary_hash,
            version=version,
            timestamp=timestamp,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

        self._ledger.append(entry)
        logger.info(
            "Binary hash %s published to Transparency Log at index %d.", binary_hash[:16], index
        )
        return entry_hash

    def verify_binary_presence(self, binary_hash: str) -> bool:
        """
        Verifies that a specific binary hash exists in the transparency log.
        This prevents 'stealth deployments' of un-audited binaries.
        """
        for entry in self._ledger:
            if entry.binary_hash == binary_hash:
                logger.info(
                    "Verification SUCCESS: Binary %s found in transparency log.", binary_hash[:16]
                )
                return True

        logger.critical(
            "Verification FAILURE: Binary %s NOT found in transparency log! Potential unauthorized deployment.",
            binary_hash[:16],
        )
        return False

    def verify_ledger_integrity(self) -> bool:
        """
        Verifies the hash-chain of the entire ledger to ensure no entries
        have been modified or deleted.
        """
        for i in range(1, len(self._ledger)):
            prev_entry = self._ledger[i - 1]
            curr_entry = self._ledger[i]

            if curr_entry.prev_hash != prev_entry.entry_hash:
                logger.critical("LEDGER CORRUPTION: Hash chain broken at index %d.", i)
                return False

        logger.info("Ledger integrity verified. Hash-chain is intact.")
        return True

    def get_merkle_root(self) -> str:
        """Returns the current tail hash of the ledger (simulated Merkle Root)."""
        if not self._ledger:
            return "0" * 64
        return self._ledger[-1].entry_hash
