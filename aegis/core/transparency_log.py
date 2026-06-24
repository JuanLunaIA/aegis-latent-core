"""
aegis.core.transparency_log — Binary Transparency Log.
Implements a public, immutable ledger for deployment hashes to ensure
that only audited and published binaries are executed in production.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass
from pathlib import Path

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
    Manages an append-only hash-chain ledger for deployment hashes.

    When ``storage_path`` is provided the ledger is backed by a JSONL file
    opened in append mode; existing entries are replayed on construction so
    the chain survives process restarts.  Without ``storage_path`` the ledger
    is in-process only (suitable for short-lived attestation sessions or tests).

    The hash chain guarantees tamper evidence: each entry commits to its
    predecessor's hash, so any modification or deletion breaks
    ``verify_ledger_integrity``.
    """

    def __init__(self, storage_path: Path | str | None = None):
        self._ledger: list[LogEntry] = []
        self._storage_path: Path | None = Path(storage_path) if storage_path is not None else None

        if self._storage_path is not None:
            self._storage_path.parent.mkdir(parents=True, exist_ok=True)
            self._replay_from_disk()

        logger.info(
            "TransparencyLogManager initialized. Storage: %s.",
            str(self._storage_path) if self._storage_path else "in-memory",
        )

    def _replay_from_disk(self) -> None:
        """Load existing entries from the JSONL file into the in-memory ledger."""
        assert self._storage_path is not None
        if not self._storage_path.exists():
            return
        with self._storage_path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                    self._ledger.append(LogEntry(**data))
                except Exception as exc:  # noqa: BLE001
                    logger.warning("Skipping malformed ledger line: %s", exc)

    def _append_to_disk(self, entry: LogEntry) -> None:
        """Append a single entry to the JSONL backing file."""
        assert self._storage_path is not None
        with self._storage_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(entry)) + "\n")

    def publish_binary_hash(self, binary_hash: str, version: str) -> str:
        """
        Publishes a binary hash to the transparency log.
        Creates a hash-chain to ensure the ledger is append-only.
        """
        prev_hash = self._ledger[-1].entry_hash if self._ledger else "0" * 64

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
        if self._storage_path is not None:
            self._append_to_disk(entry)

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
        """Returns the current tail hash of the ledger (last entry_hash in the chain)."""
        if not self._ledger:
            return "0" * 64
        return self._ledger[-1].entry_hash
