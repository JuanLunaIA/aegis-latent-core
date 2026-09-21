"""
aegis.core.transparency_log — Binary Transparency Log.

An append-only, fsynced hash chain of deployment hashes, used to check that a
binary hash was published by this deployment before it is run. Each entry
commits to its predecessor's hash *and* to its own fields, so an edit to any
entry's material is detected by :meth:`TransparencyLogManager.verify_ledger_integrity`
(AUD-11). The chain is unkeyed: an attacker who can rewrite the storage file can
also recompute entry hashes, so detection covers edits that leave the rest of the
suffix alone. There is no keyed signature and no external anchoring in this
module, and nothing is published beyond the configured file — the boundary is
published as ``UC-061``.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

logger = logging.getLogger(__name__)


GENESIS_PREV_HASH = "0" * 64


def compute_entry_hash(
    index: int, binary_hash: str, version: str, timestamp: float, prev_hash: str
) -> str:
    """SHA-256 over an entry's committed material.

    One definition, used by the writer and by the verifier, so the two cannot
    drift apart — a recompute that used a different serialisation would either
    pass everything or fail everything.
    """
    data_to_hash = f"{index}{binary_hash}{version}{timestamp}{prev_hash}".encode()
    return hashlib.sha256(data_to_hash).hexdigest()


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
        """Append a single entry to the JSONL backing file, synchronously.

        ``flush`` + ``os.fsync`` before returning, so the caller that receives
        the entry hash receives a commitment that is on stable storage rather
        than one sitting in a buffer (AUD-11; the pattern
        ``aegis.core.export_audit_log._append_line`` already used). An OSError
        propagates: a caller that cannot make the entry durable must not be told
        it was published.
        """
        assert self._storage_path is not None
        with self._storage_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(asdict(entry)) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    def publish_binary_hash(self, binary_hash: str, version: str) -> str:
        """
        Publishes a binary hash to the transparency log.
        Creates a hash-chain to ensure the ledger is append-only.
        """
        prev_hash = self._ledger[-1].entry_hash if self._ledger else GENESIS_PREV_HASH

        timestamp = time.time()
        index = len(self._ledger)
        entry_hash = compute_entry_hash(index, binary_hash, version, timestamp, prev_hash)

        entry = LogEntry(
            index=index,
            binary_hash=binary_hash,
            version=version,
            timestamp=timestamp,
            prev_hash=prev_hash,
            entry_hash=entry_hash,
        )

        # Disk first, memory second: if the durable append fails the in-memory
        # ledger must not claim an entry the file does not have.
        if self._storage_path is not None:
            self._append_to_disk(entry)
        self._ledger.append(entry)

        logger.info(
            "Binary hash %s published to Transparency Log at index %d.", binary_hash[:16], index
        )
        return entry_hash

    def verify_binary_presence(self, binary_hash: str) -> bool:
        """
        Verifies that a specific binary hash exists in the transparency log
        **and** that the ledger it exists in verifies.

        The integrity gate is what makes this a check rather than a lookup: a
        substituted hash sitting in a ledger whose entries no longer recompute
        (AUD-11) must not be reported as published. This prevents 'stealth
        deployments' of un-audited binaries.
        """
        if not self.verify_ledger_integrity():
            logger.critical(
                "Verification FAILURE: ledger integrity check failed; refusing to confirm binary %s.",
                binary_hash[:16],
            )
            return False

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
        Verifies the whole ledger: every entry's own hash, and the chain.

        For each entry the committed material is re-hashed from the entry's
        fields and compared with the hash the entry carries, and the entry's
        position is checked against its recorded index. Only comparing
        ``prev_hash`` against the predecessor's *stored* ``entry_hash`` left
        in-place edits invisible — rewriting ``binary_hash``, ``version`` or
        ``timestamp`` on any entry kept the linkage graph intact, so the ledger
        verified and ``verify_binary_presence`` then confirmed the substituted
        binary (AUD-11 / AF-021).

        What this detects: any edit to an entry's fields, a reordering, a
        deletion, and an edit whose author recomputed that entry's hash but not
        the hashes of the entries after it. What it cannot detect: an author who
        rewrites an entry *and* recomputes every following entry's hash, because
        the chain is unkeyed — that boundary is published as ``UC-061``.
        """
        for i, entry in enumerate(self._ledger):
            if entry.index != i:
                logger.critical(
                    "LEDGER CORRUPTION: entry at position %d records index %d.",
                    i,
                    entry.index,
                )
                return False

            expected_prev = GENESIS_PREV_HASH if i == 0 else self._ledger[i - 1].entry_hash
            if entry.prev_hash != expected_prev:
                logger.critical("LEDGER CORRUPTION: Hash chain broken at index %d.", i)
                return False

            recomputed = compute_entry_hash(
                entry.index,
                entry.binary_hash,
                entry.version,
                entry.timestamp,
                entry.prev_hash,
            )
            if recomputed != entry.entry_hash:
                logger.critical(
                    "LEDGER CORRUPTION: entry %d does not hash to its recorded value.", i
                )
                return False

        logger.info("Ledger integrity verified. Hash-chain is intact.")
        return True

    def get_merkle_root(self) -> str:
        """Returns the current tail hash of the ledger (last entry_hash in the chain)."""
        if not self._ledger:
            return "0" * 64
        return self._ledger[-1].entry_hash
