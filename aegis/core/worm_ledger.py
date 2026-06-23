# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.worm_ledger — WORM (Write-Once Read-Many) storage enforcement.

Implements storage-layer immutability for WAL segments: once a segment is
sealed, it is protected at both application level (``WORMViolationError`` on
any delete/overwrite attempt) and OS level (``0o400`` read-only permissions for
non-root processes).

Compliance targets
------------------
- 21 CFR Part 11 Annex 11 §5: audit trail lock-out — records cannot be
  altered or deleted after commitment.
- NIST SP 800-53 AU-9: protection of audit information against unauthorized
  access, modification, and deletion.
- ISO/IEC 27037 forensic chain-of-custody: immutable evidence segments.

Usage::

    from aegis.core.worm_ledger import WORMEnforcer, WORMViolationError

    enforcer = WORMEnforcer()
    seal = enforcer.seal("/var/aegis/wal/audit.wal.000001", node_count=1200)
    # → writes a seal sentinel to the segment, sets permissions to 0o400

    # Before any write/delete, call:
    enforcer.enforce_immutability("/var/aegis/wal/audit.wal.000001")
    # → raises WORMViolationError for sealed paths

    # Audit nodes cannot be deleted, ever:
    enforcer.delete_node("state-abc-123")
    # → raises WORMViolationError unconditionally
"""

from __future__ import annotations

import json
import os
import stat
import time
from dataclasses import dataclass, field

_WORM_SEAL_RECORD_TYPE = "worm_seal"
_WORM_READONLY_MODE = 0o400


# ── Exception ─────────────────────────────────────────────────────────────────


class WORMViolationError(Exception):
    """Raised when an operation would violate WORM immutability.

    May be raised by:
    - :meth:`WORMEnforcer.seal` if a segment is already sealed.
    - :meth:`WORMEnforcer.enforce_immutability` if a sealed segment is targeted.
    - :meth:`WORMEnforcer.delete_node` unconditionally (nodes are never deletable).
    """


# ── Seal record ───────────────────────────────────────────────────────────────


@dataclass
class WORMSealRecord:
    """Sentinel record appended as the final line of a sealed WAL segment.

    Written as a JSON line so it can be identified by ``verify()`` without
    special tooling; any standard JSON parser can confirm the seal.

    Attributes
    ----------
    record_type:
        Always ``"worm_seal"`` — discriminator for WAL readers.
    sealed_at:
        Unix timestamp (float, UTC) when the segment was sealed.
    sealed_by:
        Identity string of the enforcer that applied the seal.
    node_count:
        Number of ``AuditNode`` records in the segment at seal time.
    """

    record_type: str = _WORM_SEAL_RECORD_TYPE
    sealed_at: float = field(default_factory=time.time)
    sealed_by: str = "WORMEnforcer"
    node_count: int = 0

    def to_dict(self) -> dict[str, object]:
        return {
            "record_type": self.record_type,
            "sealed_at": self.sealed_at,
            "sealed_by": self.sealed_by,
            "node_count": self.node_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, object]) -> WORMSealRecord:
        raw_at = data.get("sealed_at", 0.0)
        raw_count = data.get("node_count", 0)
        return cls(
            record_type=str(data.get("record_type", _WORM_SEAL_RECORD_TYPE)),
            sealed_at=float(raw_at) if isinstance(raw_at, (int, float)) else 0.0,
            sealed_by=str(data.get("sealed_by", "")),
            node_count=int(raw_count) if isinstance(raw_count, (int, float)) else 0,
        )


# ── Enforcer ──────────────────────────────────────────────────────────────────


class WORMEnforcer:
    """Application-level WORM enforcer for WAL segments.

    Enforcement operates at two levels:
    1. **Application level** — the enforcer tracks sealed paths in memory and
       raises :class:`WORMViolationError` on any write/delete attempt.  This is
       the primary guard for in-process protection.
    2. **OS level** — sealed segments are set to ``0o400`` (owner read-only).
       This protects against out-of-process modification by non-root actors.
       Root processes can still bypass OS permission bits; in high-security
       deployments combine with filesystem immutable flags (``chattr +i`` on
       Linux ext4) or WORM-capable storage hardware.

    Parameters
    ----------
    sealed_by:
        Identity string written into every :class:`WORMSealRecord`.
    """

    def __init__(self, sealed_by: str = "WORMEnforcer") -> None:
        self._sealed_by = sealed_by
        self._sealed_paths: set[str] = set()

    # ── Primary API ───────────────────────────────────────────────────────────

    def seal(self, path: str, node_count: int = 0) -> WORMSealRecord:
        """Seal a WAL segment, making it immutable.

        Writes a :class:`WORMSealRecord` sentinel as the final JSON line of the
        segment, then sets the file permissions to ``0o400`` (owner read-only).
        The path is tracked internally so that subsequent calls to
        :meth:`enforce_immutability` raise :class:`WORMViolationError`.

        Parameters
        ----------
        path:
            Absolute or relative path to the WAL segment to seal.
        node_count:
            Number of audit nodes in the segment (recorded in the seal record
            for forensic accounting).

        Returns
        -------
        WORMSealRecord
            The seal sentinel written to the segment.

        Raises
        ------
        WORMViolationError
            If the segment is already tracked as sealed by this enforcer.
        FileNotFoundError
            If *path* does not exist.
        """
        abs_path = os.path.abspath(path)
        if abs_path in self._sealed_paths:
            raise WORMViolationError(f"Segment is already sealed: {path}")
        if not os.path.exists(path):
            raise FileNotFoundError(f"WAL segment not found: {path}")

        record = WORMSealRecord(
            sealed_at=time.time(),
            sealed_by=self._sealed_by,
            node_count=node_count,
        )
        seal_line = json.dumps(record.to_dict(), separators=(",", ":")) + "\n"

        # Append sentinel while the file is still writable.
        with open(path, "a") as fh:
            fh.write(seal_line)
            fh.flush()
            os.fsync(fh.fileno())

        # Set read-only permissions (OS-level defense-in-depth).
        try:
            os.chmod(path, _WORM_READONLY_MODE)
        except OSError:
            pass

        self._sealed_paths.add(abs_path)
        return record

    def verify(self, path: str) -> bool:
        """Return True if *path* is a properly formed WORM-sealed segment.

        A segment is considered properly sealed when:
        1. Its mode bits are exactly ``0o400`` (owner read-only).
        2. Its last non-empty line parses as a JSON record with
           ``"record_type": "worm_seal"``.

        Parameters
        ----------
        path:
            Path to the WAL segment.
        """
        if not os.path.exists(path):
            return False

        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)
        except OSError:
            return False

        if mode != _WORM_READONLY_MODE:
            return False

        return self._has_seal_record(path)

    def enforce_immutability(self, path: str) -> None:
        """Raise :class:`WORMViolationError` if *path* is sealed.

        Call this guard before any write or delete operation targeting a WAL
        segment.  Checks both the in-memory seal registry (fast) and on-disk
        verification (authoritative).

        Raises
        ------
        WORMViolationError
            If the path is sealed, either in-memory or on-disk.
        """
        abs_path = os.path.abspath(path)
        if abs_path in self._sealed_paths or self.verify(path):
            raise WORMViolationError(
                f"Cannot modify sealed WORM segment: {path} — "
                "21 CFR Part 11 Annex 11 §5 / NIST AU-9 immutability violation"
            )

    def delete_node(self, state_id: str | None = None, **_: object) -> None:
        """Unconditionally raise :class:`WORMViolationError`.

        Audit nodes are immutable once committed to the WAL chain.  No
        deletion path exists.  This method exists so that code attempting to
        call ``enforcer.delete_node(...)`` receives a clear, policy-attributed
        error rather than an ``AttributeError``.

        Raises
        ------
        WORMViolationError
            Always.
        """
        raise WORMViolationError(
            "Audit nodes cannot be deleted once committed to the WAL chain. "
            "WORM enforcement (21 CFR Part 11 Annex 11 §5, NIST SP 800-53 AU-9) "
            "prohibits deletion of audit records."
        )

    def unseal_for_testing(self, path: str) -> None:
        """Remove a path from the sealed set and restore write permissions.

        **For use in tests only.**  This method exists so that temporary files
        created during tests can be cleaned up by the test framework even after
        being sealed.  It must not be called in production paths.
        """
        abs_path = os.path.abspath(path)
        self._sealed_paths.discard(abs_path)
        if os.path.exists(path):
            try:
                os.chmod(path, 0o600)
            except OSError:
                pass

    # ── Properties ────────────────────────────────────────────────────────────

    @property
    def sealed_segments(self) -> frozenset[str]:
        """Absolute paths of segments explicitly sealed by this enforcer."""
        return frozenset(self._sealed_paths)

    def is_sealed(self, path: str) -> bool:
        """Return True if *path* is sealed (in-memory or on-disk verification)."""
        return os.path.abspath(path) in self._sealed_paths or self.verify(path)

    # ── Private helpers ───────────────────────────────────────────────────────

    @staticmethod
    def _has_seal_record(path: str) -> bool:
        """Return True if the last non-empty line of *path* is a worm_seal record."""
        try:
            with open(path) as fh:
                lines = fh.readlines()
        except OSError:
            return False

        for line in reversed(lines):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
                return bool(data.get("record_type") == _WORM_SEAL_RECORD_TYPE)
            except (json.JSONDecodeError, AttributeError):
                return False
        return False


# ── Convenience helpers ───────────────────────────────────────────────────────


def count_nodes_in_segment(path: str) -> int:
    """Count the number of AuditNode records in a WAL segment file.

    Skips WORM seal sentinel records.  Returns 0 if the file is empty or
    does not exist.
    """
    if not os.path.exists(path):
        return 0
    count = 0
    try:
        with open(path) as fh:
            for line in fh:
                stripped = line.strip()
                if not stripped:
                    continue
                try:
                    data = json.loads(stripped)
                    if data.get("record_type") != _WORM_SEAL_RECORD_TYPE:
                        count += 1
                except (json.JSONDecodeError, AttributeError):
                    continue
    except OSError:
        pass
    return count
