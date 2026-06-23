# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.export_audit_log — Tamper-evident compliance export audit log.

Every call to ``POST /v1/enterprise/compliance/export`` is recorded here in a
separate, non-repudiable append-only log that is **independent from the Merkle
audit chain**.  Independence is critical: if the main chain were compromised,
the export log still proves when and by whom exports occurred.

Each entry is a single JSON line terminated by ``\\n`` (JSONL format) and
carries an HMAC-SHA256 ``entry_sig`` computed over the canonical serialisation
of the entry body.  Verification re-computes the HMAC and uses
``hmac.compare_digest`` for constant-time comparison.

File security:
    - Created with mode ``0o600`` (owner read/write only) on first write.
    - File mode is enforced on every ``__init__`` if the file already exists.
    - The log is opened in append mode; writes are flushed and ``fsync``-ed
      after every entry so crash-consistency is guaranteed.

Usage::

    from aegis.core.export_audit_log import ExportAuditLog

    log = ExportAuditLog("/var/lib/aegis/export_audit.jsonl", signing_key="...")
    log.record(
        operator="alice@example.org",
        package_id="pkg-uuid",
        client_ip="10.0.0.1",
        api_key_hash="sha256:abcdef...",
        node_count=500,
    )

    # Offline verification
    ok, errors = log.verify()
    assert ok, errors

Tamper evidence:
    Entries are individually signed.  Modifying or deleting any line, or
    inserting a line without the correct signing key, produces a verification
    failure for that entry.  The entry index is included in the signed payload
    so entries cannot be silently reordered.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import stat
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

_HASH_ALGORITHM = "HMAC-SHA256"
_LOG_VERSION = 1


# ── Entry dataclass ───────────────────────────────────────────────────────────


@dataclass
class ExportLogEntry:
    """A single compliance export audit record.

    Attributes
    ----------
    index:
        Zero-based monotonic counter for this entry within the log file.
    timestamp_iso:
        UTC ISO-8601 timestamp of the export event.
    operator:
        Identity of the operator or service account that triggered the export.
    package_id:
        UUID of the generated ``EvidencePackage``.
    client_ip:
        IP address of the requesting client (IPv4 or IPv6, or ``"unknown"``).
    api_key_hash:
        SHA-256 hex digest of the API key used (never the key itself).
    node_count:
        Number of audit chain nodes included in the export.
    extra:
        Optional free-form dict for extensibility (not signed into the core
        HMAC — kept in ``body`` so it is still part of the JSONL record).
    entry_sig:
        HMAC-SHA256 hex digest over the canonical body.  Empty until signed.
    """

    index: int
    timestamp_iso: str
    operator: str
    package_id: str
    client_ip: str
    api_key_hash: str
    node_count: int
    extra: dict[str, Any]
    entry_sig: str = ""

    def _body_dict(self) -> dict[str, Any]:
        """Canonical body used as HMAC input (excludes entry_sig)."""
        return {
            "version": _LOG_VERSION,
            "index": self.index,
            "timestamp_iso": self.timestamp_iso,
            "operator": self.operator,
            "package_id": self.package_id,
            "client_ip": self.client_ip,
            "api_key_hash": self.api_key_hash,
            "node_count": self.node_count,
            "hash_algorithm": _HASH_ALGORITHM,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self._body_dict()
        d["extra"] = self.extra
        d["entry_sig"] = self.entry_sig
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ExportLogEntry:
        return cls(
            index=d["index"],
            timestamp_iso=d["timestamp_iso"],
            operator=d["operator"],
            package_id=d["package_id"],
            client_ip=d["client_ip"],
            api_key_hash=d["api_key_hash"],
            node_count=d["node_count"],
            extra=d.get("extra", {}),
            entry_sig=d.get("entry_sig", ""),
        )


# ── Signing helpers ───────────────────────────────────────────────────────────


def _sign_entry(entry: ExportLogEntry, key: bytes) -> str:
    """Return the HMAC-SHA256 hex signature over *entry*'s canonical body."""
    canonical = json.dumps(entry._body_dict(), sort_keys=True, separators=(",", ":"))
    return hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()


def _verify_entry_sig(entry: ExportLogEntry, key: bytes) -> bool:
    expected = _sign_entry(entry, key)
    return hmac.compare_digest(expected, entry.entry_sig)


# ── Main log class ────────────────────────────────────────────────────────────


class ExportAuditLog:
    """Append-only HMAC-signed export audit log.

    Parameters
    ----------
    path:
        Filesystem path for the JSONL log file.
    signing_key:
        Secret key used for HMAC-SHA256 signing.  Must be non-empty.
    """

    def __init__(self, path: str | Path, signing_key: str) -> None:
        if not signing_key:
            raise ValueError("ExportAuditLog requires a non-empty signing_key")
        self._path = Path(path)
        self._key: bytes = signing_key.encode()
        self._ensure_file()

    # ── Internal ─────────────────────────────────────────────────────────

    def _ensure_file(self) -> None:
        """Create the log file at 0o600 if absent; enforce mode if present."""
        if self._path.exists():
            current_mode = stat.S_IMODE(os.stat(self._path).st_mode)
            if current_mode != 0o600:
                os.chmod(self._path, 0o600)
        else:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            # Create with restricted permissions before any data is written.
            fd = os.open(self._path, os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
            os.close(fd)

    def _next_index(self) -> int:
        """Return the next entry index by counting existing lines."""
        if not self._path.exists():
            return 0
        count = 0
        with self._path.open("rb") as fh:
            for line in fh:
                if line.strip():
                    count += 1
        return count

    def _append_line(self, line: str) -> None:
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(line + "\n")
            fh.flush()
            os.fsync(fh.fileno())

    # ── Public API ────────────────────────────────────────────────────────

    def record(
        self,
        *,
        operator: str,
        package_id: str,
        client_ip: str = "unknown",
        api_key_hash: str = "",
        node_count: int = 0,
        extra: dict[str, Any] | None = None,
        timestamp_iso: str | None = None,
    ) -> ExportLogEntry:
        """Append a signed entry for one compliance export event.

        Parameters
        ----------
        operator:
            Identity of the requesting operator or service.
        package_id:
            UUID of the produced ``EvidencePackage``.
        client_ip:
            Client IP address (log ``"unknown"`` when unavailable).
        api_key_hash:
            SHA-256 hex digest of the API key (never the raw key).
        node_count:
            Audit chain nodes included in the export.
        extra:
            Optional metadata dict (not HMAC-signed).
        timestamp_iso:
            Override timestamp; defaults to ``datetime.now(UTC).isoformat()``.

        Returns
        -------
        ExportLogEntry
            The signed entry that was written.
        """
        ts = timestamp_iso or datetime.now(UTC).isoformat()
        idx = self._next_index()
        entry = ExportLogEntry(
            index=idx,
            timestamp_iso=ts,
            operator=operator,
            package_id=package_id,
            client_ip=client_ip,
            api_key_hash=api_key_hash,
            node_count=node_count,
            extra=extra or {},
        )
        entry.entry_sig = _sign_entry(entry, self._key)
        self._append_line(json.dumps(entry.to_dict(), separators=(",", ":")))
        logger.info(
            "ExportAuditLog: recorded export #%d package=%s operator=%s",
            idx,
            package_id,
            operator,
        )
        return entry

    def verify(self) -> tuple[bool, list[str]]:
        """Verify every entry's HMAC signature and index sequence.

        Returns
        -------
        tuple[bool, list[str]]
            ``(True, [])`` when all entries are intact;
            ``(False, [error_messages])`` otherwise.
        """
        errors: list[str] = []
        expected_idx = 0

        if not self._path.exists():
            return True, []

        with self._path.open(encoding="utf-8") as fh:
            for lineno, raw in enumerate(fh, start=1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    data = json.loads(raw)
                except json.JSONDecodeError as exc:
                    errors.append(f"line {lineno}: invalid JSON — {exc}")
                    expected_idx += 1
                    continue

                try:
                    entry = ExportLogEntry.from_dict(data)
                except (KeyError, TypeError) as exc:
                    errors.append(f"line {lineno}: missing required fields — {exc}")
                    expected_idx += 1
                    continue

                if entry.index != expected_idx:
                    errors.append(
                        f"line {lineno}: index mismatch — expected {expected_idx}, got {entry.index}"
                    )

                if not _verify_entry_sig(entry, self._key):
                    errors.append(
                        f"line {lineno}: HMAC signature invalid (entry index {entry.index})"
                    )

                expected_idx += 1

        return len(errors) == 0, errors

    def read_all(self) -> list[ExportLogEntry]:
        """Return all entries from the log file (unsignature-checked)."""
        entries: list[ExportLogEntry] = []
        if not self._path.exists():
            return entries
        with self._path.open(encoding="utf-8") as fh:
            for raw in fh:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    entries.append(ExportLogEntry.from_dict(json.loads(raw)))
                except (json.JSONDecodeError, KeyError):
                    pass
        return entries

    @property
    def path(self) -> Path:
        return self._path

    @property
    def entry_count(self) -> int:
        return self._next_index()
