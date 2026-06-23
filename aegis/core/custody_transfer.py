# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.custody_transfer — ISO/IEC 27037 custody transfer protocol.

Records structured, non-repudiable handoff events when digital evidence moves
between custodians.  Each transfer record is HMAC-SHA256 signed (same signing
primitive as ExportAuditLog) and stored in an append-only JSONL file at 0o600.

Transfer record fields
----------------------
index            Monotonically increasing per-log sequence number.
timestamp_iso    ISO 8601 UTC timestamp of the handoff.
transferor       Identity of the party releasing custody (name or email).
transferee       Identity of the party accepting custody.
package_id       Evidence bundle identifier (correlates to ExportAuditLog).
evidence_hash    SHA-256 hex digest of the evidence package at handoff time.
reason           Free-text reason for transfer (court order, investigation, etc.).
authorization    Reference to the authorizing document or case number.
transfer_sig     HMAC-SHA256 over the canonical body (excludes transfer_sig).

Security properties
-------------------
- 0o600 file permissions enforced at creation and on every open of an existing file.
- fsync after every append — no data loss on crash.
- Sequential index enforced during verify() to detect record deletion.
- HMAC-SHA256 signing key must be set in AEGIS_SIGNING_KEY (separate from API keys).
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import stat
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# ── Dataclass ─────────────────────────────────────────────────────────────────


@dataclass
class CustodyTransferRecord:
    """A single custody handoff event."""

    index: int
    timestamp_iso: str
    transferor: str
    transferee: str
    package_id: str
    evidence_hash: str
    reason: str
    authorization: str
    extra: dict[str, Any] = field(default_factory=dict)
    transfer_sig: str = ""

    # Schema version — bumped when fields are added.
    _VERSION: str = field(default="1", init=False, repr=False, compare=False)

    def _body_dict(self) -> dict[str, Any]:
        """Canonical body for HMAC computation (excludes transfer_sig)."""
        return {
            "version": "1",
            "index": self.index,
            "timestamp_iso": self.timestamp_iso,
            "transferor": self.transferor,
            "transferee": self.transferee,
            "package_id": self.package_id,
            "evidence_hash": self.evidence_hash,
            "reason": self.reason,
            "authorization": self.authorization,
            "extra": self.extra,
        }

    def to_dict(self) -> dict[str, Any]:
        d = self._body_dict()
        d["transfer_sig"] = self.transfer_sig
        return d

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CustodyTransferRecord:
        rec = cls(
            index=d["index"],
            timestamp_iso=d["timestamp_iso"],
            transferor=d["transferor"],
            transferee=d["transferee"],
            package_id=d["package_id"],
            evidence_hash=d.get("evidence_hash", ""),
            reason=d.get("reason", ""),
            authorization=d.get("authorization", ""),
            extra=d.get("extra", {}),
        )
        rec.transfer_sig = d.get("transfer_sig", "")
        return rec


# ── HMAC helpers ──────────────────────────────────────────────────────────────


def _sign_record(record: CustodyTransferRecord, key: bytes) -> str:
    canonical = json.dumps(record._body_dict(), sort_keys=True, separators=(",", ":"))
    return hmac.new(key, canonical.encode(), hashlib.sha256).hexdigest()


def _verify_record_sig(record: CustodyTransferRecord, key: bytes) -> bool:
    expected = _sign_record(record, key)
    return hmac.compare_digest(expected, record.transfer_sig)


# ── Log ───────────────────────────────────────────────────────────────────────


class CustodyTransferLog:
    """Append-only, HMAC-signed custody transfer log.

    Parameters
    ----------
    path:
        File system path for the JSONL log.
    signing_key:
        Shared secret for HMAC-SHA256 per-record signatures.  Must be non-empty.
        Use AEGIS_SIGNING_KEY (never an API key).
    """

    def __init__(self, path: str | Path, signing_key: str) -> None:
        if not signing_key:
            raise ValueError("signing_key must be non-empty")
        self.path = Path(path)
        self._key = signing_key.encode()
        self._count = 0

        self.path.parent.mkdir(parents=True, exist_ok=True)

        if self.path.exists():
            current_mode = stat.S_IMODE(os.stat(self.path).st_mode)
            if current_mode != 0o600:
                os.chmod(self.path, 0o600)
            self._count = self._count_records()
        else:
            fd = os.open(str(self.path), os.O_CREAT | os.O_WRONLY | os.O_EXCL, 0o600)
            os.close(fd)

    # ── Public API ────────────────────────────────────────────────────────────

    @property
    def entry_count(self) -> int:
        return self._count

    def record(
        self,
        *,
        transferor: str,
        transferee: str,
        package_id: str,
        evidence_hash: str = "",
        reason: str = "",
        authorization: str = "",
        extra: dict[str, Any] | None = None,
        timestamp_iso: str | None = None,
    ) -> CustodyTransferRecord:
        """Append a signed custody transfer record and fsync."""
        if timestamp_iso is None:
            timestamp_iso = datetime.now(UTC).isoformat()

        rec = CustodyTransferRecord(
            index=self._count,
            timestamp_iso=timestamp_iso,
            transferor=transferor,
            transferee=transferee,
            package_id=package_id,
            evidence_hash=evidence_hash,
            reason=reason,
            authorization=authorization,
            extra=extra or {},
        )
        rec.transfer_sig = _sign_record(rec, self._key)

        with self.path.open("a") as fh:
            fcntl.flock(fh, fcntl.LOCK_EX)
            fh.write(json.dumps(rec.to_dict()) + "\n")
            fh.flush()
            os.fsync(fh.fileno())

        self._count += 1
        return rec

    def verify(self) -> tuple[bool, list[str]]:
        """Verify all records: HMAC validity and sequential index.

        Returns (True, []) when the log is intact, (False, [errors]) otherwise.
        """
        if not self.path.exists():
            return True, []

        errors: list[str] = []
        expected_index = 0

        with self.path.open() as fh:
            for lineno, raw in enumerate(fh, start=1):
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    d = json.loads(raw)
                except json.JSONDecodeError as exc:
                    errors.append(f"line {lineno}: JSON parse error: {exc}")
                    expected_index += 1
                    continue

                try:
                    rec = CustodyTransferRecord.from_dict(d)
                except (KeyError, TypeError) as exc:
                    errors.append(f"line {lineno}: record schema error: {exc}")
                    expected_index += 1
                    continue

                if rec.index != expected_index:
                    errors.append(
                        f"line {lineno}: index mismatch: expected {expected_index}, got {rec.index}"
                    )

                if not _verify_record_sig(rec, self._key):
                    errors.append(
                        f"line {lineno}: HMAC verification failed "
                        f"(record may have been tampered with)"
                    )

                expected_index += 1

        return len(errors) == 0, errors

    def read_all(self) -> list[CustodyTransferRecord]:
        """Return all records in order."""
        if not self.path.exists():
            return []
        records: list[CustodyTransferRecord] = []
        with self.path.open() as fh:
            for raw in fh:
                raw = raw.strip()
                if raw:
                    records.append(CustodyTransferRecord.from_dict(json.loads(raw)))
        return records

    # ── Private ───────────────────────────────────────────────────────────────

    def _count_records(self) -> int:
        count = 0
        with self.path.open() as fh:
            for raw in fh:
                if raw.strip():
                    count += 1
        return count
