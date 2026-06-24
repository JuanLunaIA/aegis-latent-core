# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.worm_ledger — WORM (Write-Once Read-Many) storage enforcement.

Implements storage-layer immutability for WAL segments: once a segment is
sealed, it is protected at both application level (``WORMViolationError`` on
any delete/overwrite attempt) and OS level (``0o400`` read-only permissions for
non-root processes).

Also provides SEC Rule 17a-4 / FINRA 4511 retention-period enforcement and
evidence export via :class:`RetentionPolicy`, :class:`WORMAttestationBundle`,
and :meth:`WORMEnforcer.attest`.

Compliance targets
------------------
- SEC Rule 17a-4(b)(1)–(4): broker-dealer records retained 3 years accessible
  (first 2 years in an easily accessible place), 6 years total, on
  non-rewriteable, non-erasable media.
- FINRA Rule 4511: records must be preserved for the periods required by
  applicable laws and rules.
- 21 CFR Part 11 Annex 11 §5: audit trail lock-out — records cannot be
  altered or deleted after commitment.
- NIST SP 800-53 AU-9: protection of audit information against unauthorized
  access, modification, and deletion.
- ISO/IEC 27037 forensic chain-of-custody: immutable evidence segments.

Usage::

    from aegis.core.worm_ledger import (
        WORMEnforcer,
        WORMViolationError,
        SEC_17A4_BROKER_DEALER,
    )

    enforcer = WORMEnforcer()
    seal = enforcer.seal("/var/aegis/wal/audit.wal.000001", node_count=1200)

    # Generate an attestation bundle for a regulator / auditor.
    signing_key = os.environb[b"AEGIS_SIGNING_KEY"]
    bundle = enforcer.attest(
        policy=SEC_17A4_BROKER_DEALER,
        signing_key=signing_key,
    )
    print(bundle.to_json())  # submit to regulator / store alongside WAL
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import stat
import time
from dataclasses import dataclass, field

_WORM_SEAL_RECORD_TYPE = "worm_seal"
_WORM_READONLY_MODE = 0o400
_SECS_PER_YEAR = 365.25 * 86_400  # mean Julian year


# ── Retention policy ──────────────────────────────────────────────────────────


@dataclass(frozen=True)
class RetentionPolicy:
    """Named retention policy for sealed WAL segments.

    Parameters
    ----------
    name:
        Short identifier used in attestation bundles.
    accessible_years:
        Number of years the records must remain accessible.
    total_years:
        Total retention period; records may only be purged after this.
    citations:
        Regulatory citations this policy satisfies.
    """

    name: str
    accessible_years: float
    total_years: float
    citations: tuple[str, ...]

    def accessible_until(self, sealed_at: float) -> float:
        """Unix timestamp after which the segment need not be *immediately* accessible."""
        return sealed_at + self.accessible_years * _SECS_PER_YEAR

    def purge_eligible_at(self, sealed_at: float) -> float:
        """Unix timestamp after which the segment may be purged."""
        return sealed_at + self.total_years * _SECS_PER_YEAR

    def retention_status(self, sealed_at: float, now: float | None = None) -> str:
        """Return ``"ACCESSIBLE"``, ``"LONG_TERM"``, or ``"PURGE_ELIGIBLE"``."""
        t = now if now is not None else time.time()
        if t < self.accessible_until(sealed_at):
            return "ACCESSIBLE"
        if t < self.purge_eligible_at(sealed_at):
            return "LONG_TERM"
        return "PURGE_ELIGIBLE"


# Pre-built regulatory retention policies.

SEC_17A4_BROKER_DEALER = RetentionPolicy(
    name="SEC_17A4_BROKER_DEALER",
    accessible_years=3.0,
    total_years=6.0,
    citations=(
        "SEC Rule 17a-4(b)(1)",
        "SEC Rule 17a-4(b)(4)",
        "FINRA Rule 4511",
    ),
)

SEC_17A4_THREE_YEAR = RetentionPolicy(
    name="SEC_17A4_THREE_YEAR",
    accessible_years=2.0,
    total_years=3.0,
    citations=(
        "SEC Rule 17a-4(b)(2)",
        "FINRA Rule 4511",
    ),
)


# ── Attestation bundle ────────────────────────────────────────────────────────


@dataclass
class WORMSegmentAttestation:
    """Per-segment attestation evidence included in a :class:`WORMAttestationBundle`.

    Attributes
    ----------
    segment_path:
        Absolute path to the sealed WAL segment.
    sealed_at:
        Unix timestamp when the segment was sealed.
    node_count:
        Audit node count recorded in the seal sentinel.
    seal_hmac:
        HMAC-SHA256 (hex) of the raw seal-sentinel JSON line, keyed by
        ``AEGIS_SIGNING_KEY``.  Lets a verifier confirm the sentinel has
        not been tampered with.
    retention_policy:
        Name of the :class:`RetentionPolicy` applied to this segment.
    accessible_until:
        Unix timestamp marking the end of the *accessible* retention period.
    purge_eligible_at:
        Unix timestamp after which the segment may be deleted.
    status:
        Current retention status: ``"ACCESSIBLE"``, ``"LONG_TERM"``, or
        ``"PURGE_ELIGIBLE"``.
    """

    segment_path: str
    sealed_at: float
    node_count: int
    seal_hmac: str
    retention_policy: str
    accessible_until: float
    purge_eligible_at: float
    status: str

    def to_dict(self) -> dict[str, object]:
        return {
            "segment_path": self.segment_path,
            "sealed_at": self.sealed_at,
            "node_count": self.node_count,
            "seal_hmac": self.seal_hmac,
            "retention_policy": self.retention_policy,
            "accessible_until": self.accessible_until,
            "purge_eligible_at": self.purge_eligible_at,
            "status": self.status,
        }


@dataclass
class WORMAttestationBundle:
    """SEC Rule 17a-4 / FINRA 4511 attestation bundle.

    Contains per-segment WORM evidence (seal time, node count, HMAC of the
    seal sentinel, retention deadlines) and a bundle-level HMAC covering all
    segment evidence so the bundle cannot be silently edited.

    Parameters
    ----------
    generated_at:
        Unix timestamp when this bundle was produced.
    generated_by:
        Identity string of the ``WORMEnforcer`` that produced the bundle.
    regulatory_citations:
        Regulatory references satisfied by the policy applied.
    segments:
        Per-segment attestation records.
    bundle_hmac:
        HMAC-SHA256 (hex) of the canonical JSON representation of all
        *segments* (sorted by ``segment_path``), keyed by
        ``AEGIS_SIGNING_KEY``.
    """

    generated_at: float = field(default_factory=time.time)
    generated_by: str = "WORMEnforcer"
    regulatory_citations: tuple[str, ...] = ()
    segments: list[WORMSegmentAttestation] = field(default_factory=list)
    bundle_hmac: str = ""

    def to_dict(self) -> dict[str, object]:
        return {
            "generated_at": self.generated_at,
            "generated_by": self.generated_by,
            "regulatory_citations": list(self.regulatory_citations),
            "segments": [s.to_dict() for s in self.segments],
            "bundle_hmac": self.bundle_hmac,
        }

    def to_json(self, indent: int | None = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def verify_bundle_hmac(self, signing_key: bytes) -> bool:
        """Return True if the bundle HMAC is valid for *signing_key*."""
        expected = _compute_bundle_hmac(self.segments, signing_key)
        return hmac.compare_digest(expected, self.bundle_hmac)


# ── HMAC helpers ──────────────────────────────────────────────────────────────


def _hmac_hex(key: bytes, data: bytes) -> str:
    return hmac.new(key, data, hashlib.sha256).hexdigest()


def _compute_bundle_hmac(segments: list[WORMSegmentAttestation], key: bytes) -> str:
    canonical = json.dumps(
        sorted([s.to_dict() for s in segments], key=lambda d: d["segment_path"]),
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    return _hmac_hex(key, canonical)


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

    def attest(
        self,
        policy: RetentionPolicy,
        signing_key: bytes,
        segment_paths: list[str] | None = None,
        now: float | None = None,
    ) -> WORMAttestationBundle:
        """Generate a SEC Rule 17a-4 / FINRA 4511 attestation bundle.

        For each sealed segment, reads the seal-sentinel line from disk,
        computes an HMAC-SHA256 of it (keyed by *signing_key*), and records
        the retention deadlines dictated by *policy*.  A bundle-level HMAC
        covers all segment records so the bundle cannot be silently edited.

        Parameters
        ----------
        policy:
            :class:`RetentionPolicy` to apply (e.g., ``SEC_17A4_BROKER_DEALER``).
        signing_key:
            Raw bytes from ``AEGIS_SIGNING_KEY``; used for HMAC-SHA256.
        segment_paths:
            Optional explicit list of paths to attest.  Defaults to all paths
            currently tracked by this enforcer's in-memory seal registry.
        now:
            Override for current time (tests only).

        Returns
        -------
        WORMAttestationBundle
            Fully populated attestation bundle ready for ``to_json()`` export.
        """
        ts = now if now is not None else time.time()
        paths = list(segment_paths) if segment_paths is not None else list(self._sealed_paths)

        segment_attestations: list[WORMSegmentAttestation] = []
        for raw_path in sorted(paths):
            abs_path = os.path.abspath(raw_path)
            seal_rec = self._read_seal_record(abs_path)
            sealed_at = seal_rec.sealed_at if seal_rec is not None else 0.0
            node_count = seal_rec.node_count if seal_rec is not None else 0
            seal_line = self._read_seal_line(abs_path)
            seal_hmac = _hmac_hex(signing_key, seal_line.encode("utf-8"))
            segment_attestations.append(
                WORMSegmentAttestation(
                    segment_path=abs_path,
                    sealed_at=sealed_at,
                    node_count=node_count,
                    seal_hmac=seal_hmac,
                    retention_policy=policy.name,
                    accessible_until=policy.accessible_until(sealed_at),
                    purge_eligible_at=policy.purge_eligible_at(sealed_at),
                    status=policy.retention_status(sealed_at, now=ts),
                )
            )

        bundle_hmac = _compute_bundle_hmac(segment_attestations, signing_key)
        return WORMAttestationBundle(
            generated_at=ts,
            generated_by=self._sealed_by,
            regulatory_citations=policy.citations,
            segments=segment_attestations,
            bundle_hmac=bundle_hmac,
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

    @staticmethod
    def _read_seal_line(path: str) -> str:
        """Return the raw seal-sentinel JSON line, or empty string if not found."""
        try:
            with open(path) as fh:
                lines = fh.readlines()
        except OSError:
            return ""
        for line in reversed(lines):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
                if data.get("record_type") == _WORM_SEAL_RECORD_TYPE:
                    return stripped
            except (json.JSONDecodeError, AttributeError):
                pass
            return ""
        return ""

    @staticmethod
    def _read_seal_record(path: str) -> WORMSealRecord | None:
        """Parse and return the seal sentinel from *path*, or None if absent."""
        try:
            with open(path) as fh:
                lines = fh.readlines()
        except OSError:
            return None
        for line in reversed(lines):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                data = json.loads(stripped)
                if data.get("record_type") == _WORM_SEAL_RECORD_TYPE:
                    return WORMSealRecord.from_dict(data)
            except (json.JSONDecodeError, AttributeError):
                pass
            return None
        return None


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
