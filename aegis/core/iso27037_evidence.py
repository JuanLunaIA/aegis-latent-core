# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""aegis.core.iso27037_evidence — ISO/IEC 27037 compliant digital evidence packages.

Implements the ISO/IEC 27037:2012 (Guidelines for identification, collection,
acquisition and preservation of digital evidence) evidence package format for
the Aegis audit ledger.

An evidence package contains five mandatory ISO/IEC 27037 elements:

1. **Chain of Custody Manifest** — ordered log of every acquisition, transfer,
   and access event for the evidence, including operator identity and timestamp.
2. **Acquisition Metadata** — tool identity (name + version), operator identity,
   and acquisition timestamp, enabling re-verification by a third party.
3. **Hash Algorithm Declaration** — explicit declaration of the algorithm used
   to compute all hashes in the package (SHA-256).
4. **Evidence Nodes** — the original forensic records (state_id, node_hash,
   timestamp, tenant_id, signature, signature_scheme) extracted from the
   Merkle audit chain.
5. **Evidence Integrity Seal** — SHA-256 over the canonical JSON of all fields
   above (sorted keys, no whitespace), computed last and appended.  Re-run
   :func:`verify_seal` to confirm the package has not been tampered with.

Usage::

    from aegis.core.iso27037_evidence import build_evidence_package, verify_seal

    pkg = build_evidence_package(
        ledger=ledger,
        operator="Alice Smith <alice@example.org>",
        tool_version="aegis-latent-core/3.0.0",
        acquisition_reason="incident-response-2026-06-21",
    )
    pkg_dict = pkg.to_dict()
    assert verify_seal(pkg_dict), "Package integrity compromised"

Serialisation::

    import json
    with open("evidence_package.json", "w") as f:
        json.dump(pkg.to_dict(), f, indent=2)

Re-verification (offline, without the running proxy)::

    import json
    from aegis.core.iso27037_evidence import verify_seal
    with open("evidence_package.json") as f:
        data = json.load(f)
    ok = verify_seal(data)
"""

from __future__ import annotations

import hashlib
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from aegis.core.crypto_audit import CryptographicAuditLedger

_TOOL_NAME: str = "aegis-latent-core"
_HASH_ALGORITHM: str = "SHA-256"
_STANDARD_REF: str = "ISO/IEC 27037:2012"


class LegalAdmissibility(StrEnum):
    """Per-bundle legal admissibility classification.

    Values map to evidential weight under ISO/IEC 27037:2012 §9.3:

    Admissible
        Chain integrity verified; all nodes signed; no tampering detected.
        Suitable for court presentation without qualification.
    Conditional
        Minor integrity concerns (e.g. partial WAL loss, signing-key rotation
        during capture window) that do not invalidate core evidence but require
        expert qualification before court presentation.
    Compromised
        Integrity seal failed or hash-chain break detected; evidence may not
        be presented as authentic without independent re-verification.
    """

    Admissible = "Admissible"
    Conditional = "Conditional"
    Compromised = "Compromised"


# ── Chain of Custody ──────────────────────────────────────────────────────────


@dataclass
class CustodyEvent:
    """A single entry in the chain of custody.

    Attributes
    ----------
    event_type:
        One of: ``acquisition``, ``transfer``, ``access``, ``verification``.
    operator:
        Free-form identity of the person or system that performed the event
        (e.g. "Alice Smith <alice@example.org>").
    timestamp_iso:
        UTC ISO-8601 timestamp when the event occurred.
    notes:
        Optional free-form description (reason for access, destination, etc.).
    """

    event_type: str
    operator: str
    timestamp_iso: str
    notes: str = ""

    def to_dict(self) -> dict[str, str]:
        return {
            "event_type": self.event_type,
            "operator": self.operator,
            "timestamp_iso": self.timestamp_iso,
            "notes": self.notes,
        }


# ── Acquisition Metadata ──────────────────────────────────────────────────────


@dataclass
class AcquisitionMetadata:
    """ISO/IEC 27037 §8 acquisition metadata.

    Attributes
    ----------
    tool_name:
        Name of the acquisition tool (default: ``_TOOL_NAME``).
    tool_version:
        Semantic version string for the tool (e.g. ``"3.0.0"``).
    operator:
        Identity of the operator who initiated the acquisition.
    acquisition_timestamp_iso:
        UTC ISO-8601 timestamp when acquisition started.
    acquisition_reason:
        Human-readable reason for the acquisition (optional; e.g. for
        incident response or periodic compliance export).
    hash_algorithm:
        Name of the hash algorithm used for all content hashes in the
        package.  Always ``"SHA-256"`` for Aegis.
    standard_reference:
        The standard this package conforms to
        (``"ISO/IEC 27037:2012"``).
    """

    tool_name: str
    tool_version: str
    operator: str
    acquisition_timestamp_iso: str
    acquisition_reason: str = ""
    hash_algorithm: str = _HASH_ALGORITHM
    standard_reference: str = _STANDARD_REF

    def to_dict(self) -> dict[str, str]:
        return {
            "tool_name": self.tool_name,
            "tool_version": self.tool_version,
            "operator": self.operator,
            "acquisition_timestamp_iso": self.acquisition_timestamp_iso,
            "acquisition_reason": self.acquisition_reason,
            "hash_algorithm": self.hash_algorithm,
            "standard_reference": self.standard_reference,
        }


# ── Evidence Node ─────────────────────────────────────────────────────────────


@dataclass
class EvidenceNode:
    """A single evidence item extracted from the Merkle audit chain.

    Attributes
    ----------
    index:
        Position of the node in the audit chain (0 = genesis).
    state_id:
        Unique identifier for this audit record.
    node_hash:
        SHA-256 chain accumulator; covers ``prev_hash`` and all chain fields.
    prev_hash:
        Hash of the preceding node (64 zero digits for genesis).
    timestamp_iso:
        UTC ISO-8601 timestamp of the audit event.
    tenant_id:
        Tenant that originated the request.
    request_hash:
        SHA-256 of the raw request bytes.
    response_hash:
        SHA-256 of the raw response bytes (empty string if not captured).
    signature:
        Hex-encoded cryptographic signature (HMAC-SHA256 or ML-DSA-65).
    signature_scheme:
        Algorithm identifier: ``"hmac-sha256"`` | ``"pqc-ml-dsa"`` |
        ``"ed25519-fallback"``.
    model:
        LLM model identifier used for this request.
    """

    index: int
    state_id: str
    node_hash: str
    prev_hash: str
    timestamp_iso: str
    tenant_id: str
    request_hash: str
    response_hash: str
    signature: str
    signature_scheme: str
    model: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "index": self.index,
            "state_id": self.state_id,
            "node_hash": self.node_hash,
            "prev_hash": self.prev_hash,
            "timestamp_iso": self.timestamp_iso,
            "tenant_id": self.tenant_id,
            "request_hash": self.request_hash,
            "response_hash": self.response_hash,
            "signature": self.signature,
            "signature_scheme": self.signature_scheme,
            "model": self.model,
        }


# ── Evidence Package ──────────────────────────────────────────────────────────


@dataclass
class EvidencePackage:
    """ISO/IEC 27037 compliant evidence package.

    Attributes
    ----------
    package_id:
        UUID v4 uniquely identifying this export.
    acquisition_metadata:
        Tool, operator, timestamp, hash-algorithm declaration.
    chain_of_custody:
        Ordered list of :class:`CustodyEvent` entries.
    evidence_nodes:
        Ordered list of :class:`EvidenceNode` extracted from the audit chain.
    chain_integrity_valid:
        Result of :meth:`~aegis.core.crypto_audit.CryptographicAuditLedger.verify_integrity`
        at the time of acquisition.
    chain_integrity_error_index:
        Index of the first broken link, or ``-1`` if the chain is intact.
    node_count:
        Number of nodes captured in this package.
    tail_hash:
        ``node_hash`` of the most recent node in the chain (empty when
        chain is empty).
    legal_admissibility:
        Admissibility label from the ledger (``"High"`` / ``"Medium"`` /
        ``"Low"``).
    integrity_seal:
        SHA-256 over the canonical serialisation of every other field.
        Computed by :func:`build_evidence_package` and verified by
        :func:`verify_seal`.
    """

    package_id: str
    acquisition_metadata: AcquisitionMetadata
    chain_of_custody: list[CustodyEvent]
    evidence_nodes: list[EvidenceNode]
    chain_integrity_valid: bool
    chain_integrity_error_index: int
    node_count: int
    tail_hash: str
    legal_admissibility: str
    legal_admissibility_justification: str = field(default="")
    integrity_seal: str = field(default="")

    def to_dict(self) -> dict[str, Any]:
        return {
            "package_id": self.package_id,
            "acquisition_metadata": self.acquisition_metadata.to_dict(),
            "chain_of_custody": [e.to_dict() for e in self.chain_of_custody],
            "evidence_nodes": [n.to_dict() for n in self.evidence_nodes],
            "chain_integrity_valid": self.chain_integrity_valid,
            "chain_integrity_error_index": self.chain_integrity_error_index,
            "node_count": self.node_count,
            "tail_hash": self.tail_hash,
            "legal_admissibility": self.legal_admissibility,
            "legal_admissibility_justification": self.legal_admissibility_justification,
            "integrity_seal": self.integrity_seal,
        }


# ── Seal helpers ──────────────────────────────────────────────────────────────


def _compute_seal(package_dict: dict[str, Any]) -> str:
    """SHA-256 over canonical JSON of *package_dict* with ``integrity_seal`` set to ''."""
    payload = {k: v for k, v in package_dict.items() if k != "integrity_seal"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode()).hexdigest()


def verify_seal(package_dict: dict[str, Any]) -> bool:
    """Return ``True`` if *package_dict*'s ``integrity_seal`` is correct.

    Parameters
    ----------
    package_dict:
        A :class:`EvidencePackage` serialised to a plain dict (via
        :meth:`EvidencePackage.to_dict` or loaded from JSON).

    Returns
    -------
    bool
        ``True`` when the computed seal matches the stored
        ``integrity_seal``; ``False`` on any mismatch or missing field.
    """
    stored = package_dict.get("integrity_seal", "")
    if not stored:
        return False
    return hmac_safe_compare(stored, _compute_seal(package_dict))


def hmac_safe_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    import hmac as _hmac  # noqa: PLC0415

    return _hmac.compare_digest(a.encode(), b.encode())


# ── Builder ───────────────────────────────────────────────────────────────────


def build_evidence_package(
    ledger: CryptographicAuditLedger,
    operator: str,
    tool_version: str = "unknown",
    acquisition_reason: str = "",
    legal_admissibility_override: LegalAdmissibility | None = None,
    legal_admissibility_justification: str = "",
) -> EvidencePackage:
    """Build an ISO/IEC 27037 compliant evidence package from *ledger*.

    The package is self-contained: all cryptographic commitments, chain-
    linkage hashes, and signatures from the audit ledger are embedded.
    The final ``integrity_seal`` covers all fields so that any post-export
    tampering is detectable without a live Aegis instance.

    Parameters
    ----------
    ledger:
        A :class:`~aegis.core.crypto_audit.CryptographicAuditLedger` instance.
    operator:
        Identity of the person or system exporting the evidence
        (e.g. ``"Alice Smith <alice@example.org>"``).
    tool_version:
        Version string of the running Aegis deployment
        (e.g. ``"3.0.0"``).
    acquisition_reason:
        Optional free-form reason for this export (e.g.
        ``"scheduled-compliance-export"`` or ``"incident-response"``).
    legal_admissibility_override:
        Optional :class:`LegalAdmissibility` enum value that overrides the
        chain-level admissibility.  When provided, ``legal_admissibility``
        in the package is set to this value instead of the ledger's value.
        Use when an investigator's review has upgraded or downgraded the
        chain-level assessment (e.g. downgrade to ``Conditional`` due to
        a gap in WAL coverage, upgrade to ``Admissible`` after expert
        re-verification).
    legal_admissibility_justification:
        Free-form justification for the override (e.g. case number, expert
        name, or summary of the re-verification result).  Stored in the
        package and covered by the integrity seal.

    Returns
    -------
    EvidencePackage
        A fully populated and sealed evidence package.
    """
    now_ts = time.time()
    now_iso = datetime.fromtimestamp(now_ts, tz=UTC).isoformat()

    # Snapshot ledger under its own lock
    with ledger._lock:
        chain_snapshot = list(ledger.chain)
        legal_admissibility = ledger.legal_admissibility

    # Apply per-bundle override when provided.
    if legal_admissibility_override is not None:
        legal_admissibility = legal_admissibility_override.value

    # Chain integrity check
    is_valid, err_idx = ledger.verify_integrity()

    tail_hash = chain_snapshot[-1].node_hash if chain_snapshot else ""

    acquisition_metadata = AcquisitionMetadata(
        tool_name=_TOOL_NAME,
        tool_version=tool_version,
        operator=operator,
        acquisition_timestamp_iso=now_iso,
        acquisition_reason=acquisition_reason,
    )

    custody = [
        CustodyEvent(
            event_type="acquisition",
            operator=operator,
            timestamp_iso=now_iso,
            notes=f"ISO/IEC 27037 evidence package export; reason: {acquisition_reason}"
            if acquisition_reason
            else "ISO/IEC 27037 evidence package export",
        )
    ]

    evidence_nodes = [
        EvidenceNode(
            index=i,
            state_id=node.state_id,
            node_hash=node.node_hash,
            prev_hash=node.prev_hash,
            timestamp_iso=datetime.fromtimestamp(node.timestamp, tz=UTC).isoformat(),
            tenant_id=node.tenant_id,
            request_hash=node.request_hash,
            response_hash=node.response_hash,
            signature=node.signature,
            signature_scheme=node.signature_scheme,
            model=node.model,
        )
        for i, node in enumerate(chain_snapshot)
    ]

    pkg = EvidencePackage(
        package_id=str(uuid.uuid4()),
        acquisition_metadata=acquisition_metadata,
        chain_of_custody=custody,
        evidence_nodes=evidence_nodes,
        chain_integrity_valid=is_valid,
        chain_integrity_error_index=err_idx if err_idx is not None else -1,
        node_count=len(chain_snapshot),
        tail_hash=tail_hash,
        legal_admissibility=legal_admissibility,
        legal_admissibility_justification=legal_admissibility_justification,
        integrity_seal="",
    )

    # Compute and attach seal
    pkg_dict = pkg.to_dict()
    pkg.integrity_seal = _compute_seal(pkg_dict)
    return pkg


# ── Custody log append ────────────────────────────────────────────────────────


def add_custody_event(
    package: EvidencePackage,
    event_type: str,
    operator: str,
    notes: str = "",
    timestamp: float | None = None,
) -> EvidencePackage:
    """Append a custody event and re-seal the package.

    Parameters
    ----------
    package:
        An existing :class:`EvidencePackage`.
    event_type:
        One of ``"acquisition"``, ``"transfer"``, ``"access"``, ``"verification"``.
    operator:
        Identity of the person or system performing the event.
    notes:
        Optional free-form description.
    timestamp:
        Unix timestamp for the event; defaults to ``time.time()``.

    Returns
    -------
    EvidencePackage
        The same package with the new event appended and a fresh
        ``integrity_seal``.
    """
    ts = timestamp if timestamp is not None else time.time()
    ts_iso = datetime.fromtimestamp(ts, tz=UTC).isoformat()
    package.chain_of_custody.append(
        CustodyEvent(event_type=event_type, operator=operator, timestamp_iso=ts_iso, notes=notes)
    )
    pkg_dict = package.to_dict()
    package.integrity_seal = _compute_seal(pkg_dict)
    return package
