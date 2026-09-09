# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

"""Veracity engine — evidence commitment and inclusion proofs, without the proxy.

Wraps :class:`~aegis.core.crypto_audit.CryptographicAuditLedger` and
:class:`~aegis.core.crypto_shredder.CryptoShredder` so an application already
running its own gateway can commit evidence and issue portable proofs by
library call:

    engine = VeracityEngine(wal_path="/var/lib/aegis/evidence.jsonl",
                            signing_key=os.environ["AEGIS_SIGNING_KEY"])
    record = engine.commit_evidence_record(
        state_id="req-1", request_bytes=b"...", response_bytes=b"...")
    proof = engine.generate_inclusion_proof(record.leaf_index)
    engine.verify_evidence_proof(record.leaf_digest, proof, trusted_root)

Boundaries carried over unchanged
---------------------------------

This is a facade. It adds no cryptographic property and relaxes none, so every
boundary on the underlying components still applies:

- Proofs are **non-zero-knowledge** inclusion proofs for a disclosed leaf
  against a **separately trusted root** (``CLM-006``). Passing the proof's own
  root back as ``trusted_root`` proves internal consistency and nothing else.
- One process, one WAL path. The single-writer lock refuses a second writer
  rather than serialising it; this facade does not change that.
- ``fsync`` returning is a process-observed acknowledgement, not a power-loss
  guarantee on any particular device.
- Crypto-shredding here is the unwired mechanism described in ``CLM-068``: it
  is **not** wired into the ledger's own commit path, so
  :meth:`crypto_shred` destroys a key for payloads *this facade sealed*, and
  establishes nothing about media sanitisation or any legal obligation.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any

from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.crypto_shredder import CryptoShredder, SealedPayload
from aegis.core.mmr import MMRInclusionProofV1
from aegis.engines import require_module
from aegis.licensing.validator import LicenseEntitlement

_MODULE_NAME = "veracity"


@dataclass(frozen=True, slots=True)
class EvidenceRecord:
    """What a commit produced, enough to verify it later without the ledger.

    ``proof`` is the node's own self-contained inclusion proof, captured at
    commit time. It stays verifiable after a peak-set restore has summarised
    the leaf away, which is why it is carried here rather than fetched later.
    """

    state_id: str
    node_hash: str
    merkle_root: str
    leaf_index: int
    leaf_digest: str
    proof: dict[str, Any] | None = None


class VeracityEngine:
    """Evidence commitment and portable inclusion proofs as a library."""

    def __init__(
        self,
        wal_path: str,
        *,
        signing_key: str = "",
        shredder_vault_path: str | None = None,
        entitlement: LicenseEntitlement | None = None,
        **ledger_kwargs: Any,
    ) -> None:
        self._entitlement = require_module(_MODULE_NAME, entitlement=entitlement)
        self._ledger = CryptographicAuditLedger(wal_path, signing_key=signing_key, **ledger_kwargs)
        self._shredder = CryptoShredder(shredder_vault_path)

    @property
    def ledger(self) -> CryptographicAuditLedger:
        """The underlying ledger, for callers needing the full surface."""

        return self._ledger

    @property
    def entitlement(self) -> LicenseEntitlement | None:
        return self._entitlement

    # ── commitment ──────────────────────────────────────────────────────

    def commit_evidence_record(
        self,
        *,
        state_id: str,
        request_bytes: bytes,
        response_bytes: bytes | None = None,
        tenant_id: str = "default",
        model: str = "unknown",
        endpoint: str = "library",
        **extra: Any,
    ) -> EvidenceRecord:
        """Commit one evidence node and return its identifiers.

        The write is durable before this returns, in the same sense the gateway
        means it: appended, flushed and ``fsync``-ed. See the module docstring
        on what ``fsync`` does and does not establish.
        """

        node = self._ledger.commit_forensic(
            state_id=state_id,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            tenant_id=tenant_id,
            model=model,
            endpoint=endpoint,
            **extra,
        )
        return self._record_from_node(node)

    def _record_from_node(self, node: Any) -> EvidenceRecord:
        """Read the identifiers the node already carries.

        ``mmr_leaf_hash`` and ``mmr_proof`` are written by the ledger at commit
        time. Recomputing a leaf digest here would be a second, independent
        guess at the ledger's leaf construction, and a wrong one would produce
        proofs that never verify.
        """

        proof: Mapping[str, Any] | None = getattr(node, "mmr_proof", None)
        return EvidenceRecord(
            state_id=str(getattr(node, "state_id", "")),
            node_hash=str(getattr(node, "node_hash", "")),
            merkle_root=str(getattr(node, "merkle_root", "")),
            leaf_index=int(proof["leaf_index"]) if proof else -1,
            leaf_digest=str(getattr(node, "mmr_leaf_hash", "")),
            proof=dict(proof) if proof else None,
        )

    # ── proofs ──────────────────────────────────────────────────────────

    def generate_inclusion_proof(self, leaf_index: int) -> dict[str, Any]:
        """Return the portable ``aegis-mmr-inclusion-v1`` proof for a leaf.

        Returned as a plain dict so it can be serialised straight onto the
        wire. Raises ``MMRHistoricalLeafUnavailableError`` for a leaf summarised
        away by a peak-set restore; every committed node also carries its own
        self-contained copy, which is the durable one.
        """

        proof = self._ledger._mmr.get_portable_inclusion_proof(leaf_index)
        as_dict: dict[str, Any] = proof.to_dict()
        return as_dict

    def verify_evidence_proof(
        self,
        leaf_digest: str,
        proof: Mapping[str, Any] | MMRInclusionProofV1,
        trusted_root: str,
    ) -> bool:
        """Verify a portable proof against a root obtained independently.

        Accepts the proof as the dataclass or as the dict it serialises to, so
        a proof that arrived over the wire needs no unwrapping by the caller.

        ``trusted_root`` must come from somewhere other than the proof itself —
        supplying ``proof["root"]`` back is circular and shows only that the
        envelope is internally consistent.
        """

        envelope = (
            proof
            if isinstance(proof, MMRInclusionProofV1)
            else MMRInclusionProofV1.from_dict(dict(proof))
        )
        result: bool = self._ledger._mmr.verify_portable_inclusion_hash(
            leaf_digest, envelope, trusted_root
        )
        return result

    def current_root(self) -> str:
        root: str = self._ledger._mmr.get_root_hash()
        return root

    def verify_integrity(self) -> tuple[bool, int | None]:
        """Walk the retained window. Not a full-history verification."""

        return self._ledger.verify_integrity()

    # ── cryptographic erasure ───────────────────────────────────────────

    def seal_payload(self, subject_id: str, plaintext: bytes) -> SealedPayload:
        """Seal a payload under ``subject_id``'s key; commit its ``commitment``."""

        return self._shredder.seal(subject_id, plaintext)

    def open_payload(self, sealed: SealedPayload) -> bytes:
        return self._shredder.open(sealed)

    def crypto_shred(self, subject_id: str) -> bool:
        """Destroy a subject's key. Returns whether one was present.

        The ledger does not move: roots, peaks and previously issued proofs are
        bit-for-bit unchanged. This makes the plaintext unrecoverable **to a
        holder of the ciphertext** and says nothing about the physical medium,
        vault backups, or any regulatory obligation (``CLM-068``).
        """

        return self._shredder.erase(subject_id)

    def close(self) -> None:
        self._shredder.close()
        self._ledger.close()

    def __enter__(self) -> VeracityEngine:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


__all__ = ["EvidenceRecord", "VeracityEngine"]
