"""Verify agent-to-agent execution receipts.

The gateway issues receipts with :mod:`aegis.core.a2a`. This is the consumer
half: it verifies one without importing the server package, so an agent can
check a receipt handed to it by a peer it does not trust.

    from aegis_sdk.a2a import AgentReceipt, verify_receipt

    receipt = AgentReceipt.from_mapping(payload)
    verify_receipt(receipt, trusted_root)   # -> bool

A receipt is valid when both hold: the leaf named by its proof is the one its
own fields reproduce, and that leaf is included under the supplied root. The
first check is what stops a receipt quoting some other execution's leaf while
asserting whatever metadata it likes.

**A valid receipt establishes inclusion under the root you supplied, and
nothing else.** It does not establish that the tool ran, that either agent
identifier is authentic, that the caller was authorised, or that the timestamp
is accurate — that is the issuer's unattested clock. The root must be obtained
independently of whoever gave you the receipt; verified against a root from the
same party, a receipt shows internal consistency only.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import json
import logging
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from typing import Any

from aegis_sdk.proof import AegisProofError, InclusionProof, verify_inclusion_hash

logger = logging.getLogger(__name__)

__all__ = [
    "A2A_ENDPOINT",
    "A2A_MODEL",
    "A2A_RECEIPT_VERSION",
    "AgentReceipt",
    "a2a_envelope_bytes",
    "a2a_leaf_hash",
    "verify_receipt",
]

A2A_RECEIPT_VERSION = "aegis-a2a-receipt-v1"
A2A_MODEL = "a2a"
A2A_ENDPOINT = "a2a.tool"

# Must match aegis.core.a2a exactly. These values are hashed into the leaf, so
# a divergence here does not produce a lenient verifier — it produces one that
# rejects every valid receipt.
_MAX_IDENTIFIER_CHARS = 128
_LEAF_MAX_BYTES = 2048

_RECEIPT_FIELDS = (
    "version",
    "execution_id",
    "caller_agent_id",
    "target_agent_id",
    "tool_name",
    "input_hash",
    "output_hash",
    "timestamp",
    "mmr_root",
    "inclusion_proof",
)


def _require_identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise AegisProofError(f"{name} must be a non-empty string")
    if len(value) > _MAX_IDENTIFIER_CHARS:
        raise AegisProofError(f"{name} exceeds {_MAX_IDENTIFIER_CHARS} characters")
    if "\x00" in value:
        raise AegisProofError(f"{name} must not contain a NULL byte")
    return value


def _require_digest(name: str, value: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise AegisProofError(f"{name} must be a SHA-256 hex digest")
    if any(character not in "0123456789abcdef" for character in value):
        raise AegisProofError(f"{name} must be lowercase hexadecimal")
    return value


@dataclass(frozen=True)
class AgentReceipt:
    """A receipt for one agent-to-agent tool execution."""

    version: str
    execution_id: str
    caller_agent_id: str
    target_agent_id: str
    tool_name: str
    input_hash: str
    output_hash: str
    timestamp: float
    mmr_root: str
    inclusion_proof: dict[str, Any]

    def to_mapping(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> AgentReceipt:
        """Parse a transported receipt.

        Raises:
            AegisProofError: If a field is absent or of the wrong type. Parsing
                refuses rather than defaulting, because a defaulted field
                changes the envelope that gets verified.
        """
        missing = [key for key in _RECEIPT_FIELDS if key not in value]
        if missing:
            raise AegisProofError(f"receipt is missing required fields: {missing}")
        proof = value["inclusion_proof"]
        if not isinstance(proof, Mapping):
            raise AegisProofError("inclusion_proof must be a mapping")
        timestamp = value["timestamp"]
        if isinstance(timestamp, bool) or not isinstance(timestamp, (int, float)):
            raise AegisProofError("timestamp must be a number")
        return cls(
            version=_require_identifier("version", value["version"]),
            execution_id=_require_identifier("execution_id", value["execution_id"]),
            caller_agent_id=_require_identifier("caller_agent_id", value["caller_agent_id"]),
            target_agent_id=_require_identifier("target_agent_id", value["target_agent_id"]),
            tool_name=_require_identifier("tool_name", value["tool_name"]),
            input_hash=_require_digest("input_hash", value["input_hash"]),
            output_hash=_require_digest("output_hash", value["output_hash"]),
            timestamp=float(timestamp),
            mmr_root=_require_digest("mmr_root", value["mmr_root"]),
            inclusion_proof=dict(proof),
        )


def a2a_envelope_bytes(receipt: AgentReceipt) -> bytes:
    """Canonical envelope bytes reproduced from a receipt's own fields."""
    envelope = {
        "version": A2A_RECEIPT_VERSION,
        "execution_id": _require_identifier("execution_id", receipt.execution_id),
        "caller_agent_id": _require_identifier("caller_agent_id", receipt.caller_agent_id),
        "target_agent_id": _require_identifier("target_agent_id", receipt.target_agent_id),
        "tool_name": _require_identifier("tool_name", receipt.tool_name),
        "input_hash": _require_digest("input_hash", receipt.input_hash),
        "output_hash": _require_digest("output_hash", receipt.output_hash),
        "timestamp": f"{float(receipt.timestamp):.6f}",
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()


def a2a_leaf_hash(receipt: AgentReceipt) -> str:
    """SHA-256 of the MMR leaf the issuing ledger committed for this receipt.

    Mirrors ``build_merkle_leaf`` for the pinned A2A coordinates. The envelope
    is bounded well under ``_LEAF_MAX_BYTES``, so the preview is a copy of it
    and the result does not depend on the issuer's configuration.
    """
    envelope = a2a_envelope_bytes(receipt)
    leaf = {
        "state_id": receipt.execution_id,
        "request_hash": hashlib.sha256(envelope).hexdigest(),
        "response_hash": "",
        "request_size": len(envelope),
        "response_size": 0,
        "request_preview_hex": envelope[:_LEAF_MAX_BYTES].hex(),
        "response_preview_hex": "",
        "model": A2A_MODEL,
        "endpoint": A2A_ENDPOINT,
    }
    encoded = json.dumps(leaf, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def verify_receipt(receipt: AgentReceipt | Mapping[str, Any], trusted_root: str) -> bool:
    """Verify a receipt against a root obtained independently of its supplier.

    Returns:
        ``True`` only when the receipt reproduces the proven leaf and that leaf
        is included under ``trusted_root``. Every failure returns ``False``
        rather than raising, so an error cannot be mistaken for a pass; the
        reason is logged.
    """
    try:
        parsed = AgentReceipt.from_mapping(receipt) if isinstance(receipt, Mapping) else receipt
        if parsed.version != A2A_RECEIPT_VERSION:
            logger.warning("A2A receipt rejected: unknown version %r", parsed.version)
            return False
        if parsed.mmr_root != trusted_root:
            logger.warning("A2A receipt rejected: receipt root is not the trusted root")
            return False
        leaf_hash = a2a_leaf_hash(parsed)
        proof = InclusionProof.from_mapping(parsed.inclusion_proof)
    except (AegisProofError, TypeError, ValueError, KeyError) as exc:
        logger.warning("A2A receipt rejected: %s", exc)
        return False
    return verify_inclusion_hash(leaf_hash, proof, trusted_root)
