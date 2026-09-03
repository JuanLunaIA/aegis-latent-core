"""
aegis.core.a2a — receipts for agent-to-agent tool execution.

When one agent calls another's tool, the caller ends up holding an answer and
no way to show where it came from. A receipt closes that gap: it lets the
caller demonstrate, to a third party, that a specific execution was recorded in
an Aegis ledger — without either party disclosing the arguments or the result.

The receipt travels as data. Verification needs only the receipt and a root the
verifier already trusts, obtained independently of whoever supplied the
receipt:

    receipt = generate_receipt(ledger, caller_agent_id=..., target_agent_id=...,
                               tool_name=..., input_bytes=..., output_bytes=...)
    verify_receipt(receipt, trusted_root)      # -> bool

**Confidentiality.** Arguments and results appear only as SHA-256 digests. A
holder of the receipt learns the tool name, the two agent identifiers, the
timestamp, and the two digests. A digest is not a commitment scheme: an input
drawn from a small or guessable domain can be recovered by enumeration, so
low-entropy arguments are not protected by hashing alone.

**What a valid receipt establishes.** Exactly one thing: the canonical envelope
below is included, at the stated leaf index, under the root the verifier
supplied. Because the envelope is a deterministic function of the receipt's own
fields, a receipt cannot be re-pointed at some other execution's leaf.

**What it does not establish** — none of this follows from a valid receipt, and
none of it may be claimed on its strength:

- *That the tool ran, or produced that output.* The ledger records what it was
  told. A receipt attests to a record, not to an execution.
- *Identity or authority.* ``caller_agent_id`` and ``target_agent_id`` are
  strings the issuer chose. Nothing here authenticates an agent or establishes
  that it was permitted to make the call.
- *Time.* ``timestamp`` is the issuer's clock, unattested. There is no
  timestamping authority in this path.
- *Trust in the root.* Verification is only as good as the root, which must be
  obtained from a source independent of the receipt's supplier. A receipt
  verified against a root taken from the same party proves internal
  consistency and nothing more.
- *Non-membership, ordering, or custody.* The MMR proves inclusion only.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any

from aegis.core.forensic import build_merkle_leaf, sha256_hex
from aegis.core.mmr import MerkleMountainRange, MMRInclusionProofV1

if TYPE_CHECKING:  # pragma: no cover - import cycle guard, typing only
    from aegis.core.crypto_audit import CryptographicAuditLedger

logger = logging.getLogger(__name__)

__all__ = [
    "A2A_ENDPOINT",
    "A2A_MODEL",
    "A2A_RECEIPT_VERSION",
    "AgentReceipt",
    "a2a_envelope_bytes",
    "a2a_leaf_hash",
    "generate_receipt",
    "verify_receipt",
]

#: Wire version. A verifier rejects anything it does not recognise rather than
#: guessing at a layout, so this changes only for an incompatible envelope.
A2A_RECEIPT_VERSION = "aegis-a2a-receipt-v1"

#: Fixed leaf coordinates. They are part of the hashed envelope, so a verifier
#: must reproduce them exactly; pinning them here keeps a receipt verifiable
#: independently of how the issuing ledger happened to be configured.
A2A_MODEL = "a2a"
A2A_ENDPOINT = "a2a.tool"

#: Bound on the identifier fields. Keeping the envelope small guarantees it
#: stays under any sane ``max_forensic_bytes``, so the leaf preview is never
#: truncated and the leaf hash does not depend on ledger configuration.
_MAX_IDENTIFIER_CHARS = 128

#: Floor the issuing ledger must allow, so ``build_merkle_leaf`` copies the
#: envelope whole. Comfortably above the largest envelope this module can build.
_MIN_LEDGER_FORENSIC_BYTES = 2048


def _require_identifier(name: str, value: str) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a non-empty string")
    if len(value) > _MAX_IDENTIFIER_CHARS:
        raise ValueError(f"{name} exceeds {_MAX_IDENTIFIER_CHARS} characters")
    if "\x00" in value:
        raise ValueError(f"{name} must not contain a NULL byte")
    return value


def _require_digest(name: str, value: str) -> str:
    if not isinstance(value, str) or len(value) != 64:
        raise ValueError(f"{name} must be a SHA-256 hex digest")
    if any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{name} must be lowercase hexadecimal")
    return value


@dataclass(frozen=True)
class AgentReceipt:
    """A verifiable record that one agent's tool execution was logged.

    Every field is public: the receipt is designed to be handed to a party that
    is not trusted, and carries no secret. See the module docstring for the
    exact boundary of what a valid receipt does and does not establish.
    """

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

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, value: dict[str, Any]) -> AgentReceipt:
        """Rebuild a receipt from transported JSON.

        Raises:
            ValueError: If a field is missing or of the wrong type. A receipt
                that cannot be parsed is refused rather than partially filled,
                since a defaulted field would silently change what is verified.
        """
        missing = set(cls.__dataclass_fields__) - set(value)
        if missing:
            raise ValueError(f"receipt is missing required fields: {sorted(missing)}")
        try:
            return cls(
                version=str(value["version"]),
                execution_id=str(value["execution_id"]),
                caller_agent_id=str(value["caller_agent_id"]),
                target_agent_id=str(value["target_agent_id"]),
                tool_name=str(value["tool_name"]),
                input_hash=str(value["input_hash"]),
                output_hash=str(value["output_hash"]),
                timestamp=float(value["timestamp"]),
                mmr_root=str(value["mmr_root"]),
                inclusion_proof=dict(value["inclusion_proof"]),
            )
        except (TypeError, ValueError) as exc:
            raise ValueError(f"receipt field has the wrong type: {exc}") from exc


def a2a_envelope_bytes(
    *,
    execution_id: str,
    caller_agent_id: str,
    target_agent_id: str,
    tool_name: str,
    input_hash: str,
    output_hash: str,
    timestamp: float,
) -> bytes:
    """Canonical bytes committed for one agent-to-agent execution.

    Sorted keys and compact separators make this reproducible byte-for-byte by
    any verifier from the receipt's own fields, which is what stops a receipt
    from being re-pointed at a different leaf.
    """
    envelope = {
        "version": A2A_RECEIPT_VERSION,
        "execution_id": _require_identifier("execution_id", execution_id),
        "caller_agent_id": _require_identifier("caller_agent_id", caller_agent_id),
        "target_agent_id": _require_identifier("target_agent_id", target_agent_id),
        "tool_name": _require_identifier("tool_name", tool_name),
        "input_hash": _require_digest("input_hash", input_hash),
        "output_hash": _require_digest("output_hash", output_hash),
        "timestamp": f"{float(timestamp):.6f}",
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()


def a2a_leaf_hash(envelope: bytes) -> str:
    """SHA-256 of the MMR leaf built from an A2A envelope.

    The envelope is wrapped by :func:`~aegis.core.forensic.build_merkle_leaf`
    with pinned coordinates so the leaf matches what the ledger committed. The
    cap is fixed by this protocol rather than taken from the ledger, so the
    result never depends on how the issuer was configured.
    """
    leaf = build_merkle_leaf(
        state_id=json.loads(envelope.decode())["execution_id"],
        request_bytes=envelope,
        response_bytes=None,
        model=A2A_MODEL,
        endpoint=A2A_ENDPOINT,
        max_bytes=_MIN_LEDGER_FORENSIC_BYTES,
    )
    return sha256_hex(leaf)


def generate_receipt(
    ledger: CryptographicAuditLedger,
    *,
    caller_agent_id: str,
    target_agent_id: str,
    tool_name: str,
    input_bytes: bytes,
    output_bytes: bytes,
    execution_id: str | None = None,
    tenant_id: str = "a2a",
    timestamp: float | None = None,
) -> AgentReceipt:
    """Commit one agent-to-agent execution and return its receipt.

    ``input_bytes`` and ``output_bytes`` are hashed and discarded; neither is
    written to the ledger or carried in the receipt.

    Args:
        ledger: The ledger to commit into. Its ``max_forensic_bytes`` must be
            at least ``2048`` so the envelope is committed whole — a smaller
            cap would truncate the leaf preview and produce a leaf no verifier
            could reproduce.
        caller_agent_id: Identifier the calling agent asserts for itself.
        target_agent_id: Identifier of the agent whose tool was executed.
        tool_name: Name of the executed tool.
        input_bytes: Arguments, hashed only.
        output_bytes: Result, hashed only.
        execution_id: Identifier for this execution. Derived from the
            participants and digests when omitted, which makes the same
            execution produce the same identifier.
        tenant_id: Attribution recorded on the committed node.
        timestamp: Issuer clock reading to seal into the envelope. Defaults to
            now. It is chosen before the commit because it is part of the
            hashed envelope: reading it back from the node afterwards would
            mean committing once to learn it and again to seal it.

    Returns:
        A receipt whose inclusion proof verifies against the ledger's root.

    Raises:
        ValueError: On a malformed identifier or a ledger cap below the floor.
    """
    if ledger.max_forensic_bytes < _MIN_LEDGER_FORENSIC_BYTES:
        raise ValueError(
            "ledger max_forensic_bytes must be at least "
            f"{_MIN_LEDGER_FORENSIC_BYTES} to issue A2A receipts; "
            f"got {ledger.max_forensic_bytes}"
        )

    input_hash = sha256_hex(input_bytes)
    output_hash = sha256_hex(output_bytes)
    resolved_id = (
        execution_id
        or "a2a-"
        + sha256_hex(
            f"{caller_agent_id}|{target_agent_id}|{tool_name}|{input_hash}|{output_hash}".encode()
        )[:32]
    )

    sealed_at = time.time() if timestamp is None else float(timestamp)
    envelope = a2a_envelope_bytes(
        execution_id=_require_identifier("execution_id", resolved_id),
        caller_agent_id=caller_agent_id,
        target_agent_id=target_agent_id,
        tool_name=tool_name,
        input_hash=input_hash,
        output_hash=output_hash,
        timestamp=sealed_at,
    )
    node = ledger.commit_forensic(
        state_id=resolved_id,
        request_bytes=envelope,
        response_bytes=None,
        tenant_id=tenant_id,
        model=A2A_MODEL,
        endpoint=A2A_ENDPOINT,
    )
    if node.mmr_proof is None:  # pragma: no cover - commit always attaches one
        raise RuntimeError("ledger committed an A2A node without an inclusion proof")

    return AgentReceipt(
        version=A2A_RECEIPT_VERSION,
        execution_id=resolved_id,
        caller_agent_id=caller_agent_id,
        target_agent_id=target_agent_id,
        tool_name=tool_name,
        input_hash=input_hash,
        output_hash=output_hash,
        timestamp=sealed_at,
        mmr_root=node.merkle_root,
        inclusion_proof=dict(node.mmr_proof),
    )


def verify_receipt(receipt: AgentReceipt | dict[str, Any], trusted_root: str) -> bool:
    """Verify a receipt against a root obtained independently of its supplier.

    Two things are checked, and a receipt is valid only if both hold:

    1. The leaf named by the proof is the one the receipt's own fields produce.
       Without this a receipt could quote any leaf already in the tree and
       assert whatever metadata it liked about it.
    2. That leaf is included under ``trusted_root`` at the stated index, by the
       ``aegis-mmr-inclusion-v1`` verifier.

    Returns:
        ``True`` only when both hold. Every failure — unknown version,
        malformed field, unparseable proof, root mismatch — returns ``False``
        rather than raising, so a caller cannot mistake an error for a pass.
        The reason is logged.

    See the module docstring for what a ``True`` result does and does not mean.
    In particular it does not establish that the tool ran, who the agents were,
    or when.
    """
    try:
        parsed = AgentReceipt.from_dict(receipt) if isinstance(receipt, dict) else receipt
    except ValueError as exc:
        logger.warning("A2A receipt rejected: %s", exc)
        return False

    if parsed.version != A2A_RECEIPT_VERSION:
        logger.warning("A2A receipt rejected: unknown version %r", parsed.version)
        return False

    try:
        envelope = a2a_envelope_bytes(
            execution_id=parsed.execution_id,
            caller_agent_id=parsed.caller_agent_id,
            target_agent_id=parsed.target_agent_id,
            tool_name=parsed.tool_name,
            input_hash=parsed.input_hash,
            output_hash=parsed.output_hash,
            timestamp=parsed.timestamp,
        )
        leaf_hash = a2a_leaf_hash(envelope)
        proof = MMRInclusionProofV1.from_dict(parsed.inclusion_proof)
    except (ValueError, TypeError, KeyError) as exc:
        logger.warning("A2A receipt rejected: %s", exc)
        return False

    if parsed.mmr_root != trusted_root:
        logger.warning("A2A receipt rejected: receipt root does not match the trusted root")
        return False

    return MerkleMountainRange.verify_portable_inclusion_hash(leaf_hash, proof, trusted_root)
