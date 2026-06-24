"""
aegis.core.blockchain_anchor — external root anchoring (pluggable backend).

Anchors Merkle roots into an external, immutable authority so the audit chain's
state can be proven to have existed at a point in time, independently of Aegis.

**Honesty contract:** there is no fabricated-proof fallback. When no anchoring
backend is configured, :meth:`BlockchainAnchorProvider.publish_root` raises
:class:`AnchorUnavailableError` rather than inventing a transaction hash. A real
backend must be supplied:

* :class:`RFC3161AnchorBackend` — anchors to an RFC 3161 Time-Stamping Authority
  (a real, third-party-verifiable trusted-timestamp authority) using the existing
  :class:`~aegis.core.rfc3161_timestamper.RFC3161Timestamper`.
* Public-blockchain backends (OpenTimestamps/Bitcoin, Ethereum/Polygon via
  ``web3``) can be added behind the same :class:`AnchorBackend` interface and are
  tracked in ``docs/ROADMAP.md`` (DX-Forensic).
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from aegis.core.rfc3161_timestamper import RFC3161Timestamper

logger = logging.getLogger(__name__)


class AnchorUnavailableError(RuntimeError):
    """Raised when anchoring is requested but no real backend is available."""


@dataclass
class AnchorReceipt:
    """A real anchoring receipt returned by a backend.

    ``metadata`` carries whatever the backend needs to later verify the receipt
    (for RFC 3161, the stamped evidence package including the token).
    """

    backend: str
    root_hash: str
    anchor_ref: str  # token/transaction identifier
    timestamp: float
    verification_url: str = ""
    metadata: dict[str, object] = field(default_factory=dict)


@runtime_checkable
class AnchorBackend(Protocol):
    """Interface every real anchoring backend implements."""

    name: str

    async def anchor(self, root_hash: str) -> AnchorReceipt: ...

    async def verify(self, receipt: AnchorReceipt, expected_root: str) -> bool: ...


class RFC3161AnchorBackend:
    """Anchor to an RFC 3161 Time-Stamping Authority (real external authority)."""

    name = "rfc3161"

    def __init__(self, timestamper: RFC3161Timestamper | None = None) -> None:
        self._ts = timestamper or RFC3161Timestamper()

    async def anchor(self, root_hash: str) -> AnchorReceipt:
        # RFC3161Timestamper.stamp performs blocking HTTP; run it off the loop.
        result = await asyncio.to_thread(self._ts.stamp, {"merkle_root": root_hash})
        if not result.success:
            raise AnchorUnavailableError(f"RFC3161 anchoring failed: {result.error}")
        anchor_ref = hashlib.sha256(result.token_b64.encode()).hexdigest()[:32]
        return AnchorReceipt(
            backend=self.name,
            root_hash=root_hash,
            anchor_ref=anchor_ref,
            timestamp=time.time(),
            verification_url=result.tsa_url,
            metadata=dict(result.package_dict),
        )

    async def verify(self, receipt: AnchorReceipt, expected_root: str) -> bool:
        if receipt.metadata.get("merkle_root") != expected_root:
            return False
        result = await asyncio.to_thread(self._ts.verify, receipt.metadata)
        return result.valid


class BlockchainAnchorProvider:
    """Anchors Merkle roots via a pluggable, real :class:`AnchorBackend`.

    With no backend configured the provider is **fail-closed**: ``publish_root``
    raises :class:`AnchorUnavailableError` and ``verify_proof`` returns ``False``.
    It never fabricates a transaction hash, block number, or explorer URL.
    """

    def __init__(self, backend: AnchorBackend | None = None) -> None:
        self._backend = backend

    @property
    def backend_name(self) -> str:
        return self._backend.name if self._backend is not None else "none"

    @property
    def is_available(self) -> bool:
        return self._backend is not None

    async def publish_root(self, root_hash: str) -> AnchorReceipt:
        if self._backend is None:
            raise AnchorUnavailableError(
                "no anchoring backend configured; refusing to fabricate a blockchain proof. "
                "Provide an RFC3161AnchorBackend or another real AnchorBackend."
            )
        receipt = await self._backend.anchor(root_hash)
        logger.info(
            "Merkle root %s anchored via %s (ref=%s)",
            root_hash,
            receipt.backend,
            receipt.anchor_ref,
        )
        return receipt

    async def verify_proof(self, receipt: AnchorReceipt | None, expected_root: str) -> bool:
        if self._backend is None or receipt is None:
            return False
        return await self._backend.verify(receipt, expected_root)


# Default provider is fail-closed (no backend) — configure a real backend to anchor.
blockchain_provider = BlockchainAnchorProvider()
