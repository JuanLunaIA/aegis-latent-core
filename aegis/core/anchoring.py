"""
aegis.core.anchoring — external root anchoring orchestration.

Anchors Merkle roots into immutable storage for legal admissibility. WORM storage
is always written (in-process durable store); public anchoring is attempted via
the configured :class:`~aegis.core.blockchain_anchor.BlockchainAnchorProvider`
backend and is recorded honestly as available or unavailable — no fabricated
blockchain proof is ever produced.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
import time
from dataclasses import dataclass

from aegis.core.blockchain_anchor import (
    AnchorReceipt,
    AnchorUnavailableError,
    blockchain_provider,
)
from aegis.core.worm_storage import worm_provider

logger = logging.getLogger(__name__)


@dataclass
class AnchorProof:
    root_hash: str
    anchor_id: str
    timestamp: float
    provider: str
    worm_index: int
    blockchain_available: bool
    verification_url: str = ""


class AnchorManager:
    """
    Orchestrates anchoring of Merkle roots across immutable providers.

    WORM storage is the always-available durable anchor; public/external anchoring
    is layered on top when a real backend is configured.
    """

    def __init__(self) -> None:
        self._anchors: dict[str, AnchorProof] = {}
        self._receipts: dict[str, AnchorReceipt] = {}

    async def anchor_root(self, root_hash: str) -> AnchorProof:
        """
        Anchor *root_hash* to WORM storage (always) and to the external anchoring
        backend (when configured). The returned proof states honestly whether the
        blockchain/external anchor was actually obtained.
        """
        logger.info("Anchoring root [%s]...", root_hash)

        # 1. WORM storage (real, in-process durable write).
        worm_idx = await worm_provider.write_entry(root_hash.encode())

        # 2. External/public anchoring — only if a real backend is configured.
        bc_receipt: AnchorReceipt | None = None
        try:
            bc_receipt = await blockchain_provider.publish_root(root_hash)
        except AnchorUnavailableError as exc:
            logger.warning(
                "External anchoring unavailable (%s); proceeding with WORM-only anchor.", exc
            )

        anchor_id = bc_receipt.anchor_ref if bc_receipt is not None else f"worm-{worm_idx}"
        proof = AnchorProof(
            root_hash=root_hash,
            anchor_id=anchor_id,
            timestamp=time.time(),
            provider=(
                f"Hybrid(external:{blockchain_provider.backend_name}|"
                f"WORM:{worm_provider.storage_type})"
            ),
            worm_index=worm_idx,
            blockchain_available=bc_receipt is not None,
            verification_url=bc_receipt.verification_url if bc_receipt is not None else "",
        )

        self._anchors[anchor_id] = proof
        if bc_receipt is not None:
            self._receipts[anchor_id] = bc_receipt
        logger.info(
            "Root anchored (id=%s, worm_idx=%d, external=%s).",
            anchor_id,
            worm_idx,
            proof.blockchain_available,
        )
        return proof

    async def verify_anchor(self, anchor_id: str, expected_root: str) -> bool:
        """
        Verify the root against the providers that actually anchored it.

        WORM is checked by searching stored entries. The external anchor is
        verified only when a real receipt was captured; if anchoring was
        WORM-only, verification relies on WORM alone (and does not claim a
        blockchain proof that does not exist).
        """
        worm_ok = any(
            entry.data.decode() == expected_root for entry in worm_provider._storage.values()
        )

        receipt = self._receipts.get(anchor_id)
        if receipt is None:
            # No external proof was obtained — WORM is the sole anchor.
            return worm_ok

        bc_ok = await blockchain_provider.verify_proof(receipt, expected_root)
        return worm_ok and bc_ok


anchor_manager = AnchorManager()
