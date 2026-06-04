"""
aegis.proxy.audit_api — Read-only REST endpoints for the Merkle audit chain.

Mounted at /v1/audit/* and protected by AuditKeyAuth.
"""

# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import logging
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status

from aegis.proxy.dependencies import validate_audit_auth
from aegis.proxy.schemas import AuditNodeOut, IntegrityReport

logger = logging.getLogger(__name__)


def build_audit_router(
    ledger: Any,
    auth_dependency: Any,
) -> APIRouter:
    router = APIRouter(tags=["audit"])

    @router.get("/health", include_in_schema=True)
    async def audit_health(
        _key: Annotated[str, Depends(validate_audit_auth)],
        request: Request,
    ) -> dict:
        """Returns audit subsystem health and node count."""
        return {
            "status": "ok",
            "node_count": len(ledger.chain),
            "legal_admissibility": ledger.legal_admissibility,
            "fault_state": ledger._fault_state,
        }

    @router.get("/integrity", response_model=IntegrityReport)
    async def check_integrity(
        _key: Annotated[str, Depends(validate_audit_auth)],
    ) -> IntegrityReport:
        """Verify the full Merkle chain integrity.  O(N) — use sparingly."""
        is_valid, err_idx = ledger.verify_integrity()
        tail = ledger.chain[-1].node_hash if ledger.chain else ""
        return IntegrityReport(
            valid=is_valid,
            error_index=err_idx,
            node_count=len(ledger.chain),
            tail_hash=tail,
            legal_admissibility=ledger.legal_admissibility,
        )

    @router.get("/nodes", response_model=list[AuditNodeOut])
    async def list_nodes(
        _key: Annotated[str, Depends(validate_audit_auth)],
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
        tenant_id: Annotated[str | None, Query()] = None,
    ) -> list[AuditNodeOut]:
        """
        Paginated listing of audit nodes, optionally filtered by tenant.
        Nodes are ordered oldest-first (chain order).
        """
        chain_list = list(ledger.chain)
        if tenant_id:
            chain_list = [n for n in chain_list if n.tenant_id == tenant_id]

        page = chain_list[offset : offset + limit]
        return [
            AuditNodeOut(
                index=offset + i,
                timestamp=n.timestamp,
                state_id=n.state_id,
                entropy=n.entropy,
                payload_hash=n.payload_hash,
                node_hash=n.node_hash,
                tenant_id=n.tenant_id,
                sampling_params=n.sampling_params,
            )
            for i, n in enumerate(page)
        ]

    @router.get("/nodes/{node_hash}", response_model=AuditNodeOut)
    async def get_node(
        node_hash: str,
        _key: Annotated[str, Depends(validate_audit_auth)],
    ) -> AuditNodeOut:
        """Retrieve a single audit node by its hash."""
        for i, n in enumerate(ledger.chain):
            if n.node_hash == node_hash:
                return AuditNodeOut(
                    index=i,
                    timestamp=n.timestamp,
                    state_id=n.state_id,
                    entropy=n.entropy,
                    payload_hash=n.payload_hash,
                    node_hash=n.node_hash,
                    tenant_id=n.tenant_id,
                    sampling_params=n.sampling_params,
                )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node with hash {node_hash!r} not found in memory window.",
        )

    @router.get("/tenants", response_model=list[str])
    async def list_tenants(
        _key: Annotated[str, Depends(validate_audit_auth)],
    ) -> list[str]:
        """Return distinct tenant IDs present in the current memory window."""
        return sorted({n.tenant_id for n in ledger.chain})

    return router
