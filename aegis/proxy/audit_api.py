"""
aegis.proxy.audit_api — Read-only REST endpoints for the Merkle audit chain.

Mounted at /v1/audit/* and protected by AuditKeyAuth.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import asyncio
import base64
import hashlib
import logging
from datetime import UTC
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status

from aegis.auth.principal import Principal, Role
from aegis.auth.scopes import SCOPE_AUDIT_EXPORT, SCOPE_AUDIT_READ
from aegis.core.forensic_bundle import (
    ForensicBundleError,
    build_forensic_bundle,
    canonical_dag_cbor_bytes,
    canonical_jcs_bytes,
    dag_cbor_cid,
)
from aegis.proxy.dependencies import principal_tenant
from aegis.proxy.schemas import (
    AuditNodeOut,
    ForensicExportRequest,
    IntegrityReport,
    MMRProofOut,
    RawEvidenceOut,
)

logger = logging.getLogger(__name__)


def build_audit_router(
    ledger: Any,
    auth_dependency: Any,
) -> APIRouter:
    router = APIRouter(tags=["audit"])
    read_dependency = auth_dependency

    def _as_principal(value: object) -> Principal:
        if isinstance(value, Principal):
            return value
        # Test-only compatibility for directly constructed routers. Production
        # passes the principal-first dependency from app.py.
        return Principal(
            subject="router-test",
            tenant_id="development",
            roles=frozenset({Role.ADMIN}),
            scopes=frozenset({SCOPE_AUDIT_READ, SCOPE_AUDIT_EXPORT}),
            auth_method="development",
            credential_id="router-test",
        )

    def _require(principal_value: object, scope: str) -> Principal:
        principal = _as_principal(principal_value)
        if scope not in principal.scopes:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient scope")
        return principal

    def _visible(node: Any, principal: Principal) -> bool:
        return Role.ADMIN in principal.roles or node.tenant_id == principal.tenant_id

    def _string_attr(node: Any, name: str, default: str) -> str:
        value = getattr(node, name, default)
        return value if isinstance(value, str) else default

    def _canonical_node(node: Any) -> tuple[dict[str, Any], bytes]:
        record = node.to_dict()
        record["node_hash"] = node.node_hash
        return record, canonical_dag_cbor_bytes(record)

    def _node_out(index: int, node: Any, *, verify_signature: bool = False) -> AuditNodeOut:
        signature_status = ledger.signature_status(node) if verify_signature else "not-checked"
        params = node.sampling_params if isinstance(node.sampling_params, dict) else {}
        elapsed = params.get("elapsed_seconds")
        latency_ms = float(elapsed) * 1000.0 if isinstance(elapsed, (int, float)) else None
        raw_hits = params.get("redaction_hits")
        hits = raw_hits if isinstance(raw_hits, dict) else {}
        dag_cbor = canonical_dag_cbor_bytes({"node_hash": node.node_hash})
        return AuditNodeOut(
            index=index,
            timestamp=node.timestamp,
            state_id=node.state_id,
            entropy=node.entropy,
            payload_hash=node.payload_hash,
            node_hash=node.node_hash,
            tenant_id=node.tenant_id,
            sampling_params=params,
            merkle_root=_string_attr(node, "merkle_root", ""),
            signature_scheme=_string_attr(node, "signature_scheme", "unknown"),
            signature_status=(
                signature_status if isinstance(signature_status, str) else "unverified"
            ),
            model=_string_attr(node, "model", "unknown"),
            endpoint=_string_attr(node, "endpoint", "unknown"),
            phi_scrubbed=(
                node.phi_scrubbed
                if isinstance(getattr(node, "phi_scrubbed", None), bool)
                else False
            ),
            token_count=max(0, int(getattr(node, "token_trail_count", 0))),
            latency_ms=latency_ms,
            terminal_outcome=(
                str(params["terminal_outcome"]) if "terminal_outcome" in params else None
            ),
            redaction_hits={
                str(key): value
                for key, value in hits.items()
                if isinstance(value, int) and value >= 0
            },
            cid=dag_cbor_cid(dag_cbor),
        )

    @router.get("/health", include_in_schema=True)
    async def audit_health(
        auth: object = Depends(read_dependency),
    ) -> dict[str, Any]:
        """Returns audit subsystem health and node count."""
        principal = _require(auth, SCOPE_AUDIT_READ)
        fault_state = _string_attr(ledger, "_fault_state", "healthy")
        window_anchor = _string_attr(ledger, "window_anchor_hash", "0" * 64)
        return {
            "status": "ok" if fault_state == "healthy" else "degraded",
            "node_count": sum(_visible(node, principal) for node in ledger.chain),
            "legal_admissibility": ledger.legal_admissibility,
            "fault_state": fault_state,
            "scope": "retained-memory-window",
            "window_anchor_hash": window_anchor,
            "full_history_retained": window_anchor == "0" * 64,
        }

    @router.get("/integrity", response_model=IntegrityReport)
    async def check_integrity(
        auth: object = Depends(read_dependency),
    ) -> IntegrityReport:
        """Verify the retained Merkle-chain window. O(N); use sparingly."""
        _require(auth, SCOPE_AUDIT_READ)
        is_valid, err_idx = ledger.verify_integrity()
        tail = ledger.chain[-1].node_hash if ledger.chain else ""
        window_anchor = _string_attr(ledger, "window_anchor_hash", "0" * 64)
        return IntegrityReport(
            valid=is_valid,
            error_index=err_idx,
            node_count=len(ledger.chain),
            tail_hash=tail,
            legal_admissibility=ledger.legal_admissibility,
            scope="retained-memory-window",
            window_anchor_hash=window_anchor,
            full_history_retained=window_anchor == "0" * 64,
        )

    @router.get("/nodes", response_model=list[AuditNodeOut])
    async def list_nodes(
        auth: object = Depends(read_dependency),
        offset: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=1000)] = 100,
        tenant_id: Annotated[str | None, Query()] = None,
        model: Annotated[str | None, Query()] = None,
        endpoint: Annotated[str | None, Query()] = None,
        phi_scrubbed: Annotated[bool | None, Query()] = None,
        terminal_outcome: Annotated[str | None, Query()] = None,
        min_latency_ms: Annotated[float | None, Query(ge=0.0)] = None,
        failures_only: Annotated[bool, Query()] = False,
    ) -> list[AuditNodeOut]:
        """Paginated and filtered listing of retained audit nodes."""
        principal = _require(auth, SCOPE_AUDIT_READ)
        effective_tenant = principal_tenant(principal, tenant_id)
        chain_list = [node for node in ledger.chain if _visible(node, principal)]
        if effective_tenant:
            chain_list = [node for node in chain_list if node.tenant_id == effective_tenant]
        if model:
            chain_list = [node for node in chain_list if node.model == model]
        if endpoint:
            chain_list = [node for node in chain_list if node.endpoint == endpoint]
        if phi_scrubbed is not None:
            chain_list = [node for node in chain_list if node.phi_scrubbed is phi_scrubbed]
        if terminal_outcome:
            chain_list = [
                node
                for node in chain_list
                if node.sampling_params.get("terminal_outcome") == terminal_outcome
            ]
        if min_latency_ms is not None:
            chain_list = [
                node
                for node in chain_list
                if isinstance(node.sampling_params.get("elapsed_seconds"), (int, float))
                and float(node.sampling_params["elapsed_seconds"]) * 1000.0 >= min_latency_ms
            ]
        if failures_only:
            chain_list = [
                node
                for node in chain_list
                if node.sampling_params.get("terminal_outcome") not in {None, "complete"}
            ]
        page = chain_list[offset : offset + limit]
        return [_node_out(offset + index, node) for index, node in enumerate(page)]

    @router.get("/nodes/{node_hash}", response_model=AuditNodeOut)
    async def get_node(
        node_hash: str,
        auth: object = Depends(read_dependency),
    ) -> AuditNodeOut:
        """Retrieve a single audit node by its hash."""
        principal = _require(auth, SCOPE_AUDIT_READ)
        for index, node in enumerate(ledger.chain):
            if node.node_hash == node_hash and _visible(node, principal):
                return _node_out(index, node, verify_signature=True)
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Node with hash {node_hash!r} not found in memory window.",
        )

    @router.get("/nodes/{node_hash}/evidence", response_model=RawEvidenceOut)
    async def get_node_evidence(
        node_hash: str,
        auth: object = Depends(read_dependency),
    ) -> RawEvidenceOut:
        """Return byte-exact JCS and deterministic DAG-CBOR projections."""
        principal = _require(auth, SCOPE_AUDIT_READ)
        for node in ledger.chain:
            if node.node_hash != node_hash or not _visible(node, principal):
                continue
            record, dag_cbor = _canonical_node(node)
            jcs = canonical_jcs_bytes(record)
            return RawEvidenceOut(
                node_hash=node.node_hash,
                cid=dag_cbor_cid(dag_cbor),
                jcs_json=jcs.decode("utf-8"),
                dag_cbor_base64=base64.b64encode(dag_cbor).decode("ascii"),
                dag_cbor_sha256=hashlib.sha256(dag_cbor).hexdigest(),
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Audit node is not present in the retained memory window.",
        )

    @router.get("/proofs/{state_id}", response_model=MMRProofOut)
    async def get_proof(
        state_id: str,
        auth: object = Depends(read_dependency),
    ) -> MMRProofOut:
        """Retrieve a portable inclusion proof by request/state identifier."""
        principal = _require(auth, SCOPE_AUDIT_READ)
        for node in reversed(ledger.chain):
            if node.state_id != state_id or not _visible(node, principal):
                continue
            if node.mmr_proof is None or not node.mmr_leaf_hash:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail="This legacy record predates portable MMR proofs.",
                )
            return MMRProofOut(
                state_id=node.state_id,
                node_hash=node.node_hash,
                leaf_hash=node.mmr_leaf_hash,
                leaf_index=node.mmr_leaf_index,
                leaf_count=node.mmr_leaf_count,
                root=node.merkle_root,
                proof=node.mmr_proof,
                signature_scheme=node.signature_scheme,
                signature_status=ledger.signature_status(node),
            )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="No audit record exists for this state identifier.",
        )

    @router.get("/tenants", response_model=list[str])
    async def list_tenants(
        auth: object = Depends(read_dependency),
    ) -> list[str]:
        """Return distinct tenant IDs present in the current memory window."""
        principal = _require(auth, SCOPE_AUDIT_READ)
        if Role.ADMIN not in principal.roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN, detail="Administrator required"
            )
        return sorted({node.tenant_id for node in ledger.chain})

    @router.get("/export/part11", response_model=list[dict[str, Any]])
    async def export_part11(
        auth: object = Depends(read_dependency),
    ) -> list[dict[str, Any]]:
        """Export 21 CFR Part 11 annotation fields plus cryptographic bindings."""
        principal = _require(auth, SCOPE_AUDIT_EXPORT)
        records = ledger.export_part11_signatures()
        visible_ids = {node.state_id for node in ledger.chain if _visible(node, principal)}
        return [record for record in records if record.get("state_id") in visible_ids]

    @router.post("/forensics/export")
    async def export_forensic_bundle(
        payload: ForensicExportRequest,
        auth: object = Depends(read_dependency),
    ) -> Response:
        """Export a bounded ISO/IEC 27037-oriented technical evidence bundle."""
        principal = _require(auth, SCOPE_AUDIT_EXPORT)
        effective_tenant = principal_tenant(principal, payload.tenant_id)
        start = payload.start_time
        end = payload.end_time
        if start.tzinfo is None or end.tzinfo is None:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="start_time and end_time must include UTC offsets.",
            )
        start_utc = start.astimezone(UTC)
        end_utc = end.astimezone(UTC)
        if start_utc >= end_utc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="start_time must precede end_time.",
            )
        selected = [
            node
            for node in ledger.chain
            if start_utc.timestamp() <= node.timestamp <= end_utc.timestamp()
            and _visible(node, principal)
            and (effective_tenant is None or node.tenant_id == effective_tenant)
        ]
        try:
            archive = await asyncio.to_thread(
                build_forensic_bundle,
                selected,
                operator=payload.operator,
                acquisition_reason=payload.acquisition_reason,
                scope_start=start_utc,
                scope_end=end_utc,
            )
        except ForensicBundleError as exc:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=str(exc),
            ) from exc
        stamp = end_utc.strftime("%Y%m%dT%H%M%SZ")
        return Response(
            content=archive,
            media_type="application/zip",
            headers={
                "Cache-Control": "no-store",
                "Content-Disposition": f'attachment; filename="aegis-forensic-{stamp}.zip"',
                "X-Content-Type-Options": "nosniff",
            },
        )

    return router
