# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis.proxy.audit_api — missing branch coverage."""

from __future__ import annotations

import time
import io
import zipfile
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest
from fastapi import FastAPI

from aegis.proxy.audit_api import build_audit_router
from aegis.core.crypto_audit import CryptographicAuditLedger

# ── helpers ───────────────────────────────────────────────────────────────────


def _make_node(
    node_hash: str = "a" * 64,
    tenant_id: str = "tenant1",
    state_id: str = "state-1",
    entropy: float = 2.5,
) -> MagicMock:
    node = MagicMock()
    node.node_hash = node_hash
    node.tenant_id = tenant_id
    node.state_id = state_id
    node.entropy = entropy
    node.timestamp = time.time()
    node.payload_hash = "ph" * 32
    node.sampling_params = {}
    return node


def _make_ledger(nodes=None, integrity=(True, None)):
    ledger = MagicMock()
    ledger.chain = nodes or []
    ledger.legal_admissibility = "ADMITTED"
    ledger._fault_state = None
    ledger.verify_integrity = MagicMock(return_value=integrity)
    return ledger


def _make_app(ledger) -> FastAPI:
    app = FastAPI()
    app.state.aegis = SimpleNamespace(settings=SimpleNamespace(api_key_scopes=""))

    # Bypass auth: override validate_audit_auth to always return "test"

    async def _noop_auth(request):
        return "test"

    router = build_audit_router(ledger, auth_dependency=_noop_auth)
    # Override the dependency in the router
    router.dependencies = []
    app.include_router(router, prefix="/v1/audit")

    # Override the validate_audit_auth dependency
    from aegis.proxy.dependencies import validate_audit_auth

    app.dependency_overrides[validate_audit_auth] = lambda: "test"

    return app


@pytest.mark.asyncio
async def test_forensic_export_returns_verifiable_zip(tmp_path):
    ledger = CryptographicAuditLedger(
        persistence_path=str(tmp_path / "audit.jsonl"),
        signing_key="test-signing-key",
    )
    ledger.commit_forensic(
        state_id="export-1",
        request_bytes=b"request",
        response_bytes=b"response",
        tenant_id="tenant-a",
    )
    app = _make_app(ledger)
    now = datetime.now(UTC)
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        response = await client.post(
            "/v1/audit/forensics/export",
            json={
                "start_time": (now - timedelta(minutes=1)).isoformat(),
                "end_time": (now + timedelta(minutes=1)).isoformat(),
                "operator": "Examiner A",
                "acquisition_reason": "Authorized test",
            },
        )
    ledger.close()
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert "VERIFY.sh" in archive.namelist()
        assert "ledger_slice.cbor" in archive.namelist()


# ── /health ───────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_audit_health_returns_status():
    ledger = _make_ledger(nodes=[_make_node()])
    app = _make_app(ledger)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/audit/health")

    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ok"
    assert data["node_count"] == 1


# ── /integrity ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_audit_integrity_valid():
    node = _make_node()
    ledger = _make_ledger(nodes=[node], integrity=(True, None))
    app = _make_app(ledger)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/audit/integrity")

    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is True


@pytest.mark.asyncio
async def test_audit_integrity_invalid():
    ledger = _make_ledger(nodes=[], integrity=(False, 2))
    app = _make_app(ledger)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/audit/integrity")

    assert resp.status_code == 200
    data = resp.json()
    assert data["valid"] is False
    assert data["error_index"] == 2


# ── /nodes (listing) ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_audit_list_nodes_no_filter():
    nodes = [_make_node(node_hash="a" * 64), _make_node(node_hash="b" * 64)]
    ledger = _make_ledger(nodes=nodes)
    app = _make_app(ledger)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/audit/nodes")

    assert resp.status_code == 200
    assert len(resp.json()) == 2


@pytest.mark.asyncio
async def test_audit_list_nodes_tenant_filter(request):
    """Line 69: tenant_id filter applied."""
    node_t1 = _make_node(node_hash="a" * 64, tenant_id="t1")
    node_t2 = _make_node(node_hash="b" * 64, tenant_id="t2")
    ledger = _make_ledger(nodes=[node_t1, node_t2])
    app = _make_app(ledger)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/audit/nodes", params={"tenant_id": "t1"})

    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["tenant_id"] == "t1"


# ── /nodes/{node_hash} (lines 92-104) ────────────────────────────────────────


@pytest.mark.asyncio
async def test_audit_get_node_found():
    node_hash = "c" * 64
    node = _make_node(node_hash=node_hash, tenant_id="t1")
    ledger = _make_ledger(nodes=[node])
    app = _make_app(ledger)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get(f"/v1/audit/nodes/{node_hash}")

    assert resp.status_code == 200
    data = resp.json()
    assert data["node_hash"] == node_hash
    assert data["tenant_id"] == "t1"


@pytest.mark.asyncio
async def test_audit_get_node_not_found():
    ledger = _make_ledger(nodes=[])
    app = _make_app(ledger)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/audit/nodes/" + "x" * 64)

    assert resp.status_code == 404


# ── /tenants (line 114) ───────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_audit_list_tenants():
    nodes = [
        _make_node(node_hash="a" * 64, tenant_id="t2"),
        _make_node(node_hash="b" * 64, tenant_id="t1"),
        _make_node(node_hash="c" * 64, tenant_id="t2"),
    ]
    ledger = _make_ledger(nodes=nodes)
    app = _make_app(ledger)

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        resp = await client.get("/v1/audit/tenants")

    assert resp.status_code == 200
    tenants = resp.json()
    assert tenants == sorted({"t1", "t2"})
