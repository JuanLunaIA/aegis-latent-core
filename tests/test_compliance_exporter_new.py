# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis_server.compliance.exporter — ComplianceExporter."""

from __future__ import annotations

import json
import os
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from aegis_server.compliance.exporter import (
    ComplianceExporter,
    ExportParams,
    ExportResult,
    _MAX_EXPORT_NODES,
)
from aegis_server.crypto.base import LocalHMACSigner
from aegis_server.storage.sqlite_provider import SQLiteStorageProvider


# ── helpers ───────────────────────────────────────────────────────────────────


def _make_signer() -> LocalHMACSigner:
    return LocalHMACSigner("a" * 32)


def _make_mock_storage(nodes: list[dict[str, Any]] | None = None) -> MagicMock:
    nodes = nodes or []
    storage = MagicMock()
    storage.list_nodes = AsyncMock(return_value=nodes)
    storage.check_integrity = AsyncMock(
        return_value={
            "is_valid": True,
            "node_count": len(nodes),
            "checked_at": "2025-01-01T00:00:00.000000Z",
        }
    )
    return storage


# ── ExportParams ───────────────────────────────────────────────────────────────


def test_export_params_construction():
    params = ExportParams(from_offset=0, limit=1000, tenant_id=None)
    assert params.from_offset == 0
    assert params.limit == 1000
    assert params.tenant_id is None


def test_export_params_with_tenant():
    params = ExportParams(from_offset=100, limit=500, tenant_id="acme-corp")
    assert params.tenant_id == "acme-corp"


# ── ExportResult ──────────────────────────────────────────────────────────────


def test_export_result_fields():
    r = ExportResult(
        export_id="uuid-x",
        output_path="/tmp/bundle.json",
        node_count=5,
        chain_hash="abc123",
        bundle_signature="sig",
        signer_scheme="hmac-sha256",
        generated_at="2025-01-01T00:00:00Z",
        integrity_valid=True,
    )
    assert r.export_id == "uuid-x"
    assert r.node_count == 5
    assert r.integrity_valid is True


# ── ComplianceExporter.export ─────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_export_empty_chain(tmp_path):
    signer = _make_signer()
    storage = _make_mock_storage([])
    exporter = ComplianceExporter(storage=storage, signer=signer, export_dir=str(tmp_path))

    result = await exporter.export(ExportParams(from_offset=0, limit=1000, tenant_id=None))

    assert result.node_count == 0
    assert result.integrity_valid is True
    assert os.path.exists(result.output_path)


@pytest.mark.asyncio
async def test_export_writes_valid_json_file(tmp_path):
    signer = _make_signer()
    nodes = [{"node_id": "n1", "timestamp": "2025-01-01T00:00:00Z"}]
    storage = _make_mock_storage(nodes)
    exporter = ComplianceExporter(storage=storage, signer=signer, export_dir=str(tmp_path))

    result = await exporter.export(ExportParams(from_offset=0, limit=100, tenant_id=None))

    with open(result.output_path, encoding="utf-8") as f:
        bundle = json.load(f)

    root = bundle["aegis_compliance_bundle"]
    assert root["node_count"] == 1
    assert root["audit_chain"] == nodes
    assert "chain_hash" in root["verification_manifest"]
    assert "bundle_signature" in root["verification_manifest"]


@pytest.mark.asyncio
async def test_export_result_contains_chain_hash(tmp_path):
    signer = _make_signer()
    storage = _make_mock_storage([{"id": "test"}])
    exporter = ComplianceExporter(storage=storage, signer=signer, export_dir=str(tmp_path))

    result = await exporter.export(ExportParams(from_offset=0, limit=100, tenant_id=None))

    assert len(result.chain_hash) == 64  # SHA-256 hex
    bytes.fromhex(result.chain_hash)


@pytest.mark.asyncio
async def test_export_clamps_limit_over_max(tmp_path, caplog):
    signer = _make_signer()
    storage = _make_mock_storage([])
    exporter = ComplianceExporter(storage=storage, signer=signer, export_dir=str(tmp_path))

    import logging

    with caplog.at_level(logging.WARNING, logger="aegis_server.compliance.exporter"):
        await exporter.export(
            ExportParams(from_offset=0, limit=_MAX_EXPORT_NODES + 1, tenant_id=None)
        )

    # Should warn about clamping
    assert any("cap" in m.lower() or "clamp" in m.lower() for m in caplog.messages)


@pytest.mark.asyncio
async def test_export_bundle_signature_is_valid(tmp_path):
    signer = _make_signer()
    storage = _make_mock_storage([{"n": 1}])
    exporter = ComplianceExporter(storage=storage, signer=signer, export_dir=str(tmp_path))

    result = await exporter.export(ExportParams(from_offset=0, limit=100, tenant_id=None))

    # Verify the signature matches
    chain_hash_bytes = result.chain_hash.encode("ascii")
    sig_valid = await signer.verify(chain_hash_bytes, result.bundle_signature)
    assert sig_valid is True


@pytest.mark.asyncio
async def test_export_integrity_failure_flagged(tmp_path):
    signer = _make_signer()
    storage = MagicMock()
    storage.list_nodes = AsyncMock(return_value=[{"id": "broken"}])
    storage.check_integrity = AsyncMock(
        return_value={"is_valid": False, "error_message": "broken link", "node_count": 1}
    )
    exporter = ComplianceExporter(storage=storage, signer=signer, export_dir=str(tmp_path))

    result = await exporter.export(ExportParams(from_offset=0, limit=100, tenant_id=None))

    assert result.integrity_valid is False
    # Bundle file still produced
    assert os.path.exists(result.output_path)
    with open(result.output_path) as f:
        bundle = json.load(f)
    manifest = bundle["aegis_compliance_bundle"]["verification_manifest"]
    assert manifest["integrity_status"] == "INTEGRITY_FAILURE"


# ── verify_bundle ─────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_verify_bundle_valid(tmp_path):
    signer = _make_signer()
    storage = _make_mock_storage([{"node_id": "x", "val": 42}])
    exporter = ComplianceExporter(storage=storage, signer=signer, export_dir=str(tmp_path))
    result = await exporter.export(ExportParams(from_offset=0, limit=100, tenant_id=None))

    verification = await ComplianceExporter.verify_bundle(result.output_path, signer)

    assert verification["valid"] is True
    assert verification["chain_hash_match"] is True
    assert verification["signature_valid"] is True
    assert verification["node_count"] == 1
    assert verification["error"] is None


@pytest.mark.asyncio
async def test_verify_bundle_file_not_found():
    signer = _make_signer()
    with pytest.raises(FileNotFoundError):
        await ComplianceExporter.verify_bundle("/nonexistent/path.json", signer)


@pytest.mark.asyncio
async def test_verify_bundle_invalid_json(tmp_path):
    bad_file = tmp_path / "bad.json"
    bad_file.write_text("not json!!!", encoding="utf-8")
    signer = _make_signer()
    with pytest.raises(ValueError, match="Cannot parse"):
        await ComplianceExporter.verify_bundle(str(bad_file), signer)


@pytest.mark.asyncio
async def test_verify_bundle_missing_root_key(tmp_path):
    bad_file = tmp_path / "nobundle.json"
    bad_file.write_text(json.dumps({"some": "data"}), encoding="utf-8")
    signer = _make_signer()
    with pytest.raises(ValueError, match="not an Aegis compliance bundle"):
        await ComplianceExporter.verify_bundle(str(bad_file), signer)


@pytest.mark.asyncio
async def test_verify_bundle_detects_tampered_chain(tmp_path):
    signer = _make_signer()
    storage = _make_mock_storage([{"node_id": "original"}])
    exporter = ComplianceExporter(storage=storage, signer=signer, export_dir=str(tmp_path))
    result = await exporter.export(ExportParams(from_offset=0, limit=100, tenant_id=None))

    # Tamper with the bundle
    with open(result.output_path, encoding="utf-8") as f:
        bundle = json.load(f)
    bundle["aegis_compliance_bundle"]["audit_chain"].append({"tampered": True})
    with open(result.output_path, "w", encoding="utf-8") as f:
        json.dump(bundle, f)

    verification = await ComplianceExporter.verify_bundle(result.output_path, signer)
    assert verification["chain_hash_match"] is False
    assert verification["valid"] is False


# ── export_range_paginated ────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_export_range_paginated_single_page(tmp_path):
    signer = _make_signer()
    storage = MagicMock()
    storage.check_integrity = AsyncMock(
        return_value={"is_valid": True, "node_count": 3, "checked_at": ""}
    )
    storage.list_nodes = AsyncMock(return_value=[{"n": i} for i in range(3)])

    exporter = ComplianceExporter(storage=storage, signer=signer, export_dir=str(tmp_path))
    results = await exporter.export_range_paginated(total_limit=3, page_size=10, tenant_id=None)
    assert len(results) == 1
    assert results[0].node_count == 3


@pytest.mark.asyncio
async def test_export_range_paginated_exhausts_storage(tmp_path):
    signer = _make_signer()
    storage = MagicMock()
    storage.check_integrity = AsyncMock(
        return_value={"is_valid": True, "node_count": 0, "checked_at": ""}
    )
    # First call returns 5 nodes (less than page_size=10) → exhausted
    storage.list_nodes = AsyncMock(return_value=[{"n": i} for i in range(5)])

    exporter = ComplianceExporter(storage=storage, signer=signer, export_dir=str(tmp_path))
    results = await exporter.export_range_paginated(total_limit=100, page_size=10, tenant_id=None)
    # Only one bundle since storage had fewer than page_size nodes
    assert len(results) == 1


# ── storage failure paths ─────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_export_storage_failure_raises(tmp_path):
    signer = _make_signer()
    storage = MagicMock()
    storage.list_nodes = AsyncMock(side_effect=RuntimeError("DB down"))
    exporter = ComplianceExporter(storage=storage, signer=signer, export_dir=str(tmp_path))

    with pytest.raises(RuntimeError, match="storage.list_nodes"):
        await exporter.export(ExportParams(from_offset=0, limit=100, tenant_id=None))
