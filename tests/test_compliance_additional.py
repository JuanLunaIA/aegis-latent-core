# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Additional compliance exporter tests for missing branch coverage."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from aegis_server.compliance.exporter import ComplianceExporter, ExportParams
from aegis_server.crypto.base import LocalHMACSigner


def _make_signer() -> LocalHMACSigner:
    return LocalHMACSigner("a" * 32)


def _make_mock_storage(nodes=None, check_integrity_raises=False) -> MagicMock:
    nodes = nodes or []
    storage = MagicMock()
    storage.list_nodes = AsyncMock(return_value=nodes)
    if check_integrity_raises:
        storage.check_integrity = AsyncMock(side_effect=RuntimeError("db error"))
    else:
        storage.check_integrity = AsyncMock(
            return_value={
                "is_valid": True,
                "node_count": len(nodes),
                "checked_at": "2025-01-01T00:00:00.000000Z",
            }
        )
    return storage


# ── integrity check failed (lines 225-231) ───────────────────────────────────


@pytest.mark.asyncio
async def test_export_integrity_check_exception_does_not_raise(tmp_path):
    """When check_integrity raises, export continues with error_message set (225-231)."""
    signer = _make_signer()
    storage = _make_mock_storage(nodes=[], check_integrity_raises=True)
    exporter = ComplianceExporter(
        storage=storage,
        signer=signer,
        export_dir=str(tmp_path),
    )

    params = ExportParams(from_offset=0, limit=100, tenant_id=None)
    result = await exporter.export(params)

    # Export should succeed even when integrity check fails
    assert result is not None
    # The bundle should be flagged as INTEGRITY_FAILURE
    bundle = json.loads(Path(result.output_path).read_text())
    manifest = bundle["aegis_compliance_bundle"]["verification_manifest"]
    assert manifest["integrity_status"] != "CHAIN_VALID"


# ── signing failed (lines 264-265) ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_export_signing_failure_raises_runtime_error(tmp_path):
    """When signer.sign_payload raises, export raises RuntimeError (264-265)."""
    mock_signer = MagicMock()
    mock_signer.sign_payload = AsyncMock(side_effect=RuntimeError("HSM unavailable"))

    storage = _make_mock_storage()
    exporter = ComplianceExporter(
        storage=storage,
        signer=mock_signer,
        export_dir=str(tmp_path),
    )

    params = ExportParams(from_offset=0, limit=100, tenant_id=None)
    with pytest.raises(RuntimeError, match="signing failed"):
        await exporter.export(params)


# ── verify_bundle — signer.verify raises (lines 441-443) ─────────────────────


@pytest.mark.asyncio
async def test_verify_bundle_signer_verify_exception(tmp_path):
    """When signer.verify raises, sig_error is set and result is partial (441-443)."""
    signer = _make_signer()
    storage = _make_mock_storage(nodes=[])
    exporter = ComplianceExporter(
        storage=storage,
        signer=signer,
        export_dir=str(tmp_path),
    )

    params = ExportParams(from_offset=0, limit=100, tenant_id=None)
    result = await exporter.export(params)

    # Now verify with a signer that raises
    failing_signer = MagicMock()
    failing_signer.verify = AsyncMock(side_effect=RuntimeError("HSM error"))

    verify_result = await ComplianceExporter.verify_bundle(result.output_path, failing_signer)

    assert verify_result["error"] is not None
    assert "HSM error" in verify_result["error"]
    assert verify_result["signature_valid"] is None


# ── _write_atomic — write failure cleanup (lines 507-513) ────────────────────


def test_write_atomic_failure_raises_runtime_error(tmp_path):
    """When tmp_path.write_text raises, cleanup + RuntimeError is raised (507-513)."""
    output_path = tmp_path / "test.json"

    with patch("pathlib.Path.write_text", side_effect=OSError("disk full")):
        with pytest.raises(RuntimeError, match="failed to write bundle"):
            ComplianceExporter._write_atomic(output_path, {"key": "value"})


def test_write_atomic_unlink_also_raises_is_silenced(tmp_path):
    """When write_text and unlink both raise, OSError from unlink is silenced (511-512)."""
    output_path = tmp_path / "test.json"

    with (
        patch("pathlib.Path.write_text", side_effect=OSError("disk full")),
        patch("pathlib.Path.unlink", side_effect=OSError("unlink failed")),
    ):
        with pytest.raises(RuntimeError, match="failed to write bundle"):
            ComplianceExporter._write_atomic(output_path, {"key": "value"})
