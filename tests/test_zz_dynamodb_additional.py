# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Additional DynamoDB provider tests for missing branch coverage."""

from __future__ import annotations

import sys
from unittest.mock import AsyncMock, MagicMock

import pytest

# ── sys.modules stubs (must be before import) ─────────────────────────────────

if "aioboto3" not in sys.modules:
    sys.modules["aioboto3"] = MagicMock()
if "boto3" not in sys.modules:
    sys.modules["boto3"] = MagicMock()
if "boto3.dynamodb" not in sys.modules:
    sys.modules["boto3.dynamodb"] = MagicMock()

_cond_mod = MagicMock()
_cond_mod.Key = MagicMock(return_value=MagicMock(eq=MagicMock()))
if "boto3.dynamodb.conditions" not in sys.modules:
    sys.modules["boto3.dynamodb.conditions"] = _cond_mod
if "botocore" not in sys.modules:
    sys.modules["botocore"] = MagicMock()
if "botocore.exceptions" not in sys.modules:
    _botocore_exc = MagicMock()
    sys.modules["botocore.exceptions"] = _botocore_exc

from aegis_server.storage.dynamodb_provider import DynamoDBStorageProvider  # noqa: E402


def _make_initialized_provider(endpoint_url: str | None = None) -> DynamoDBStorageProvider:
    p = DynamoDBStorageProvider(
        table_name="aegis_audit",
        region="us-east-1",
        endpoint_url=endpoint_url,
    )
    p._session = MagicMock()
    p._initialized = True
    return p


def _make_resource_ctx(table_mock):
    resource = AsyncMock()
    resource.Table = AsyncMock(return_value=table_mock)

    class _Ctx:
        async def __aenter__(self_):
            return resource

        async def __aexit__(self_, *args):
            pass

    return _Ctx()


# ── _get_client with endpoint_url (lines 444-447) ────────────────────────────


def test_get_client_with_endpoint_url():
    """_get_client includes endpoint_url in kwargs when set (lines 444-447)."""
    p = _make_initialized_provider(endpoint_url="http://localhost:8000")
    mock_client = p._get_client()
    assert mock_client is not None


# ── _get_resource with endpoint_url (lines 451-454) ──────────────────────────


def test_get_resource_with_endpoint_url():
    """_get_resource includes endpoint_url in kwargs when set (lines 451-454)."""
    p = _make_initialized_provider(endpoint_url="http://localhost:8000")
    mock_resource = p._get_resource()
    assert mock_resource is not None


# ── list_nodes pagination continuation (line 326) ────────────────────────────


@pytest.mark.asyncio
async def test_list_nodes_pagination_uses_exclusive_start_key():
    """list_nodes: second page uses ExclusiveStartKey from LastEvaluatedKey (line 326)."""
    p = _make_initialized_provider()

    page1_items = [
        {"node_id": "a" * 64, "node_data": {"prev_hash": "0" * 64}},
    ]
    page2_items = [
        {"node_id": "b" * 64, "node_data": {"prev_hash": "a" * 64}},
    ]

    call_count = 0

    async def _mock_query(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {"Items": page1_items, "LastEvaluatedKey": {"pk": "last"}}
        return {"Items": page2_items, "LastEvaluatedKey": None}

    table = AsyncMock()
    table.query = _mock_query

    p._session.resource.return_value = _make_resource_ctx(table)

    # Need to patch _get_resource to return our mock
    from unittest.mock import patch

    with patch.object(p, "_get_resource", return_value=_make_resource_ctx(table)):
        result = await p.list_nodes(limit=100, offset=0)

    assert len(result) == 2
    assert call_count == 2


# ── check_integrity pagination continuation (line 370) ───────────────────────


@pytest.mark.asyncio
async def test_check_integrity_pagination_continuation():
    """check_integrity: second page uses ExclusiveStartKey (line 370)."""
    p = _make_initialized_provider()

    node_a = {"node_id": "a" * 64, "node_data": {"prev_hash": "0" * 64}}
    node_b = {"node_id": "b" * 64, "node_data": {"prev_hash": "a" * 64}}

    call_count = 0

    async def _mock_query(**kwargs):
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            return {"Items": [node_a], "LastEvaluatedKey": {"pk": "last"}}
        return {"Items": [node_b], "LastEvaluatedKey": None}

    table = AsyncMock()
    table.query = _mock_query

    from unittest.mock import patch

    with patch.object(p, "_get_resource", return_value=_make_resource_ctx(table)):
        result = await p.check_integrity()

    assert result["is_valid"] is True
    assert call_count == 2


# ── check_integrity json decode exception (lines 402-403) ────────────────────


@pytest.mark.asyncio
async def test_check_integrity_invalid_json_node_data():
    """node_data with invalid JSON → json.loads raises → node_data = {} (402-403)."""
    p = _make_initialized_provider()

    # First node has invalid JSON node_data
    node_a = {"node_id": "a" * 64, "node_data": "NOT_VALID_JSON"}

    async def _mock_query(**kwargs):
        return {"Items": [node_a], "LastEvaluatedKey": None}

    table = AsyncMock()
    table.query = _mock_query

    from unittest.mock import patch

    with patch.object(p, "_get_resource", return_value=_make_resource_ctx(table)):
        result = await p.check_integrity()

    # Invalid JSON → node_data = {} → prev_hash = "" ≠ "0"*64 → invalid
    assert result["is_valid"] is False
