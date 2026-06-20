# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis_server.storage.dynamodb_provider — aioboto3-backed DynamoDB storage."""

from __future__ import annotations

import json
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Optional-backend stubs (aioboto3/boto3/botocore) are installed globally by
# tests/conftest.py before any test module is collected, which guarantees
# botocore.exceptions.ClientError is a real exception class shared across every
# test module regardless of collection order. Reuse that exact class as
# _ClientError so the provider's `except ClientError` matches what these tests
# raise — defining a separate local class here would reintroduce an
# order-dependent identity mismatch.
from botocore.exceptions import ClientError as _ClientError  # noqa: E402

from aegis_server.storage.dynamodb_provider import DynamoDBStorageProvider  # noqa: E402

# ── helpers ───────────────────────────────────────────────────────────────────


def _make_provider(table="aegis_audit", region="us-east-1") -> DynamoDBStorageProvider:
    return DynamoDBStorageProvider(table_name=table, region=region)


def _make_initialized_provider(table="aegis_audit") -> DynamoDBStorageProvider:
    p = _make_provider(table)
    p._session = MagicMock()
    p._initialized = True
    return p


def _make_table_mock(items=None, last_key=None):
    """Build an async table mock for DynamoDB resource."""
    table = AsyncMock()
    # put_item, get_item, query
    table.put_item = AsyncMock(return_value={})
    table.get_item = AsyncMock(return_value={"Item": None})
    table.query = AsyncMock(
        return_value={
            "Items": items or [],
            "LastEvaluatedKey": last_key,
        }
    )
    return table


def _make_resource_ctx(table_mock):
    """Build an async context manager that returns a dynamodb resource."""
    resource = AsyncMock()
    resource.Table = AsyncMock(return_value=table_mock)

    class _Ctx:
        async def __aenter__(self):
            return resource

        async def __aexit__(self, *args):
            pass

    return _Ctx()


def _make_client_ctx():
    """Build an async context manager for DynamoDB client (for create_table)."""
    client = AsyncMock()
    client.create_table = AsyncMock(return_value={})
    client.get_waiter = MagicMock(return_value=AsyncMock())

    class _Ctx:
        async def __aenter__(self):
            return client

        async def __aexit__(self, *args):
            pass

    return _Ctx(), client


# ── __init__ ─────────────────────────────────────────────────────────────────


def test_init_empty_table_name_raises():
    with pytest.raises(ValueError, match="table_name"):
        DynamoDBStorageProvider(table_name="")


def test_init_stores_table_name():
    p = _make_provider("my_table")
    assert p._table_name == "my_table"


def test_init_with_endpoint_url():
    p = DynamoDBStorageProvider(
        table_name="t",
        endpoint_url="http://localhost:8000",
    )
    assert p._endpoint_url == "http://localhost:8000"


def test_init_empty_endpoint_url_becomes_none():
    p = DynamoDBStorageProvider(table_name="t", endpoint_url="")
    assert p._endpoint_url is None


# ── initialize ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_initialize_creates_table():
    p = _make_provider()
    client_ctx, mock_client = _make_client_ctx()
    mock_waiter = AsyncMock()
    mock_client.get_waiter.return_value = mock_waiter

    with patch.object(p, "_get_client", return_value=client_ctx):
        await p.initialize()

    assert p._initialized is True
    mock_client.create_table.assert_called_once()
    mock_waiter.wait.assert_called_once()


@pytest.mark.asyncio
async def test_initialize_table_already_exists():
    p = _make_provider()
    client_ctx, mock_client = _make_client_ctx()
    mock_client.create_table.side_effect = _ClientError(code="ResourceInUseException")

    with patch.object(p, "_get_client", return_value=client_ctx):
        await p.initialize()  # should not raise

    assert p._initialized is True


@pytest.mark.asyncio
async def test_initialize_other_client_error_raises():
    p = _make_provider()
    client_ctx, mock_client = _make_client_ctx()
    mock_client.create_table.side_effect = _ClientError(code="AccessDeniedException")

    with patch.object(p, "_get_client", return_value=client_ctx):
        with pytest.raises(RuntimeError, match="initialize failed"):
            await p.initialize()


# ── close ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_close_resets_state():
    p = _make_initialized_provider()
    await p.close()
    assert p._session is None
    assert p._initialized is False


# ── _require_initialized ──────────────────────────────────────────────────────


def test_require_initialized_raises_when_not():
    p = _make_provider()
    with pytest.raises(RuntimeError, match="initialize"):
        p._require_initialized()


# ── write_node ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_write_node_uninitialized_raises():
    p = _make_provider()
    with pytest.raises(RuntimeError, match="initialize"):
        await p.write_node(
            node_id="n",
            timestamp="t",
            node_data={},
            request_hash="r",
            response_hash="s",
            merkle_root="m",
            signature="sig",
            client_id="c",
        )


@pytest.mark.asyncio
async def test_write_node_success():
    p = _make_initialized_provider()
    table = _make_table_mock()
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        await p.write_node(
            node_id="n1",
            timestamp="2024-01-01",
            node_data={"k": "v"},
            request_hash="r",
            response_hash="s",
            merkle_root="m",
            signature="sig",
            client_id="c",
        )

    table.put_item.assert_called_once()


@pytest.mark.asyncio
async def test_write_node_conditional_check_is_noop():
    p = _make_initialized_provider()
    table = _make_table_mock()
    table.put_item = AsyncMock(side_effect=_ClientError(code="ConditionalCheckFailedException"))
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        await p.write_node(
            node_id="dup",
            timestamp="t",
            node_data={},
            request_hash="r",
            response_hash="s",
            merkle_root="m",
            signature="sig",
            client_id="c",
        )
    # no exception raised


@pytest.mark.asyncio
async def test_write_node_other_client_error_raises():
    p = _make_initialized_provider()
    table = _make_table_mock()
    table.put_item = AsyncMock(side_effect=_ClientError(code="ProvisionedThroughputExceeded"))
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        with pytest.raises(RuntimeError, match="write_node failed"):
            await p.write_node(
                node_id="n",
                timestamp="t",
                node_data={},
                request_hash="r",
                response_hash="s",
                merkle_root="m",
                signature="sig",
                client_id="c",
            )


# ── get_latest_node ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_latest_node_uninitialized_raises():
    p = _make_provider()
    with pytest.raises(RuntimeError, match="initialize"):
        await p.get_latest_node()


@pytest.mark.asyncio
async def test_get_latest_node_empty_returns_none():
    p = _make_initialized_provider()
    table = _make_table_mock(items=[])
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        result = await p.get_latest_node()

    assert result is None


@pytest.mark.asyncio
async def test_get_latest_node_returns_item():
    p = _make_initialized_provider()
    items = [
        {
            "node_id": "abc",
            "partition_key": "ALL",
            "timestamp": "2024-01-01",
            "node_data": json.dumps({"prev_hash": "0" * 64}),
        }
    ]
    table = _make_table_mock(items=items)
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        result = await p.get_latest_node()

    assert result is not None
    assert result["node_id"] == "abc"
    assert "partition_key" not in result


@pytest.mark.asyncio
async def test_get_latest_node_exception_raises():
    p = _make_initialized_provider()
    table = _make_table_mock()
    table.query = AsyncMock(side_effect=Exception("DDB error"))
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        with pytest.raises(RuntimeError, match="get_latest_node failed"):
            await p.get_latest_node()


# ── get_node ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_node_uninitialized_raises():
    p = _make_provider()
    with pytest.raises(RuntimeError, match="initialize"):
        await p.get_node("hash")


@pytest.mark.asyncio
async def test_get_node_not_found():
    p = _make_initialized_provider()
    table = _make_table_mock()
    table.get_item = AsyncMock(return_value={"Item": None})
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        result = await p.get_node("missing")

    assert result is None


@pytest.mark.asyncio
async def test_get_node_found():
    p = _make_initialized_provider()
    item = {"node_id": "xyz", "partition_key": "ALL", "node_data": "{}"}
    table = _make_table_mock()
    table.get_item = AsyncMock(return_value={"Item": item})
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        result = await p.get_node("xyz")

    assert result["node_id"] == "xyz"
    assert "partition_key" not in result


@pytest.mark.asyncio
async def test_get_node_client_error_raises():
    p = _make_initialized_provider()
    table = _make_table_mock()
    table.get_item = AsyncMock(side_effect=_ClientError())
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        with pytest.raises(RuntimeError, match="get_node failed"):
            await p.get_node("h")


# ── list_nodes ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_nodes_uninitialized_raises():
    p = _make_provider()
    with pytest.raises(RuntimeError, match="initialize"):
        await p.list_nodes(10, 0)


@pytest.mark.asyncio
async def test_list_nodes_negative_offset_raises():
    p = _make_initialized_provider()
    with pytest.raises(ValueError):
        await p.list_nodes(10, -1)


@pytest.mark.asyncio
async def test_list_nodes_no_filter_returns_items():
    p = _make_initialized_provider()
    items = [{"node_id": f"n{i}", "partition_key": "ALL", "node_data": "{}"} for i in range(3)]
    table = _make_table_mock(items=items, last_key=None)
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        result = await p.list_nodes(10, 0)

    assert len(result) == 3
    assert all("partition_key" not in r for r in result)


@pytest.mark.asyncio
async def test_list_nodes_with_tenant_filter():
    p = _make_initialized_provider()
    items = [{"node_id": "n1", "partition_key": "ALL", "client_id": "t1", "node_data": "{}"}]
    table = _make_table_mock(items=items, last_key=None)
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        result = await p.list_nodes(10, 0, tenant_id="t1")

    assert len(result) == 1


@pytest.mark.asyncio
async def test_list_nodes_client_error_raises():
    p = _make_initialized_provider()
    table = _make_table_mock()
    table.query = AsyncMock(side_effect=_ClientError())
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        with pytest.raises(RuntimeError, match="list_nodes failed"):
            await p.list_nodes(10, 0)


# ── check_integrity ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_check_integrity_uninitialized_raises():
    p = _make_provider()
    with pytest.raises(RuntimeError, match="initialize"):
        await p.check_integrity()


@pytest.mark.asyncio
async def test_check_integrity_empty_is_valid():
    p = _make_initialized_provider()
    table = _make_table_mock(items=[], last_key=None)
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        result = await p.check_integrity()

    assert result["is_valid"] is True
    assert result["node_count"] == 0


@pytest.mark.asyncio
async def test_check_integrity_valid_chain():
    p = _make_initialized_provider()
    node_a_id = "a" * 64
    node_b_id = "b" * 64
    items = [
        {
            "node_id": node_a_id,
            "partition_key": "ALL",
            "node_data": json.dumps({"prev_hash": "0" * 64}),
        },
        {
            "node_id": node_b_id,
            "partition_key": "ALL",
            "node_data": json.dumps({"prev_hash": node_a_id}),
        },
    ]
    table = _make_table_mock(items=items, last_key=None)
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        result = await p.check_integrity()

    assert result["is_valid"] is True
    assert result["node_count"] == 2


@pytest.mark.asyncio
async def test_check_integrity_broken_chain():
    p = _make_initialized_provider()
    items = [
        {
            "node_id": "a" * 64,
            "partition_key": "ALL",
            "node_data": json.dumps({"prev_hash": "0" * 64}),
        },
        {
            "node_id": "b" * 64,
            "partition_key": "ALL",
            "node_data": json.dumps({"prev_hash": "wrong" * 13}),
        },
    ]
    table = _make_table_mock(items=items, last_key=None)
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        result = await p.check_integrity()

    assert result["is_valid"] is False
    assert result["broken_link_index"] == 1


@pytest.mark.asyncio
async def test_check_integrity_client_error_raises():
    p = _make_initialized_provider()
    table = _make_table_mock()
    table.query = AsyncMock(side_effect=_ClientError())
    resource_ctx = _make_resource_ctx(table)

    with patch.object(p, "_get_resource", return_value=resource_ctx):
        with pytest.raises(RuntimeError, match="check_integrity failed"):
            await p.check_integrity()


# ── _item_to_dict ─────────────────────────────────────────────────────────────


def test_item_to_dict_string_node_data():
    item = {
        "node_id": "n1",
        "partition_key": "ALL",
        "node_data": '{"key": "val"}',
    }
    result = DynamoDBStorageProvider._item_to_dict(item)
    assert result["node_data"] == {"key": "val"}
    assert "partition_key" not in result


def test_item_to_dict_dict_node_data():
    item = {
        "node_id": "n1",
        "partition_key": "ALL",
        "node_data": {"key": "val"},
    }
    result = DynamoDBStorageProvider._item_to_dict(item)
    assert result["node_data"] == {"key": "val"}


def test_item_to_dict_invalid_json_becomes_empty():
    item = {
        "node_id": "n1",
        "partition_key": "ALL",
        "node_data": "not-json{{",
    }
    result = DynamoDBStorageProvider._item_to_dict(item)
    assert result["node_data"] == {}


def test_item_to_dict_non_dict_non_string_node_data():
    item = {
        "node_id": "n1",
        "partition_key": "ALL",
        "node_data": 42,  # int, not str or dict
    }
    result = DynamoDBStorageProvider._item_to_dict(item)
    assert result["node_data"] == {}
