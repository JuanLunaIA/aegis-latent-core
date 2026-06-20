# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis_server.storage.postgres_provider — asyncpg-backed storage."""

from __future__ import annotations

import json
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# ── Mock asyncpg before importing postgres_provider ───────────────────────────

if "asyncpg" not in sys.modules:
    _mock_asyncpg = MagicMock()
    sys.modules["asyncpg"] = _mock_asyncpg
else:
    _mock_asyncpg = sys.modules["asyncpg"]

from aegis_server.storage.postgres_provider import PostgreSQLStorageProvider  # noqa: E402


# ── helpers ───────────────────────────────────────────────────────────────────


def _make_provider(dsn="postgresql://user:pass@localhost/aegis") -> PostgreSQLStorageProvider:
    return PostgreSQLStorageProvider(dsn=dsn)


def _make_mock_pool():
    """Build a mock asyncpg connection pool with context manager support."""
    mock_conn = AsyncMock()
    mock_conn.execute = AsyncMock(return_value=None)
    mock_conn.fetchrow = AsyncMock(return_value=None)
    mock_conn.fetch = AsyncMock(return_value=[])
    mock_txn = AsyncMock()
    mock_txn.__aenter__ = AsyncMock(return_value=mock_txn)
    mock_txn.__aexit__ = AsyncMock(return_value=False)
    mock_conn.transaction = MagicMock(return_value=mock_txn)

    class _AcquireCtx:
        async def __aenter__(self_):
            return mock_conn
        async def __aexit__(self_, *args):
            pass

    mock_pool = AsyncMock()
    mock_pool.acquire = MagicMock(return_value=_AcquireCtx())
    mock_pool.close = AsyncMock()
    return mock_pool, mock_conn


# ── __init__ ─────────────────────────────────────────────────────────────────


def test_init_empty_dsn_raises():
    with pytest.raises(ValueError, match="DSN"):
        PostgreSQLStorageProvider(dsn="")


def test_init_stores_dsn():
    p = _make_provider("postgresql://h/db")
    assert p._dsn == "postgresql://h/db"


def test_init_custom_pool_sizes():
    p = PostgreSQLStorageProvider(
        dsn="postgresql://h/db",
        min_size=5,
        max_size=20,
    )
    assert p._min_size == 5
    assert p._max_size == 20


# ── initialize ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_initialize_creates_pool_and_runs_ddl():
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()

    with patch.object(_mock_asyncpg, "create_pool", AsyncMock(return_value=mock_pool)):
        await p.initialize()

    assert p._pool is mock_pool
    assert mock_conn.execute.call_count >= 4  # 4 DDL statements


@pytest.mark.asyncio
async def test_initialize_pool_creation_fails_raises():
    p = _make_provider()

    with patch.object(_mock_asyncpg, "create_pool", AsyncMock(side_effect=OSError("conn refused"))):
        with pytest.raises(RuntimeError, match="failed to create pool"):
            await p.initialize()


@pytest.mark.asyncio
async def test_initialize_ddl_fails_closes_pool_and_raises():
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()
    mock_conn.execute = AsyncMock(side_effect=Exception("DDL error"))

    with patch.object(_mock_asyncpg, "create_pool", AsyncMock(return_value=mock_pool)):
        with pytest.raises(RuntimeError, match="schema migration failed"):
            await p.initialize()

    assert p._pool is None
    mock_pool.close.assert_called_once()


# ── close ─────────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_close_calls_pool_close():
    p = _make_provider()
    mock_pool, _ = _make_mock_pool()
    p._pool = mock_pool

    await p.close()

    mock_pool.close.assert_called_once()
    assert p._pool is None


@pytest.mark.asyncio
async def test_close_no_pool_is_noop():
    p = _make_provider()
    p._pool = None
    await p.close()  # should not raise


# ── _require_pool ─────────────────────────────────────────────────────────────


def test_require_pool_raises_when_none():
    p = _make_provider()
    p._pool = None
    with pytest.raises(RuntimeError, match="initialize"):
        p._require_pool()


# ── write_node ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_write_node_uninitialized_raises():
    p = _make_provider()
    with pytest.raises(RuntimeError, match="initialize"):
        await p.write_node(
            node_id="abc",
            timestamp="2024-01-01T00:00:00Z",
            node_data={},
            request_hash="r",
            response_hash="s",
            merkle_root="m",
            signature="sig",
            client_id="c",
        )


@pytest.mark.asyncio
async def test_write_node_success():
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()
    p._pool = mock_pool

    await p.write_node(
        node_id="n1",
        timestamp="2024-01-01T00:00:00Z",
        node_data={"key": "val"},
        request_hash="rh",
        response_hash="sh",
        merkle_root="mr",
        signature="sig",
        client_id="client1",
    )

    mock_conn.execute.assert_called_once()


@pytest.mark.asyncio
async def test_write_node_exception_wraps_as_runtime_error():
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()
    mock_conn.execute = AsyncMock(side_effect=Exception("db error"))
    p._pool = mock_pool

    with pytest.raises(RuntimeError, match="write_node failed"):
        await p.write_node(
            node_id="n1",
            timestamp="2024-01-01T00:00:00Z",
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
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()
    mock_conn.fetchrow = AsyncMock(return_value=None)
    p._pool = mock_pool

    result = await p.get_latest_node()
    assert result is None


@pytest.mark.asyncio
async def test_get_latest_node_returns_record():
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()
    mock_conn.fetchrow = AsyncMock(return_value={
        "node_id": "abc",
        "timestamp": "2024-01-01T00:00:00Z",
        "request_hash": "rh",
        "response_hash": "sh",
        "merkle_root": "mr",
        "signature": "sig",
        "client_id": "c1",
        "node_data": json.dumps({"prev_hash": "0" * 64}),
    })
    p._pool = mock_pool

    result = await p.get_latest_node()
    assert result is not None
    assert result["node_id"] == "abc"
    assert isinstance(result["node_data"], dict)


@pytest.mark.asyncio
async def test_get_latest_node_exception_raises():
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()
    mock_conn.fetchrow = AsyncMock(side_effect=Exception("conn lost"))
    p._pool = mock_pool

    with pytest.raises(RuntimeError, match="get_latest_node failed"):
        await p.get_latest_node()


# ── get_node ──────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_get_node_uninitialized_raises():
    p = _make_provider()
    with pytest.raises(RuntimeError, match="initialize"):
        await p.get_node("abc123")


@pytest.mark.asyncio
async def test_get_node_not_found_returns_none():
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()
    mock_conn.fetchrow = AsyncMock(return_value=None)
    p._pool = mock_pool

    result = await p.get_node("missing-hash")
    assert result is None


@pytest.mark.asyncio
async def test_get_node_found_returns_dict():
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()
    mock_conn.fetchrow = AsyncMock(return_value={
        "node_id": "xyz",
        "timestamp": "2024-01-01T00:00:00Z",
        "request_hash": "",
        "response_hash": "",
        "merkle_root": "",
        "signature": "",
        "client_id": "",
        "node_data": "{}",
    })
    p._pool = mock_pool

    result = await p.get_node("xyz")
    assert result["node_id"] == "xyz"


@pytest.mark.asyncio
async def test_get_node_exception_raises():
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()
    mock_conn.fetchrow = AsyncMock(side_effect=Exception("db error"))
    p._pool = mock_pool

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
    p = _make_provider()
    mock_pool, _ = _make_mock_pool()
    p._pool = mock_pool

    with pytest.raises(ValueError):
        await p.list_nodes(10, -1)


@pytest.mark.asyncio
async def test_list_nodes_no_tenant():
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()
    mock_conn.fetch = AsyncMock(return_value=[{
        "node_id": "n1",
        "timestamp": "2024-01-01",
        "request_hash": "",
        "response_hash": "",
        "merkle_root": "",
        "signature": "",
        "client_id": "",
        "node_data": "{}",
    }])
    p._pool = mock_pool

    result = await p.list_nodes(10, 0)
    assert len(result) == 1
    assert result[0]["node_id"] == "n1"


@pytest.mark.asyncio
async def test_list_nodes_with_tenant():
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()
    mock_conn.fetch = AsyncMock(return_value=[])
    p._pool = mock_pool

    result = await p.list_nodes(10, 0, tenant_id="tenant1")
    assert result == []
    mock_conn.fetch.assert_called_once()


@pytest.mark.asyncio
async def test_list_nodes_exception_raises():
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()
    mock_conn.fetch = AsyncMock(side_effect=Exception("conn error"))
    p._pool = mock_pool

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
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()
    mock_conn.fetch = AsyncMock(return_value=[])
    p._pool = mock_pool

    result = await p.check_integrity()
    assert result["is_valid"] is True
    assert result["node_count"] == 0


@pytest.mark.asyncio
async def test_check_integrity_valid_chain():
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()

    node_a_id = "a" * 64
    node_b_id = "b" * 64

    # asyncpg decodes JSONB as dicts automatically — pass dicts directly
    mock_conn.fetch = AsyncMock(return_value=[
        {
            "node_id": node_a_id,
            "node_data": {"prev_hash": "0" * 64},
        },
        {
            "node_id": node_b_id,
            "node_data": {"prev_hash": node_a_id},
        },
    ])
    p._pool = mock_pool

    result = await p.check_integrity()
    assert result["is_valid"] is True
    assert result["node_count"] == 2


@pytest.mark.asyncio
async def test_check_integrity_broken_chain():
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()

    # asyncpg decodes JSONB as dicts automatically
    mock_conn.fetch = AsyncMock(return_value=[
        {
            "node_id": "a" * 64,
            "node_data": {"prev_hash": "0" * 64},
        },
        {
            "node_id": "b" * 64,
            "node_data": {"prev_hash": "wrong" * 13},  # wrong link
        },
    ])
    p._pool = mock_pool

    result = await p.check_integrity()
    assert result["is_valid"] is False
    assert result["broken_link_index"] == 1


@pytest.mark.asyncio
async def test_check_integrity_exception_raises():
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()
    mock_conn.fetch = AsyncMock(side_effect=Exception("db error"))
    p._pool = mock_pool

    with pytest.raises(RuntimeError, match="check_integrity failed"):
        await p.check_integrity()


# ── _record_to_dict ───────────────────────────────────────────────────────────


def test_record_to_dict_string_node_data():
    record = {
        "node_id": "n1",
        "node_data": '{"key": "val"}',
        "seq": 1,
    }
    result = PostgreSQLStorageProvider._record_to_dict(record)
    assert result["node_data"] == {"key": "val"}
    assert "seq" not in result


def test_record_to_dict_dict_node_data():
    record = {
        "node_id": "n1",
        "node_data": {"key": "val"},
        "seq": 2,
    }
    result = PostgreSQLStorageProvider._record_to_dict(record)
    assert result["node_data"] == {"key": "val"}
    assert "seq" not in result


def test_record_to_dict_invalid_json_node_data():
    record = {
        "node_id": "n1",
        "node_data": "not-json{{{",
        "seq": 3,
    }
    result = PostgreSQLStorageProvider._record_to_dict(record)
    assert result["node_data"] == {}


# ── get_latest_node — invalid JSON node_data silently falls back (lines 278-279)


@pytest.mark.asyncio
async def test_get_latest_node_invalid_json_node_data():
    """When node_data is an invalid JSON string, json.loads raises → pass (278-279)."""
    p = _make_provider()
    mock_pool, mock_conn = _make_mock_pool()
    mock_conn.fetchrow = AsyncMock(return_value={
        "node_id": "abc" * 21 + "a",
        "node_data": "{ NOT VALID JSON {{",
        "timestamp": "2024-01-01T00:00:00",
        "request_hash": "rh",
        "response_hash": "rh2",
        "merkle_root": "mr",
        "signature": "sig",
        "client_id": "c1",
    })
    p._pool = mock_pool

    result = await p.get_latest_node()
    assert result is not None
    # node_data was invalid JSON; stays as the original string (not replaced)
    assert result["node_data"] == "{ NOT VALID JSON {{"
