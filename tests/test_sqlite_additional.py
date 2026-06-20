# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Additional SQLiteStorageProvider tests for missing branch coverage."""

from __future__ import annotations

import json
from unittest.mock import patch

import aiosqlite
import pytest

from aegis_server.storage.sqlite_provider import SQLiteStorageProvider


def _make_provider(db_path: str) -> SQLiteStorageProvider:
    return SQLiteStorageProvider(db_path)


async def _write(p: SQLiteStorageProvider, node_id: str, prev_hash: str) -> None:
    import datetime
    await p.write_node(
        node_id=node_id,
        timestamp=datetime.datetime.utcnow().isoformat(),
        node_data={"prev_hash": prev_hash},
        request_hash="rh",
        response_hash="rh2",
        merkle_root="mr",
        signature="sig",
        client_id="tenant",
    )


# ── initialize() error path (lines 195-196) ──────────────────────────────────


@pytest.mark.asyncio
async def test_initialize_fails_on_db_error(tmp_path):
    p = _make_provider(str(tmp_path / "test.db"))
    with patch("aiosqlite.connect", side_effect=Exception("disk full")):
        with pytest.raises(RuntimeError, match="initialize failed"):
            await p.initialize()


# ── get_latest_node() error paths (lines 240-244) ────────────────────────────


@pytest.mark.asyncio
async def test_get_latest_node_invalid_json_node_data(tmp_path):
    """node_data is a non-JSON string → json.loads raises → pass (lines 240-241)."""
    db_path = str(tmp_path / "test.db")
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "CREATE TABLE audit_nodes ("
            "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
            "node_id TEXT NOT NULL,"
            "timestamp TEXT,"
            "request_hash TEXT,"
            "response_hash TEXT,"
            "merkle_root TEXT,"
            "signature TEXT,"
            "client_id TEXT,"
            "node_data TEXT)"
        )
        await db.execute(
            "INSERT INTO audit_nodes (node_id, node_data) VALUES (?, ?)",
            ("a" * 64, "{not valid json"),
        )
        await db.commit()

    p = _make_provider(db_path)
    p._initialized = True
    result = await p.get_latest_node()
    assert result is not None
    assert result["node_id"] == "a" * 64


@pytest.mark.asyncio
async def test_get_latest_node_db_error(tmp_path):
    """aiosqlite.connect raises → RuntimeError (lines 243-244)."""
    p = _make_provider(str(tmp_path / "test.db"))
    p._initialized = True
    with patch("aiosqlite.connect", side_effect=Exception("disk error")):
        with pytest.raises(RuntimeError, match="get_latest_node failed"):
            await p.get_latest_node()


# ── write_node() error path (lines 294-295) ──────────────────────────────────


@pytest.mark.asyncio
async def test_write_node_db_error(tmp_path):
    p = _make_provider(str(tmp_path / "test.db"))
    p._initialized = True
    with patch("aiosqlite.connect", side_effect=Exception("write failed")):
        with pytest.raises(RuntimeError, match="write_node failed"):
            await _write(p, "b" * 64, "0" * 64)


# ── get_node() — entire method (lines 313-330) ───────────────────────────────


@pytest.mark.asyncio
async def test_get_node_found(tmp_path):
    p = _make_provider(str(tmp_path / "test.db"))
    await p.initialize()
    await _write(p, "c" * 64, "0" * 64)

    result = await p.get_node("c" * 64)
    assert result is not None
    assert result["node_id"] == "c" * 64


@pytest.mark.asyncio
async def test_get_node_not_found(tmp_path):
    p = _make_provider(str(tmp_path / "test.db"))
    await p.initialize()

    result = await p.get_node("z" * 64)
    assert result is None


@pytest.mark.asyncio
async def test_get_node_not_initialized_raises(tmp_path):
    p = _make_provider(str(tmp_path / "test.db"))
    with pytest.raises(RuntimeError, match="initialize.*was not called"):
        await p.get_node("x" * 64)


@pytest.mark.asyncio
async def test_get_node_db_error(tmp_path):
    p = _make_provider(str(tmp_path / "test.db"))
    p._initialized = True
    with patch("aiosqlite.connect", side_effect=Exception("io fail")):
        with pytest.raises(RuntimeError, match="get_node failed"):
            await p.get_node("a" * 64)


# ── list_nodes() error path (lines 361-362) ──────────────────────────────────


@pytest.mark.asyncio
async def test_list_nodes_db_error(tmp_path):
    p = _make_provider(str(tmp_path / "test.db"))
    p._initialized = True
    with patch("aiosqlite.connect", side_effect=Exception("io fail")):
        with pytest.raises(RuntimeError, match="list_nodes failed"):
            await p.list_nodes(10, 0)


# ── check_integrity() error path (lines 386-387) ─────────────────────────────


@pytest.mark.asyncio
async def test_check_integrity_db_error(tmp_path):
    p = _make_provider(str(tmp_path / "test.db"))
    p._initialized = True
    with patch("aiosqlite.connect", side_effect=Exception("io fail")):
        with pytest.raises(RuntimeError, match="check_integrity failed"):
            await p.check_integrity()


# ── check_integrity() json decode error (lines 410-411) ──────────────────────


@pytest.mark.asyncio
async def test_check_integrity_invalid_json_node_data(tmp_path):
    """Row with invalid JSON node_data → json.loads except → node_data = {} (410-411)."""
    db_path = str(tmp_path / "test.db")
    async with aiosqlite.connect(db_path) as db:
        await db.execute(
            "CREATE TABLE audit_nodes ("
            "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
            "node_id TEXT NOT NULL,"
            "timestamp TEXT,"
            "request_hash TEXT,"
            "response_hash TEXT,"
            "merkle_root TEXT,"
            "signature TEXT,"
            "client_id TEXT,"
            "node_data TEXT)"
        )
        await db.execute(
            "INSERT INTO audit_nodes (node_id, node_data) VALUES (?, ?)",
            ("a" * 64, "NOT_JSON"),
        )
        await db.commit()

    p = _make_provider(db_path)
    p._initialized = True
    result = await p.check_integrity()
    # With invalid JSON, node_data becomes {}, so prev_hash is "" ≠ "0"*64
    assert result["is_valid"] is False


# ── _row_to_dict() json error (lines 455-456) ────────────────────────────────


def test_row_to_dict_invalid_json_falls_back_to_empty_dict():
    row = {
        "node_id": "d" * 64,
        "node_data": "{broken json",
        "timestamp": "2024-01-01T00:00:00",
        "request_hash": "rh",
        "response_hash": "rh2",
        "merkle_root": "mr",
        "signature": "sig",
        "client_id": "t1",
    }
    result = SQLiteStorageProvider._row_to_dict(row)
    assert result["node_data"] == {}
    assert "seq" not in result
