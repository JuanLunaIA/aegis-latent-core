# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Tests for aegis_server.storage.sqlite_provider — SQLite audit node persistence."""

from __future__ import annotations

import pytest

from aegis_server.storage.sqlite_provider import _SQLITE_LOCK_TIMEOUT, SQLiteStorageProvider

# ── constants ─────────────────────────────────────────────────────────────────


def test_lock_timeout_constant():
    assert _SQLITE_LOCK_TIMEOUT == 30.0


# ── lifecycle ─────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_initialize_creates_database(tmp_path):
    db = tmp_path / "test.db"
    provider = SQLiteStorageProvider(str(db))
    await provider.initialize()
    assert db.exists()
    await provider.close()


@pytest.mark.asyncio
async def test_initialize_is_idempotent(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    await provider.initialize()
    await provider.initialize()  # Must not raise
    await provider.close()


@pytest.mark.asyncio
async def test_close_clears_initialized_flag(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    await provider.initialize()
    assert provider._initialized is True
    await provider.close()
    assert provider._initialized is False


# ── write_node and get_latest_node ───────────────────────────────────────────


@pytest.mark.asyncio
async def test_write_node_then_get_latest(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    await provider.initialize()

    await provider.write_node(
        node_id="hash-abc-001",
        timestamp="2025-01-01T00:00:00Z",
        node_data={"prev_hash": "0" * 64, "model": "gpt-4"},
        request_hash="req-hash",
        response_hash="resp-hash",
        merkle_root="merkle-root",
        signature="sig",
        client_id="tenant-a",
    )

    latest = await provider.get_latest_node()
    assert latest is not None
    assert latest["node_id"] == "hash-abc-001"
    assert latest["client_id"] == "tenant-a"
    await provider.close()


@pytest.mark.asyncio
async def test_get_latest_node_empty_db_returns_none(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    await provider.initialize()
    result = await provider.get_latest_node()
    assert result is None
    await provider.close()


@pytest.mark.asyncio
async def test_get_latest_node_returns_most_recent(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    await provider.initialize()

    await provider.write_node(
        node_id="hash-001",
        timestamp="2025-01-01T00:00:00Z",
        node_data={"prev_hash": "0" * 64},
        request_hash="r1",
        response_hash="rs1",
        merkle_root="m1",
        signature="s1",
        client_id="c1",
    )
    await provider.write_node(
        node_id="hash-002",
        timestamp="2025-01-01T01:00:00Z",
        node_data={"prev_hash": "hash-001"},
        request_hash="r2",
        response_hash="rs2",
        merkle_root="m2",
        signature="s2",
        client_id="c1",
    )

    latest = await provider.get_latest_node()
    assert latest["node_id"] == "hash-002"
    await provider.close()


@pytest.mark.asyncio
async def test_write_node_duplicate_id_is_ignored(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    await provider.initialize()

    await provider.write_node(
        node_id="dup-001",
        timestamp="2025-01-01T00:00:00Z",
        node_data={"prev_hash": "0" * 64},
        request_hash="r1",
        response_hash="rs1",
        merkle_root="m1",
        signature="s1",
        client_id="c1",
    )
    # Duplicate insert — INSERT OR IGNORE, must not raise
    await provider.write_node(
        node_id="dup-001",
        timestamp="2025-01-01T01:00:00Z",
        node_data={"prev_hash": "other"},
        request_hash="r2",
        response_hash="rs2",
        merkle_root="m2",
        signature="s2",
        client_id="c2",
    )
    # Only one node
    nodes = await provider.list_nodes(limit=10, offset=0)
    assert len(nodes) == 1
    await provider.close()


# ── list_nodes ────────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_list_nodes_empty(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    await provider.initialize()
    nodes = await provider.list_nodes(limit=10, offset=0)
    assert nodes == []
    await provider.close()


@pytest.mark.asyncio
async def test_list_nodes_returns_in_insertion_order(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    await provider.initialize()

    for i in range(5):
        await provider.write_node(
            node_id=f"node-{i:03d}",
            timestamp=f"2025-01-0{i + 1}T00:00:00Z",
            node_data={"prev_hash": "0" * 64},
            request_hash=f"r{i}",
            response_hash=f"rs{i}",
            merkle_root=f"m{i}",
            signature=f"s{i}",
            client_id="tenant",
        )

    nodes = await provider.list_nodes(limit=10, offset=0)
    assert len(nodes) == 5
    ids = [n["node_id"] for n in nodes]
    assert ids == [f"node-{i:03d}" for i in range(5)]
    await provider.close()


@pytest.mark.asyncio
async def test_list_nodes_limit_and_offset(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    await provider.initialize()

    for i in range(10):
        await provider.write_node(
            node_id=f"n{i:02d}",
            timestamp=f"2025-01-{i + 1:02d}T00:00:00Z",
            node_data={"prev_hash": "0" * 64},
            request_hash=f"r{i}",
            response_hash=f"rs{i}",
            merkle_root=f"m{i}",
            signature=f"s{i}",
            client_id="t",
        )

    page1 = await provider.list_nodes(limit=3, offset=0)
    page2 = await provider.list_nodes(limit=3, offset=3)
    assert len(page1) == 3
    assert len(page2) == 3
    assert page1[0]["node_id"] == "n00"
    assert page2[0]["node_id"] == "n03"
    await provider.close()


@pytest.mark.asyncio
async def test_list_nodes_tenant_filter(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    await provider.initialize()

    for i in range(3):
        await provider.write_node(
            node_id=f"t1-{i}",
            timestamp=f"2025-01-0{i + 1}T00:00:00Z",
            node_data={"prev_hash": "0" * 64},
            request_hash=f"r{i}",
            response_hash=f"rs{i}",
            merkle_root=f"m{i}",
            signature=f"s{i}",
            client_id="tenant-1",
        )
    for i in range(2):
        await provider.write_node(
            node_id=f"t2-{i}",
            timestamp=f"2025-01-0{i + 4}T00:00:00Z",
            node_data={"prev_hash": "0" * 64},
            request_hash=f"rx{i}",
            response_hash=f"rsx{i}",
            merkle_root=f"mx{i}",
            signature=f"sx{i}",
            client_id="tenant-2",
        )

    t1_nodes = await provider.list_nodes(limit=10, offset=0, tenant_id="tenant-1")
    t2_nodes = await provider.list_nodes(limit=10, offset=0, tenant_id="tenant-2")
    assert len(t1_nodes) == 3
    assert len(t2_nodes) == 2
    await provider.close()


# ── check_integrity ───────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_check_integrity_empty_db_is_valid(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    await provider.initialize()
    report = await provider.check_integrity()
    assert report["is_valid"] is True
    assert report["node_count"] == 0
    await provider.close()


@pytest.mark.asyncio
async def test_check_integrity_single_node_is_valid(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    await provider.initialize()

    await provider.write_node(
        node_id="node-x",
        timestamp="2025-01-01T00:00:00Z",
        node_data={"prev_hash": "0" * 64},
        request_hash="rh",
        response_hash="rs",
        merkle_root="mr",
        signature="sig",
        client_id="c",
    )
    report = await provider.check_integrity()
    assert report["is_valid"] is True
    assert report["node_count"] == 1
    assert report["first_node_id"] == "node-x"
    await provider.close()


@pytest.mark.asyncio
async def test_check_integrity_chain_linkage_valid(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    await provider.initialize()

    genesis = "0" * 64
    await provider.write_node(
        node_id="node-alpha",
        timestamp="2025-01-01T00:00:00Z",
        node_data={"prev_hash": genesis},
        request_hash="r1",
        response_hash="rs1",
        merkle_root="m1",
        signature="s1",
        client_id="c",
    )
    await provider.write_node(
        node_id="node-beta",
        timestamp="2025-01-01T01:00:00Z",
        node_data={"prev_hash": "node-alpha"},
        request_hash="r2",
        response_hash="rs2",
        merkle_root="m2",
        signature="s2",
        client_id="c",
    )
    report = await provider.check_integrity()
    assert report["is_valid"] is True
    assert report["node_count"] == 2
    await provider.close()


@pytest.mark.asyncio
async def test_check_integrity_detects_broken_link(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    await provider.initialize()

    await provider.write_node(
        node_id="n1",
        timestamp="2025-01-01T00:00:00Z",
        node_data={"prev_hash": "0" * 64},
        request_hash="r1",
        response_hash="rs1",
        merkle_root="m1",
        signature="s1",
        client_id="c",
    )
    # n2 has wrong prev_hash — doesn't link back to n1
    await provider.write_node(
        node_id="n2",
        timestamp="2025-01-01T01:00:00Z",
        node_data={"prev_hash": "wrong-hash"},
        request_hash="r2",
        response_hash="rs2",
        merkle_root="m2",
        signature="s2",
        client_id="c",
    )
    report = await provider.check_integrity()
    assert report["is_valid"] is False
    assert report["broken_link_index"] == 1
    await provider.close()


# ── error cases ───────────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_write_node_without_initialize_raises(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    with pytest.raises(RuntimeError, match="initialize"):
        await provider.write_node(
            node_id="x",
            timestamp="t",
            node_data={},
            request_hash="r",
            response_hash="rs",
            merkle_root="m",
            signature="s",
            client_id="c",
        )


@pytest.mark.asyncio
async def test_list_nodes_without_initialize_raises(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    with pytest.raises(RuntimeError, match="initialize"):
        await provider.list_nodes(limit=10, offset=0)


@pytest.mark.asyncio
async def test_get_latest_node_without_initialize_raises(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    with pytest.raises(RuntimeError, match="initialize"):
        await provider.get_latest_node()


@pytest.mark.asyncio
async def test_check_integrity_without_initialize_raises(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    with pytest.raises(RuntimeError, match="initialize"):
        await provider.check_integrity()


# ── node_data JSON handling ───────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_node_data_is_deserialized_from_json(tmp_path):
    provider = SQLiteStorageProvider(str(tmp_path / "audit.db"))
    await provider.initialize()

    await provider.write_node(
        node_id="json-node",
        timestamp="2025-01-01T00:00:00Z",
        node_data={"prev_hash": "0" * 64, "entropy": 2.5, "model": "gpt-4"},
        request_hash="r",
        response_hash="rs",
        merkle_root="m",
        signature="s",
        client_id="c",
    )

    nodes = await provider.list_nodes(limit=1, offset=0)
    assert nodes[0]["node_data"]["entropy"] == 2.5
    assert nodes[0]["node_data"]["model"] == "gpt-4"
    await provider.close()
