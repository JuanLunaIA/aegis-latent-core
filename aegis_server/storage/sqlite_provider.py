# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis_server.storage.sqlite_provider — SQLite audit node persistence.

Uses ``aiosqlite`` for non-blocking async I/O on top of SQLite's WAL mode,
which allows one writer and unlimited concurrent readers with no locking
contention under the typical Aegis access pattern (frequent reads, moderate
writes from background analytics tasks).

WAL pragmas applied on every connection open:
    PRAGMA journal_mode = WAL;        — enables WAL journaling
    PRAGMA synchronous  = NORMAL;     — durable on power failure via WAL
    PRAGMA foreign_keys = ON;         — referential integrity
    PRAGMA temp_store   = MEMORY;     — avoid temp-file I/O

Schema (single table ``audit_nodes``)::

    CREATE TABLE IF NOT EXISTS audit_nodes (
        node_id      TEXT NOT NULL,
        timestamp    TEXT NOT NULL,
        request_hash TEXT NOT NULL DEFAULT '',
        response_hash TEXT NOT NULL DEFAULT '',
        merkle_root  TEXT NOT NULL DEFAULT '',
        signature    TEXT NOT NULL DEFAULT '',
        client_id    TEXT NOT NULL DEFAULT '',
        node_data    TEXT NOT NULL DEFAULT '{}',   -- JSON blob
        seq          INTEGER PRIMARY KEY AUTOINCREMENT
    );

``seq`` is an auto-increment surrogate used for stable insertion-order
pagination, avoiding ambiguity when two nodes share the same ``timestamp``.
``node_id`` has a UNIQUE index to enforce idempotency.

Dependencies:
    aiosqlite>=0.20.0
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import sqlite3
from typing import Any

import aiosqlite

from aegis_server.storage.base import (
    GENESIS_PREV_HASH,
    ConcurrentChainMutationError,
    IntegrityReport,
    StorageProvider,
)

logger = logging.getLogger(__name__)

# SQLite busy-timeout: how long to wait for a write lock before raising
# OperationalError. 30 s is generous for local-disk WAL but prevents a
# stalled writer from hanging the process indefinitely (I-03).
_SQLITE_LOCK_TIMEOUT = 30.0

_CREATE_TABLE_SQL = """
CREATE TABLE IF NOT EXISTS audit_nodes (
    node_id       TEXT NOT NULL,
    timestamp     TEXT NOT NULL,
    request_hash  TEXT NOT NULL DEFAULT '',
    response_hash TEXT NOT NULL DEFAULT '',
    merkle_root   TEXT NOT NULL DEFAULT '',
    signature     TEXT NOT NULL DEFAULT '',
    client_id     TEXT NOT NULL DEFAULT '',
    node_data     TEXT NOT NULL DEFAULT '{}',
    seq           INTEGER PRIMARY KEY AUTOINCREMENT
);
"""

_CREATE_UNIQUE_INDEX_SQL = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_node_id
    ON audit_nodes (node_id);
"""

_CREATE_TIMESTAMP_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_audit_timestamp
    ON audit_nodes (timestamp);
"""

_CREATE_CLIENT_INDEX_SQL = """
CREATE INDEX IF NOT EXISTS idx_audit_client
    ON audit_nodes (client_id);
"""

# The chain link, lifted out of the node_data JSON into a column so the
# database itself can enforce that it is unique.
#
# In a linear chain every node has exactly one successor, so no two nodes ever
# share a prev_hash — and a fork is precisely two nodes that do. A unique index
# therefore does not *detect* forks, it makes them unrepresentable, without a
# lock, across processes and across hosts. It also closes the one case a
# compare-and-append misses: an empty table has no row to lock, so two genesis
# writers can otherwise both succeed.
_ADD_PREV_HASH_COLUMN_SQL = """
ALTER TABLE audit_nodes ADD COLUMN prev_hash TEXT NOT NULL DEFAULT '';
"""

_BACKFILL_PREV_HASH_SQL = """
UPDATE audit_nodes
   SET prev_hash = COALESCE(json_extract(node_data, '$.prev_hash'), '')
 WHERE prev_hash = '';
"""

# Partial: legacy rows whose node_data carried no prev_hash backfill to '' and
# must not collide with each other. Real links are always 64 hex characters.
_CREATE_PREV_HASH_INDEX_SQL = """
CREATE UNIQUE INDEX IF NOT EXISTS idx_audit_prev_hash
    ON audit_nodes (prev_hash) WHERE prev_hash <> '';
"""

_WAL_PRAGMAS = [
    "PRAGMA journal_mode = WAL;",
    "PRAGMA synchronous  = NORMAL;",
    "PRAGMA foreign_keys = ON;",
    "PRAGMA temp_store   = MEMORY;",
    "PRAGMA cache_size   = -8000;",  # ~8 MB page cache
]

_INSERT_SQL = """
INSERT OR IGNORE INTO audit_nodes
    (node_id, timestamp, request_hash, response_hash,
     merkle_root, signature, client_id, node_data)
VALUES
    (?, ?, ?, ?, ?, ?, ?, ?);
"""

_INSERT_ATOMIC_SQL = """
INSERT OR IGNORE INTO audit_nodes
    (node_id, timestamp, request_hash, response_hash,
     merkle_root, signature, client_id, node_data, prev_hash)
VALUES
    (?, ?, ?, ?, ?, ?, ?, ?, ?);
"""

_TIP_NODE_ID_SQL = """
SELECT node_id FROM audit_nodes ORDER BY seq DESC LIMIT 1;
"""

_SELECT_BY_ID_SQL = """
SELECT node_id, timestamp, request_hash, response_hash,
       merkle_root, signature, client_id, node_data
FROM audit_nodes
WHERE node_id = ?;
"""

_LIST_ALL_SQL = """
SELECT node_id, timestamp, request_hash, response_hash,
       merkle_root, signature, client_id, node_data
FROM audit_nodes
ORDER BY seq ASC
LIMIT ? OFFSET ?;
"""

_LIST_TENANT_SQL = """
SELECT node_id, timestamp, request_hash, response_hash,
       merkle_root, signature, client_id, node_data
FROM audit_nodes
WHERE client_id = ?
ORDER BY seq ASC
LIMIT ? OFFSET ?;
"""

_ALL_FOR_INTEGRITY_SQL = """
SELECT node_id, node_data
FROM audit_nodes
ORDER BY seq ASC;
"""

# BLOCKER-01 fix: retrieves the LAST inserted node (highest seq) for prev_hash chain linkage.
# Using ORDER BY seq DESC LIMIT 1 instead of ASC LIMIT 1 which returned the genesis node.
_LATEST_NODE_SQL = """
SELECT node_id, timestamp, request_hash, response_hash,
       merkle_root, signature, client_id, node_data
FROM audit_nodes
ORDER BY seq DESC
LIMIT 1;
"""


class SQLiteStorageProvider(StorageProvider):
    """
    Async SQLite audit node storage using ``aiosqlite``.

    Thread-safety note: ``aiosqlite`` serialises all writes through a
    dedicated thread per database connection.  For a single-process
    Uvicorn worker this is sufficient; for multi-worker deployments use
    ``PostgreSQLStorageProvider`` or ``DynamoDBStorageProvider``.

    Args:
        db_path: Filesystem path to the SQLite database file.
                 Created automatically if it does not exist.
                 Parent directories must already exist.
    """

    def __init__(self, db_path: str) -> None:
        self._db_path = db_path
        self._initialized: bool = False
        # BLOCKER-02 fix: serialise read-prev → write-node pairs within a single
        # process so concurrent BackgroundTasks cannot produce a forked chain.
        # This lock is process-local; for multi-process deployments use PostgreSQL
        # with the atomic CTE insert pattern.
        self._chain_lock: asyncio.Lock = asyncio.Lock()

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    @staticmethod
    async def _migrate_prev_hash(db: aiosqlite.Connection) -> None:
        """Lift ``prev_hash`` into a column and index it uniquely.

        Idempotent, and deliberately loud on one case: if the unique index
        cannot be built, the existing rows already contain two nodes naming the
        same predecessor. That is a chain that has **already forked**, and
        starting anyway would mean appending to a history with no single past.
        The error names the duplicate so an operator can decide which branch is
        the record; there is no correct answer this code could pick for them.
        """
        async with db.execute("PRAGMA table_info(audit_nodes);") as cursor:
            columns = {row[1] for row in await cursor.fetchall()}
        if "prev_hash" not in columns:
            await db.execute(_ADD_PREV_HASH_COLUMN_SQL)
        await db.execute(_BACKFILL_PREV_HASH_SQL)
        try:
            await db.execute(_CREATE_PREV_HASH_INDEX_SQL)
        except sqlite3.IntegrityError as exc:
            async with db.execute(
                "SELECT prev_hash, COUNT(*) c FROM audit_nodes "
                "WHERE prev_hash <> '' GROUP BY prev_hash HAVING c > 1 LIMIT 1;"
            ) as cursor:
                row = await cursor.fetchone()
            duplicate = row[0] if row else "unknown"
            raise RuntimeError(
                "audit chain is already forked: more than one node names "
                f"prev_hash={duplicate!r} as its predecessor. Refusing to open "
                "the store, because appending to a chain with two histories "
                "produces evidence that cannot be verified. Resolve which "
                "branch is authoritative before restarting."
            ) from exc

    async def initialize(self) -> None:
        """
        Open the database, apply WAL pragmas, and create the schema.

        Idempotent: safe to call on an existing database.

        Raises:
            RuntimeError: If the database file cannot be opened or the
                          schema migrations fail.
        """
        parent = os.path.dirname(os.path.abspath(self._db_path))
        os.makedirs(parent, exist_ok=True)

        try:
            async with aiosqlite.connect(self._db_path, timeout=_SQLITE_LOCK_TIMEOUT) as db:
                # WAL mode must be set before any other operations
                for pragma in _WAL_PRAGMAS:
                    await db.execute(pragma)
                await db.execute(_CREATE_TABLE_SQL)
                await db.execute(_CREATE_UNIQUE_INDEX_SQL)
                await db.execute(_CREATE_TIMESTAMP_INDEX_SQL)
                await db.execute(_CREATE_CLIENT_INDEX_SQL)
                await self._migrate_prev_hash(db)
                await db.commit()
        except Exception as exc:
            raise RuntimeError(
                f"SQLiteStorageProvider.initialize failed for {self._db_path!r}: {exc}"
            ) from exc

        self._initialized = True
        logger.info(
            "SQLiteStorageProvider initialised: path=%r journal_mode=WAL",
            self._db_path,
        )

    async def close(self) -> None:
        """No persistent connection to close; aiosqlite opens per-operation."""
        self._initialized = False
        logger.debug("SQLiteStorageProvider closed (no persistent connection)")

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    async def get_latest_node(self) -> dict[str, Any] | None:
        """
        Return the most recently inserted audit node (highest seq), or None.

        BLOCKER-01 fix: uses ORDER BY seq DESC LIMIT 1 so callers always
        receive the last node, not the genesis node.

        The caller must hold ``self._chain_lock`` while reading this value
        and writing the subsequent node to prevent a fork under concurrency.
        """
        if not self._initialized:
            raise RuntimeError("SQLiteStorageProvider.initialize() was not called")
        try:
            async with aiosqlite.connect(self._db_path, timeout=_SQLITE_LOCK_TIMEOUT) as db:
                db.row_factory = aiosqlite.Row
                for pragma in _WAL_PRAGMAS:
                    await db.execute(pragma)
                async with db.execute(_LATEST_NODE_SQL) as cursor:
                    row = await cursor.fetchone()
            if row is None:
                return None
            raw = dict(row)
            if raw.get("node_data"):
                try:
                    raw["node_data"] = json.loads(raw["node_data"])
                except (json.JSONDecodeError, TypeError):
                    pass
            return raw
        except Exception as exc:
            raise RuntimeError(f"SQLiteStorageProvider.get_latest_node failed: {exc}") from exc

    async def write_node(
        self,
        node_id: str,
        timestamp: str,
        node_data: dict[str, Any],
        request_hash: str,
        response_hash: str,
        merkle_root: str,
        signature: str,
        client_id: str,
    ) -> None:
        """
        Insert an audit node under the chain lock.

        BLOCKER-02 fix: the ``_chain_lock`` serialises concurrent background
        tasks so no two tasks can interleave their read-prev / write sequence
        within the same process, preventing chain forks.

        Silently ignores duplicate ``node_id`` (``INSERT OR IGNORE``) so
        retries are safe.

        Raises:
            RuntimeError: On database I/O failures.
        """
        if not self._initialized:
            raise RuntimeError("SQLiteStorageProvider.initialize() was not called")

        node_data_json = json.dumps(node_data, separators=(",", ":"), default=str)

        async with self._chain_lock:
            try:
                async with aiosqlite.connect(self._db_path, timeout=_SQLITE_LOCK_TIMEOUT) as db:
                    for pragma in _WAL_PRAGMAS:
                        await db.execute(pragma)
                    await db.execute(
                        _INSERT_SQL,
                        (
                            node_id,
                            timestamp,
                            request_hash,
                            response_hash,
                            merkle_root,
                            signature,
                            client_id,
                            node_data_json,
                        ),
                    )
                    await db.commit()
            except Exception as exc:
                raise RuntimeError(
                    f"SQLiteStorageProvider.write_node failed for node_id={node_id!r}: {exc}"
                ) from exc

    async def write_node_atomic(
        self,
        node_id: str,
        timestamp: str,
        node_data: dict[str, Any],
        request_hash: str,
        response_hash: str,
        merkle_root: str,
        signature: str,
        client_id: str,
        expected_prev_hash: str,
    ) -> None:
        """Append only if the tip is still ``expected_prev_hash``.

        ``BEGIN IMMEDIATE`` takes SQLite's write lock before the tip is read
        and holds it through the insert, so the check and the append are one
        indivisible step. The process-local ``_chain_lock`` is kept as well —
        it costs nothing and keeps tasks in this process from queueing on the
        database lock — but it is no longer what makes this correct, which
        matters because it never protected anything across processes.

        Raises:
            ConcurrentChainMutationError: The tip moved; nothing was written.
            RuntimeError: On database I/O failures.
        """
        if not self._initialized:
            raise RuntimeError("SQLiteStorageProvider.initialize() was not called")

        node_data_json = json.dumps(node_data, separators=(",", ":"), default=str)

        async with self._chain_lock:
            try:
                async with aiosqlite.connect(self._db_path, timeout=_SQLITE_LOCK_TIMEOUT) as db:
                    for pragma in _WAL_PRAGMAS:
                        await db.execute(pragma)
                    # Not BEGIN DEFERRED: a deferred transaction takes the write
                    # lock only at the insert, leaving the read outside it and
                    # the race exactly where it was.
                    await db.execute("BEGIN IMMEDIATE;")
                    try:
                        async with db.execute(_TIP_NODE_ID_SQL) as cursor:
                            row = await cursor.fetchone()
                        tip = row[0] if row else GENESIS_PREV_HASH
                        if tip != expected_prev_hash:
                            await db.execute("ROLLBACK;")
                            raise ConcurrentChainMutationError(
                                f"chain tip moved: caller linked to {expected_prev_hash[:16]}… "
                                f"but the tip is {tip[:16]}…; nothing was written"
                            )
                        await db.execute(
                            _INSERT_ATOMIC_SQL,
                            (
                                node_id,
                                timestamp,
                                request_hash,
                                response_hash,
                                merkle_root,
                                signature,
                                client_id,
                                node_data_json,
                                expected_prev_hash,
                            ),
                        )
                        await db.commit()
                    except sqlite3.IntegrityError as exc:
                        # The unique index on prev_hash fired: another writer
                        # already linked to this predecessor. Same meaning as a
                        # moved tip, reached by the backstop rather than the check.
                        await db.execute("ROLLBACK;")
                        raise ConcurrentChainMutationError(
                            f"another node already links to {expected_prev_hash[:16]}…; "
                            "nothing was written"
                        ) from exc
            except ConcurrentChainMutationError:
                raise
            except Exception as exc:
                raise RuntimeError(
                    f"SQLiteStorageProvider.write_node_atomic failed for node_id={node_id!r}: {exc}"
                ) from exc

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    async def get_node(self, node_hash: str) -> dict[str, Any] | None:
        """
        Retrieve a node by its SHA-256 hash.

        Returns:
            Dict compatible with ``StorageNode.from_dict``, or ``None``.

        Raises:
            RuntimeError: On database I/O failures.
        """
        if not self._initialized:
            raise RuntimeError("SQLiteStorageProvider.initialize() was not called")

        try:
            async with aiosqlite.connect(self._db_path, timeout=_SQLITE_LOCK_TIMEOUT) as db:
                for pragma in _WAL_PRAGMAS:
                    await db.execute(pragma)
                db.row_factory = aiosqlite.Row
                cursor = await db.execute(_SELECT_BY_ID_SQL, (node_hash,))
                row = await cursor.fetchone()
        except Exception as exc:
            raise RuntimeError(
                f"SQLiteStorageProvider.get_node failed for hash={node_hash!r}: {exc}"
            ) from exc

        if row is None:
            return None
        return self._row_to_dict(row)

    async def list_nodes(
        self,
        limit: int,
        offset: int,
        tenant_id: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Return a paginated list of nodes in insertion order.

        Raises:
            ValueError:   If ``offset < 0``.
            RuntimeError: On database I/O failures.
        """
        if not self._initialized:
            raise RuntimeError("SQLiteStorageProvider.initialize() was not called")

        clamped = self._clamp_limit(limit)
        offset = self._validate_offset(offset)

        try:
            async with aiosqlite.connect(self._db_path, timeout=_SQLITE_LOCK_TIMEOUT) as db:
                for pragma in _WAL_PRAGMAS:
                    await db.execute(pragma)
                db.row_factory = aiosqlite.Row
                if tenant_id:
                    cursor = await db.execute(_LIST_TENANT_SQL, (tenant_id, clamped, offset))
                else:
                    cursor = await db.execute(_LIST_ALL_SQL, (clamped, offset))
                rows = await cursor.fetchall()
        except Exception as exc:
            raise RuntimeError(f"SQLiteStorageProvider.list_nodes failed: {exc}") from exc

        return [self._row_to_dict(r) for r in rows]

    async def check_integrity(self) -> dict[str, Any]:
        """
        Verify chain linkage across all stored nodes (ordered by seq).

        Returns:
            ``IntegrityReport.to_dict()``-compatible dict.

        Raises:
            RuntimeError: On database I/O failures.
        """
        if not self._initialized:
            raise RuntimeError("SQLiteStorageProvider.initialize() was not called")

        try:
            async with aiosqlite.connect(self._db_path, timeout=_SQLITE_LOCK_TIMEOUT) as db:
                for pragma in _WAL_PRAGMAS:
                    await db.execute(pragma)
                db.row_factory = aiosqlite.Row
                cursor = await db.execute(_ALL_FOR_INTEGRITY_SQL)
                rows = await cursor.fetchall()
        except Exception as exc:
            raise RuntimeError(f"SQLiteStorageProvider.check_integrity failed: {exc}") from exc

        checked_at = self._utcnow_iso()

        if not rows:
            return IntegrityReport(
                is_valid=True,
                node_count=0,
                first_node_id=None,
                last_node_id=None,
                broken_link_index=None,
                error_message=None,
                checked_at=checked_at,
            ).to_dict()

        first_id: str = rows[0]["node_id"]
        last_id: str = rows[-1]["node_id"]
        prev_node_id: str = "0" * 64  # genesis sentinel

        for i, row in enumerate(rows):
            current_node_id: str = row["node_id"]
            try:
                node_data: dict[str, Any] = json.loads(row["node_data"])
            except (json.JSONDecodeError, TypeError):
                node_data = {}

            stored_prev: str = node_data.get("prev_hash", "")

            if stored_prev != prev_node_id:
                return IntegrityReport(
                    is_valid=False,
                    node_count=len(rows),
                    first_node_id=first_id,
                    last_node_id=last_id,
                    broken_link_index=i,
                    error_message=(
                        f"Node {i} (id={current_node_id[:16]}…): "
                        f"prev_hash mismatch — "
                        f"expected={prev_node_id[:16]}…, "
                        f"stored={stored_prev[:16] if stored_prev else '(empty)'}…"
                    ),
                    checked_at=checked_at,
                ).to_dict()

            prev_node_id = current_node_id

        return IntegrityReport(
            is_valid=True,
            node_count=len(rows),
            first_node_id=first_id,
            last_node_id=last_id,
            broken_link_index=None,
            error_message=None,
            checked_at=checked_at,
        ).to_dict()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _row_to_dict(row: aiosqlite.Row) -> dict[str, Any]:
        """Convert an ``aiosqlite.Row`` into a plain dict."""
        d = dict(row)
        raw_node_data = d.get("node_data", "{}")
        if isinstance(raw_node_data, str):
            try:
                d["node_data"] = json.loads(raw_node_data)
            except (json.JSONDecodeError, ValueError):
                d["node_data"] = {}
        # Drop internal surrogate columns
        d.pop("seq", None)
        return d
