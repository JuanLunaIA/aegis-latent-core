# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
"""Real SQLite worker cleanup across task and level-triggered cancellation."""

from __future__ import annotations

import asyncio
from pathlib import Path

import anyio
import pytest

from aegis.core.ha import PendingNode, SQLiteSequenceStore


@pytest.mark.parametrize("statement", ["BEGIN IMMEDIATE", "COMMIT"])
@pytest.mark.parametrize("mode", ["task", "scope"])
async def test_cancellation_cleans_real_transaction(
    tmp_path: Path, statement: str, mode: str
) -> None:
    store = SQLiteSequenceStore(str(tmp_path / "sequence.db"))
    await store.open()
    db = store._db
    entered = asyncio.Event()

    class Pause:
        async def execute(self, sql, *args):
            result = await db.execute(sql, *args)
            if sql == statement:
                entered.set()
                await asyncio.Event().wait()
            return result

        def __getattr__(self, name):
            return getattr(db, name)

    store._db = Pause()
    items = [PendingNode(1, "n1", "g")]
    try:
        with anyio.fail_after(3):
            if mode == "task":
                task = asyncio.create_task(store.append("a", 1, items))
                await entered.wait()
                task.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await task
            else:
                async with anyio.create_task_group() as group:
                    group.start_soon(store.append, "a", 1, items)
                    await entered.wait()
                    group.cancel_scope.cancel()
        assert not db.in_transaction
        store._db = db
        # COMMIT may already have succeeded despite a cancelled acknowledgement.
        # Retrying the same chain position must be idempotent, not duplicate it.
        await store.append("a", 1, items)
        assert len(await store.entries()) == 1
    finally:
        store._db = db
        await store.close()


async def test_repeated_task_cancel_waits_for_rollback(tmp_path: Path) -> None:
    store = SQLiteSequenceStore(str(tmp_path / "sequence.db"))
    await store.open()
    db = store._db
    began, rolling_back, release = asyncio.Event(), asyncio.Event(), asyncio.Event()

    class Pause:
        async def execute(self, sql, *args):
            result = await db.execute(sql, *args)
            if sql == "BEGIN IMMEDIATE":
                began.set()
                await asyncio.Event().wait()
            return result

        async def rollback(self):
            rolling_back.set()
            await release.wait()
            await db.rollback()

        def __getattr__(self, name):
            return getattr(db, name)

    store._db = Pause()
    task = asyncio.create_task(store.append("a", 1, [PendingNode(1, "n1", "g")]))
    try:
        with anyio.fail_after(3):
            await began.wait()
            task.cancel()
            await rolling_back.wait()
            task.cancel()
            await asyncio.sleep(0)
            assert not task.done()
            assert store._lock.locked()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert not db.in_transaction
    finally:
        release.set()
        store._db = db
        await store.close()


async def test_failed_rollback_discards_connection(tmp_path: Path) -> None:
    store = SQLiteSequenceStore(str(tmp_path / "sequence.db"))
    await store.open()
    db = store._db

    class Broken:
        async def execute(self, sql, *args):
            await db.execute(sql, *args)
            raise OSError("injected begin acknowledgement failure")

        async def rollback(self):
            raise OSError("injected rollback failure")

        def __getattr__(self, name):
            return getattr(db, name)

    store._db = Broken()
    try:
        with pytest.raises(OSError, match="rollback failure"):
            await store.append("a", 1, [PendingNode(1, "n1", "g")])
        assert store._db is None
        # Explicit recovery opens a new connection, rather than reusing unknown state.
        await store.open()
        await store.append("a", 1, [PendingNode(1, "n1", "g")])
        assert len(await store.entries()) == 1
    finally:
        await store.close()
