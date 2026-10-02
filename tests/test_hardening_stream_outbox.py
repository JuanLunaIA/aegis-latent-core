# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
"""Fault injection at outbox descriptor and handoff accounting boundaries."""
from __future__ import annotations

import asyncio
import os
from pathlib import Path

from aegis.proxy.streaming import TerminalCommitHandoff
from tests.test_terminal_outbox import _context, _open, _summary


async def test_cancelled_handoff_retires_queue_item_once() -> None:
    entered = asyncio.Event()

    async def commit(summary):
        entered.set()
        await asyncio.Event().wait()

    handoff = TerminalCommitHandoff()
    handoff.start()
    task = handoff._task
    try:
        assert handoff.submit(commit, _summary())
        await asyncio.wait_for(entered.wait(), 2)
        await handoff.stop(timeout=0.01)
        assert task.cancelled(), repr(task.exception())
        assert handoff._queue._unfinished_tasks == 0
    finally:
        if handoff.running:
            await handoff.stop(timeout=0.01)


def test_short_write_does_not_poison_next_record(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "outbox"
    outbox = _open(path)
    original = os.write
    fd = outbox._fd
    shortened = False

    def short_once(target, data):
        nonlocal shortened
        if target == fd and not shortened:
            shortened = True
            return original(target, data[:20])
        return original(target, data)

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr(os, "write", short_once)
            assert outbox.record(_context("first"), _summary()) is None
        assert outbox.record(_context("second"), _summary()) is not None
    finally:
        outbox.close()
    reopened = _open(path)
    try:
        assert [entry.context.state_id for entry in reopened.pending_entries()] == ["second"]
    finally:
        reopened.close()


def test_compaction_directory_failure_does_not_write_unlinked_inode(tmp_path: Path, monkeypatch) -> None:
    path = tmp_path / "outbox"
    outbox = _open(path)
    assert outbox.record(_context("before"), _summary())

    def fail(directory):
        raise OSError("injected directory fsync failure after replace")

    try:
        with monkeypatch.context() as patcher:
            patcher.setattr("aegis.proxy.terminal_outbox._fsync_directory", fail)
            outbox.compact()
        assert outbox.record(_context("after"), _summary())
        assert os.fstat(outbox._fd).st_ino == path.stat().st_ino
    finally:
        outbox.close()
    reopened = _open(path)
    try:
        assert {entry.context.state_id for entry in reopened.pending_entries()} == {"before", "after"}
    finally:
        reopened.close()


def test_one_record_cannot_exceed_spool_byte_budget(tmp_path: Path) -> None:
    path = tmp_path / "outbox"
    outbox = _open(path, max_bytes=32)
    try:
        assert outbox.record(_context(), _summary()) is None
        assert path.stat().st_size <= 32
    finally:
        outbox.close()
