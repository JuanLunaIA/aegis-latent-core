# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
"""Handoff admission must reserve teardown slots and latch evidence failures."""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from aegis.proxy.streaming import TerminalCommitHandoff
from tests.test_terminal_outbox import _context, _open, _summary


async def test_admission_reserves_room_for_all_active_teardowns() -> None:
    entered, release = asyncio.Event(), asyncio.Event()

    async def commit(summary):
        entered.set()
        await release.wait()

    handoff = TerminalCommitHandoff(max_pending=2)
    handoff.start()
    try:
        assert handoff.admission_error(active_streams=1) is None
        assert handoff.admission_error(active_streams=2) is not None
        assert handoff.submit(commit, _summary())
        await entered.wait()
        assert handoff.admission_error(active_streams=1) is not None
        release.set()
        await handoff._queue.join()
        assert handoff.admission_error(active_streams=1) is None
    finally:
        release.set()
        await handoff.stop(timeout=1)


@pytest.mark.parametrize("failure", ["spool", "commit", "overflow"])
async def test_terminal_failure_latches_new_admission(tmp_path: Path, failure: str) -> None:
    release = asyncio.Event()
    outbox = _open(tmp_path / "outbox", max_bytes=1)

    async def commit(summary):
        if failure == "commit":
            raise OSError("injected ledger failure")
        await release.wait()

    handoff = TerminalCommitHandoff(max_pending=1)
    if failure == "spool":
        handoff.attach_outbox(outbox)
    handoff.start()
    try:
        handoff.submit(commit, _summary(), replay=_context())
        if failure == "overflow":
            assert not handoff.submit(commit, _summary())
        release.set()
        await handoff._queue.join()
        assert handoff.admission_error(active_streams=0) is not None
    finally:
        release.set()
        await handoff.stop(timeout=1)
        outbox.close()
