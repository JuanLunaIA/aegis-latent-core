# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
"""Sequencer lifecycle and contradictory notification regressions."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from aegis.core.ha import GlobalSequencer, SQLiteSequenceStore


def node(value: str, previous: str = "0" * 64):
    return SimpleNamespace(node_hash=value, prev_hash=previous, timestamp=0.0)


async def test_stopped_listener_does_not_keep_collecting(tmp_path: Path) -> None:
    store = SQLiteSequenceStore(str(tmp_path / "sequence.db"))
    sequencer = GlobalSequencer(store, "a", lambda: 1, max_lag_seconds=30)
    await sequencer.start(lambda: [])
    await sequencer.stop()
    for index in range(100):
        sequencer.notify(node(str(index), str(index - 1)))
    assert sequencer.status()["backlog"] == 0
    assert sequencer.admission_error() is not None


async def test_backfill_failure_closes_open_store(tmp_path: Path) -> None:
    store = SQLiteSequenceStore(str(tmp_path / "sequence.db"))
    sequencer = GlobalSequencer(store, "a", lambda: 1, max_lag_seconds=30)

    def broken_wal():
        raise OSError("injected WAL read failure")

    try:
        with pytest.raises(OSError, match="WAL read failure"):
            await sequencer.start(broken_wal)
        assert store._db is None
        assert sequencer.admission_error() is not None
    finally:
        await sequencer.stop()


def test_conflicting_notifications_are_not_silently_overwritten(tmp_path: Path) -> None:
    sequencer = GlobalSequencer(
        SQLiteSequenceStore(str(tmp_path / "sequence.db")),
        "a",
        lambda: 1,
        max_lag_seconds=30,
    )
    first = node("one")
    sequencer.notify(first)
    sequencer.notify(node("two"))
    assert sequencer.status()["diverged"]
    assert sequencer._pending[first.prev_hash][0] == "one"
