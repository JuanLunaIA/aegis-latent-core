# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""REG-D07 — terminal evidence lands on every teardown style the ASGI stack delivers.

The v5.0.1-prep audit reproduced the defect first-hand: on a real-app
send-failure (Starlette's collapsing anyio task group, cancelled before the
generator observes the disconnect) the first await inside the
``CancelledError`` handler was re-cancelled, so the shielded ``_finalize``
never ran and ``wal_terminal_nodes`` was 0 while the response advertised
``X-Aegis-Evidence-Status: pending-terminal``.  ``aclose()``/``GeneratorExit``
teardown wrote no terminal node either.

These tests pin the fixed contract: teardown freezes the summary and hands the
commit off *synchronously* (nothing the cancellation can reach), the
app-owned :class:`TerminalCommitHandoff` runs it outside the cancelled scope,
the ``complete`` path still commits inline before the terminal marker is
offered downstream, and an inline commit interrupted by teardown is
re-dispatched rather than dropped.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from typing import Any

import anyio
import pytest

from aegis.proxy.streaming import (
    BoundedStreamProxy,
    StreamEvidenceSummary,
    TerminalCommitHandoff,
)


class _FakeUpstream:
    """Async iterator of ``(raw, parsed)`` SSE tuples; counts closures."""

    def __init__(self, *, chunks: int = 1000, interval: float = 0.01) -> None:
        self.closed = 0
        self._chunks = chunks
        self._interval = interval
        self._agen = self._gen()

    def __aiter__(self) -> _FakeUpstream:
        return self

    def __anext__(self) -> Any:
        return self._agen.__anext__()

    async def _gen(self) -> AsyncIterator[tuple[bytes, Any]]:
        for index in range(self._chunks):
            payload = b'data: {"choices":[{"delta":{"content":"chunk%d"}}]}\n' % index
            yield (payload, {"choices": [{"delta": {"content": f"chunk{index}"}}]})
            await asyncio.sleep(self._interval)
        yield (b"data: [DONE]\n", None)

    async def aclose(self) -> None:
        self.closed += 1


def _summary(index: int = 0, outcome: str = "complete") -> StreamEvidenceSummary:
    return StreamEvidenceSummary(
        response_hash="0" * 64,
        response_size=index,
        response_preview=b"",
        terminal_outcome=outcome,  # type: ignore[arg-type]
        final_marker_included=False,
        token_count=0,
        elapsed_seconds=0.0,
        redaction_hits={},
    )


def _build(
    commits: list[StreamEvidenceSummary],
    *,
    handed: list[StreamEvidenceSummary] | None = None,
    terminal_commit: Any = None,
    upstream: Any = None,
) -> BoundedStreamProxy:
    async def default_commit(summary: StreamEvidenceSummary) -> None:
        commits.append(summary)

    kwargs: dict[str, Any] = {}
    if handed is not None:
        kwargs["terminal_handoff"] = handed.append
    return BoundedStreamProxy(
        upstream if upstream is not None else _FakeUpstream(),
        terminal_commit=terminal_commit if terminal_commit is not None else default_commit,
        max_response_bytes=1 << 20,
        max_duration_seconds=30.0,
        max_event_bytes=4096,
        queue_max_items=8,
        queue_max_bytes=1 << 16,
        **kwargs,
    )


# ── T1: aclose() / GeneratorExit teardown ─────────────────────────────────────


async def test_aclose_teardown_hands_off_terminal_evidence():
    commits: list[StreamEvidenceSummary] = []
    handed: list[StreamEvidenceSummary] = []
    proxy = _build(commits, handed=handed)

    agen = proxy.__aiter__()
    await agen.__anext__()
    # The concrete async generator has aclose(); the AsyncIterator ABC does not
    # declare it.
    await agen.aclose()  # type: ignore[attr-defined]

    assert [summary.terminal_outcome for summary in handed] == ["client_disconnected"]
    assert commits == []  # the handoff owns the commit; the proxy does not run it

    await agen.aclose()  # type: ignore[attr-defined]  # idempotent
    assert len(handed) == 1


# ── T2: cancellation delivered to a bare asyncio task ─────────────────────────


async def test_asyncio_cancel_teardown_hands_off_terminal_evidence():
    commits: list[StreamEvidenceSummary] = []
    handed: list[StreamEvidenceSummary] = []
    proxy = _build(commits, handed=handed)

    async def consume() -> None:
        async for _chunk in proxy:
            pass

    task = asyncio.create_task(consume())
    await asyncio.sleep(0.05)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert [summary.terminal_outcome for summary in handed] == ["client_disconnected"]
    assert len(handed) == 1


# ── T3: the complete path commits inline and hands nothing off ────────────────


async def test_complete_stream_commits_inline_without_handoff():
    commits: list[StreamEvidenceSummary] = []
    handed: list[StreamEvidenceSummary] = []
    proxy = _build(commits, handed=handed, upstream=_FakeUpstream(chunks=3, interval=0.001))

    chunks = [chunk async for chunk in proxy]

    assert chunks[-1] == b"data: [DONE]\n\n"
    assert [summary.terminal_outcome for summary in commits] == ["complete"]
    assert commits[0].final_marker_included is True
    assert handed == []


# ── the ASGI shape itself: an anyio task group cancelled before the generator ─


async def test_anyio_cancelled_scope_lands_evidence_through_the_handoff():
    """Starlette cancels the response's anyio task group; evidence must survive.

    This is the regression test for the reproduced defect: with the pre-fix
    code the generator's shielded finalize was never reached and no terminal
    node was written.
    """

    handoff = TerminalCommitHandoff()
    handoff.start()  # what the app lifespan does: outside any request scope

    commits: list[StreamEvidenceSummary] = []

    async def commit(summary: StreamEvidenceSummary) -> None:
        commits.append(summary)

    proxy = BoundedStreamProxy(
        _FakeUpstream(interval=0.001),
        terminal_commit=commit,
        terminal_handoff=handoff.for_commit(commit),
        max_response_bytes=1 << 20,
        max_duration_seconds=30.0,
        max_event_bytes=4096,
        queue_max_items=8,
        queue_max_bytes=1 << 16,
    )

    async with anyio.create_task_group() as task_group:

        async def consume() -> None:
            async for _chunk in proxy:
                pass

        task_group.start_soon(consume)
        await anyio.sleep(0.05)
        task_group.cancel_scope.cancel()  # what the disconnect delivers

    await handoff.stop(timeout=5.0)

    assert [summary.terminal_outcome for summary in commits] == ["client_disconnected"]
    assert handoff.committed == 1
    assert handoff.running is False


# ── handoff bounds, counters, drain ───────────────────────────────────────────


async def test_handoff_queue_is_bounded_and_counts_drops():
    gate = asyncio.Event()
    commits: list[StreamEvidenceSummary] = []

    async def slow_commit(summary: StreamEvidenceSummary) -> None:
        await gate.wait()
        commits.append(summary)

    handoff = TerminalCommitHandoff(max_pending=1)
    handoff.start()

    assert handoff.submit(slow_commit, _summary(0)) is True
    while handoff.pending:  # let the worker pick the first one up
        await asyncio.sleep(0.005)
    assert handoff.submit(slow_commit, _summary(1)) is True
    assert handoff.submit(slow_commit, _summary(2)) is False  # queue full
    assert handoff.dropped == 1

    gate.set()
    await handoff.stop(timeout=5.0)

    assert [summary.response_size for summary in commits] == [0, 1]
    assert handoff.committed == 2


async def test_handoff_stop_drains_pending_then_stops_the_worker():
    commits: list[StreamEvidenceSummary] = []
    handoff = TerminalCommitHandoff()
    handoff.start()

    async def commit(summary: StreamEvidenceSummary) -> None:
        commits.append(summary)

    for index in range(3):
        assert handoff.submit(commit, _summary(index)) is True

    await handoff.stop(timeout=5.0)

    assert [summary.response_size for summary in commits] == [0, 1, 2]
    assert handoff.running is False


# ── best effort for callers that inject no handoff (library use, tests) ───────


async def test_detached_commit_runs_without_a_handoff():
    commits: list[StreamEvidenceSummary] = []
    proxy = _build(commits)

    agen = proxy.__aiter__()
    await agen.__anext__()
    await agen.aclose()  # type: ignore[attr-defined]

    for _ in range(100):
        if commits:
            break
        await asyncio.sleep(0.01)

    assert [summary.terminal_outcome for summary in commits] == ["client_disconnected"]


# ── an inline commit interrupted by teardown is re-dispatched, not dropped ────


async def test_interrupted_inline_commit_is_dispatched_by_teardown():
    started = asyncio.Event()

    async def hanging_commit(summary: StreamEvidenceSummary) -> None:
        started.set()
        await asyncio.sleep(30)

    handed: list[StreamEvidenceSummary] = []
    proxy = _build(
        [],
        handed=handed,
        terminal_commit=hanging_commit,
        upstream=_FakeUpstream(chunks=3, interval=0.001),
    )

    async def consume() -> None:
        async for _chunk in proxy:
            pass

    task = asyncio.create_task(consume())
    await asyncio.wait_for(started.wait(), timeout=5.0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    # The frozen summary of the interrupted commit is what gets dispatched: the
    # teardown does not silently drop it, and it does not freeze a second one.
    assert len(handed) == 1
    assert handed[0].terminal_outcome == "complete"
