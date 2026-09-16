"""
tests/test_stream_admission_gate.py — the bound on how many bounded streams run.

Each governed SSE stream already has a finite retained-byte ceiling
(``R_max = 4W + Q + E + P``). What had no ceiling was the number of them: a
client opening streams and reading slowly held every one of those ceilings live
at once, so aggregate memory scaled with connection count.

Two properties have to hold together, and the second is the one that is easy to
get wrong:

* over the limit, admission is *refused* rather than queued — waiting for a slot
  would trade a memory bound for a latency bound;
* a slot is returned when the stream ends **however** it ends, including the
  client vanishing mid-stream, because an abandoned stream is exactly what would
  otherwise leak a slot permanently.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from aegis.proxy.streaming import (
    StreamAdmissionFullError,
    StreamAdmissionGate,
    guarded_stream,
)


async def _chunks(*values: bytes) -> AsyncIterator[bytes]:
    for value in values:
        yield value


async def _explodes() -> AsyncIterator[bytes]:
    yield b"first"
    raise RuntimeError("upstream died mid-stream")


def test_admission_is_refused_at_the_limit_not_queued() -> None:
    gate = StreamAdmissionGate(limit=2)
    gate.acquire()
    gate.acquire()
    assert gate.active == 2
    with pytest.raises(StreamAdmissionFullError) as excinfo:
        gate.acquire()
    # The message has to name both numbers: an operator reading one 429 in a log
    # needs to know whether the ceiling is wrong or the traffic is.
    assert "2 concurrent streams" in str(excinfo.value)
    assert "limit 2" in str(excinfo.value)
    assert gate.rejected == 1
    assert gate.active == 2, "a refused acquire must not consume a slot"


def test_zero_limit_disables_the_ceiling() -> None:
    gate = StreamAdmissionGate(limit=0)
    for _ in range(500):
        gate.acquire()
    assert gate.active == 500
    assert gate.rejected == 0


def test_negative_limit_is_rejected_at_construction() -> None:
    with pytest.raises(ValueError, match="max_concurrent_streams must be >= 0"):
        StreamAdmissionGate(limit=-1)


def test_release_never_goes_negative() -> None:
    gate = StreamAdmissionGate(limit=4)
    gate.release()
    gate.release()
    assert gate.active == 0
    gate.acquire()
    assert gate.active == 1


@pytest.mark.asyncio
async def test_slot_is_returned_after_a_stream_completes() -> None:
    gate = StreamAdmissionGate(limit=1)
    gate.acquire()
    collected = [chunk async for chunk in guarded_stream(_chunks(b"a", b"b"), gate)]
    assert collected == [b"a", b"b"]
    assert gate.active == 0, "a completed stream must return its slot"
    gate.acquire()  # the freed slot is reusable


@pytest.mark.asyncio
async def test_slot_is_returned_when_the_stream_raises() -> None:
    gate = StreamAdmissionGate(limit=1)
    gate.acquire()
    with pytest.raises(RuntimeError, match="upstream died mid-stream"):
        async for _ in guarded_stream(_explodes(), gate):
            pass
    assert gate.active == 0, "a failed stream must still return its slot"


@pytest.mark.asyncio
async def test_slot_is_returned_when_the_client_disconnects_mid_stream() -> None:
    """The case a request-rate limiter never sees, and the one that leaks.

    Abandoning the generator without exhausting it is what a disconnecting
    client does. Closing it raises ``GeneratorExit`` inside ``guarded_stream``,
    which its ``finally`` must still honour.
    """
    gate = StreamAdmissionGate(limit=1)
    gate.acquire()
    stream = guarded_stream(_chunks(b"a", b"b", b"c"), gate)
    assert await stream.__anext__() == b"a"
    assert gate.active == 1, "the slot is held for the life of the stream"
    await stream.aclose()
    assert gate.active == 0, "an abandoned stream must not leak its slot"


@pytest.mark.asyncio
async def test_saturation_then_drain_readmits() -> None:
    """End to end: fill the gate, get refused, drain one, get admitted."""
    gate = StreamAdmissionGate(limit=2)
    first = guarded_stream(_chunks(b"x"), gate)
    second = guarded_stream(_chunks(b"y"), gate)
    gate.acquire()
    gate.acquire()
    with pytest.raises(StreamAdmissionFullError):
        gate.acquire()

    assert [c async for c in first] == [b"x"]
    gate.acquire()  # the drained slot is free again
    assert gate.active == 2

    assert [c async for c in second] == [b"y"]
    assert gate.active == 1
