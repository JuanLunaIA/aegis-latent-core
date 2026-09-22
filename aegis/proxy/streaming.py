# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Bounded, cancellation-owned SSE proxy sessions."""

from __future__ import annotations

import asyncio
import copy
import hashlib
import json
import logging
import time
from collections.abc import AsyncIterable, AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Literal

from aegis.core import observability
from aegis.core.stream_bounds import UTF8_MAX_BYTES_PER_CHAR, StreamRetentionBounds
from aegis.core.stream_redactor import (
    ENGINE_GRAMMAR_FRONTIER,
    StreamRedactor,
    build_stream_redactor,
)
from aegis.core.streaming_deidentifier import StreamingDeidentificationError

if TYPE_CHECKING:
    from aegis.proxy.terminal_outbox import TerminalOutbox, TerminalReplayContext

logger = logging.getLogger(__name__)

TerminalOutcome = Literal[
    "complete",
    "client_disconnected",
    "upstream_error",
    "upstream_incomplete",
    "timeout",
    "byte_limit",
    "event_limit",
    "privacy_failure",
    "shutdown_cancelled",
]


class StreamProxyError(RuntimeError):
    """Base class for bounded stream failures."""


class StreamByteLimitError(StreamProxyError):
    """The cumulative canonical response exceeded its configured ceiling."""


class StreamEventLimitError(StreamProxyError):
    """One upstream or canonical SSE event exceeded its configured ceiling."""


@dataclass(frozen=True)
class StreamEvidenceSummary:
    response_hash: str
    response_size: int
    response_preview: bytes
    terminal_outcome: TerminalOutcome
    final_marker_included: bool
    token_count: int
    elapsed_seconds: float
    redaction_hits: dict[str, int]


_DETACHED_TERMINAL_COMMITS: set[asyncio.Task[None]] = set()


def _reap_detached_commit(task: asyncio.Task[None]) -> None:
    """Strong-reference holder for detached commits; logs what they raised."""

    _DETACHED_TERMINAL_COMMITS.discard(task)
    if task.cancelled():
        return
    exc = task.exception()
    if exc is not None:
        logger.error("detached terminal-evidence commit failed", exc_info=exc)


class TerminalCommitHandoff:
    """Run handed-off terminal commits outside the scope that tore the stream down.

    Starlette cancels the response's anyio task group *before* the streaming
    generator observes the disconnect, so a terminal commit awaited from the
    generator's teardown never lands: any await there is re-cancelled, or is
    illegal (``GeneratorExit``) — reproduced first-hand as AUD-03 / REG-D07.

    The app owns one of these, started from its lifespan — a context no
    request scope reaches — and the generator only ever calls the synchronous
    :meth:`submit`, which nothing can cancel.  Commits run one at a time, in
    submission order, so evidence lands in teardown order.

    ``max_pending`` bounds the queue: teardown must not block, so a full queue
    drops the commit, counts it (``dropped``) and logs at error level rather
    than waiting.  ``committed`` and ``dropped`` are exposed for operators and
    tests.
    """

    def __init__(self, *, max_pending: int = 64) -> None:
        if max_pending < 1:
            raise ValueError("max_pending must be positive")
        self._max_pending = max_pending
        self._queue: asyncio.Queue[
            tuple[
                Callable[[StreamEvidenceSummary], Awaitable[None]],
                StreamEvidenceSummary,
                str | None,
            ]
        ] = asyncio.Queue(maxsize=max_pending)
        self._task: asyncio.Task[None] | None = None
        self._committed = 0
        self._dropped = 0
        self._outbox: TerminalOutbox | None = None

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    @property
    def pending(self) -> int:
        return self._queue.qsize()

    @property
    def committed(self) -> int:
        return self._committed

    @property
    def dropped(self) -> int:
        return self._dropped

    def attach_outbox(self, outbox: TerminalOutbox | None) -> None:
        """Spool every handoff that carries a replay context (REG-D32, opt-in)."""

        self._outbox = outbox

    def start(self) -> None:
        """Start the worker.  Call from the app lifespan, outside any request."""

        if self.running:
            return
        self._task = asyncio.create_task(self._drain(), name="aegis-terminal-commit-handoff")

    def for_commit(
        self,
        commit: Callable[[StreamEvidenceSummary], Awaitable[None]],
        replay: TerminalReplayContext | None = None,
    ) -> Callable[[StreamEvidenceSummary], None]:
        """Bind ``commit`` into the synchronous callback a stream hands off to."""

        def handoff(summary: StreamEvidenceSummary) -> None:
            self.submit(commit, summary, replay=replay)

        return handoff

    def submit(
        self,
        commit: Callable[[StreamEvidenceSummary], Awaitable[None]],
        summary: StreamEvidenceSummary,
        *,
        replay: TerminalReplayContext | None = None,
    ) -> bool:
        """Queue one commit.  Synchronous and non-blocking: it cannot be cancelled.

        With an outbox attached and a replay context given, the commit is first
        spooled (one ``write``, no await), so it survives a crash before the
        worker reaches it — and a full queue defers it to the next start
        instead of losing it.
        """

        spool_id = None
        if self._outbox is not None and replay is not None:
            spool_id = self._outbox.record(replay, summary)
        if not self.running:
            # Fallback for a caller that never started the worker (a test or a
            # library user).  The lifespan start is still the right home: this
            # context may be the cancelled scope being torn down.
            logger.warning("terminal-evidence handoff worker was not running; starting it lazily")
            self.start()
        try:
            self._queue.put_nowait((commit, summary, spool_id))
        except asyncio.QueueFull:
            self._dropped += 1
            observability.AUDIT_HANDOFF_DROPPED.inc()
            logger.error(
                "terminal-evidence handoff queue full (max_pending=%d); commit dropped "
                "(outcome=%s, dropped=%d, spooled for the next start=%s)",
                self._max_pending,
                summary.terminal_outcome,
                self._dropped,
                spool_id is not None,
            )
            return False
        return True

    async def stop(self, *, timeout: float) -> None:
        """Drain pending commits (bounded), then stop the worker."""

        if self._task is None:
            return
        try:
            async with asyncio.timeout(timeout):
                await self._queue.join()
        except TimeoutError:
            logger.error(
                "terminal-evidence handoff did not drain within %.1fs; pending=%d",
                timeout,
                self._queue.qsize(),
            )
        finally:
            task, self._task = self._task, None
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def _drain(self) -> None:
        while True:
            commit, summary, spool_id = await self._queue.get()
            outbox = self._outbox if spool_id is not None else None
            try:
                if outbox is not None:
                    # Power-loss durability for the spooled record, before the
                    # commit it stands in for is attempted.
                    await outbox.sync()
                await commit(summary)
            except asyncio.CancelledError:
                self._queue.task_done()
                raise
            except Exception:
                # A spooled record stays pending and is replayed at the next start.
                observability.AUDIT_COMMIT_ERRORS.inc()
                logger.exception(
                    "handed-off terminal commit failed (outcome=%s)", summary.terminal_outcome
                )
            else:
                self._committed += 1
                observability.AUDIT_HANDOFF_COMMITTED.inc()
                if outbox is not None and spool_id is not None:
                    outbox.mark_done(spool_id)
            finally:
                self._queue.task_done()


@dataclass(frozen=True)
class _QueueItem:
    kind: Literal["data", "complete", "error"]
    data: bytes = b""
    outcome: TerminalOutcome = "upstream_error"
    error: BaseException | None = None


class _ByteBoundedQueue:
    def __init__(self, *, max_items: int, max_bytes: int) -> None:
        if max_items < 1 or max_bytes < 1:
            raise ValueError("queue bounds must be positive")
        self._queue: asyncio.Queue[_QueueItem] = asyncio.Queue(maxsize=max_items)
        self._max_bytes = max_bytes
        self._bytes = 0
        self._condition = asyncio.Condition()
        self.peak_items = 0
        self.peak_bytes = 0

    async def put(self, item: _QueueItem) -> None:
        size = len(item.data)
        if size > self._max_bytes:
            raise StreamEventLimitError("one stream item exceeds the queue byte budget")
        async with self._condition:
            await self._condition.wait_for(
                lambda: self._bytes + size <= self._max_bytes and not self._queue.full()
            )
            self._queue.put_nowait(item)
            self._bytes += size
            self.peak_items = max(self.peak_items, self._queue.qsize())
            self.peak_bytes = max(self.peak_bytes, self._bytes)

    async def get(self) -> _QueueItem:
        item = await self._queue.get()
        async with self._condition:
            self._bytes -= len(item.data)
            self._condition.notify_all()
        return item

    @property
    def retained_bytes(self) -> int:
        return self._bytes

    @property
    def max_bytes(self) -> int:
        return self._max_bytes


class StreamAdmissionFullError(Exception):
    """No stream slot was free. The caller must refuse admission, not queue."""


class StreamAdmissionGate:
    """Counts concurrent governed streams in this process and caps them.

    Every individual stream is already bounded — ``R_max = 4W + Q + E + P``,
    about 1.18 MiB by default. What was never bounded is how many of them run
    at once, so aggregate retained bytes scaled with connection count and a
    slow consumer could hold a slot open indefinitely. This is the missing
    multiplicand.

    **Not a rate limiter.** It counts what is *in flight*, so a slot is held
    for the life of the stream and returned when iteration ends — including
    when the client disconnects mid-stream, which is the case a request-rate
    limiter never sees.

    **One process.** Each worker has its own gate, so a deployment with N
    replicas admits up to N x ``limit``. A cluster-wide ceiling would need
    shared state this deliberately does not take: the failure it prevents is
    local memory exhaustion, which is a local property.

    No lock is taken. Admission runs on the event loop thread with no ``await``
    between the test and the increment, so the check-then-act is atomic with
    respect to other coroutines; releases from the same loop are likewise
    serialized. A thread-safe variant would need one, and would buy nothing
    here.
    """

    __slots__ = ("_active", "_limit", "_rejected")

    def __init__(self, limit: int) -> None:
        if limit < 0:
            raise ValueError(f"max_concurrent_streams must be >= 0, got {limit}")
        self._limit = limit
        self._active = 0
        self._rejected = 0

    def acquire(self) -> None:
        """Take a slot, or raise :class:`StreamAdmissionFullError`.

        Fail-closed by construction: there is no blocking variant. Waiting for
        a slot would hold the connection open and convert a memory bound into a
        latency bound, which is the failure this exists to prevent.
        """
        if self._limit and self._active >= self._limit:
            self._rejected += 1
            raise StreamAdmissionFullError(
                f"{self._active} concurrent streams already admitted (limit {self._limit})"
            )
        self._active += 1

    def release(self) -> None:
        """Return a slot. Idempotent below zero: never goes negative."""
        if self._active > 0:
            self._active -= 1

    @property
    def active(self) -> int:
        return self._active

    @property
    def limit(self) -> int:
        return self._limit

    @property
    def rejected(self) -> int:
        """Total admissions refused since construction."""
        return self._rejected


async def guarded_stream(
    stream: AsyncIterable[bytes], gate: StreamAdmissionGate
) -> AsyncIterator[bytes]:
    """Yield from *stream*, returning the gate slot exactly once when it ends.

    The slot cannot be released in the request handler: the handler returns a
    ``StreamingResponse`` and the body is iterated afterwards, so a ``finally``
    there would free the slot before a single byte was sent. Tying it to this
    generator's own ``finally`` covers normal completion, an exception, and the
    ``GeneratorExit``/``CancelledError`` raised when a client disconnects —
    which is the case that matters, since an abandoned stream is exactly what
    would otherwise leak a slot forever.
    """
    try:
        async for chunk in stream:
            yield chunk
    finally:
        gate.release()


class BoundedStreamProxy:
    """Transform an upstream OpenAI SSE iterator under finite resource bounds.

    The terminal callback is invoked at most once.  A successful canonical
    ``[DONE]`` is offered downstream only after that callback returns.
    """

    _DONE = b"data: [DONE]\n\n"

    def __init__(
        self,
        upstream: AsyncIterator[tuple[bytes, Any]],
        *,
        terminal_commit: Callable[[StreamEvidenceSummary], Awaitable[None]],
        terminal_handoff: Callable[[StreamEvidenceSummary], None] | None = None,
        max_response_bytes: int,
        max_duration_seconds: float,
        max_event_bytes: int,
        queue_max_items: int,
        queue_max_bytes: int,
        preview_bytes: int = 65_536,
        deidentifier_window_chars: int = 128,
        enable_phi: bool = False,
        enable_pci: bool = False,
        streaming_engine: str = ENGINE_GRAMMAR_FRONTIER,
        protocol: Literal["openai", "anthropic"] = "openai",
        terminal_predicate: Callable[[bytes, Any], bool] | None = None,
        terminal_marker: bytes = _DONE,
    ) -> None:
        if max_response_bytes < 1 or max_event_bytes < 1 or preview_bytes < 0:
            raise ValueError("stream byte limits must be positive")
        if max_duration_seconds <= 0:
            raise ValueError("max_duration_seconds must be positive")
        self._upstream = upstream
        self._terminal_commit = terminal_commit
        self._terminal_handoff = terminal_handoff
        self._max_response_bytes = max_response_bytes
        self._max_duration_seconds = max_duration_seconds
        self._max_event_bytes = max_event_bytes
        self._preview_limit = preview_bytes
        if protocol not in {"openai", "anthropic"}:
            raise ValueError("unsupported streaming protocol")
        self._protocol = protocol
        self._terminal_predicate = terminal_predicate or (
            lambda raw, _parsed: raw.strip() == b"data: [DONE]"
        )
        self._terminal_marker = terminal_marker
        self._queue = _ByteBoundedQueue(max_items=queue_max_items, max_bytes=queue_max_bytes)
        self._deidentifier: StreamRedactor = build_stream_redactor(
            streaming_engine,
            window_chars=deidentifier_window_chars,
            enable_phi=enable_phi,
            enable_pci=enable_pci,
        )
        self._started = time.perf_counter()
        self._digest = hashlib.sha256()
        self._size = 0
        self._preview = bytearray()
        self._token_count = 0
        self._last_content_template: dict[str, Any] | None = None
        self._producer: asyncio.Task[None] | None = None
        self._finalized = False
        self._frozen_summary: StreamEvidenceSummary | None = None
        self._terminal_dispatched = False
        self._closed = False
        self._upstream_closed = False

    @property
    def retained_bytes(self) -> int:
        return (
            self._queue.retained_bytes
            + self._deidentifier.retained_chars * UTF8_MAX_BYTES_PER_CHAR
            + len(self._preview)
        )

    @property
    def bounds(self) -> StreamRetentionBounds:
        """The declared retained-byte bounds for this stream's configuration.

        Reporting only. Admission is unchanged: the queue enforces ``Q``, the
        event check enforces ``E``, the preview is truncated at ``P``, and the
        redactor enforces ``W``. A configuration outside the ranges
        ``specs/aegis_stream_buffer.smt2`` declares is still accepted here —
        ``AegisSettings`` is what constrains an operator-supplied one — and
        :attr:`StreamRetentionBounds.in_declared_domain` reports that rather
        than raising, so this accessor cannot reject a stream the previous
        release admitted.
        """

        return StreamRetentionBounds(
            window_chars=self._deidentifier.window_chars,
            queue_bytes=self._queue.max_bytes,
            # The queue refuses any single item larger than its whole budget,
            # so the largest event that can actually be retained is the smaller
            # of the two. Taking the minimum is the effective bound, not a
            # convenience to keep the constructor from rejecting the pair.
            event_bytes=min(self._max_event_bytes, self._queue.max_bytes),
            preview_bytes=self._preview_limit,
        )

    @property
    def retained_bytes_ceiling(self) -> int:
        """``R_max = 4W + Q + E + P`` in bytes for this stream."""

        return self.bounds.max_retained_bytes

    @property
    def peak_queue_bytes(self) -> int:
        return self._queue.peak_bytes

    @property
    def peak_queue_items(self) -> int:
        return self._queue.peak_items

    def __aiter__(self) -> AsyncIterator[bytes]:
        return self._iterate()

    async def _iterate(self) -> AsyncIterator[bytes]:
        if self._producer is not None:
            raise RuntimeError("BoundedStreamProxy is single-use")
        self._producer = asyncio.create_task(self._produce(), name="aegis-stream-producer")
        try:
            while True:
                remaining = self._max_duration_seconds - (time.perf_counter() - self._started)
                if remaining <= 0:
                    raise TimeoutError("stream duration exceeded")
                try:
                    item = await asyncio.wait_for(self._queue.get(), timeout=remaining)
                except TimeoutError:
                    await self._cancel_producer()
                    await self._finalize("timeout", final_marker_included=False)
                    return
                if item.kind == "data":
                    self._accumulate(item.data)
                    yield item.data
                    continue
                if item.kind == "error":
                    await self._finalize(item.outcome, final_marker_included=False)
                    return

                tail = self._deidentifier.flush()
                if tail:
                    tail_event = self._encode_tail(tail)
                    self._check_event(tail_event)
                    self._accumulate(tail_event)
                    yield tail_event
                self._check_event(self._terminal_marker)
                self._accumulate(self._terminal_marker)
                try:
                    await self._finalize("complete", final_marker_included=True)
                except Exception:
                    logger.exception("terminal stream evidence commit failed")
                    return
                yield self._terminal_marker
                return
        except asyncio.CancelledError:
            # The teardown this app actually runs (Starlette's collapsing anyio
            # task group, cancelled before the generator observes the
            # disconnect) re-cancels the first await in this handler, so the
            # shielded finalize that used to live here never reached the
            # commit (AUD-03 / REG-D07).  Freeze and hand off synchronously
            # FIRST; the awaits below are best effort only.
            self._handoff_terminal("client_disconnected", final_marker_included=False)
            try:
                await self._cancel_producer()
            except asyncio.CancelledError:
                logger.debug("producer cancellation re-delivered during teardown")
            except Exception:
                logger.exception("producer cancellation failed during teardown")
            raise
        except Exception as exc:
            await self._cancel_producer()
            if isinstance(exc, TimeoutError):
                outcome: TerminalOutcome = "timeout"
            elif isinstance(exc, StreamByteLimitError):
                outcome = "byte_limit"
            elif isinstance(exc, StreamEventLimitError):
                outcome = "event_limit"
            elif isinstance(exc, StreamingDeidentificationError):
                outcome = "privacy_failure"
            else:
                outcome = "upstream_error"
            try:
                await self._finalize(outcome, final_marker_included=False)
            except Exception:
                logger.exception("stream failure terminal commit failed")
            return
        finally:
            await self.aclose()

    async def _produce(self) -> None:
        done = False
        try:
            async with asyncio.timeout(self._max_duration_seconds):
                async for raw, parsed in self._upstream:
                    if len(raw) > self._max_event_bytes:
                        raise StreamEventLimitError("upstream SSE event exceeds configured limit")
                    if self._terminal_predicate(raw, parsed):
                        done = True
                        break
                    for event in self._transform_event(raw, parsed):
                        self._check_event(event)
                        if (
                            self._size + self._queue.retained_bytes + len(event)
                            > self._max_response_bytes
                        ):
                            raise StreamByteLimitError("stream response exceeds configured limit")
                        await self._queue.put(_QueueItem(kind="data", data=event))
            if done:
                await self._queue.put(_QueueItem(kind="complete"))
            else:
                await self._queue.put(_QueueItem(kind="error", outcome="upstream_incomplete"))
        except asyncio.CancelledError:
            raise
        except TimeoutError as exc:
            await self._close_upstream_once()
            await self._queue.put(_QueueItem(kind="error", outcome="timeout", error=exc))
        except StreamByteLimitError as exc:
            await self._close_upstream_once()
            await self._queue.put(_QueueItem(kind="error", outcome="byte_limit", error=exc))
        except StreamEventLimitError as exc:
            await self._close_upstream_once()
            await self._queue.put(_QueueItem(kind="error", outcome="event_limit", error=exc))
        except Exception as exc:
            outcome: TerminalOutcome = (
                "privacy_failure"
                if isinstance(exc, StreamingDeidentificationError)
                else "upstream_error"
            )
            await self._close_upstream_once()
            await self._queue.put(_QueueItem(kind="error", outcome=outcome, error=exc))
        finally:
            await self._close_upstream_once()

    def _transform_event(self, raw: bytes, parsed: Any) -> list[bytes]:
        if not isinstance(parsed, dict):
            return [self._canonical_raw(raw)]
        if self._protocol == "anthropic":
            return self._transform_anthropic_event(parsed)
        payload = copy.deepcopy(parsed)
        choices = payload.get("choices")
        changed = False
        if isinstance(choices, list):
            for choice in choices:
                if not isinstance(choice, dict):
                    continue
                delta = choice.get("delta")
                if not isinstance(delta, dict) or not isinstance(delta.get("content"), str):
                    continue
                self._last_content_template = copy.deepcopy(payload)
                settled = self._deidentifier.feed(delta["content"])
                delta["content"] = settled
                if settled:
                    self._token_count += 1
                changed = True
        usage = payload.get("usage")
        if isinstance(usage, dict) and isinstance(usage.get("completion_tokens"), int):
            self._token_count = max(self._token_count, usage["completion_tokens"])
        if not changed and not raw.strip():
            return []
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        return [b"data: " + encoded + b"\n\n"]

    def _transform_anthropic_event(self, parsed: dict[str, Any]) -> list[bytes]:
        payload = copy.deepcopy(parsed)
        event_type = payload.get("type", "message")
        prefix: list[bytes] = []
        if event_type == "content_block_delta":
            delta = payload.get("delta")
            if isinstance(delta, dict) and isinstance(delta.get("text"), str):
                settled = self._deidentifier.feed(delta["text"])
                delta["text"] = settled
                if settled:
                    self._token_count += 1
        elif event_type == "content_block_start":
            block = payload.get("content_block")
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                settled = self._deidentifier.feed(block["text"])
                block["text"] = settled
                if settled:
                    self._token_count += 1
        elif event_type == "content_block_stop":
            tail = self._deidentifier.flush()
            if tail:
                prefix.append(self._encode_tail(tail))
        usage = payload.get("usage")
        if isinstance(usage, dict) and isinstance(usage.get("output_tokens"), int):
            self._token_count = max(self._token_count, usage["output_tokens"])
        encoded = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
        event_name = event_type if isinstance(event_type, str) else "message"
        prefix.append(
            b"event: "
            + event_name.encode("ascii", errors="replace")
            + b"\n"
            + b"data: "
            + encoded
            + b"\n\n"
        )
        return prefix

    def _encode_tail(self, tail: str) -> bytes:
        if self._protocol == "anthropic":
            anthropic_payload = {
                "type": "content_block_delta",
                "index": 0,
                "delta": {"type": "text_delta", "text": tail},
            }
            self._token_count += 1
            return (
                b"event: content_block_delta\n"
                + b"data: "
                + json.dumps(anthropic_payload, separators=(",", ":"), ensure_ascii=True).encode(
                    "utf-8"
                )
                + b"\n\n"
            )
        if self._last_content_template is None:
            payload: dict[str, Any] = {"choices": [{"index": 0, "delta": {"content": tail}}]}
        else:
            payload = copy.deepcopy(self._last_content_template)
            for choice in payload.get("choices", []):
                if isinstance(choice, dict) and isinstance(choice.get("delta"), dict):
                    choice["delta"]["content"] = tail
                    choice["finish_reason"] = None
            payload.pop("usage", None)
        self._token_count += 1
        return (
            b"data: "
            + json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
            + b"\n\n"
        )

    @staticmethod
    def _canonical_raw(raw: bytes) -> bytes:
        stripped = raw.strip()
        if not stripped:
            return b""
        if stripped.startswith((b"data:", b"event:", b"id:", b"retry:", b":")):
            return stripped + b"\n\n"
        return b"data: " + stripped + b"\n\n"

    def _check_event(self, event: bytes) -> None:
        if len(event) > self._max_event_bytes:
            raise StreamEventLimitError("canonical SSE event exceeds configured limit")

    def _accumulate(self, data: bytes) -> None:
        if self._size + len(data) > self._max_response_bytes:
            raise StreamByteLimitError("canonical response exceeds configured limit")
        self._digest.update(data)
        self._size += len(data)
        remaining = self._preview_limit - len(self._preview)
        if remaining > 0:
            self._preview.extend(data[:remaining])

    def _freeze_summary(
        self, outcome: TerminalOutcome, *, final_marker_included: bool
    ) -> StreamEvidenceSummary | None:
        """Freeze the terminal summary exactly once; synchronous by design.

        The teardown styles the ASGI stack delivers cannot await anything
        before the summary is secured (anyio re-cancels the first await; a
        ``GeneratorExit`` path cannot await at all), so the once-only guard
        must not be an ``asyncio.Lock``: check-and-set with no await between
        the two is atomic on a single event loop.
        """
        if self._finalized:
            return None
        self._finalized = True
        self._frozen_summary = summary = StreamEvidenceSummary(
            response_hash=self._digest.hexdigest(),
            response_size=self._size,
            response_preview=bytes(self._preview),
            terminal_outcome=outcome,
            final_marker_included=final_marker_included,
            token_count=self._token_count,
            elapsed_seconds=time.perf_counter() - self._started,
            redaction_hits=self._deidentifier.stats.entity_hits,
        )
        return summary

    def _handoff_terminal(self, outcome: TerminalOutcome, *, final_marker_included: bool) -> None:
        """Secure the terminal summary and hand the commit off without awaiting.

        Used by the teardown paths (cancellation, ``aclose``/``GeneratorExit``)
        where an await either re-raises immediately or is illegal.  The
        configured handoff runs the commit outside the cancelled scope; with
        no handoff configured, a strongly-referenced detached task is
        scheduled as a best effort — fine for a bare asyncio caller, while the
        ASGI app injects the app-owned handoff instead.
        """
        summary = self._freeze_summary(outcome, final_marker_included=final_marker_included)
        if summary is None:
            # Already frozen: either its commit finished, or an inline commit
            # was interrupted by this very teardown — in which case the frozen
            # summary is dispatched now rather than lost.
            summary = self._frozen_summary
        if summary is None or self._terminal_dispatched:
            return
        self._terminal_dispatched = True
        if self._terminal_handoff is not None:
            try:
                self._terminal_handoff(summary)
            except Exception:
                logger.exception("terminal-evidence handoff failed")
            return
        self._spawn_detached_commit(summary)

    async def _detached_commit(self, summary: StreamEvidenceSummary) -> None:
        await self._terminal_commit(summary)

    def _spawn_detached_commit(self, summary: StreamEvidenceSummary) -> None:
        try:
            task: asyncio.Task[None] = asyncio.get_running_loop().create_task(
                self._detached_commit(summary), name="aegis-terminal-commit-detached"
            )
        except RuntimeError:
            logger.error(
                "terminal evidence dropped (outcome=%s): no running loop to schedule the commit",
                summary.terminal_outcome,
            )
            return
        _DETACHED_TERMINAL_COMMITS.add(task)
        task.add_done_callback(_reap_detached_commit)

    async def _finalize(self, outcome: TerminalOutcome, *, final_marker_included: bool) -> None:
        summary = self._freeze_summary(outcome, final_marker_included=final_marker_included)
        if summary is None:
            return
        await self._terminal_commit(summary)
        # Marked only after the commit returned: an inline commit that a
        # teardown interrupts is retried by the handoff path instead of being
        # dropped.  At-least-once on teardown is the deliberate trade against
        # silently unrecorded disconnects (see REG-D07 / UC-052).
        self._terminal_dispatched = True

    async def _cancel_producer(self) -> None:
        if self._producer is not None and not self._producer.done():
            self._producer.cancel()
            await asyncio.gather(self._producer, return_exceptions=True)

    async def _close_upstream_once(self) -> None:
        if self._upstream_closed:
            return
        self._upstream_closed = True
        close = getattr(self._upstream, "aclose", None)
        if close is not None:
            await close()

    async def aclose(self) -> None:
        if self._closed:
            return
        self._closed = True
        # ``aclose``/``GeneratorExit`` teardown cannot await, and this is the
        # only teardown hook Starlette's abandoned-iterator path gives us, so
        # the terminal evidence is secured and handed off before the producer
        # cancellation below (AUD-03 / REG-D07).
        self._handoff_terminal("client_disconnected", final_marker_included=False)
        await self._cancel_producer()
