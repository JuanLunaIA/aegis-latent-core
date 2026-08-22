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
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from typing import Any, Literal

from aegis.core.streaming_deidentifier import (
    StreamingDeidentificationError,
    StreamingDeidentifier,
)

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
        max_response_bytes: int,
        max_duration_seconds: float,
        max_event_bytes: int,
        queue_max_items: int,
        queue_max_bytes: int,
        preview_bytes: int = 65_536,
        deidentifier_window_chars: int = 128,
        enable_phi: bool = False,
        enable_pci: bool = False,
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
        self._deidentifier = StreamingDeidentifier(
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
        self._finalize_lock = asyncio.Lock()
        self._finalized = False
        self._closed = False
        self._upstream_closed = False

    @property
    def retained_bytes(self) -> int:
        return (
            self._queue.retained_bytes + self._deidentifier.retained_chars * 4 + len(self._preview)
        )

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
            await self._cancel_producer()
            try:
                await asyncio.shield(
                    self._finalize("client_disconnected", final_marker_included=False)
                )
            except Exception:
                logger.exception("client-disconnect terminal commit failed")
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

    async def _finalize(self, outcome: TerminalOutcome, *, final_marker_included: bool) -> None:
        async with self._finalize_lock:
            if self._finalized:
                return
            self._finalized = True
            summary = StreamEvidenceSummary(
                response_hash=self._digest.hexdigest(),
                response_size=self._size,
                response_preview=bytes(self._preview),
                terminal_outcome=outcome,
                final_marker_included=final_marker_included,
                token_count=self._token_count,
                elapsed_seconds=time.perf_counter() - self._started,
                redaction_hits=self._deidentifier.stats.entity_hits,
            )
            await self._terminal_commit(summary)

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
        await self._cancel_producer()
