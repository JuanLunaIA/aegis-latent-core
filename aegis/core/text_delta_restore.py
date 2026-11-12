"""Restore tokens in SSE without breaking a token split across events.

The whole-event restorer (T2.3) fails when the provider emits ``[[AEGIS:D`` in
one event and ``NI:abc]]`` in the next. ``TextDeltaRestorer`` keeps, per text
stream, the suffix that could still be the start of a token and prepends it to
the next delta, so restoration is exact at any event boundary, not only at
boundaries that fall outside a token.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
from __future__ import annotations

import copy
import json
from collections.abc import AsyncIterator
from typing import Any

from aegis.core.evidence_hash import StreamDigestRecorder
from aegis.core.pii_vault import PREFIX, SUFFIX, PIIMap, restore_text

#: Largest suffix a delta may hold back while waiting for a token to close.
#: A token never exceeds ``MAX_TOKEN_LEN``; this upper bound only stops a
#: malformed stream (an unclosed ``[[AEGIS:``) from holding unbounded memory.
DEFAULT_MAX_PENDING = 65_536

TEXT_FIELDS = frozenset({"content", "text", "reasoning", "reasoning_content"})

_ANTHROPIC_EVENTS = frozenset(
    {
        "content_block_delta",
        "content_block_start",
        "content_block_stop",
        "message_delta",
        "message_start",
        "message_stop",
    }
)


class TextDeltaRestorer:
    """Restore tokens across consecutive text deltas.

    One instance per text stream (a ``content``, a tool's ``arguments``): each
    instance keeps its own buffer. Do not share an instance between two streams
    or their buffers mix.
    """

    def __init__(self, mapping: PIIMap, max_pending: int = DEFAULT_MAX_PENDING) -> None:
        if max_pending < 1:
            raise ValueError("max_pending must be positive")
        self._mapping = mapping
        self._pending = ""
        self._max_pending = max_pending

    @property
    def pending(self) -> str:
        return self._pending

    def feed(self, delta: str) -> str:
        """Add *delta* and return the text that is now safe to emit."""
        if not delta:
            return ""
        buf = self._pending + delta
        cut = len(buf)
        start = buf.rfind(PREFIX)
        if start != -1 and SUFFIX not in buf[start:]:
            # A token is open: hold back from its prefix, not from the end,
            # because the closing marker can arrive in any later delta.
            cut = start
        else:
            # No open token: hold back only a suffix that could still be the
            # start of ``[[AEGIS:``. Without this, a split prefix would leak as
            # text and the token would never be recognised.
            for n in range(min(len(PREFIX) - 1, len(buf)), 0, -1):
                if buf.endswith(PREFIX[:n]):
                    cut = min(cut, len(buf) - n)
                    break
        ready, self._pending = buf[:cut], buf[cut:]
        if len(self._pending) > self._max_pending:
            # Malformed stream (prefix never closed): release it so the buffer
            # cannot grow without bound. The text is emitted as is; there is no
            # value to restore.
            ready, self._pending = ready + self._pending, ""
        return restore_text(ready, self._mapping)

    def flush(self) -> str:
        """Return what is left when the stream closes and empty the buffer."""
        out, self._pending = self._pending, ""
        return restore_text(out, self._mapping)


def _event_name(raw: bytes, payload: dict[str, Any]) -> str:
    marker = b"event: "
    for line in raw.split(b"\n"):
        if line.startswith(marker):
            return line[len(marker) :].strip().decode("ascii", "replace")
    event_type = payload.get("type")
    return event_type if isinstance(event_type, str) else "message"


def _encode_anthropic(payload: dict[str, Any], raw: bytes | None = None) -> bytes:
    name = _event_name(raw, payload) if raw is not None else str(payload.get("type", "message"))
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return b"event: " + name.encode("ascii", "replace") + b"\ndata: " + body + b"\n\n"


def _encode_openai(payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    return b"data: " + body + b"\n\n"


class SseDeltaRestorer:
    """Apply ``TextDeltaRestorer`` to each text stream of an SSE response.

    An SSE stream can carry content and tool arguments at the same time; each is
    an independent stream with its own buffer. Events without text fields are
    returned byte for byte, without re-serialising.
    """

    def __init__(self, mapping: PIIMap, max_pending: int = DEFAULT_MAX_PENDING) -> None:
        self._mapping = mapping
        self._max_pending = max_pending
        self._restorers: dict[str, TextDeltaRestorer] = {}
        self._protocol = "openai"
        self._kinds: dict[str, str] = {}

    def _restorer(self, key: str, kind: str) -> TextDeltaRestorer:
        restorer = self._restorers.get(key)
        if restorer is None:
            restorer = TextDeltaRestorer(self._mapping, max_pending=self._max_pending)
            self._restorers[key] = restorer
            self._kinds[key] = kind
        return restorer

    def _feed(self, key: str, kind: str, text: str) -> str:
        return self._restorer(key, kind).feed(text)

    def restore_event(self, raw: bytes, parsed: Any) -> tuple[bytes, Any]:
        """Restore one ``(raw, parsed)`` event and return the updated pair."""
        if not isinstance(parsed, dict):
            return raw, parsed
        payload = copy.deepcopy(parsed)
        changed = False
        event_type = payload.get("type")

        if event_type in _ANTHROPIC_EVENTS:
            self._protocol = "anthropic"
            changed = self._restore_anthropic(payload)
        else:
            changed = self._restore_openai(payload)

        if not changed:
            return raw, parsed
        if self._protocol == "anthropic":
            return _encode_anthropic(payload, raw), payload
        return _encode_openai(payload), payload

    def _restore_openai(self, payload: dict[str, Any]) -> bool:
        changed = False
        choices = payload.get("choices")
        if not isinstance(choices, list):
            return False
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            index = choice.get("index", 0)
            delta = choice.get("delta")
            if isinstance(delta, dict):
                if isinstance(delta.get("content"), str):
                    delta["content"] = self._feed(f"content:{index}", "text", delta["content"])
                    changed = True
                tool_calls = delta.get("tool_calls")
                if isinstance(tool_calls, list):
                    for position, tool_call in enumerate(tool_calls):
                        if not isinstance(tool_call, dict):
                            continue
                        function = tool_call.get("function")
                        if isinstance(function, dict) and isinstance(
                            function.get("arguments"), str
                        ):
                            tool_index = tool_call.get("index", position)
                            function["arguments"] = self._feed(
                                f"arguments:{index}:{tool_index}",
                                "arguments",
                                function["arguments"],
                            )
                            changed = True
            # Legacy /v1/completions endpoint in stream mode.
            if isinstance(choice.get("text"), str) and "delta" not in choice:
                choice["text"] = self._feed(f"text:{index}", "text", choice["text"])
                changed = True
        return changed

    def _restore_anthropic(self, payload: dict[str, Any]) -> bool:
        index = payload.get("index", 0)
        changed = False
        if payload.get("type") == "content_block_delta":
            delta = payload.get("delta")
            if not isinstance(delta, dict):
                return False
            if isinstance(delta.get("text"), str):
                delta["text"] = self._feed(f"content:{index}", "text", delta["text"])
                changed = True
            if isinstance(delta.get("partial_json"), str):
                delta["partial_json"] = self._feed(
                    f"partial_json:{index}", "partial_json", delta["partial_json"]
                )
                changed = True
            if isinstance(delta.get("thinking"), str):
                delta["thinking"] = self._feed(f"thinking:{index}", "thinking", delta["thinking"])
                changed = True
        elif payload.get("type") == "content_block_start":
            block = payload.get("content_block")
            if isinstance(block, dict) and isinstance(block.get("text"), str):
                block["text"] = self._feed(f"content:{index}", "text", block["text"])
                changed = True
        return changed

    def flush_events(self) -> list[tuple[bytes, dict[str, Any]]]:
        """Emit what is left of each stream, shaped for the protocol in use."""
        events: list[tuple[bytes, dict[str, Any]]] = []
        for key, restorer in self._restorers.items():
            text = restorer.flush()
            if not text:
                continue
            kind = self._kinds.get(key, "text")
            parts = key.split(":")
            if self._protocol == "anthropic":
                index = int(parts[-1]) if parts[-1].isdigit() else 0
                payload = self._anthropic_flush_payload(kind, index, text)
                raw = _encode_anthropic(payload)
            else:
                payload = self._openai_flush_payload(kind, parts, text)
                raw = _encode_openai(payload)
            events.append((raw, payload))
        return events

    @staticmethod
    def _openai_flush_payload(kind: str, parts: list[str], text: str) -> dict[str, Any]:
        index = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 0
        if kind == "arguments":
            tool_index = int(parts[2]) if len(parts) > 2 and parts[2].isdigit() else 0
            return {
                "choices": [
                    {
                        "index": index,
                        "delta": {
                            "tool_calls": [
                                {
                                    "index": tool_index,
                                    "function": {"arguments": text},
                                }
                            ]
                        },
                    }
                ]
            }
        return {"choices": [{"index": index, "delta": {"content": text}}]}

    @staticmethod
    def _anthropic_flush_payload(kind: str, index: int, text: str) -> dict[str, Any]:
        if kind == "partial_json":
            delta = {"type": "input_json_delta", "partial_json": text}
        elif kind == "thinking":
            delta = {"type": "thinking_delta", "thinking": text}
        else:
            delta = {"type": "text_delta", "text": text}
        return {"type": "content_block_delta", "index": index, "delta": delta}


def is_terminal_event(raw: bytes, parsed: Any) -> bool:
    """``data: [DONE]`` or ``message_stop``: the stream emits no more content."""
    if raw.strip() == b"data: [DONE]":
        return True
    return isinstance(parsed, dict) and parsed.get("type") == "message_stop"


async def restoring_delta_stream(
    source: AsyncIterator[tuple[bytes, Any]],
    mapping: PIIMap,
    digests: StreamDigestRecorder | None = None,
) -> AsyncIterator[tuple[bytes, Any]]:
    """Wrap an SSE ``(raw, parsed)`` stream, restoring tokens.

    What is left is emitted just before the terminal event, so the consumer
    (``BoundedStreamProxy``) counts it as content and not as bytes after close.
    """
    restorer = SseDeltaRestorer(mapping)
    async for raw, parsed in source:
        if digests is not None:
            digests.update_upstream(raw)
        if is_terminal_event(raw, parsed):
            for flush_raw, flush_parsed in restorer.flush_events():
                if digests is not None:
                    digests.update_client(flush_raw)
                yield flush_raw, flush_parsed
            out_raw, out_parsed = raw, parsed
        else:
            out_raw, out_parsed = restorer.restore_event(raw, parsed)
        if digests is not None:
            digests.update_client(out_raw)
        yield out_raw, out_parsed


__all__ = [
    "DEFAULT_MAX_PENDING",
    "SseDeltaRestorer",
    "TEXT_FIELDS",
    "TextDeltaRestorer",
    "is_terminal_event",
    "restoring_delta_stream",
]
