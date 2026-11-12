# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""SSE token restoration with the token split at any boundary."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator, Iterable
from typing import Any

import pytest

from aegis.core.evidence_hash import StreamDigestRecorder
from aegis.core.pii_vault import PIIMap, tokenize_text
from aegis.core.text_delta_restore import (
    SseDeltaRestorer,
    TextDeltaRestorer,
    is_terminal_event,
    restoring_delta_stream,
)

try:
    from hypothesis import HealthCheck, given, settings
    from hypothesis import strategies as st

    HAS_HYPOTHESIS = True
except ImportError:  # pragma: no cover
    HAS_HYPOTHESIS = False
    given = None  # type: ignore[assignment]


DNI = "30123456"


def _token_for(mapping: PIIMap) -> str:
    tokenized = tokenize_text(f"DNI: {DNI}", mapping)
    return tokenized.split("DNI: ")[1]


def _chunks(text: str, sizes: Iterable[int]) -> list[str]:
    out: list[str] = []
    position = 0
    for size in sizes:
        if position >= len(text):
            break
        out.append(text[position : position + size])
        position += size
    if position < len(text):
        out.append(text[position:])
    return out


# ── clase TextDeltaRestorer (§27) ───────────────────────────────────────────


def test_feed_restores_complete_token() -> None:
    m = PIIMap()
    token = _token_for(m)
    restorer = TextDeltaRestorer(m)
    assert restorer.feed(f"Su DNI es {token}.") == f"Su DNI es {DNI}."
    assert restorer.pending == ""
    assert restorer.flush() == ""


def test_token_split_at_every_character_boundary() -> None:
    m = PIIMap()
    token = _token_for(m)
    text = f"Su DNI es {token}."
    expected = f"Su DNI es {DNI}."
    for cut in range(len(text) + 1):
        restorer = TextDeltaRestorer(m)
        out = restorer.feed(text[:cut]) + restorer.feed(text[cut:]) + restorer.flush()
        assert out == expected, f"cut={cut}"


def test_token_split_into_single_characters() -> None:
    m = PIIMap()
    token = _token_for(m)
    text = f"a{token}b"
    restorer = TextDeltaRestorer(m)
    out = "".join(restorer.feed(ch) for ch in text) + restorer.flush()
    assert out == f"a{DNI}b"


def test_three_way_split_inside_prefix() -> None:
    m = PIIMap()
    token = _token_for(m)
    text = f"x{token}y"
    restorer = TextDeltaRestorer(m)
    parts = [text[:3], text[3:7], text[7:]]
    out = "".join(restorer.feed(part) for part in parts) + restorer.flush()
    assert out == f"x{DNI}y"


def test_prefix_partial_is_held_not_leaked() -> None:
    """An incomplete prefix is not emitted: it would go out as text and never be restored."""
    m = PIIMap()
    token = m.token_for("EMAIL", "a@b.com")
    restorer = TextDeltaRestorer(m)
    assert restorer.feed(f"hola {token[:5]}") == "hola "
    assert restorer.pending == token[:5]
    assert restorer.feed(token[5:]) == "a@b.com"


def test_flush_releases_a_truncated_prefix_literally() -> None:
    m = PIIMap()
    restorer = TextDeltaRestorer(m)
    assert restorer.feed("texto [[AEGIS:") == "texto "
    assert restorer.flush() == "[[AEGIS:"
    assert restorer.pending == ""


def test_empty_delta_is_a_noop() -> None:
    m = PIIMap()
    restorer = TextDeltaRestorer(m)
    assert restorer.feed("") == ""
    assert restorer.feed("hola") == "hola"
    assert restorer.feed("") == ""
    assert restorer.flush() == ""


def test_unknown_token_is_preserved() -> None:
    m = PIIMap()
    restorer = TextDeltaRestorer(m)
    out = restorer.feed("[[AEGIS:EMAIL:deadbeef00]]") + restorer.flush()
    assert out == "[[AEGIS:EMAIL:deadbeef00]]"


def test_two_tokens_in_one_delta() -> None:
    m = PIIMap()
    first = m.token_for("EMAIL", "a@b.com")
    second = m.token_for("DNI", DNI)
    restorer = TextDeltaRestorer(m)
    assert restorer.feed(f"{first} y {second}") == f"a@b.com y {DNI}"


def test_pending_cap_releases_malformed_prefix() -> None:
    m = PIIMap()
    restorer = TextDeltaRestorer(m, max_pending=16)
    out = restorer.feed("[[AEGIS:" + "x" * 64)
    assert out.startswith("[[AEGIS:")
    assert restorer.pending == ""


def test_negative_cap_is_rejected() -> None:
    with pytest.raises(ValueError):
        TextDeltaRestorer(PIIMap(), max_pending=0)


# ── stream de tuplas (raw, parsed) ──────────────────────────────────────────


def openai_event(payload: dict[str, Any]) -> tuple[bytes, dict[str, Any]]:
    raw = b"data: " + json.dumps(payload, separators=(",", ":")).encode() + b"\n\n"
    return raw, payload


def anthropic_event(
    payload: dict[str, Any], name: str | None = None
) -> tuple[bytes, dict[str, Any]]:
    event_name = name or str(payload.get("type", "message"))
    raw = (
        b"event: "
        + event_name.encode()
        + b"\ndata: "
        + json.dumps(payload, separators=(",", ":")).encode()
        + b"\n\n"
    )
    return raw, payload


async def _collect(source: AsyncIterator[tuple[bytes, Any]]) -> list[tuple[bytes, Any]]:
    return [item async for item in source]


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _content_events(events: list[tuple[bytes, Any]]) -> str:
    out = ""
    for _raw, parsed in events:
        if not isinstance(parsed, dict):
            continue
        if parsed.get("type") == "content_block_delta":
            out += parsed.get("delta", {}).get("text", "")
            continue
        for choice in parsed.get("choices", []):
            out += choice.get("delta", {}).get("content", "")
    return out


def test_stream_restores_token_split_across_events() -> None:
    m = PIIMap()
    token = _token_for(m)
    text = f"Su DNI es {token}."
    for cut in range(len(text) + 1):
        events = [
            openai_event({"choices": [{"index": 0, "delta": {"content": text[:cut]}}]}),
            openai_event({"choices": [{"index": 0, "delta": {"content": text[cut:]}}]}),
            (b"data: [DONE]\n\n", None),
        ]

        async def source(
            events: list[tuple[bytes, Any]] = events,
        ) -> AsyncIterator[tuple[bytes, Any]]:
            for event in events:
                yield event

        out = _run(_collect(restoring_delta_stream(source(), m)))
        assert _content_events(out) == f"Su DNI es {DNI}.", f"cut={cut}"
        assert out[-1][1] is None


def test_stream_restores_openai_tool_arguments() -> None:
    m = PIIMap()
    token = _token_for(m)
    arguments = '{"dni":"' + token + '","nota":"ok"}'
    expected = '{"dni":"' + DNI + '","nota":"ok"}'
    for cut in range(1, len(arguments)):
        events = [
            openai_event(
                {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "tool_calls": [
                                    {"index": 0, "function": {"arguments": arguments[:cut]}}
                                ]
                            },
                        }
                    ]
                }
            ),
            openai_event(
                {
                    "choices": [
                        {
                            "index": 0,
                            "delta": {
                                "tool_calls": [
                                    {"index": 0, "function": {"arguments": arguments[cut:]}}
                                ]
                            },
                        }
                    ]
                }
            ),
            (b"data: [DONE]\n\n", None),
        ]

        async def source(
            events: list[tuple[bytes, Any]] = events,
        ) -> AsyncIterator[tuple[bytes, Any]]:
            for event in events:
                yield event

        out = _run(_collect(restoring_delta_stream(source(), m)))
        restored = "".join(
            tool_call.get("function", {}).get("arguments", "")
            for _raw, parsed in out
            if isinstance(parsed, dict)
            for choice in parsed.get("choices", [])
            for tool_call in choice.get("delta", {}).get("tool_calls", [])
        )
        assert restored == expected, f"cut={cut}"


def test_stream_restores_anthropic_partial_json() -> None:
    m = PIIMap()
    token = _token_for(m)
    fragment = '{"dni": "' + token + '"}'
    expected = '{"dni": "' + DNI + '"}'
    for cut in range(1, len(fragment)):
        events = [
            anthropic_event(
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": fragment[:cut]},
                }
            ),
            anthropic_event(
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": fragment[cut:]},
                }
            ),
            anthropic_event({"type": "message_stop"}, "message_stop"),
        ]

        async def source(
            events: list[tuple[bytes, Any]] = events,
        ) -> AsyncIterator[tuple[bytes, Any]]:
            for event in events:
                yield event

        out = _run(_collect(restoring_delta_stream(source(), m)))
        restored = "".join(
            parsed["delta"].get("partial_json", "")
            for _raw, parsed in out
            if isinstance(parsed, dict) and parsed.get("type") == "content_block_delta"
        )
        assert restored == expected, f"cut={cut}"


def test_non_text_events_are_byte_identical() -> None:
    m = PIIMap()
    ping = (b": keepalive\n\n", None)
    start = openai_event({"id": "x", "choices": [], "usage": {"total_tokens": 0}})

    async def source() -> AsyncIterator[tuple[bytes, Any]]:
        yield ping
        yield start
        yield (b"data: [DONE]\n\n", None)

    out = _run(_collect(restoring_delta_stream(source(), m)))
    assert out[0][0] == ping[0]
    assert out[1][0] == start[0]


def test_terminal_flushes_pending_before_done() -> None:
    """A stream cut inside a token does not lose the pending text."""
    m = PIIMap()
    token = _token_for(m)
    half = token[:9]  # cut inside the kind
    events = [
        openai_event({"choices": [{"index": 0, "delta": {"content": f"DNI: {half}"}}]}),
        (b"data: [DONE]\n\n", None),
    ]

    async def source() -> AsyncIterator[tuple[bytes, Any]]:
        for event in events:
            yield event

    out = _run(_collect(restoring_delta_stream(source(), m)))
    assert out[-1][0] == b"data: [DONE]\n\n"
    # What is left is an incomplete prefix: emitted as is, never lost.
    assert half in _content_events(out)


def test_multiple_streams_do_not_share_buffers() -> None:
    """Content and tool arguments are restored separately."""
    m = PIIMap()
    token = _token_for(m)
    events = [
        openai_event({"choices": [{"index": 0, "delta": {"content": "DNI: [[AEGIS:DN"}}]}),
        openai_event(
            {
                "choices": [
                    {
                        "index": 0,
                        "delta": {"tool_calls": [{"index": 0, "function": {"arguments": token}}]},
                    }
                ]
            }
        ),
        openai_event(
            {"choices": [{"index": 0, "delta": {"content": f"I:{token.split(':')[-1]}"}}]}
        ),
        (b"data: [DONE]\n\n", None),
    ]

    async def source() -> AsyncIterator[tuple[bytes, Any]]:
        for event in events:
            yield event

    out = _run(_collect(restoring_delta_stream(source(), m)))
    content = _content_events(out)
    arguments = "".join(
        tool_call.get("function", {}).get("arguments", "")
        for _raw, parsed in out
        if isinstance(parsed, dict)
        for choice in parsed.get("choices", [])
        for tool_call in choice.get("delta", {}).get("tool_calls", [])
    )
    assert arguments == DNI
    assert content == f"DNI: {DNI}"  # content was closed with its own buffer


def test_digest_recorder_sees_both_sides() -> None:
    m = PIIMap()
    token = _token_for(m)
    recorder = StreamDigestRecorder()
    events = [
        openai_event({"choices": [{"index": 0, "delta": {"content": token}}]}),
        (b"data: [DONE]\n\n", None),
    ]

    async def source() -> AsyncIterator[tuple[bytes, Any]]:
        for event in events:
            yield event

    _run(_collect(restoring_delta_stream(source(), m, recorder)))
    snapshot = recorder.snapshot()
    assert snapshot.restored is True
    assert len(snapshot.upstream_sha256) == 64
    assert len(snapshot.client_sha256) == 64


def test_sse_restorer_event_without_choices_is_unchanged() -> None:
    m = PIIMap()
    restorer = SseDeltaRestorer(m)
    raw = b'data: {"type":"message_delta","delta":{"stop_reason":"end_turn"}}\n\n'
    parsed = {"type": "message_delta", "delta": {"stop_reason": "end_turn"}}
    assert restorer.restore_event(raw, parsed) == (raw, parsed)


def test_is_terminal_event() -> None:
    assert is_terminal_event(b"data: [DONE]\n\n", None) is True
    assert is_terminal_event(b"event: message_stop\ndata: {}\n\n", {"type": "message_stop"}) is True
    assert is_terminal_event(b"data: {}\n\n", {"choices": []}) is False


# ── propiedades ─────────────────────────────────────────────────────────────


@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
@given(
    st.text(max_size=200),
    st.integers(min_value=1, max_value=40),
)
@settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_token_split_across_arbitrary_parts(text: str, parts: int) -> None:
    """Any text, split into `parts` equal pieces, is restored exactly."""
    m = PIIMap()
    tokenized = tokenize_text(f"DNI: {DNI} {text}", m)
    expected = f"DNI: {DNI} {text}"
    size = max(1, len(tokenized) // parts)
    pieces = _chunks(tokenized, [size] * parts)
    restorer = TextDeltaRestorer(m)
    out = "".join(restorer.feed(piece) for piece in pieces) + restorer.flush()
    assert out == expected


@pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")
@given(
    st.text(max_size=120),
    st.lists(st.integers(min_value=1, max_value=7), max_size=60),
)
@settings(max_examples=500, deadline=None, suppress_health_check=[HealthCheck.too_slow])
def test_token_split_at_random_sizes(text: str, sizes: list[int]) -> None:
    m = PIIMap()
    tokenized = tokenize_text(f"{text} DNI: {DNI} fin", m)
    expected = f"{text} DNI: {DNI} fin"
    restorer = TextDeltaRestorer(m)
    out = "".join(restorer.feed(piece) for piece in _chunks(tokenized, sizes))
    out += restorer.flush()
    assert out == expected
