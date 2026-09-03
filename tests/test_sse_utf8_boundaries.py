"""tests/test_sse_utf8_boundaries.py — multi-byte UTF-8 across chunk boundaries.

A TCP read can end anywhere, including the middle of a multi-byte UTF-8
character. The concern this file addresses is whether such a split can reach a
``.decode()`` call and either crash the proxy or corrupt a character.

It cannot, and the reason is structural rather than incidental:
``_iter_bounded_lines`` accumulates raw bytes and only yields at ``b"\\n"``
(0x0A). UTF-8 is self-synchronising — every byte of a multi-byte sequence has
its high bit set (0xC2-0xF4 lead, 0x80-0xBF continuation) — so 0x0A can never
occur inside a character. A line boundary is therefore always a character
boundary, and the decode never sees a partial character no matter where the
transport split the stream.

These tests pin that property across every possible split point, so a future
change to the chunking strategy that broke it would fail here rather than in
production. They are the reason the SSE path does not need an incremental
decoder: there is no cross-chunk decode state to carry.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

from __future__ import annotations

from collections.abc import AsyncIterator

import pytest

from aegis.proxy.forwarder import _iter_bounded_lines

# Two-, three- and four-byte characters, plus an astral-plane emoji that is a
# surrogate pair in UTF-16 and four bytes in UTF-8.
MULTIBYTE_TEXT = "café — naïve 日本語 🜲 🙂 Ωμέγα ñ"


class _ChunkedResponse:
    """Minimal stand-in for httpx.Response exposing only aiter_bytes."""

    def __init__(self, payload: bytes, split_at: int) -> None:
        self._chunks = [payload[:split_at], payload[split_at:]]

    async def aiter_bytes(self, chunk_size: int | None = None) -> AsyncIterator[bytes]:
        for chunk in self._chunks:
            if chunk:
                yield chunk


async def _collect(payload: bytes, split_at: int, *, max_line_bytes: int = 65_536) -> list[str]:
    response = _ChunkedResponse(payload, split_at)
    return [
        line.decode("utf-8", errors="replace")
        async for line in _iter_bounded_lines(response, max_line_bytes=max_line_bytes)
    ]


def test_newline_never_occurs_inside_a_multibyte_character() -> None:
    """The structural property the line framing relies on."""
    encoded = MULTIBYTE_TEXT.encode("utf-8")
    multibyte_positions = {index for index, byte in enumerate(encoded) if byte >= 0x80}
    assert multibyte_positions, "fixture must actually contain multi-byte characters"
    assert all(encoded[index] != 0x0A for index in multibyte_positions)


@pytest.mark.asyncio
@pytest.mark.parametrize("split_at", range(1, len(MULTIBYTE_TEXT.encode("utf-8")) + 20))
async def test_multibyte_text_survives_a_split_at_every_byte_offset(split_at: int) -> None:
    """Splitting the transport anywhere must not corrupt a character."""
    payload = f"data: {MULTIBYTE_TEXT}\n".encode()
    if split_at >= len(payload):
        pytest.skip("split point beyond the payload")
    lines = await _collect(payload, split_at)
    assert lines == [f"data: {MULTIBYTE_TEXT}"]
    assert "�" not in lines[0]


@pytest.mark.asyncio
async def test_split_inside_a_four_byte_character_is_rejoined() -> None:
    """The narrow case: a chunk boundary falling between two bytes of one emoji."""
    payload = "data: 🙂\n".encode()
    emoji_start = payload.index("🙂".encode())
    for offset in range(1, 4):
        lines = await _collect(payload, emoji_start + offset)
        assert lines == ["data: 🙂"]


@pytest.mark.asyncio
async def test_multiple_events_split_mid_character_keep_their_framing() -> None:
    """Line framing and character integrity hold together across several events."""
    payload = ("data: 日本語\ndata: café\ndata: [DONE]\n").encode()
    for split_at in range(1, len(payload)):
        lines = await _collect(payload, split_at)
        assert lines == ["data: 日本語", "data: café", "data: [DONE]"]


@pytest.mark.asyncio
async def test_upstream_truncated_mid_character_is_replaced_not_raised() -> None:
    """A genuinely truncated final character degrades, it does not crash.

    This is the case an incremental decoder could not fix either: the bytes
    that would complete the character never arrive.
    """
    payload = "data: 🙂".encode()[:-2]  # unterminated line, truncated emoji
    lines = await _collect(payload, 3)
    assert len(lines) == 1
    assert lines[0].startswith("data: ")
    assert "�" in lines[0]


@pytest.mark.asyncio
async def test_a_multibyte_character_is_never_counted_as_a_line_terminator() -> None:
    """0x8A and 0x0A differ; a continuation byte must not split a line."""
    # U+060A ARABIC-INDIC PER MILLE SIGN encodes as d8 8a — the trailing byte is
    # 0x8A, one bit away from the 0x0A the framing splits on.
    payload = "data: ؊؊؊\n".encode()
    assert b"\x8a" in payload
    for split_at in range(1, len(payload)):
        lines = await _collect(payload, split_at)
        assert lines == ["data: ؊؊؊"]
