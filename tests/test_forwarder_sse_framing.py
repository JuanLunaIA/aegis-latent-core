# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The SSE framer's limits, and the native Anthropic relay's two paths.

`aegis/proxy/forwarder.py` frames upstream server-sent events on raw bytes and
bounds every line, because an upstream that never sends a newline is an upstream
that can make the gateway buffer without limit. The bound is only real if the
refusals fire, and each refusal is a distinct branch: a zero budget, a transport
that exposes neither reader, a line whose terminator arrives past the budget, an
unterminated line, a too-long line from the line-oriented fallback.

The framing is also the reason the SSE path is safe against a split inside a
multi-byte character, so the cross-chunk cases are pinned here too: a CRLF pair
split across two transport reads must still yield a line without the CR, and a
terminator must be found across chunk boundaries.

The second half covers the two native Anthropic relays. Both refuse to run under
a different provider, both consult the circuit breaker, the non-streaming one
consults the egress guard and reports upstream failure, and the streaming one
caps a *whole event* rather than a line — an event assembled from many
in-limit lines is the case a per-line cap alone would miss.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from aegis.config import AegisSettings
from aegis.providers.anthropic_provider import AnthropicAdapter
from aegis.proxy.forwarder import (
    _iter_bounded_lines,
    _native_sse_event,
)
from aegis.proxy.streaming import StreamEventLimitError


def _settings(**kwargs: Any) -> AegisSettings:
    defaults = {
        "backend_api_key": "sk-test",
        "api_keys": "k",
        "provider": "openai",
        "backend_url": "http://127.0.0.1:9",
    }
    defaults.update(kwargs)
    return AegisSettings(**defaults)


class _ChunkedResponse:
    """A response exposing ``aiter_bytes`` and nothing else."""

    def __init__(self, chunks: list[bytes]) -> None:
        self._chunks = chunks

    async def aiter_bytes(self, chunk_size: int | None = None) -> Any:
        for chunk in self._chunks:
            yield chunk


class _LineResponse:
    """A response exposing ``aiter_lines`` and no ``aiter_bytes``."""

    def __init__(self, lines: list[str]) -> None:
        self._lines = lines

    async def aiter_lines(self) -> Any:
        for line in self._lines:
            yield line


class _BareResponse:
    """A response with neither streaming interface."""


async def _collect(response: Any, *, max_line_bytes: int) -> list[bytes]:
    return [line async for line in _iter_bounded_lines(response, max_line_bytes=max_line_bytes)]


class TestLineBudget:
    async def test_a_zero_budget_is_refused(self) -> None:
        with pytest.raises(ValueError, match="max_line_bytes must be positive"):
            await _collect(_ChunkedResponse([b"x\n"]), max_line_bytes=0)

    async def test_a_response_without_a_streaming_interface_is_refused(self) -> None:
        with pytest.raises(TypeError, match="neither aiter_bytes nor aiter_lines"):
            await _collect(_BareResponse(), max_line_bytes=64)

    async def test_a_line_whose_terminator_arrives_past_the_budget_is_refused(self) -> None:
        with pytest.raises(StreamEventLimitError, match="exceeds configured limit"):
            await _collect(_ChunkedResponse([b"x" * 6 + b"\n"]), max_line_bytes=5)

    async def test_a_line_exactly_at_the_budget_is_accepted(self) -> None:
        """The bound is inclusive: five bytes of content under a five-byte budget."""
        assert await _collect(_ChunkedResponse([b"x" * 5 + b"\n"]), max_line_bytes=5) == [b"x" * 5]

    async def test_an_unterminated_line_over_the_budget_is_refused(self) -> None:
        """No newline ever arrives, so the per-chunk check is the only bound."""
        with pytest.raises(StreamEventLimitError, match="unterminated upstream SSE line"):
            await _collect(_ChunkedResponse([b"x" * 7]), max_line_bytes=5)

    async def test_a_terminal_line_without_a_terminator_is_still_yielded(self) -> None:
        assert await _collect(_ChunkedResponse([b"abc"]), max_line_bytes=10) == [b"abc"]

    async def test_the_line_oriented_fallback_is_used_when_only_it_exists(self) -> None:
        assert await _collect(_LineResponse(["first", "second"]), max_line_bytes=64) == [
            b"first",
            b"second",
        ]

    async def test_the_line_oriented_fallback_applies_the_same_budget(self) -> None:
        with pytest.raises(StreamEventLimitError, match="exceeds configured limit"):
            await _collect(_LineResponse(["x" * 6]), max_line_bytes=5)


class TestFramingAcrossChunks:
    async def test_a_crlf_split_across_reads_still_yields_a_bare_line(self) -> None:
        """The CR arrives in one transport read and the LF in the next."""
        assert await _collect(_ChunkedResponse([b"a\r", b"\nb\n"]), max_line_bytes=64) == [
            b"a",
            b"b",
        ]

    async def test_several_lines_in_one_chunk_are_all_yielded(self) -> None:
        assert await _collect(_ChunkedResponse([b"a\nb\nc\n"]), max_line_bytes=64) == [
            b"a",
            b"b",
            b"c",
        ]

    async def test_a_line_split_across_reads_is_reassembled(self) -> None:
        assert await _collect(_ChunkedResponse([b"he", b"llo\n"]), max_line_bytes=64) == [b"hello"]

    async def test_a_blank_line_is_yielded_as_an_empty_line(self) -> None:
        """Event boundaries are blank lines, so an empty line must survive framing."""
        assert await _collect(_ChunkedResponse([b"data: {}\n\n"]), max_line_bytes=64) == [
            b"data: {}",
            b"",
        ]


class TestNativeEventParsing:
    def test_a_data_line_carrying_json_is_parsed(self) -> None:
        raw, parsed = _native_sse_event([b"event: message", b'data: {"type": "content_block"}'])
        assert parsed == {"type": "content_block"}
        assert raw == b'event: message\ndata: {"type": "content_block"}\n\n'

    def test_a_data_line_that_is_not_json_parses_to_none(self) -> None:
        raw, parsed = _native_sse_event([b"data: not-json"])
        assert parsed is None
        assert raw == b"data: not-json\n\n"

    def test_an_event_without_a_data_line_parses_to_none(self) -> None:
        _, parsed = _native_sse_event([b": keep-alive"])
        assert parsed is None

    def test_only_the_first_data_line_is_parsed(self) -> None:
        """Pinned as observed: Anthropic sends one data line per event, and this
        reader takes that line rather than concatenating a multi-line payload the
        provider does not send."""
        _, parsed = _native_sse_event([b'data: {"a": 1}', b'data: {"b": 2}'])
        assert parsed == {"a": 1}


class _FakeResponse:
    def __init__(self, status_code: int) -> None:
        self.status_code = status_code


class _FakePostClient:
    def __init__(self, result: Any) -> None:
        self.calls: list[tuple[str, dict[str, Any], Any]] = []
        self._result = result

    async def post(self, path: str, *, json: dict[str, Any], headers: Any) -> Any:
        self.calls.append((path, json, headers))
        if isinstance(self._result, Exception):
            raise self._result
        return self._result


class _RecordingBreaker:
    def __init__(self) -> None:
        self.failures = 0
        self.successes = 0
        self.checks = 0

    def check(self) -> None:
        self.checks += 1

    def record_failure(self) -> None:
        self.failures += 1

    def record_success(self) -> None:
        self.successes += 1


class _RecordingGuard:
    def __init__(self) -> None:
        self.checked: list[str] = []

    def check(self, url: str) -> None:
        self.checked.append(url)


def _anthropic_forwarder(**kwargs: Any) -> Any:
    from aegis.proxy.forwarder import LLMForwarder

    return LLMForwarder(
        settings=_settings(provider="anthropic"),
        provider=AnthropicAdapter(),
        **kwargs,
    )


class TestNativeAnthropicRelay:
    async def test_a_non_anthropic_provider_is_refused(self) -> None:
        from aegis.proxy.forwarder import LLMForwarder

        forwarder = LLMForwarder(settings=_settings(provider="openai"))
        with pytest.raises(ValueError, match="requires AEGIS_PROVIDER=anthropic"):
            await forwarder.forward_native_anthropic({"model": "m"})

    async def test_the_egress_guard_is_consulted_before_the_upstream_call(self) -> None:
        guard = _RecordingGuard()
        forwarder = _anthropic_forwarder(egress_guard=guard)
        forwarder._client = _FakePostClient(_FakeResponse(200))
        await forwarder.forward_native_anthropic({"model": "m"})
        assert guard.checked == [forwarder._settings.backend_url_str]

    async def test_a_five_hundred_is_recorded_as_an_upstream_failure(self) -> None:
        forwarder = _anthropic_forwarder()
        forwarder._client = _FakePostClient(_FakeResponse(503))
        breaker = _RecordingBreaker()
        forwarder._circuit_breaker = breaker
        response = await forwarder.forward_native_anthropic({"model": "m"})
        assert response.status_code == 503
        assert (breaker.successes, breaker.failures) == (0, 1)

    async def test_a_success_is_recorded_as_a_success(self) -> None:
        forwarder = _anthropic_forwarder()
        forwarder._client = _FakePostClient(_FakeResponse(200))
        breaker = _RecordingBreaker()
        forwarder._circuit_breaker = breaker
        await forwarder.forward_native_anthropic({"model": "m"})
        assert (breaker.successes, breaker.failures) == (1, 0)

    async def test_a_transport_failure_is_recorded_and_re_raised(self) -> None:
        forwarder = _anthropic_forwarder()
        forwarder._client = _FakePostClient(httpx.ConnectError("refused"))
        breaker = _RecordingBreaker()
        forwarder._circuit_breaker = breaker
        with pytest.raises(httpx.ConnectError):
            await forwarder.forward_native_anthropic({"model": "m"})
        assert (breaker.successes, breaker.failures) == (0, 1)


class _StreamingResponse:
    def __init__(self, chunks: list[bytes], status_code: int = 200) -> None:
        self._chunks = chunks
        self.status_code = status_code

    async def aiter_bytes(self, chunk_size: int | None = None) -> Any:
        for chunk in self._chunks:
            yield chunk

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise httpx.HTTPStatusError("boom", request=None, response=None)  # type: ignore[arg-type]


class _FakeStreamClient:
    def __init__(self, response: _StreamingResponse) -> None:
        self._response = response
        self.opened: list[tuple[str, str, Any, Any]] = []

    def stream(self, method: str, path: str, *, json: Any, headers: Any) -> Any:
        self.opened.append((method, path, json, headers))
        response = self._response
        outer = self

        class _Ctx:
            async def __aenter__(self) -> _StreamingResponse:
                return response

            async def __aexit__(self, *exc_info: Any) -> bool:
                return False

        del outer
        return _Ctx()


class TestNativeAnthropicStream:
    async def test_a_non_anthropic_provider_is_refused(self) -> None:
        from aegis.proxy.forwarder import LLMForwarder

        forwarder = LLMForwarder(settings=_settings(provider="openai"))
        with pytest.raises(ValueError, match="requires AEGIS_PROVIDER=anthropic"):
            [event async for event in forwarder.stream_native_anthropic({"model": "m"})]

    async def test_events_are_split_on_blank_lines_and_parsed(self) -> None:
        forwarder = _anthropic_forwarder()
        forwarder._client = _FakeStreamClient(
            _StreamingResponse(
                [
                    b'event: content_block_delta\ndata: {"delta": "a"}\n\n',
                    b'event: content_block_delta\ndata: {"delta": "b"}\n\n',
                ]
            )
        )
        events = [event async for event in forwarder.stream_native_anthropic({"model": "m"})]
        assert [parsed for _raw, parsed in events] == [{"delta": "a"}, {"delta": "b"}]
        assert events[0][0] == b'event: content_block_delta\ndata: {"delta": "a"}\n\n'

    async def test_a_trailing_event_without_a_blank_line_is_still_yielded(self) -> None:
        forwarder = _anthropic_forwarder()
        forwarder._client = _FakeStreamClient(_StreamingResponse([b'data: {"delta": "last"}']))
        events = [event async for event in forwarder.stream_native_anthropic({"model": "m"})]
        assert [parsed for _raw, parsed in events] == [{"delta": "last"}]

    async def test_an_event_assembled_from_many_in_limit_lines_is_capped(self) -> None:
        """The per-line bound cannot see this: every line is small, the event is not."""
        forwarder = _anthropic_forwarder()
        lines = b"".join(b"field: value\n" for _ in range(3))
        forwarder._settings.max_stream_event_bytes = len(lines) - 1
        forwarder._client = _FakeStreamClient(_StreamingResponse([lines + b"\n"]))
        with pytest.raises(StreamEventLimitError, match="event exceeds configured limit"):
            [event async for event in forwarder.stream_native_anthropic({"model": "m"})]


class TestStreamSseEgressGuard:
    async def test_the_guard_is_consulted_before_the_stream_is_opened(self) -> None:
        from aegis.proxy.forwarder import LLMForwarder

        guard = _RecordingGuard()
        forwarder = LLMForwarder(settings=_settings(provider="openai"), egress_guard=guard)
        forwarder._client = _FakeStreamClient(_StreamingResponse([b"data: {}\n\n"]))
        stream = forwarder.stream_sse("/v1/chat/completions", {"model": "m"})
        events = [event async for event in stream]
        assert guard.checked == [forwarder._settings.backend_url_str]
        # The OpenAI passthrough yields per line, and a blank line is yielded as
        # the event boundary it is rather than swallowed.
        assert events[0] == (b"data: {}\n", {})
        assert events[1] == (b"\n", None)
