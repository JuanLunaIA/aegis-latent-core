# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The httpx relay path keeps its own bound (AF-077 / REG-D27).

The Rust non-streaming relay reads its upstream body under a cap
(`read_body_bounded`, AUD-12 / REG-D16) and the SSE relay is bounded per line and
cumulatively — but the httpx fallback called `await client.post(...)`, which
buffers the whole body with no declared-length check and no mid-read cap, while
`docs/ROADMAP.md` recorded exactly that gap as open. The gateway then parses the
body and, with a scrubber enabled, holds a second full-size copy across the
durable-evidence gate.

These tests drive a fake streaming client so the bound is exercised without a
socket: over-cap bodies are refused before the response is returned, and under-cap
bodies come back byte-intact.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from aegis.config import AegisSettings
from aegis.proxy.forwarder import LLMForwarder

CAP = 4096


def _settings(**kwargs) -> AegisSettings:
    defaults = {
        "backend_api_key": "sk-test",
        "api_keys": "k",
        "provider": "openai",
        # backend_url (not backend_url_str: the latter is a derived read-only
        # property and passing it is silently ignored).
        "backend_url": "http://127.0.0.1:9",
        "max_stream_response_bytes": CAP,
    }
    defaults.update(kwargs)
    return AegisSettings(**defaults)


class _FakeStream:
    def __init__(self, *, status_code: int, headers: dict[str, str], chunks: list[bytes]):
        self.status_code = status_code
        self.headers = headers
        self._chunks = chunks

    async def aiter_bytes(self):
        for chunk in self._chunks:
            yield chunk


class _FakeStreamContext:
    def __init__(self, stream: _FakeStream):
        self._stream = stream

    async def __aenter__(self) -> _FakeStream:
        return self._stream

    async def __aexit__(self, *exc_info: Any) -> bool:
        return False


class _FakeClient:
    def __init__(self, stream: _FakeStream):
        self._stream = stream

    def stream(self, *args: Any, **kwargs: Any) -> _FakeStreamContext:
        return _FakeStreamContext(self._stream)


def _forwarder(stream: _FakeStream, **settings_kwargs: Any) -> LLMForwarder:
    forwarder = LLMForwarder(settings=_settings(**settings_kwargs))
    forwarder._client = _FakeClient(stream)  # type: ignore[assignment]
    # Force the httpx path: the Rust relay has its own cap and its own tests.
    forwarder._rust_forwarder = None
    return forwarder


async def test_body_over_cap_is_refused_mid_read() -> None:
    stream = _FakeStream(
        status_code=200,
        headers={},
        chunks=[b"x" * 2048, b"y" * 2048, b"z"],  # 4097 bytes total, no Content-Length
    )
    forwarder = _forwarder(stream)

    with pytest.raises(RuntimeError, match="exceeds the configured limit"):
        await forwarder.forward_json("/v1/chat/completions", {"model": "m"})


async def test_declared_length_over_cap_is_refused_before_reading() -> None:
    stream = _FakeStream(status_code=200, headers={"content-length": "999999"}, chunks=[b"x"])
    forwarder = _forwarder(stream)

    with pytest.raises(RuntimeError, match="exceeds the configured limit"):
        await forwarder.forward_json("/v1/chat/completions", {"model": "m"})


async def test_body_under_cap_comes_back_intact() -> None:
    body = b'{"choices": [{"message": {"content": "hello"}}]}'
    stream = _FakeStream(status_code=200, headers={"content-length": str(len(body))}, chunks=[body])
    forwarder = _forwarder(stream)

    response = await forwarder.forward_json("/v1/chat/completions", {"model": "m"})
    assert isinstance(response, httpx.Response)
    assert response.status_code == 200
    assert response.content == body


async def test_the_bound_is_read_at_call_time() -> None:
    """A lowered bound takes effect without rebuilding the forwarder, because the
    cap is read from settings at call time rather than captured at construction."""
    stream = _FakeStream(status_code=200, headers={}, chunks=[b"x" * 2048])
    forwarder = _forwarder(stream, max_stream_response_bytes=1024)

    with pytest.raises(RuntimeError, match="exceeds the configured limit"):
        await forwarder.forward_json("/v1/chat/completions", {"model": "m"})
