# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""The gateway sends each provider the URL that provider actually serves (REG-D79).

Found by the container smoke test (``scripts/container_smoke_test.py``): with
``AEGIS_BACKEND_URL=https://llm.internal.example/v1``, exactly as
``.env.example`` and ``DEPLOYMENT_GUIDE.md`` instruct, the gateway called
``…/v1/v1/chat/completions``. The client's path already carries the ``/v1``
root and httpx appends it to the base URL's path, so every base URL with a path
doubled it — including the OpenRouter adapter's built-in default
(``https://openrouter.ai/api/v1``) and the Gemini adapter's
(``…/v1beta/openai``), which could therefore never reach their own endpoints.
Only a bare-origin OpenAI URL worked. The provider tests checked
``base_url_override`` and never the final URL, which is how it survived.

The rule now matches an OpenAI SDK's ``base_url``: a bare origin takes the
client path as is; a base URL with a path is the API root, and the client's
leading ``/v1`` is not repeated.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from aegis.config import AegisSettings
from aegis.providers.anthropic_provider import AnthropicAdapter
from aegis.providers.base import ProviderAdapter
from aegis.providers.gemini_provider import GeminiAdapter
from aegis.providers.openai_provider import OpenAIAdapter, OpenRouterAdapter
from aegis.proxy.forwarder import LLMForwarder

OPENAI_BODY = {
    "id": "chatcmpl-x",
    "object": "chat.completion",
    "created": 1,
    "model": "m",
    "choices": [
        {"index": 0, "message": {"role": "assistant", "content": "ok"}, "finish_reason": "stop"}
    ],
    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
}
ANTHROPIC_BODY = {
    "id": "msg_x",
    "type": "message",
    "role": "assistant",
    "model": "m",
    "content": [{"type": "text", "text": "ok"}],
    "stop_reason": "end_turn",
    "usage": {"input_tokens": 1, "output_tokens": 1},
}


def _forwarder(
    backend_url: str, provider: ProviderAdapter, seen: list[str], body: dict[str, Any]
) -> LLMForwarder:
    settings = AegisSettings(backend_api_key="sk-test", backend_url=backend_url)
    forwarder = LLMForwarder(settings, provider=provider)

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return httpx.Response(200, json=body)

    base = provider.base_url_override or settings.backend_url_str
    forwarder._client = httpx.AsyncClient(base_url=base, transport=httpx.MockTransport(handler))
    return forwarder


CASES = [
    # (provider, AEGIS_BACKEND_URL, expected upstream URL)
    (OpenAIAdapter(), "https://api.openai.com", "https://api.openai.com/v1/chat/completions"),
    (
        OpenAIAdapter(),
        "https://llm.internal.example/v1",
        "https://llm.internal.example/v1/chat/completions",
    ),
    (
        OpenAIAdapter(),
        "https://gateway.example/team-a/v1/",
        "https://gateway.example/team-a/v1/chat/completions",
    ),
    (
        OpenRouterAdapter(),
        "https://ignored.example",
        "https://openrouter.ai/api/v1/chat/completions",
    ),
    (
        GeminiAdapter(),
        "https://ignored.example",
        "https://generativelanguage.googleapis.com/v1beta/openai/chat/completions",
    ),
]


@pytest.mark.parametrize(("provider", "backend_url", "expected"), CASES)
async def test_a_completion_reaches_the_providers_real_endpoint(
    provider: ProviderAdapter, backend_url: str, expected: str
) -> None:
    seen: list[str] = []
    forwarder = _forwarder(backend_url, provider, seen, OPENAI_BODY)
    response = await forwarder.forward_json("/v1/chat/completions", {"model": "m", "messages": []})
    assert response.status_code == 200
    assert seen == [expected]


async def test_a_streamed_completion_uses_the_same_url() -> None:
    seen: list[str] = []
    forwarder = _forwarder("https://llm.internal.example/v1", OpenAIAdapter(), seen, OPENAI_BODY)
    body = {"model": "m", "stream": True, "messages": []}
    async for _ in forwarder.stream_sse("/v1/chat/completions", body):
        pass
    assert seen == ["https://llm.internal.example/v1/chat/completions"]


@pytest.mark.parametrize(
    ("base", "expected"),
    [
        ("", "https://api.anthropic.com/v1/messages"),
        ("https://anthropic-proxy.example/v1", "https://anthropic-proxy.example/v1/messages"),
    ],
)
async def test_anthropic_messages_are_not_doubled_either(base: str, expected: str) -> None:
    seen: list[str] = []
    forwarder = _forwarder(
        "https://ignored.example", AnthropicAdapter(base_url=base), seen, ANTHROPIC_BODY
    )
    await forwarder.forward_json("/v1/chat/completions", {"model": "m", "messages": []})
    await forwarder.forward_native_anthropic({"model": "m", "messages": [], "max_tokens": 1})
    assert seen == [expected, expected]


def test_the_join_rule_itself() -> None:
    bare = LLMForwarder(AegisSettings(backend_api_key="k", backend_url="http://127.0.0.1:9999"))
    rooted = LLMForwarder(
        AegisSettings(backend_api_key="k", backend_url="http://127.0.0.1:9999/v1")
    )
    assert bare.upstream_path("/v1/chat/completions") == "/v1/chat/completions"
    assert rooted.upstream_path("/v1/chat/completions") == "/chat/completions"
    assert rooted.upstream_path("/v1") == "/"
    # Only the version root is dropped; nothing that merely starts with "v1" is.
    assert rooted.upstream_path("/v1beta/models") == "/v1beta/models"
    assert json.dumps(rooted.upstream_path("/other")) == '"/other"'
