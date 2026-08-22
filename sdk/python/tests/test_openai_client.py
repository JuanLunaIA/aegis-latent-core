# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import json

import httpx
import openai
import pytest

from aegis_sdk.openai import AsyncOpenAI, OpenAI


def _chat_response() -> dict[str, object]:
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1,
        "model": "gpt-test",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "ok"},
                "finish_reason": "stop",
                "logprobs": None,
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


def test_sync_client_preserves_native_response_type_and_headers() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json=_chat_response(), request=request)

    client = OpenAI(
        aegis_api_key="proxy-secret",
        gateway_url="https://gateway.test",
        tenant_id="tenant-a",
        session_id="session-a",
        trace_context="00-00000000000000000000000000000000-0000000000000000-01",
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    response = client.chat.completions.create(
        model="gpt-test", messages=[{"role": "user", "content": "hi"}]
    )
    assert isinstance(client, openai.OpenAI)
    assert isinstance(response, openai.types.chat.ChatCompletion)
    assert str(seen[0].url) == "https://gateway.test/v1/chat/completions"
    assert seen[0].headers["authorization"] == "Bearer proxy-secret"
    assert seen[0].headers["x-aegis-tenant-id"] == "tenant-a"
    assert seen[0].headers["x-aegis-session-id"] == "session-a"
    assert json.loads(seen[0].content)["model"] == "gpt-test"
    client.close()


def test_stream_with_pending_terminal_evidence_defers_proof_lookup() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = (
            'data: {"id":"chunk","object":"chat.completion.chunk","created":1,'
            '"model":"gpt-test","choices":[{"index":0,"delta":{"content":"ok"},'
            '"finish_reason":null}]}\n\ndata: [DONE]\n\n'
        )
        return httpx.Response(
            200,
            text=body,
            headers={
                "content-type": "text/event-stream",
                "X-Aegis-Evidence-Status": "pending-terminal",
                "Link": '</v1/audit/proofs/request>; rel="aegis-inclusion-proof"',
            },
            request=request,
        )

    client = OpenAI(
        aegis_api_key="proxy-secret",
        gateway_url="https://gateway.test",
        tenant_id="tenant-a",
        verify_proof=True,
        trusted_mmr_root="a" * 64,
        http_client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    stream = client.chat.completions.create(
        model="gpt-test",
        messages=[{"role": "user", "content": "hi"}],
        stream=True,
    )
    assert [chunk.choices[0].delta.content for chunk in stream] == ["ok"]
    client.close()


@pytest.mark.asyncio
async def test_async_client_preserves_native_response_type() -> None:
    async def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=_chat_response(), request=request)

    client = AsyncOpenAI(
        aegis_api_key="proxy-secret",
        gateway_url="https://gateway.test/v1",
        tenant_id="tenant-a",
        http_client=httpx.AsyncClient(transport=httpx.MockTransport(handler)),
    )
    response = await client.chat.completions.create(
        model="gpt-test", messages=[{"role": "user", "content": "hi"}]
    )
    assert isinstance(client, openai.AsyncOpenAI)
    assert isinstance(response, openai.types.chat.ChatCompletion)
    await client.close()
