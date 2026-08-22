# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import json

import anthropic
import httpx2

from aegis_sdk.anthropic import Anthropic, AsyncAnthropic


def _message() -> dict[str, object]:
    return {
        "id": "msg-test",
        "type": "message",
        "role": "assistant",
        "model": "claude-test",
        "content": [{"type": "text", "text": "Hello"}],
        "stop_reason": "end_turn",
        "stop_sequence": None,
        "usage": {"input_tokens": 1, "output_tokens": 1},
    }


def test_anthropic_client_preserves_official_type_and_bearer_auth() -> None:
    seen: list[httpx2.Request] = []

    def handler(request: httpx2.Request) -> httpx2.Response:
        seen.append(request)
        return httpx2.Response(200, json=_message(), request=request)

    sync_client = Anthropic(
        aegis_api_key="proxy-secret",
        gateway_url="https://gateway.test",
        tenant_id="tenant-a",
        session_id="session-a",
        http_client=httpx2.Client(transport=httpx2.MockTransport(handler)),
    )
    response = sync_client.messages.create(
        model="claude-test",
        max_tokens=64,
        messages=[{"role": "user", "content": "Hello"}],
    )
    assert isinstance(sync_client, anthropic.Anthropic)
    assert isinstance(response, anthropic.types.Message)
    assert str(seen[0].url) == "https://gateway.test/v1/messages"
    assert seen[0].headers["authorization"] == "Bearer proxy-secret"
    assert "x-api-key" not in seen[0].headers
    assert seen[0].headers["x-aegis-tenant-id"] == "tenant-a"
    assert json.loads(seen[0].content)["model"] == "claude-test"
    sync_client.close()


def test_async_anthropic_client_is_official_subclass() -> None:
    async_client = AsyncAnthropic(
        aegis_api_key="proxy-secret",
        gateway_url="https://gateway.test",
        tenant_id="tenant-a",
    )
    assert isinstance(async_client, anthropic.AsyncAnthropic)
    assert str(async_client.base_url).rstrip("/") == "https://gateway.test"
