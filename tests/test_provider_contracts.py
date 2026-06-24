# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
tests/test_provider_contracts.py — Contract tests for all provider adapters.

Contract: OpenAI format IN → translate → assert correct upstream format →
          mock upstream response → translate back → assert OpenAI format OUT.

Covers missing branches from test_providers.py:
- AnthropicAdapter: build_headers, base_url_override, supports_logprobs,
  requires_stream_translation, system list content, scalar params copy,
  non-text response content blocks, stream [DONE], non-JSON line,
  content_block_start without message_start, input_json_delta, error event,
  _normalize_message_content: non-dict/malformed-data-uri/unknown-type.
- GeminiAdapter: build_headers with no key, translate_request passthrough.
- OpenRouterAdapter: headers with/without site_url and site_name.
- ProviderAdapter base class: translate_stream raises NotImplementedError.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

import pytest

from aegis.providers.anthropic_provider import AnthropicAdapter, _normalize_message_content
from aegis.providers.base import ProviderAdapter
from aegis.providers.gemini_provider import GeminiAdapter
from aegis.providers.openai_provider import OpenAIAdapter, OpenRouterAdapter

# ── Test helpers ──────────────────────────────────────────────────────────────


async def _aiter(*lines: str) -> AsyncIterator[str]:
    for line in lines:
        yield line


def _run_stream(adapter: AnthropicAdapter, *sse_lines: str) -> list[bytes]:
    """Collect all SSE bytes from translate_stream synchronously."""

    async def _collect():
        result = []
        async for chunk in adapter.translate_stream(
            _aiter(*sse_lines),
            original_model="claude-opus-4-5",
            request_id="req-test",
            created=1700000000,
        ):
            result.append(chunk)
        return result

    return asyncio.run(_collect())


def _parse_chunks(raw_bytes_list: list[bytes]) -> list[dict]:
    """Parse SSE bytes → list of JSON dicts (skips [DONE])."""
    chunks = []
    for b in raw_bytes_list:
        s = b.decode()
        if "data: [DONE]" in s:
            continue
        if s.startswith("data: "):
            chunks.append(json.loads(s[6:]))
    return chunks


# ── OpenAI adapter — contract: pure passthrough ───────────────────────────────


class TestOpenAIContract:
    def setup_method(self):
        self.adapter = OpenAIAdapter()

    def test_request_passthrough_no_mutation(self):
        """OpenAI format IN stays identical OUT (no translation needed)."""
        body = {
            "model": "gpt-4o",
            "messages": [{"role": "user", "content": "hello"}],
            "temperature": 0.7,
        }
        path, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert path == "/v1/chat/completions"
        assert out == body

    def test_response_passthrough(self):
        """Provider response bytes pass through unchanged."""
        raw = b'{"id":"chatcmpl-1","object":"chat.completion"}'
        assert self.adapter.translate_response(raw, "gpt-4o") == raw

    def test_build_headers_with_api_key(self):
        headers = self.adapter.build_headers("sk-test")
        assert headers["Authorization"] == "Bearer sk-test"
        assert headers["Content-Type"] == "application/json"

    def test_model_override_applied(self):
        body = {"model": "gpt-3.5-turbo", "messages": []}
        _, out = self.adapter.translate_request(
            "/v1/chat/completions", body, model_override="gpt-4o"
        )
        assert out["model"] == "gpt-4o"


# ── Anthropic adapter — request translation contract ─────────────────────────


class TestAnthropicRequestContract:
    def setup_method(self):
        self.adapter = AnthropicAdapter()

    def test_adapter_properties(self):
        """Properties used by the proxy layer return correct values."""
        assert self.adapter.name == "anthropic"
        assert self.adapter.base_url_override is not None  # covers line 136-138
        assert self.adapter.supports_logprobs is False  # covers line 141-143
        assert self.adapter.requires_stream_translation is True  # covers line 145-146

    def test_base_url_custom_override(self):
        adapter = AnthropicAdapter(base_url="https://internal-proxy.example.com")
        assert adapter.base_url_override == "https://internal-proxy.example.com"

    def test_build_headers_with_api_key(self):
        """Covers the build_headers code path (lines 141-148)."""
        headers = self.adapter.build_headers("sk-ant-key")
        assert headers["x-api-key"] == "sk-ant-key"
        assert headers["anthropic-version"] == "2023-06-01"
        assert "Authorization" not in headers

    def test_build_headers_no_api_key(self):
        """No api_key → x-api-key header omitted."""
        headers = self.adapter.build_headers("")
        assert "x-api-key" not in headers

    def test_system_message_with_list_content(self):
        """System message content as list of text parts (lines 183-187)."""
        body = {
            "messages": [
                {
                    "role": "system",
                    "content": [
                        {"type": "text", "text": "Be concise."},
                        {"type": "text", "text": "Use JSON."},
                    ],
                },
                {"role": "user", "content": "Hello"},
            ]
        }
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert out["system"] == "Be concise.\n\nUse JSON."

    def test_non_dict_message_skipped(self):
        """Non-dict entries in messages list are skipped (line 177)."""
        body = {
            "messages": [
                "this is a string not a dict",
                42,
                {"role": "user", "content": "Hello"},
            ]
        }
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        # Only the dict message survives; non-dict entries are skipped.
        assert len(out["messages"]) == 1
        assert out["messages"][0]["role"] == "user"

    def test_system_message_non_str_non_list_content_ignored(self):
        """system message content that's neither str nor list is silently ignored (183->175)."""
        body = {
            "messages": [
                {"role": "system", "content": 42},  # int content → neither str nor list
                {"role": "user", "content": "Hi"},
            ]
        }
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert "system" not in out  # int content produced no system string

    def test_system_list_with_non_text_parts_ignored(self):
        """System list content where parts are not type=text are skipped (186->185)."""
        body = {
            "messages": [
                {
                    "role": "system",
                    "content": [
                        {"type": "image_url", "image_url": {"url": "https://img.example.com"}},
                        {"type": "text", "text": "Be helpful."},
                    ],
                },
                {"role": "user", "content": "Hi"},
            ]
        }
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        # Only the text part gets into system; image_url is not type=text → skipped.
        assert out["system"] == "Be helpful."

    def test_stop_with_non_str_non_list_value_not_remapped(self):
        """stop= with a value that's not str/list doesn't produce stop_sequences (212->216)."""
        body = {
            "messages": [{"role": "user", "content": "Hi"}],
            "stop": 42,  # int stop value — neither str nor list
        }
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert "stop_sequences" not in out

    def test_scalar_params_copied(self):
        """temperature/top_p/top_k/stream values are copied to Anthropic body (line 205)."""
        body = {
            "messages": [{"role": "user", "content": "Hi"}],
            "temperature": 0.5,
            "top_p": 0.9,
            "top_k": 40,
        }
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert out["temperature"] == 0.5
        assert out["top_p"] == 0.9
        assert out["top_k"] == 40


# ── Anthropic adapter — response translation contract ─────────────────────────


class TestAnthropicResponseContract:
    def setup_method(self):
        self.adapter = AnthropicAdapter()

    def _make_resp(self, content_blocks: list, stop_reason: str = "end_turn") -> bytes:
        return json.dumps(
            {
                "id": "msg_abc",
                "type": "message",
                "model": "claude-opus-4-5",
                "content": content_blocks,
                "stop_reason": stop_reason,
                "usage": {"input_tokens": 5, "output_tokens": 3},
            }
        ).encode()

    def test_non_text_content_block_skipped(self):
        """Response with tool_use block (not type=text) → content is empty (line 253->252)."""
        raw = self._make_resp([{"type": "tool_use", "id": "tool_0", "name": "fn", "input": {}}])
        out = json.loads(self.adapter.translate_response(raw, "claude-opus-4-5"))
        assert out["choices"][0]["message"]["content"] == ""

    def test_mixed_text_and_non_text_blocks(self):
        """Text blocks aggregated; non-text blocks ignored."""
        raw = self._make_resp(
            [
                {"type": "text", "text": "Hello "},
                {"type": "tool_use", "id": "t0", "name": "fn", "input": {}},
                {"type": "text", "text": "world"},
            ]
        )
        out = json.loads(self.adapter.translate_response(raw, "claude-opus-4-5"))
        assert out["choices"][0]["message"]["content"] == "Hello world"

    def test_tool_use_stop_reason_mapped(self):
        raw = self._make_resp([], stop_reason="tool_use")
        out = json.loads(self.adapter.translate_response(raw, "claude-opus-4-5"))
        assert out["choices"][0]["finish_reason"] == "tool_calls"

    def test_unknown_stop_reason_defaults_to_stop(self):
        raw = self._make_resp([], stop_reason="unknown_reason_xyz")
        out = json.loads(self.adapter.translate_response(raw, "claude-opus-4-5"))
        assert out["choices"][0]["finish_reason"] == "stop"


# ── Anthropic adapter — streaming translation contract ────────────────────────


class TestAnthropicStreamContract:
    def setup_method(self):
        self.adapter = AnthropicAdapter()

    def _data(self, obj: dict) -> str:
        return f"data: {json.dumps(obj)}"

    def test_explicit_done_in_stream_yields_done(self):
        """When stream sends 'data: [DONE]' the adapter relays it (lines 330-331)."""
        raw = _run_stream(self.adapter, "data: [DONE]")
        assert any(b"[DONE]" in b for b in raw)

    def test_non_data_non_event_line_skipped(self):
        """Lines not starting with 'data:' or 'event:' are silently skipped (line 325)."""
        raw = _run_stream(
            self.adapter,
            "GARBAGE LINE",
            self._data({"type": "message_stop"}),
        )
        # Only [DONE] emitted; no error raised.
        assert any(b"[DONE]" in b for b in raw)

    def test_non_json_data_line_skipped(self):
        """Non-JSON data: line is logged and skipped (lines 335-337)."""
        raw = _run_stream(
            self.adapter,
            "data: not-valid-json{{{",
            self._data({"type": "message_stop"}),
        )
        chunks = _parse_chunks(raw)
        assert all("choices" in c for c in chunks)

    def test_content_block_start_without_message_start_emits_role(self):
        """
        content_block_start arriving before message_start must emit a role chunk
        to avoid the client receiving content without a preceding role (lines 358-364).
        """
        raw = _run_stream(
            self.adapter,
            self._data(
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "text", "text": ""},
                }
            ),
            self._data({"type": "message_stop"}),
        )
        chunks = _parse_chunks(raw)
        assert any(c["choices"][0]["delta"].get("role") == "assistant" for c in chunks)

    def test_input_json_delta_forwarded_as_tool_call_arguments(self):
        """input_json_delta emits an OpenAI tool_calls arguments delta, NOT content."""
        raw = _run_stream(
            self.adapter,
            self._data(
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": '{"key":'},
                }
            ),
            self._data({"type": "message_stop"}),
        )
        chunks = _parse_chunks(raw)
        # Must not corrupt the message content with tool JSON.
        assert not any(c["choices"][0]["delta"].get("content") for c in chunks)
        tool_chunks = [c for c in chunks if c["choices"][0]["delta"].get("tool_calls")]
        assert len(tool_chunks) >= 1
        tc = tool_chunks[0]["choices"][0]["delta"]["tool_calls"][0]
        assert tc["function"]["arguments"] == '{"key":'

    def test_full_tool_call_sequence_reassembles(self):
        """content_block_start(tool_use) + input_json_delta* → coherent OpenAI tool_call."""
        raw = _run_stream(
            self.adapter,
            self._data({"type": "message_start", "message": {"id": "m1", "model": "claude"}}),
            self._data(
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "tool_use", "id": "toolu_1", "name": "get_weather"},
                }
            ),
            self._data(
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": '{"city":'},
                }
            ),
            self._data(
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": '"Paris"}'},
                }
            ),
            self._data({"type": "message_delta", "delta": {"stop_reason": "tool_use"}}),
            self._data({"type": "message_stop"}),
        )
        chunks = _parse_chunks(raw)
        tool_chunks = [c for c in chunks if c["choices"][0]["delta"].get("tool_calls")]
        # First tool chunk carries id + name; subsequent carry argument fragments.
        first = tool_chunks[0]["choices"][0]["delta"]["tool_calls"][0]
        assert first["id"] == "toolu_1"
        assert first["type"] == "function"
        assert first["function"]["name"] == "get_weather"
        assert all(tc["choices"][0]["delta"]["tool_calls"][0]["index"] == 0 for tc in tool_chunks)
        # Reassembled arguments across fragments form the full JSON.
        args = "".join(
            tc["choices"][0]["delta"]["tool_calls"][0]["function"].get("arguments", "")
            for tc in tool_chunks
        )
        assert args == '{"city":"Paris"}'
        # finish_reason maps tool_use → tool_calls.
        finish = [
            c["choices"][0]["finish_reason"] for c in chunks if c["choices"][0]["finish_reason"]
        ]
        assert finish == ["tool_calls"]

    def test_multiple_tool_calls_get_distinct_indices(self):
        """Two tool_use blocks → two OpenAI tool_calls with indices 0 and 1."""
        raw = _run_stream(
            self.adapter,
            self._data({"type": "message_start", "message": {"id": "m1", "model": "claude"}}),
            self._data(
                {
                    "type": "content_block_start",
                    "index": 0,
                    "content_block": {"type": "tool_use", "id": "t0", "name": "a"},
                }
            ),
            self._data(
                {
                    "type": "content_block_start",
                    "index": 1,
                    "content_block": {"type": "tool_use", "id": "t1", "name": "b"},
                }
            ),
            self._data(
                {
                    "type": "content_block_delta",
                    "index": 1,
                    "delta": {"type": "input_json_delta", "partial_json": "{}"},
                }
            ),
            self._data({"type": "message_stop"}),
        )
        chunks = _parse_chunks(raw)
        starts = [
            c["choices"][0]["delta"]["tool_calls"][0]
            for c in chunks
            if c["choices"][0]["delta"].get("tool_calls")
            and c["choices"][0]["delta"]["tool_calls"][0].get("id")
        ]
        assert [s["index"] for s in starts] == [0, 1]
        assert [s["id"] for s in starts] == ["t0", "t1"]
        # The argument fragment for block index 1 must target tool_call index 1.
        arg_chunks = [
            c["choices"][0]["delta"]["tool_calls"][0]
            for c in chunks
            if c["choices"][0]["delta"].get("tool_calls")
            and "arguments" in c["choices"][0]["delta"]["tool_calls"][0].get("function", {})
            and not c["choices"][0]["delta"]["tool_calls"][0].get("id")
        ]
        assert arg_chunks[0]["index"] == 1

    def test_input_json_delta_empty_partial_not_forwarded(self):
        """Empty partial_json is NOT emitted (branch 370->317 / 391->317)."""
        raw = _run_stream(
            self.adapter,
            self._data(
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "input_json_delta", "partial_json": ""},
                }
            ),
            self._data({"type": "message_stop"}),
        )
        chunks = _parse_chunks(raw)
        content_chunks = [c for c in chunks if c["choices"][0]["delta"].get("content")]
        assert len(content_chunks) == 0

    def test_empty_text_delta_not_forwarded(self):
        """text_delta with empty text is NOT emitted (branch 370->317)."""
        raw = _run_stream(
            self.adapter,
            self._data(
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": ""},
                }
            ),
            self._data({"type": "message_stop"}),
        )
        chunks = _parse_chunks(raw)
        content_chunks = [c for c in chunks if c["choices"][0]["delta"].get("content")]
        assert len(content_chunks) == 0

    def test_error_event_emits_finish_and_done(self):
        """
        error event → logs error, emits finish_reason=stop chunk + [DONE] (lines 406-424).
        """
        raw = _run_stream(
            self.adapter,
            self._data(
                {
                    "type": "error",
                    "error": {"type": "overloaded_error", "message": "Server overloaded"},
                }
            ),
        )
        chunks = _parse_chunks(raw)
        finish_chunks = [c for c in chunks if c["choices"][0].get("finish_reason")]
        assert len(finish_chunks) >= 1
        assert finish_chunks[-1]["choices"][0]["finish_reason"] == "stop"
        assert any(b"[DONE]" in b for b in raw)

    def test_stream_ending_without_message_stop_emits_done(self):
        """Stream exhausted without message_stop → defensive [DONE] emitted."""
        raw = _run_stream(
            self.adapter,
            self._data(
                {
                    "type": "content_block_delta",
                    "index": 0,
                    "delta": {"type": "text_delta", "text": "hi"},
                }
            ),
            # No message_stop
        )
        assert any(b"[DONE]" in b for b in raw)

    def test_full_round_trip_openai_to_openai(self):
        """
        Full contract: OpenAI request → Anthropic format → mock response → OpenAI format.
        """
        # Step 1: translate request
        openai_req = {
            "model": "claude-opus-4-5",
            "messages": [
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "What is 2+2?"},
            ],
            "temperature": 0.0,
        }
        path, anthropic_body = self.adapter.translate_request("/v1/chat/completions", openai_req)

        # Assert correct upstream format
        assert path == "/v1/messages"
        assert "system" in anthropic_body
        assert "You are helpful." in anthropic_body["system"]
        assert anthropic_body["temperature"] == 0.0
        assert not any(m["role"] == "system" for m in anthropic_body["messages"])

        # Step 2: mock Anthropic response
        mock_anthropic_resp = json.dumps(
            {
                "id": "msg_contract",
                "type": "message",
                "model": "claude-opus-4-5",
                "content": [{"type": "text", "text": "4"}],
                "stop_reason": "end_turn",
                "usage": {"input_tokens": 15, "output_tokens": 1},
            }
        ).encode()

        # Step 3: translate response back
        openai_resp = json.loads(
            self.adapter.translate_response(mock_anthropic_resp, "claude-opus-4-5")
        )

        # Assert OpenAI format
        assert openai_resp["object"] == "chat.completion"
        assert openai_resp["choices"][0]["message"]["role"] == "assistant"
        assert openai_resp["choices"][0]["message"]["content"] == "4"
        assert openai_resp["choices"][0]["finish_reason"] == "stop"
        assert openai_resp["usage"]["prompt_tokens"] == 15
        assert openai_resp["usage"]["completion_tokens"] == 1


# ── _normalize_message_content — missing branches ─────────────────────────────


class TestNormalizeMessageContent:
    def test_non_dict_block_converted_to_text(self):
        """Non-dict item in content list → {"type":"text","text":str(item)} (lines 450-451)."""
        result = _normalize_message_content(["hello", 42])
        assert result == [
            {"type": "text", "text": "hello"},
            {"type": "text", "text": "42"},
        ]

    def test_malformed_data_uri_skipped(self):
        """Malformed data: URI in image_url block → silently skipped (lines 474-476)."""
        content = [{"type": "image_url", "image_url": {"url": "data:MALFORMED_NO_COMMA"}}]
        result = _normalize_message_content(content)
        # Malformed URI → block not appended → result is "" (empty normalized list)
        assert result == "" or result == []

    def test_unknown_block_type_skipped(self):
        """Blocks of unknown type are skipped (line 487 logger.debug)."""
        content = [
            {"type": "video", "url": "https://example.com/vid.mp4"},
        ]
        result = _normalize_message_content(content)
        assert result == "" or result == []

    def test_non_list_non_str_content_converted(self):
        """Non-str, non-list content → str() cast (line 445)."""
        result = _normalize_message_content(42)
        assert result == "42"

    def test_empty_list_returns_empty_string(self):
        """If all blocks produce no normalized entries → return "" (line 489 else branch)."""
        # All unknown-type blocks → normalized stays empty.
        content = [{"type": "unknown_xyz"}]
        result = _normalize_message_content(content)
        assert result == ""


# ── Anthropic SSE — Anthropic stream → OpenAI contract ───────────────────────


class TestAnthropicSSEContract:
    """Full SSE round-trip: realistic Anthropic event sequence → OpenAI chunks."""

    def setup_method(self):
        self.adapter = AnthropicAdapter()

    def test_complete_sse_sequence_produces_openai_chunks(self):
        """Full Anthropic event sequence → properly structured OpenAI SSE chunks."""
        sse_lines = [
            "event: message_start",
            f"data: {json.dumps({'type': 'message_start', 'message': {'id': 'msg_1', 'model': 'claude-opus-4-5'}})}",
            "event: content_block_start",
            f"data: {json.dumps({'type': 'content_block_start', 'index': 0, 'content_block': {'type': 'text', 'text': ''}})}",
            "event: content_block_delta",
            f"data: {json.dumps({'type': 'content_block_delta', 'index': 0, 'delta': {'type': 'text_delta', 'text': 'Hello'}})}",
            "event: message_delta",
            f"data: {json.dumps({'type': 'message_delta', 'delta': {'stop_reason': 'end_turn'}})}",
            "event: message_stop",
            f"data: {json.dumps({'type': 'message_stop'})}",
        ]

        async def _collect():
            result = []
            async for chunk in self.adapter.translate_stream(
                _aiter(*sse_lines),
                original_model="claude-opus-4-5",
                request_id="sse-contract",
                created=1700000000,
            ):
                result.append(chunk)
            return result

        raw = asyncio.run(_collect())
        chunks = _parse_chunks(raw)

        # Must have: role chunk, content chunk(s), finish_reason chunk.
        role_chunks = [c for c in chunks if c["choices"][0]["delta"].get("role")]
        content_chunks = [c for c in chunks if c["choices"][0]["delta"].get("content")]
        finish_chunks = [c for c in chunks if c["choices"][0].get("finish_reason")]

        assert len(role_chunks) >= 1
        assert (
            "".join(c["choices"][0]["delta"].get("content", "") for c in content_chunks) == "Hello"
        )
        assert finish_chunks[-1]["choices"][0]["finish_reason"] == "stop"
        assert any(b"[DONE]" in b for b in raw)

        # All chunks must be in OpenAI format.
        for chunk in chunks:
            assert chunk["object"] == "chat.completion.chunk"
            assert "choices" in chunk
            assert chunk["choices"][0]["index"] == 0


# ── Gemini adapter — contract ─────────────────────────────────────────────────


class TestGeminiContract:
    def setup_method(self):
        self.adapter = GeminiAdapter()

    def test_request_drops_unsupported_params(self):
        """OpenAI request with logit_bias/best_of/echo → stripped (line ~73-75)."""
        body = {
            "model": "gemini-2.0-flash",
            "messages": [{"role": "user", "content": "hi"}],
            "logit_bias": {"50256": -100},
            "best_of": 3,
            "echo": True,
            "temperature": 0.7,
        }
        path, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert "logit_bias" not in out
        assert "best_of" not in out
        assert "echo" not in out
        assert out["temperature"] == 0.7  # preserved

    def test_build_headers_with_api_key(self):
        headers = self.adapter.build_headers("google-key")
        assert headers["Authorization"] == "Bearer google-key"
        assert headers["Content-Type"] == "application/json"

    def test_build_headers_no_api_key(self):
        """No api_key → Authorization header omitted (branch 58->60)."""
        headers = self.adapter.build_headers("")
        assert "Authorization" not in headers

    def test_model_override(self):
        body = {"model": "gemini-1.5-pro", "messages": []}
        _, out = self.adapter.translate_request(
            "/v1/chat/completions", body, model_override="gemini-2.0-flash"
        )
        assert out["model"] == "gemini-2.0-flash"

    def test_base_url_override(self):
        adapter = GeminiAdapter(base_url="https://internal.example.com/v1")
        assert adapter.base_url_override == "https://internal.example.com/v1"

    def test_response_passthrough(self):
        raw = b'{"id":"gemini-resp","choices":[]}'
        assert self.adapter.translate_response(raw, "gemini-2.0-flash") == raw


# ── OpenRouter adapter — contract ─────────────────────────────────────────────


class TestOpenRouterContract:
    def test_build_headers_with_site_metadata(self):
        """HTTP-Referer and X-Title headers are set when site_url/site_name configured."""
        adapter = OpenRouterAdapter(site_url="https://myapp.com", site_name="MyApp")
        headers = adapter.build_headers("or-key")
        assert headers["HTTP-Referer"] == "https://myapp.com"
        assert headers["X-Title"] == "MyApp"
        assert headers["Authorization"] == "Bearer or-key"

    def test_build_headers_without_site_metadata(self):
        """Headers without site_url/site_name omit those fields."""
        adapter = OpenRouterAdapter()
        headers = adapter.build_headers("or-key")
        assert "HTTP-Referer" not in headers
        assert "X-Title" not in headers

    def test_request_with_model_override(self):
        adapter = OpenRouterAdapter()
        body = {"model": "openai/gpt-4", "messages": []}
        _, out = adapter.translate_request(
            "/v1/chat/completions", body, model_override="anthropic/claude-opus-4-5"
        )
        assert out["model"] == "anthropic/claude-opus-4-5"

    def test_base_url_override_to_openrouter(self):
        adapter = OpenRouterAdapter()
        assert adapter.base_url_override == "https://openrouter.ai/api/v1"

    def test_custom_base_url(self):
        adapter = OpenRouterAdapter(base_url="https://proxy.internal/v1")
        assert adapter.base_url_override == "https://proxy.internal/v1"


# ── ProviderAdapter base class — translate_stream NotImplementedError ─────────


class _ConcreteAdapter(ProviderAdapter):
    @property
    def name(self) -> str:
        return "concrete"

    @property
    def requires_stream_translation(self) -> bool:
        return True


def test_base_provider_translate_stream_raises():
    """Base class translate_stream raises NotImplementedError for providers that require it."""
    adapter = _ConcreteAdapter()

    async def _collect():
        async for _ in adapter.translate_stream(
            _aiter("data: test"),
            original_model="m",
            request_id="r",
            created=0,
        ):
            pass

    with pytest.raises(NotImplementedError, match="translate_stream"):
        asyncio.run(_collect())
