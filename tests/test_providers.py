# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
tests/test_providers.py — Unit tests for multi-provider adapter layer.

Coverage targets (v2.2.0):
  - AnthropicAdapter: request translation, response translation, stream translation
  - OpenAIAdapter:    passthrough behaviour (no mutations)
  - OpenRouterAdapter: extra headers, model passthrough
  - GeminiAdapter:    unsupported param stripping, base_url override
  - build_provider:   factory happy-path + unknown name rejection
"""
from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

import pytest

from aegis.providers import build_provider
from aegis.providers.anthropic_provider import AnthropicAdapter, _normalize_message_content
from aegis.providers.gemini_provider import GeminiAdapter
from aegis.providers.openai_provider import OpenAIAdapter, OpenRouterAdapter


# ── AnthropicAdapter — request translation ───────────────────────────────────

class TestAnthropicRequestTranslation:
    def setup_method(self):
        self.adapter = AnthropicAdapter()

    def test_path_remapped(self):
        path, _ = self.adapter.translate_request("/v1/chat/completions", {})
        assert path == "/v1/messages"

    def test_non_chat_path_untouched(self):
        path, _ = self.adapter.translate_request("/v1/embeddings", {})
        assert path == "/v1/embeddings"

    def test_system_message_extracted(self):
        body = {
            "model": "claude-opus-4-5",
            "messages": [
                {"role": "system", "content": "Be concise."},
                {"role": "user",   "content": "Hello"},
            ],
        }
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert out["system"] == "Be concise."
        assert all(m["role"] != "system" for m in out["messages"])
        assert out["messages"][0] == {"role": "user", "content": "Hello"}

    def test_multiple_system_messages_joined(self):
        body = {
            "messages": [
                {"role": "system", "content": "Part one."},
                {"role": "system", "content": "Part two."},
                {"role": "user",   "content": "Hi"},
            ],
        }
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert out["system"] == "Part one.\n\nPart two."

    def test_logprobs_stripped(self):
        body = {
            "model": "claude-opus-4-5",
            "messages": [{"role": "user", "content": "Hi"}],
            "logprobs": True,
            "top_logprobs": 20,
        }
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert "logprobs" not in out
        assert "top_logprobs" not in out

    def test_n_stripped(self):
        body = {
            "messages": [{"role": "user", "content": "Hi"}],
            "n": 3,
        }
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert "n" not in out

    def test_max_tokens_defaulted(self):
        body = {"messages": [{"role": "user", "content": "Hi"}]}
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert out["max_tokens"] == 4096

    def test_max_tokens_preserved(self):
        body = {
            "messages": [{"role": "user", "content": "Hi"}],
            "max_tokens": 512,
        }
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert out["max_tokens"] == 512

    def test_stop_remapped_to_stop_sequences_string(self):
        body = {
            "messages": [{"role": "user", "content": "Hi"}],
            "stop": "END",
        }
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert out["stop_sequences"] == ["END"]
        assert "stop" not in out

    def test_stop_remapped_to_stop_sequences_list(self):
        body = {
            "messages": [{"role": "user", "content": "Hi"}],
            "stop": ["END", "STOP"],
        }
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert out["stop_sequences"] == ["END", "STOP"]

    def test_model_override_applied(self):
        body = {"messages": [{"role": "user", "content": "Hi"}], "model": "old-model"}
        _, out = self.adapter.translate_request(
            "/v1/chat/completions", body, model_override="claude-opus-4-5"
        )
        assert out["model"] == "claude-opus-4-5"

    def test_empty_messages_fallback(self):
        body = {}
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert len(out["messages"]) == 1
        assert out["messages"][0]["role"] == "user"


# ── AnthropicAdapter — response translation ──────────────────────────────────

class TestAnthropicResponseTranslation:
    def setup_method(self):
        self.adapter = AnthropicAdapter()

    def _make_anthropic_response(self, text: str = "Hello!", stop_reason: str = "end_turn") -> bytes:
        return json.dumps({
            "id": "msg_abc123",
            "type": "message",
            "role": "assistant",
            "content": [{"type": "text", "text": text}],
            "model": "claude-opus-4-5",
            "stop_reason": stop_reason,
            "stop_sequence": None,
            "usage": {"input_tokens": 10, "output_tokens": 5},
        }).encode()

    def test_content_lifted_to_choices(self):
        raw = self._make_anthropic_response("Hello!")
        out = json.loads(self.adapter.translate_response(raw, "claude-opus-4-5"))
        assert out["choices"][0]["message"]["content"] == "Hello!"
        assert out["choices"][0]["message"]["role"] == "assistant"

    def test_stop_reason_mapped_end_turn(self):
        raw = self._make_anthropic_response(stop_reason="end_turn")
        out = json.loads(self.adapter.translate_response(raw, "claude-opus-4-5"))
        assert out["choices"][0]["finish_reason"] == "stop"

    def test_stop_reason_mapped_max_tokens(self):
        raw = self._make_anthropic_response(stop_reason="max_tokens")
        out = json.loads(self.adapter.translate_response(raw, "claude-opus-4-5"))
        assert out["choices"][0]["finish_reason"] == "length"

    def test_usage_remapped(self):
        raw = self._make_anthropic_response()
        out = json.loads(self.adapter.translate_response(raw, "claude-opus-4-5"))
        assert out["usage"]["prompt_tokens"] == 10
        assert out["usage"]["completion_tokens"] == 5
        assert out["usage"]["total_tokens"] == 15

    def test_object_type_correct(self):
        raw = self._make_anthropic_response()
        out = json.loads(self.adapter.translate_response(raw, "claude-opus-4-5"))
        assert out["object"] == "chat.completion"

    def test_id_prefixed(self):
        raw = self._make_anthropic_response()
        out = json.loads(self.adapter.translate_response(raw, "claude-opus-4-5"))
        assert out["id"].startswith("chatcmpl-")

    def test_logprobs_null(self):
        raw = self._make_anthropic_response()
        out = json.loads(self.adapter.translate_response(raw, "claude-opus-4-5"))
        assert out["choices"][0]["logprobs"] is None

    def test_error_response_wrapped(self):
        error_resp = json.dumps({
            "type": "error",
            "error": {"type": "authentication_error", "message": "Invalid API key"},
        }).encode()
        out = json.loads(self.adapter.translate_response(error_resp, "claude-opus-4-5"))
        assert "error" in out
        assert "Invalid API key" in out["error"]["message"]

    def test_invalid_json_passthrough(self):
        raw = b"not json"
        out = self.adapter.translate_response(raw, "claude-opus-4-5")
        assert out == b"not json"


# ── AnthropicAdapter — streaming translation ─────────────────────────────────

class TestAnthropicStreamTranslation:
    def setup_method(self):
        self.adapter = AnthropicAdapter()

    @staticmethod
    async def _lines(*events: dict) -> AsyncIterator[str]:
        for ev in events:
            yield f"event: {ev['type']}"
            yield f"data: {json.dumps(ev)}"

    def _run(self, coro):
        return asyncio.get_event_loop().run_until_complete(coro)

    async def _collect(self, *events: dict) -> list[dict]:
        chunks = []
        async for raw_bytes in self.adapter.translate_stream(
            self._lines(*events),
            original_model="claude-opus-4-5",
            request_id="test-req-001",
            created=1700000000,
        ):
            s = raw_bytes.decode()
            if s.strip() == "data: [DONE]":
                break
            if s.startswith("data: "):
                chunks.append(json.loads(s[6:]))
        return chunks

    def test_role_chunk_emitted_on_message_start(self):
        events = [
            {"type": "message_start", "message": {
                "id": "msg_xyz", "type": "message", "role": "assistant",
                "content": [], "model": "claude-opus-4-5",
                "stop_reason": None, "stop_sequence": None,
                "usage": {"input_tokens": 5, "output_tokens": 1},
            }},
            {"type": "message_stop"},
        ]
        chunks = self._run(self._collect(*events))
        assert chunks[0]["choices"][0]["delta"].get("role") == "assistant"

    def test_content_delta_forwarded(self):
        events = [
            {"type": "message_start", "message": {
                "id": "msg_xyz", "type": "message", "role": "assistant",
                "content": [], "model": "claude-opus-4-5",
                "stop_reason": None, "stop_sequence": None,
                "usage": {"input_tokens": 5, "output_tokens": 1},
            }},
            {"type": "content_block_start",  "index": 0, "content_block": {"type": "text", "text": ""}},
            {"type": "content_block_delta",   "index": 0, "delta": {"type": "text_delta", "text": "Hello"}},
            {"type": "content_block_delta",   "index": 0, "delta": {"type": "text_delta", "text": "!"}},
            {"type": "content_block_stop",    "index": 0},
            {"type": "message_delta",  "delta": {"stop_reason": "end_turn", "stop_sequence": None},
             "usage": {"output_tokens": 2}},
            {"type": "message_stop"},
        ]
        chunks = self._run(self._collect(*events))
        content_texts = [
            c["choices"][0]["delta"].get("content", "")
            for c in chunks
            if c["choices"][0]["delta"].get("content")
        ]
        assert "".join(content_texts) == "Hello!"

    def test_finish_reason_on_message_delta(self):
        events = [
            {"type": "message_start", "message": {
                "id": "msg_xyz", "type": "message", "role": "assistant",
                "content": [], "model": "claude-opus-4-5",
                "stop_reason": None, "stop_sequence": None,
                "usage": {"input_tokens": 5, "output_tokens": 1},
            }},
            {"type": "message_delta", "delta": {"stop_reason": "end_turn"}, "usage": {"output_tokens": 5}},
            {"type": "message_stop"},
        ]
        chunks = self._run(self._collect(*events))
        finish_chunks = [c for c in chunks if c["choices"][0].get("finish_reason")]
        assert len(finish_chunks) >= 1
        assert finish_chunks[-1]["choices"][0]["finish_reason"] == "stop"

    def test_done_on_message_stop(self):
        events = [
            {"type": "message_start", "message": {
                "id": "msg_xyz", "type": "message", "role": "assistant",
                "content": [], "model": "claude-opus-4-5",
                "stop_reason": None, "stop_sequence": None,
                "usage": {"input_tokens": 5, "output_tokens": 1},
            }},
            {"type": "message_stop"},
        ]

        async def _run():
            output = []
            async for b in self.adapter.translate_stream(
                self._lines(*events),
                original_model="claude-opus-4-5",
                request_id="x",
                created=1700000000,
            ):
                output.append(b.decode())
            return output

        output = self._run(_run())
        assert any("[DONE]" in line for line in output)

    def test_object_type_is_chunk(self):
        events = [
            {"type": "message_start", "message": {
                "id": "msg_xyz", "type": "message", "role": "assistant",
                "content": [], "model": "claude-opus-4-5",
                "stop_reason": None, "stop_sequence": None,
                "usage": {"input_tokens": 5, "output_tokens": 1},
            }},
            {"type": "message_stop"},
        ]
        chunks = self._run(self._collect(*events))
        for c in chunks:
            assert c["object"] == "chat.completion.chunk"


# ── OpenAIAdapter ─────────────────────────────────────────────────────────────

class TestOpenAIAdapter:
    def setup_method(self):
        self.adapter = OpenAIAdapter()

    def test_passthrough_path(self):
        path, body = self.adapter.translate_request("/v1/chat/completions", {"model": "gpt-4o"})
        assert path == "/v1/chat/completions"

    def test_passthrough_body(self):
        original = {"model": "gpt-4o", "messages": [{"role": "user", "content": "Hi"}]}
        _, body = self.adapter.translate_request("/v1/chat/completions", original)
        assert body["model"] == "gpt-4o"

    def test_model_override(self):
        original = {"model": "gpt-4o", "messages": []}
        _, body = self.adapter.translate_request(
            "/v1/chat/completions", original, model_override="gpt-4o-mini"
        )
        assert body["model"] == "gpt-4o-mini"

    def test_supports_logprobs_true(self):
        assert self.adapter.supports_logprobs is True

    def test_requires_no_stream_translation(self):
        assert self.adapter.requires_stream_translation is False

    def test_no_base_url_override(self):
        assert self.adapter.base_url_override is None

    def test_authorization_header(self):
        headers = self.adapter.build_headers("sk-test-key")
        assert headers["Authorization"] == "Bearer sk-test-key"


# ── OpenRouterAdapter ─────────────────────────────────────────────────────────

class TestOpenRouterAdapter:
    def test_base_url_set(self):
        adapter = OpenRouterAdapter()
        assert adapter.base_url_override == "https://openrouter.ai/api/v1"

    def test_custom_base_url(self):
        adapter = OpenRouterAdapter(base_url="https://my-router.local/api/v1")
        assert adapter.base_url_override == "https://my-router.local/api/v1"

    def test_site_headers_included(self):
        adapter = OpenRouterAdapter(site_url="https://myapp.com", site_name="My App")
        headers = adapter.build_headers("key")
        assert headers["HTTP-Referer"] == "https://myapp.com"
        assert headers["X-Title"] == "My App"

    def test_site_headers_absent_when_empty(self):
        adapter = OpenRouterAdapter()
        headers = adapter.build_headers("key")
        assert "HTTP-Referer" not in headers
        assert "X-Title" not in headers

    def test_model_override(self):
        adapter = OpenRouterAdapter()
        _, body = adapter.translate_request(
            "/v1/chat/completions",
            {"model": "gpt-4o"},
            model_override="meta-llama/llama-3.1-70b-instruct",
        )
        assert body["model"] == "meta-llama/llama-3.1-70b-instruct"


# ── GeminiAdapter ─────────────────────────────────────────────────────────────

class TestGeminiAdapter:
    def setup_method(self):
        self.adapter = GeminiAdapter()

    def test_base_url_override(self):
        assert "generativelanguage.googleapis.com" in (self.adapter.base_url_override or "")

    def test_custom_base_url(self):
        adapter = GeminiAdapter(base_url="http://localhost:5000")
        assert adapter.base_url_override == "http://localhost:5000"

    def test_unsupported_params_stripped(self):
        body = {
            "model": "gemini-2.0-flash",
            "messages": [{"role": "user", "content": "Hi"}],
            "logit_bias": {"50256": -100},
            "suffix": "...",
        }
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert "logit_bias" not in out
        assert "suffix" not in out

    def test_model_preserved(self):
        body = {
            "model": "gemini-2.0-flash",
            "messages": [{"role": "user", "content": "Hi"}],
        }
        _, out = self.adapter.translate_request("/v1/chat/completions", body)
        assert out["model"] == "gemini-2.0-flash"

    def test_bearer_auth(self):
        headers = self.adapter.build_headers("GEMINI_KEY_XYZ")
        assert headers["Authorization"] == "Bearer GEMINI_KEY_XYZ"


# ── build_provider factory ────────────────────────────────────────────────────

class TestBuildProvider:
    def test_openai(self):
        p = build_provider("openai")
        assert p.name == "openai"

    def test_anthropic(self):
        p = build_provider("anthropic")
        assert p.name == "anthropic"
        assert p.supports_logprobs is False

    def test_gemini(self):
        p = build_provider("gemini")
        assert p.name == "gemini"

    def test_openrouter(self):
        p = build_provider(
            "openrouter",
            openrouter_site_url="https://example.com",
            openrouter_site_name="Test",
        )
        assert p.name == "openrouter"

    def test_case_insensitive(self):
        p = build_provider("ANTHROPIC")
        assert p.name == "anthropic"

    def test_unknown_provider_raises(self):
        with pytest.raises(ValueError, match="Unknown provider"):
            build_provider("grok")

    def test_whitespace_stripped(self):
        p = build_provider("  openai  ")
        assert p.name == "openai"


# ── _normalize_message_content ────────────────────────────────────────────────

class TestNormalizeMessageContent:
    def test_string_passthrough(self):
        assert _normalize_message_content("hello") == "hello"

    def test_text_block_preserved(self):
        blocks = [{"type": "text", "text": "hello"}]
        result = _normalize_message_content(blocks)
        assert result == [{"type": "text", "text": "hello"}]

    def test_data_uri_image_converted(self):
        blocks = [{"type": "image_url", "image_url": {"url": "data:image/png;base64,abc123=="}}]
        result = _normalize_message_content(blocks)
        assert result[0]["type"] == "image"
        assert result[0]["source"]["type"] == "base64"
        assert result[0]["source"]["media_type"] == "image/png"

    def test_remote_url_image_converted(self):
        blocks = [{"type": "image_url", "image_url": {"url": "https://example.com/img.png"}}]
        result = _normalize_message_content(blocks)
        assert result[0]["type"] == "image"
        assert result[0]["source"]["type"] == "url"

    def test_non_list_coerced_to_string(self):
        result = _normalize_message_content(42)
        assert result == "42"

    def test_empty_list_returns_empty_string(self):
        result = _normalize_message_content([])
        assert result == ""
