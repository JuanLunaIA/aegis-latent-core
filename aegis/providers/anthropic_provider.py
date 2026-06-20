# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.providers.anthropic_provider — Anthropic Claude adapter.

Performs full bidirectional translation between the OpenAI Chat Completions
API (what Aegis exposes) and Anthropic's Messages API
(https://docs.anthropic.com/en/api/messages).

Request translation (OpenAI → Anthropic):
  - system messages extracted and joined into top-level ``system`` field.
  - Non-system messages forwarded as-is.
  - Unsupported params stripped (logprobs, n>1, logit_bias, best_of).
  - max_tokens defaulted to 4096 if absent (Anthropic requires it).

Response translation (Anthropic → OpenAI):
  - content[0].text lifted into choices[0].message.content.
  - stop_reason mapped: end_turn→stop, max_tokens→length, etc.
  - usage mapped: input_tokens→prompt_tokens, output_tokens→completion_tokens.

Streaming translation (Anthropic SSE → OpenAI SSE):
  Anthropic events: message_start, content_block_start, content_block_delta,
  content_block_stop, message_delta, message_stop.
  Mapped to OpenAI: role chunk → content chunks → finish_reason chunk → [DONE].

Logprobs: Anthropic does not expose token logprobs.  When force_logprobs is
enabled, injection is skipped for this provider and entropy falls back to
character-level Shannon computation in the forensic pipeline.

Dependencies: stdlib only.

References:
  https://docs.anthropic.com/en/api/messages
  https://docs.anthropic.com/en/api/messages-streaming
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from collections.abc import AsyncIterator
from typing import Any

from aegis.providers.base import ProviderAdapter

logger = logging.getLogger(__name__)

_ANTHROPIC_BASE_URL = "https://api.anthropic.com"
_DEFAULT_ANTHROPIC_VERSION = "2023-06-01"
_DEFAULT_MAX_TOKENS = 4096

# Anthropic stop_reason → OpenAI finish_reason
_STOP_REASON_MAP: dict[str, str] = {
    "end_turn": "stop",
    "max_tokens": "length",
    "stop_sequence": "stop",
    "tool_use": "tool_calls",
}

# OpenAI params not supported by Anthropic Messages API
_UNSUPPORTED_PARAMS = frozenset(
    {
        "logprobs",
        "top_logprobs",
        "logit_bias",
        "best_of",
        "echo",
        "suffix",
        "n",  # Anthropic only supports n=1
        "presence_penalty",
        "frequency_penalty",
    }
)


def _make_openai_chunk(
    chunk_id: str,
    model: str,
    created: int,
    delta: dict[str, Any],
    finish_reason: str | None = None,
    index: int = 0,
) -> bytes:
    """Serialize a single OpenAI chat.completion.chunk to SSE bytes."""
    chunk = {
        "id": chunk_id,
        "object": "chat.completion.chunk",
        "created": created,
        "model": model,
        "choices": [
            {
                "index": index,
                "delta": delta,
                "finish_reason": finish_reason,
            }
        ],
    }
    return f"data: {json.dumps(chunk, separators=(',', ':'))}\n\n".encode()


class AnthropicAdapter(ProviderAdapter):
    """
    Full bidirectional adapter for the Anthropic Messages API.

    Args:
        api_version: Anthropic API version header (default: 2023-06-01).
        base_url:    Override the Anthropic base URL (for testing/proxying).
    """

    def __init__(
        self,
        api_version: str = _DEFAULT_ANTHROPIC_VERSION,
        base_url: str = "",
    ) -> None:
        self._api_version = api_version
        self._base_url = base_url.rstrip("/") if base_url else _ANTHROPIC_BASE_URL

    # ── identity + capability ─────────────────────────────────────────────

    @property
    def name(self) -> str:
        return "anthropic"

    @property
    def base_url_override(self) -> str | None:
        return self._base_url

    @property
    def supports_logprobs(self) -> bool:
        return False  # Anthropic Messages API does not expose token logprobs.

    @property
    def requires_stream_translation(self) -> bool:
        return True

    # ── headers ───────────────────────────────────────────────────────────

    def build_headers(self, api_key: str) -> dict[str, str]:
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "anthropic-version": self._api_version,
        }
        if api_key:
            # Anthropic uses x-api-key, not Authorization: Bearer.
            headers["x-api-key"] = api_key
        return headers

    # ── request translation ───────────────────────────────────────────────

    def translate_request(
        self,
        path: str,
        body: dict[str, Any],
        model_override: str | None = None,
    ) -> tuple[str, dict[str, Any]]:
        """Translate OpenAI Chat Completions request → Anthropic Messages."""
        # Path: /v1/chat/completions → /v1/messages
        provider_path = "/v1/messages" if "/chat/completions" in path else path

        out: dict[str, Any] = {}

        # Model
        out["model"] = model_override or body.get("model", "claude-opus-4-5")

        # max_tokens is required by Anthropic; default if absent.
        out["max_tokens"] = body.get("max_tokens") or _DEFAULT_MAX_TOKENS

        # Extract system messages and join them.
        messages = body.get("messages", [])
        system_parts: list[str] = []
        filtered_messages: list[dict[str, Any]] = []

        for msg in messages:
            if not isinstance(msg, dict):
                continue
            role = msg.get("role", "")
            content = msg.get("content", "")
            if role == "system":
                if isinstance(content, str):
                    system_parts.append(content)
                elif isinstance(content, list):
                    # OpenAI multi-part content: extract text parts.
                    for part in content:
                        if isinstance(part, dict) and part.get("type") == "text":
                            system_parts.append(part.get("text", ""))
            else:
                # Normalize content: Anthropic accepts str or list of blocks.
                normalized = _normalize_message_content(content)
                filtered_messages.append({"role": role, "content": normalized})

        if system_parts:
            out["system"] = "\n\n".join(system_parts)

        # Anthropic requires messages to be non-empty.
        if not filtered_messages:
            filtered_messages = [{"role": "user", "content": "Hello"}]
        out["messages"] = filtered_messages

        # Optional scalar params — copy only if present and supported.
        _SCALAR_COPY = {"temperature", "top_p", "top_k", "stream", "stop_sequences"}
        for key in _SCALAR_COPY:
            if key in body:
                out[key] = body[key]

        # stop → stop_sequences (OpenAI uses "stop", Anthropic "stop_sequences").
        if "stop" in body and "stop_sequences" not in out:
            stop_val = body["stop"]
            if isinstance(stop_val, str):
                out["stop_sequences"] = [stop_val]
            elif isinstance(stop_val, list):
                out["stop_sequences"] = stop_val

        # Drop all unsupported params (logprobs, n, logit_bias, etc.)
        for key in _UNSUPPORTED_PARAMS:
            out.pop(key, None)

        return provider_path, out

    # ── response translation ──────────────────────────────────────────────

    def translate_response(
        self,
        response_bytes: bytes,
        original_model: str,
    ) -> bytes:
        """Translate Anthropic Messages response → OpenAI Chat Completions."""
        try:
            anthropic_resp = json.loads(response_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # If response is not valid JSON (e.g. error), pass through.
            return response_bytes

        # Pass through non-message responses (errors, etc.)
        resp_type = anthropic_resp.get("type", "")
        if resp_type == "error" or "error" in anthropic_resp:
            # Wrap in OpenAI-style error format.
            error = anthropic_resp.get("error", anthropic_resp)
            openai_error = {
                "error": {
                    "message": error.get("message", str(error)),
                    "type": error.get("type", "api_error"),
                    "code": None,
                }
            }
            return json.dumps(openai_error, separators=(",", ":")).encode()

        # Extract content text from Anthropic's content blocks.
        content_text = ""
        content_blocks = anthropic_resp.get("content", [])
        for block in content_blocks:
            if isinstance(block, dict) and block.get("type") == "text":
                content_text += block.get("text", "")

        # Map stop_reason → finish_reason.
        stop_reason = anthropic_resp.get("stop_reason", "end_turn")
        finish_reason = _STOP_REASON_MAP.get(stop_reason, "stop")

        # Map usage.
        usage_in = anthropic_resp.get("usage", {})
        prompt_tokens = usage_in.get("input_tokens", 0)
        completion_tokens = usage_in.get("output_tokens", 0)

        model = anthropic_resp.get("model", original_model)
        msg_id = anthropic_resp.get("id", "")
        chunk_id = f"chatcmpl-{msg_id}" if msg_id else f"chatcmpl-{uuid.uuid4().hex[:8]}"

        openai_resp = {
            "id": chunk_id,
            "object": "chat.completion",
            "created": int(time.time()),
            "model": model,
            "choices": [
                {
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": content_text,
                    },
                    "finish_reason": finish_reason,
                    "logprobs": None,
                }
            ],
            "usage": {
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "total_tokens": prompt_tokens + completion_tokens,
            },
        }

        return json.dumps(openai_resp, separators=(",", ":")).encode()

    # ── streaming translation ─────────────────────────────────────────────

    async def translate_stream(
        self,
        raw_lines: AsyncIterator[str],
        original_model: str,
        request_id: str,
        created: int,
    ) -> AsyncIterator[bytes]:
        """
        Translate Anthropic SSE stream → OpenAI SSE stream.

        Anthropic event flow:
            message_start → content_block_start → content_block_delta* →
            content_block_stop → message_delta → message_stop

        OpenAI chunk flow:
            role chunk → content chunks* → finish_reason chunk → [DONE]
        """
        chunk_id = f"chatcmpl-{request_id}"
        model = original_model
        role_emitted = False

        async for raw_line in raw_lines:
            line = raw_line.strip()

            # Skip event: lines and blank lines.
            if not line or line.startswith("event:"):
                continue

            if not line.startswith("data:"):
                continue

            data_str = line[5:].strip()

            if data_str == "[DONE]":
                yield b"data: [DONE]\n\n"
                return

            try:
                event = json.loads(data_str)
            except json.JSONDecodeError:
                logger.debug("anthropic_adapter: non-JSON SSE data: %.80s", data_str)
                continue

            event_type = event.get("type", "")

            if event_type == "message_start":
                # Extract actual model and message ID for subsequent chunks.
                msg = event.get("message", {})
                chunk_id = f"chatcmpl-{msg.get('id', request_id)}"
                model = msg.get("model", original_model)
                # Emit the role chunk.
                yield _make_openai_chunk(
                    chunk_id,
                    model,
                    created,
                    delta={"role": "assistant", "content": ""},
                )
                role_emitted = True

            elif event_type == "content_block_start":
                # Emit role chunk if message_start was somehow missed.
                if not role_emitted:
                    yield _make_openai_chunk(
                        chunk_id,
                        model,
                        created,
                        delta={"role": "assistant", "content": ""},
                    )
                    role_emitted = True

            elif event_type == "content_block_delta":
                delta = event.get("delta", {})
                if delta.get("type") == "text_delta":
                    text = delta.get("text", "")
                    if text:
                        yield _make_openai_chunk(
                            chunk_id,
                            model,
                            created,
                            delta={"content": text},
                        )
                elif delta.get("type") == "input_json_delta":
                    # Tool use partial JSON — forward as content for now.
                    partial = delta.get("partial_json", "")
                    if partial:
                        yield _make_openai_chunk(
                            chunk_id,
                            model,
                            created,
                            delta={"content": partial},
                        )

            elif event_type == "message_delta":
                delta = event.get("delta", {})
                stop_reason = delta.get("stop_reason")
                if stop_reason:
                    finish_reason = _STOP_REASON_MAP.get(stop_reason, "stop")
                    yield _make_openai_chunk(
                        chunk_id,
                        model,
                        created,
                        delta={},
                        finish_reason=finish_reason,
                    )

            elif event_type == "message_stop":
                yield b"data: [DONE]\n\n"
                return

            elif event_type == "error":
                error = event.get("error", {})
                logger.error(
                    "anthropic_adapter: stream error: %s — %s",
                    error.get("type"),
                    error.get("message"),
                )
                # Emit a minimal finish chunk so the client isn't left hanging.
                yield _make_openai_chunk(
                    chunk_id,
                    model,
                    created,
                    delta={},
                    finish_reason="stop",
                )
                yield b"data: [DONE]\n\n"
                return

        # Stream ended without message_stop — emit [DONE] defensively.
        yield b"data: [DONE]\n\n"


# ── helpers ───────────────────────────────────────────────────────────────────


def _normalize_message_content(content: Any) -> Any:
    """
    Normalize an OpenAI message content value for Anthropic.

    OpenAI content can be:
    - str: pass through as-is.
    - list of {"type": "text", "text": "..."} / image blocks: Anthropic supports
      these natively; pass through but strip unsupported fields.

    Returns:
        str or list of Anthropic-compatible content blocks.
    """
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return str(content)

    normalized: list[dict[str, Any]] = []
    for block in content:
        if not isinstance(block, dict):
            normalized.append({"type": "text", "text": str(block)})
            continue
        btype = block.get("type", "text")
        if btype == "text":
            normalized.append({"type": "text", "text": block.get("text", "")})
        elif btype == "image_url":
            # Convert OpenAI image_url block to Anthropic image block if possible.
            url_data = block.get("image_url", {})
            url = url_data.get("url", "") if isinstance(url_data, dict) else str(url_data)
            if url.startswith("data:"):
                # data URI — extract media type and base64 data.
                try:
                    header, b64data = url.split(",", 1)
                    media_type = header.split(";")[0].split(":")[1]
                    normalized.append(
                        {
                            "type": "image",
                            "source": {
                                "type": "base64",
                                "media_type": media_type,
                                "data": b64data,
                            },
                        }
                    )
                except (ValueError, IndexError):
                    # Malformed data URI — skip silently.
                    pass
            else:
                # Remote URL — Anthropic supports url source type.
                normalized.append(
                    {
                        "type": "image",
                        "source": {"type": "url", "url": url},
                    }
                )
        else:
            # Unknown block type — skip to avoid Anthropic validation errors.
            logger.debug("anthropic_adapter: skipping unknown content block type %r", btype)

    return normalized if normalized else ""
