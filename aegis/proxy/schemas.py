"""
aegis.proxy.schemas — OpenAI-compatible Pydantic v2 request/response models.

Covers: /v1/chat/completions, /v1/completions, /v1/embeddings.
Extra fields are forwarded transparently (model_config extra='allow').
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class _OpenAIBase(BaseModel):
    model_config = {"extra": "forbid"}


# ── Chat ──────────────────────────────────────────────────────────────────────


class ChatMessageContentPart(BaseModel):
    type: str
    text: str | None = None
    image_url: dict[str, Any] | None = None
    model_config = {"extra": "forbid"}


class ChatMessage(BaseModel):
    role: Literal["system", "user", "assistant", "tool", "function"]
    content: str | list[ChatMessageContentPart] | None = None
    name: str | None = None
    tool_calls: list[dict[str, Any]] | None = None
    tool_call_id: str | None = None
    model_config = {"extra": "forbid"}


class ChatCompletionRequest(_OpenAIBase):
    model: str
    messages: list[ChatMessage]
    temperature: float | None = None
    top_p: float | None = None
    n: int | None = None
    stream: bool = False
    stop: str | list[str] | None = None
    max_tokens: int | None = None
    max_completion_tokens: int | None = None
    presence_penalty: float | None = None
    frequency_penalty: float | None = None
    logit_bias: dict[str, float] | None = None
    logprobs: bool | None = None
    top_logprobs: int | None = None
    user: str | None = None
    seed: int | None = None
    tools: list[dict[str, Any]] | None = None
    tool_choice: str | dict[str, Any] | None = None
    response_format: dict[str, Any] | None = None


class TopLogprob(BaseModel):
    token: str
    logprob: float
    bytes: list[int] | None = None


class TokenLogprob(BaseModel):
    token: str
    logprob: float
    bytes: list[int] | None = None
    top_logprobs: list[TopLogprob] = Field(default_factory=list)


class ChoiceLogprobs(BaseModel):
    content: list[TokenLogprob] | None = None


class ChatCompletionChoice(BaseModel):
    index: int
    message: ChatMessage
    finish_reason: str | None = None
    logprobs: ChoiceLogprobs | None = None
    model_config = {"extra": "forbid"}


class Usage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    model_config = {"extra": "forbid"}


class ChatCompletionResponse(BaseModel):
    id: str
    object: str = "chat.completion"
    created: int
    model: str
    choices: list[ChatCompletionChoice]
    usage: Usage | None = None
    system_fingerprint: str | None = None
    model_config = {"extra": "forbid"}


# ── Completions (legacy) ──────────────────────────────────────────────────────


class CompletionRequest(_OpenAIBase):
    model: str
    prompt: str | list[str]
    max_tokens: int | None = None
    temperature: float | None = None
    top_p: float | None = None
    n: int | None = None
    stream: bool = False
    logprobs: int | None = None
    echo: bool | None = None
    stop: str | list[str] | None = None
    seed: int | None = None
    suffix: str | None = None


# ── Embeddings ────────────────────────────────────────────────────────────────


class EmbeddingRequest(_OpenAIBase):
    model: str
    input: str | list[str] | list[int] | list[list[int]]
    encoding_format: str | None = None
    dimensions: int | None = None
    user: str | None = None


# ── Audit API ─────────────────────────────────────────────────────────────────


class AuditNodeOut(BaseModel):
    index: int
    timestamp: float
    state_id: str
    entropy: float
    payload_hash: str
    node_hash: str
    tenant_id: str
    sampling_params: dict[str, Any]


class AuditSessionOut(BaseModel):
    session_id: str
    node_count: int
    tail_hash: str
    legal_admissibility: str
    integrity_valid: bool


class IntegrityReport(BaseModel):
    valid: bool
    error_index: int | None
    node_count: int
    tail_hash: str
    legal_admissibility: str


class AlertOut(BaseModel):
    session_id: str
    state_id: str
    timestamp: float
    alert_type: str  # ENTROPY_COLLAPSE | KL_SPIKE | JS_SPIKE | ENTANGLEMENT
    severity: str  # LOW | MEDIUM | HIGH | CRITICAL
    metric_name: str
    metric_value: float
    threshold: float
    detail: str
