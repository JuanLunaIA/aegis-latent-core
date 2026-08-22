"""
aegis.proxy.schemas — OpenAI-compatible Pydantic v2 request/response models.

Covers: /v1/chat/completions, /v1/completions, /v1/embeddings.
Extra fields are forwarded transparently (model_config extra='allow').
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

from datetime import datetime
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
    merkle_root: str
    signature_scheme: str
    signature_status: str
    model: str
    endpoint: str
    phi_scrubbed: bool
    token_count: int
    latency_ms: float | None
    terminal_outcome: str | None
    redaction_hits: dict[str, int]
    cid: str


class MMRProofOut(BaseModel):
    state_id: str
    node_hash: str
    leaf_hash: str
    leaf_index: int
    leaf_count: int
    root: str
    proof: dict[str, Any]
    signature_scheme: str
    signature_status: str


class RawEvidenceOut(BaseModel):
    node_hash: str
    cid: str
    media_type: str = "application/vnd.ipld.dag-cbor"
    jcs_json: str
    dag_cbor_base64: str
    dag_cbor_sha256: str


class ForensicExportRequest(BaseModel):
    start_time: datetime
    end_time: datetime
    operator: str = Field(min_length=1, max_length=200)
    acquisition_reason: str = Field(min_length=1, max_length=500)
    tenant_id: str | None = Field(default=None, min_length=1, max_length=200)


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
    scope: str = "retained-memory-window"
    window_anchor_hash: str = ""
    full_history_retained: bool = False


class ControlCapabilityOut(BaseModel):
    name: str
    category: str
    status: str  # REAL | UNAVAILABLE | SIMULATED
    module: str
    detail: str


class CapabilitiesReport(BaseModel):
    controls: list[ControlCapabilityOut]
    summary: dict[str, int]  # counts keyed by status (REAL / UNAVAILABLE / SIMULATED)
    simulation_debt: int  # number of controls reporting SIMULATED — must be 0


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
