"""
aegis.core.forensic — Forensic record builders for the audit ledger.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class TokenTrailEntry:
    index: int
    token: str
    logprob: float
    entropy_bits: float | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def cap_bytes(data: bytes, limit: int) -> bytes:
    return data[:limit] if len(data) > limit else data


def build_token_trail(logprobs_content: list[Any] | None) -> list[dict[str, Any]]:
    """Build serialisable per-token trail from OpenAI logprobs content array."""
    if not logprobs_content:
        return []
    trail: list[dict[str, Any]] = []
    for i, item in enumerate(logprobs_content):
        if isinstance(item, dict):
            token = str(item.get("token", ""))
            logprob = float(item.get("logprob", 0.0))
        else:
            token = str(getattr(item, "token", ""))
            logprob = float(getattr(item, "logprob", 0.0))
        trail.append(TokenTrailEntry(index=i, token=token, logprob=logprob).to_dict())
    return trail


def build_merkle_leaf(
    *,
    state_id: str,
    request_bytes: bytes,
    response_bytes: bytes | None,
    model: str,
    endpoint: str,
    max_bytes: int,
) -> bytes:
    """Canonical bytes hashed into the MMR (full forensic envelope)."""
    req_capped = cap_bytes(request_bytes, max_bytes)
    resp_capped = cap_bytes(response_bytes or b"", max_bytes)
    envelope = {
        "state_id": state_id,
        "request_hash": sha256_hex(request_bytes),
        "response_hash": sha256_hex(response_bytes) if response_bytes else "",
        "request_size": len(request_bytes),
        "response_size": len(response_bytes or b""),
        "request_preview_hex": req_capped.hex(),
        "response_preview_hex": resp_capped.hex(),
        "model": model,
        "endpoint": endpoint,
    }
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()


def extract_usage(resp_json: dict[str, Any] | None) -> dict[str, int]:
    if not resp_json:
        return {}
    usage = resp_json.get("usage") or {}
    return {
        k: int(usage[k])
        for k in ("prompt_tokens", "completion_tokens", "total_tokens")
        if k in usage and usage[k] is not None
    }
