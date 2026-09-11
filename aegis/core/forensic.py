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


# ── WAF verdict vocabulary ────────────────────────────────────────────────────
#
# A closed set, and closed for two reasons. The obvious one is that a verdict is
# machine-readable and an open string would let callers invent values nothing
# downstream understands. The load-bearing one is that this value is the first
# free-form field to enter the signed payload, which is joined with "|": an
# unconstrained verdict could carry a delimiter and make two different field
# lists serialise identically. Every member below is delimiter-free, and
# `validate_waf_verdict` refuses anything that is not a member, so the ambiguity
# cannot be constructed rather than merely being unlikely.
WAF_VERDICT_PASSED = "passed"
WAF_VERDICT_BLOCKED = "blocked"
#: Empty means "no verdict recorded", which is what every node written before
#: this field existed carries. It is not a third outcome.
WAF_VERDICT_UNRECORDED = ""

_WAF_VERDICTS = frozenset({WAF_VERDICT_PASSED, WAF_VERDICT_BLOCKED, WAF_VERDICT_UNRECORDED})


def validate_waf_verdict(verdict: str) -> str:
    """Return *verdict* if it is a member of the closed vocabulary, else raise."""
    if not isinstance(verdict, str) or verdict not in _WAF_VERDICTS:
        raise ValueError(f"waf_verdict must be one of {sorted(_WAF_VERDICTS)!r}, got {verdict!r}")
    return verdict


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
    waf_verdict: str = WAF_VERDICT_UNRECORDED,
) -> bytes:
    """Canonical bytes hashed into the MMR (full forensic envelope).

    ``waf_verdict`` is **omitted entirely when empty**, which is what keeps this
    change backward compatible. These bytes are a wire contract: both SDKs
    reconstruct this exact JSON field by field to verify a receipt
    (``sdk/python/src/aegis_sdk/a2a.py``, ``sdk/typescript/src/a2a.ts``), so an
    unconditional key would change every leaf and strand every already-issued
    receipt against every published SDK. Omitting it leaves a verdict-free
    envelope byte-identical to what this function has always produced, and
    confines any wire boundary to receipts that actually carry a verdict.

    Today that boundary is empty. The only envelope either SDK reconstructs is
    the A2A receipt, and ``aegis.core.a2a`` records no verdict, so those bytes
    are unchanged and every published SDK keeps verifying every A2A receipt.
    Forensic leaves, which may carry one, are never reconstructed by an SDK —
    inclusion is verified from a leaf *hash*.

    Adding the verdict here rather than only to the node signature is what makes
    it provable. The MMR commits to *these* bytes, so a statement about the
    verdict can be proved against a root only if the verdict is inside them; a
    signature binds the verdict to the node, but the tree would know nothing
    about it.
    """
    req_capped = cap_bytes(request_bytes, max_bytes)
    resp_capped = cap_bytes(response_bytes or b"", max_bytes)
    envelope: dict[str, Any] = {
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
    if validate_waf_verdict(waf_verdict) != WAF_VERDICT_UNRECORDED:
        envelope["waf_verdict"] = waf_verdict
    return json.dumps(envelope, sort_keys=True, separators=(",", ":")).encode()


def build_stream_merkle_leaf(
    *,
    state_id: str,
    request_hash: str,
    response_hash: str,
    request_size: int,
    response_size: int,
    request_preview: bytes,
    response_preview: bytes,
    model: str,
    endpoint: str,
    terminal_outcome: str,
    final_marker_included: bool,
    token_count: int,
    redaction_hits: dict[str, int],
) -> bytes:
    """Canonical version-2 MMR leaf for an incrementally hashed stream."""
    envelope = {
        "endpoint": endpoint,
        "final_marker_included": final_marker_included,
        "leaf_version": 2,
        "model": model,
        "redaction_hits": dict(sorted(redaction_hits.items())),
        "request_hash": request_hash,
        "request_preview_hex": request_preview.hex(),
        "request_size": request_size,
        "response_hash": response_hash,
        "response_preview_hex": response_preview.hex(),
        "response_size": response_size,
        "state_id": state_id,
        "terminal_outcome": terminal_outcome,
        "token_count": token_count,
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
