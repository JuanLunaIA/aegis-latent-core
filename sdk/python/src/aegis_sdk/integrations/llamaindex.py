# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Content-free LlamaIndex callback integration with no eager dependency import."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aegis_sdk.integrations._types import MetricSink, PrivacyCallbackCore, item_count, proof_headers

_EVENT_OPERATIONS = {
    "llm": "llm",
    "embedding": "embedding",
    "query": "query",
    "retrieve": "retriever",
    "retrieving": "retriever",
    "agent_step": "agent",
    "function_call": "tool",
}


class AegisLlamaIndexCallback:
    """LlamaIndex callback retaining no payload, node, embedding, or error content."""

    def __init__(self, sink: MetricSink | None = None, *, trusted_root: str | None = None) -> None:
        self._core = PrivacyCallbackCore("llamaindex", sink, trusted_root=trusted_root)

    @property
    def sink(self) -> MetricSink:
        return self._core.sink

    def on_event_start(
        self,
        event_type: object,
        payload: Mapping[str, Any] | None = None,
        event_id: str = "",
        parent_id: str = "",
        **kwargs: Any,
    ) -> str:
        identifier = event_id or str(kwargs.get("id_", "unassigned"))
        operation = _operation(event_type)
        self._core.begin(identifier, operation, item_count(payload), parent_id or None)
        return identifier

    def on_event_end(
        self,
        event_type: object,
        payload: Mapping[str, Any] | None = None,
        event_id: str = "",
        **kwargs: Any,
    ) -> None:
        identifier = event_id or str(kwargs.get("id_", "unassigned"))
        self._core.finish(
            identifier,
            output_count=item_count(payload),
            failed=bool(kwargs.get("failed", False)),
            proof_headers=proof_headers(kwargs.get("aegis_proof_headers")),
        )

    def start_trace(self, trace_id: str | None = None) -> None:
        # LlamaIndex requires this lifecycle hook; correlation remains event-scoped.
        if trace_id is not None and len(trace_id) > 128:
            raise ValueError("trace identifier is too long")

    def end_trace(
        self, trace_id: str | None = None, trace_map: Mapping[str, list[str]] | None = None
    ) -> None:
        # Validate only bounded structure; the trace map is never retained or traversed.
        if trace_id is not None and len(trace_id) > 128:
            raise ValueError("trace identifier is too long")


LlamaIndexCallbackHandler = AegisLlamaIndexCallback


def _operation(event_type: object) -> str:
    raw = getattr(event_type, "value", event_type)
    value = str(raw).lower()
    return _EVENT_OPERATIONS.get(value, "other")


__all__ = ["AegisLlamaIndexCallback", "LlamaIndexCallbackHandler"]
