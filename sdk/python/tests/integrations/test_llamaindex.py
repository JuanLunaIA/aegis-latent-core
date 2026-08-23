# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import sys
from enum import StrEnum

from aegis_sdk.integrations import AegisLlamaIndexCallback, MemoryMetricSink

SENTINEL = "NODE_EMBEDDING_TOKEN_SECRET_2a71"


class EventType(StrEnum):
    LLM = "llm"
    EMBEDDING = "embedding"


def test_payload_and_node_content_is_not_retained() -> None:
    sink = MemoryMetricSink()
    callback = AegisLlamaIndexCallback(sink)
    callback.on_event_start(EventType.EMBEDDING, {"nodes": [SENTINEL]}, "event-1")
    callback.on_event_end(EventType.EMBEDDING, {"embeddings": [SENTINEL]}, "event-1")

    metric = sink.snapshot()[0]
    assert metric.operation == "embedding"
    assert metric.input_count == 1
    assert metric.output_count == 1
    assert SENTINEL not in repr(metric)
    assert "llama_index" not in sys.modules


def test_memory_sink_is_bounded() -> None:
    sink = MemoryMetricSink(capacity=2)
    callback = AegisLlamaIndexCallback(sink)
    for index in range(3):
        event_id = f"event-{index}"
        callback.on_event_start(EventType.LLM, {"prompt": SENTINEL}, event_id)
        callback.on_event_end(EventType.LLM, {"response": SENTINEL}, event_id)

    metrics = sink.snapshot()
    assert len(metrics) == 2
    assert [metric.correlation_id for metric in metrics] == ["event-1", "event-2"]
    assert SENTINEL not in repr(metrics)


def test_trace_hooks_do_not_retain_trace_map_content() -> None:
    callback = AegisLlamaIndexCallback()
    callback.start_trace("trace-1")
    callback.end_trace("trace-1", {SENTINEL: [SENTINEL]})
    assert SENTINEL not in repr(callback)
