from __future__ import annotations

import sys
from uuid import uuid4

from aegis_sdk.integrations import AegisLangChainCallback, MemoryMetricSink, ProofStatus
from aegis_sdk.integrations._types import PrivacyCallbackCore

SENTINEL = "PROMPT_RESPONSE_TOKEN_SECRET_9b8e"


class FailingSink:
    def emit(self, metric: object) -> None:
        del metric
        raise RuntimeError(SENTINEL)


def test_sink_failure_is_contained_from_host_framework() -> None:
    core = PrivacyCallbackCore("langchain", FailingSink())
    core.begin("run-1", "llm", 1)
    metric = core.finish("run-1", output_count=1)
    assert metric.correlation_id == "run-1"
    assert core.sink_failures == 1


def test_callback_keeps_only_counts_and_correlation() -> None:
    sink = MemoryMetricSink()
    callback = AegisLangChainCallback(sink)
    run_id = uuid4()
    callback.on_llm_start({}, [SENTINEL, SENTINEL], run_id=run_id)
    callback.on_llm_end({"generations": [[SENTINEL]]}, run_id=run_id)

    metric = sink.snapshot()[0]
    assert metric.input_count == 2
    assert metric.output_count == 1
    assert metric.correlation_id == str(run_id)
    assert metric.proof_status is ProofStatus.NOT_PROVIDED
    assert SENTINEL not in repr(metric)
    assert "langchain" not in sys.modules
    assert "langchain_core" not in sys.modules


def test_exception_text_is_never_retained() -> None:
    sink = MemoryMetricSink()
    callback = AegisLangChainCallback(sink)
    callback.on_chain_start({}, {"prompt": SENTINEL}, run_id="run-1")
    callback.on_chain_error(RuntimeError(SENTINEL), run_id="run-1")

    metric = sink.snapshot()[0]
    assert metric.failed is True
    assert SENTINEL not in repr(metric)


def test_invalid_proof_is_status_only() -> None:
    sink = MemoryMetricSink()
    callback = AegisLangChainCallback(sink, trusted_root="0" * 64)
    callback.on_tool_start({}, SENTINEL, run_id="run-2")
    callback.on_tool_end(
        SENTINEL,
        run_id="run-2",
        aegis_proof_headers={"x-aegis-mmr-root": SENTINEL},
    )
    assert sink.snapshot()[0].proof_status is ProofStatus.INVALID
    assert SENTINEL not in repr(sink.snapshot()[0])
