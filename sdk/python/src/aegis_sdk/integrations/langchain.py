# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Content-free LangChain callbacks.

This module intentionally does not import LangChain.  The callback protocol is
structural, so importing :mod:`aegis_sdk` never installs or imports an optional
framework and the handler works across LangChain callback API revisions.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from aegis_sdk.integrations._types import (
    MetricSink,
    PrivacyCallbackCore,
    item_count,
    proof_headers,
)


class AegisLangChainCallback:
    """Record only operation counts, timing, correlation, failure and proof state."""

    raise_error = False
    run_inline = False

    def __init__(self, sink: MetricSink | None = None, *, trusted_root: str | None = None) -> None:
        self._core = PrivacyCallbackCore("langchain", sink, trusted_root=trusted_root)

    @property
    def sink(self) -> MetricSink:
        return self._core.sink

    def _start(
        self,
        operation: str,
        values: object,
        *,
        run_id: object,
        parent_run_id: object = None,
    ) -> None:
        self._core.begin(run_id, operation, item_count(values), parent_run_id)

    def _end(self, value: object, *, run_id: object, failed: bool = False, **kwargs: Any) -> None:
        self._core.finish(
            run_id,
            output_count=item_count(value),
            failed=failed,
            proof_headers=proof_headers(kwargs.get("aegis_proof_headers")),
        )

    def on_llm_start(
        self,
        serialized: Mapping[str, Any],
        prompts: list[str],
        *,
        run_id: object,
        parent_run_id: object = None,
        **kwargs: Any,
    ) -> None:
        self._start("llm", prompts, run_id=run_id, parent_run_id=parent_run_id)

    def on_chat_model_start(
        self,
        serialized: Mapping[str, Any],
        messages: list[list[Any]],
        *,
        run_id: object,
        parent_run_id: object = None,
        **kwargs: Any,
    ) -> None:
        self._start("chat", messages, run_id=run_id, parent_run_id=parent_run_id)

    def on_chain_start(
        self,
        serialized: Mapping[str, Any],
        inputs: object,
        *,
        run_id: object,
        parent_run_id: object = None,
        **kwargs: Any,
    ) -> None:
        self._start("chain", inputs, run_id=run_id, parent_run_id=parent_run_id)

    def on_tool_start(
        self,
        serialized: Mapping[str, Any],
        input_str: str,
        *,
        run_id: object,
        parent_run_id: object = None,
        **kwargs: Any,
    ) -> None:
        self._start("tool", input_str, run_id=run_id, parent_run_id=parent_run_id)

    def on_retriever_start(
        self,
        serialized: Mapping[str, Any],
        query: str,
        *,
        run_id: object,
        parent_run_id: object = None,
        **kwargs: Any,
    ) -> None:
        self._start("retriever", query, run_id=run_id, parent_run_id=parent_run_id)

    def on_llm_end(self, response: object, *, run_id: object, **kwargs: Any) -> None:
        self._end(response, run_id=run_id, **kwargs)

    def on_chat_model_end(self, response: object, *, run_id: object, **kwargs: Any) -> None:
        self._end(response, run_id=run_id, **kwargs)

    def on_chain_end(self, outputs: object, *, run_id: object, **kwargs: Any) -> None:
        self._end(outputs, run_id=run_id, **kwargs)

    def on_tool_end(self, output: object, *, run_id: object, **kwargs: Any) -> None:
        self._end(output, run_id=run_id, **kwargs)

    def on_retriever_end(self, documents: object, *, run_id: object, **kwargs: Any) -> None:
        self._end(documents, run_id=run_id, **kwargs)

    def on_llm_error(self, error: BaseException, *, run_id: object, **kwargs: Any) -> None:
        self._end(None, run_id=run_id, failed=True, **kwargs)

    def on_chain_error(self, error: BaseException, *, run_id: object, **kwargs: Any) -> None:
        self._end(None, run_id=run_id, failed=True, **kwargs)

    def on_tool_error(self, error: BaseException, *, run_id: object, **kwargs: Any) -> None:
        self._end(None, run_id=run_id, failed=True, **kwargs)

    def on_retriever_error(self, error: BaseException, *, run_id: object, **kwargs: Any) -> None:
        self._end(None, run_id=run_id, failed=True, **kwargs)


LangChainCallbackHandler = AegisLangChainCallback

__all__ = ["AegisLangChainCallback", "LangChainCallbackHandler"]
