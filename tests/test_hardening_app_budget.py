# Copyright (c) 2026 Juan Luna.
# SPDX-License-Identifier: Apache-2.0
"""A successful provider response must not override denied quota settlement."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from aegis.config import AegisSettings
from aegis.proxy.app import create_app
from aegis.proxy.rate_limiter import (
    DualRateLimiter,
    LocalRateLimitBackend,
    RateLimitBackendUnavailableError,
)


@pytest.mark.parametrize("endpoint", ["/v1/chat/completions", "/v1/messages", "/v1/completions"])
@pytest.mark.parametrize("unavailable", [False, True])
@pytest.mark.parametrize("storage_failure", [False, True])
async def test_settlement_refuses_output_and_records_terminal_error(
    tmp_path: Path,
    endpoint: str,
    unavailable: bool,
    storage_failure: bool,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    app = create_app(
        AegisSettings(
            security_enforcement_mode="development",
            api_keys="test-budget-key",
            backend_api_key="test-provider-key",
            wal_path=str(tmp_path / "audit.jsonl"),
            signing_key="test-signing-key-for-local-fixture",
            waf_strict_mode=False,
            analysis_sample_rate=0,
            force_logprobs=False,
        )
    )
    state = app.state.aegis
    if storage_failure:

        def fail_commit(**kwargs):
            raise OSError("injected terminal storage failure")

        monkeypatch.setattr(state.ledger, "commit_forensic", fail_commit)

    class Backend(LocalRateLimitBackend):
        async def apply(self, charges, now):
            if unavailable and len(charges) == 1:
                raise RateLimitBackendUnavailableError("injected settlement outage")
            return await super().apply(charges, now)

    state.ratelimiter = DualRateLimiter(
        request_capacity=10,
        request_refill_per_second=0,
        token_capacity=5,
        token_refill_per_second=0,
        backend=Backend(),
        clock=lambda: 0,
    )

    class Upstream:
        provider = SimpleNamespace(supports_logprobs=False, name="anthropic")

        async def forward_json(self, *args, **kwargs):
            return httpx.Response(
                200,
                json={
                    "choices": [
                        {"message": {"content": "must-not-release"}, "text": "must-not-release"}
                    ],
                    "content": [{"type": "text", "text": "must-not-release"}],
                    "usage": {"completion_tokens": 6, "output_tokens": 6},
                },
            )

        forward_native_anthropic = forward_json

    state.forwarder = Upstream()
    try:
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app, raise_app_exceptions=False),
            base_url="http://test",
        ) as client:
            result = await client.post(
                endpoint,
                headers={"Authorization": "Bearer test-budget-key"},
                json={
                    "model": "test-model",
                    "messages": [{"role": "user", "content": "Hello"}],
                    "prompt": "Hello",
                    "max_tokens": 1,
                },
            )
        assert result.status_code == (503 if unavailable or storage_failure else 429)
        assert b"must-not-release" not in result.content
        # Forwarding already happened: record a terminal error, not a
        # pre-admission rejection falsely implying no model was contacted.
        if storage_failure:
            assert result.headers.get("x-aegis-evidence-status") != "durable"
            assert len(state.ledger.chain) == 0
        else:
            assert result.headers["x-aegis-evidence-status"] == "durable"
            assert len(state.ledger.chain) == 1
        assert state.ledger.verify_integrity()[0]
    finally:
        state.ledger.close()
        await state.ratelimiter.close()
