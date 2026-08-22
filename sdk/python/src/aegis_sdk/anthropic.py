# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Drop-in defaults for the official Anthropic Python clients."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

import anthropic

from aegis_sdk._config import build_headers, normalize_gateway_url, require_trusted_root
from aegis_sdk.proof import verify_proof_headers


class _ProofMiddleware(anthropic.Middleware):
    def __init__(self, trusted_root: str) -> None:
        self._trusted_root = trusted_root

    def handle(self, request: anthropic.APIRequest, call_next: Any) -> anthropic.APIResponse[Any]:
        response: anthropic.APIResponse[Any] = call_next(request)
        if response.headers.get("X-Aegis-Evidence-Status") != "pending-terminal":
            verify_proof_headers(response.headers, self._trusted_root)
        return response

    async def handle_async(
        self, request: anthropic.APIRequest, call_next: Any
    ) -> anthropic.AsyncAPIResponse[Any]:
        response: anthropic.AsyncAPIResponse[Any] = await call_next(request)
        if response.headers.get("X-Aegis-Evidence-Status") != "pending-terminal":
            verify_proof_headers(response.headers, self._trusted_root)
        return response


class Anthropic(anthropic.Anthropic):
    """Official ``anthropic.Anthropic`` routed through an Aegis gateway.

    Native ``messages`` compatibility requires the gateway's native
    ``POST /v1/messages`` ingress; constructor compatibility alone cannot
    translate OpenAI wire shapes.
    """

    def __init__(
        self,
        *,
        aegis_api_key: str,
        gateway_url: str,
        tenant_id: str,
        session_id: str | None = None,
        trace_context: str | None = None,
        verify_proof: bool = False,
        trusted_mmr_root: str | None = None,
        default_headers: Mapping[str, str] | None = None,
        middleware: Sequence[Any] | None = None,
        **kwargs: Any,
    ) -> None:
        root = require_trusted_root(verify_proof, trusted_mmr_root)
        headers = build_headers(
            tenant_id=tenant_id,
            session_id=session_id,
            trace_context=trace_context,
            caller_headers=default_headers,
        )
        middleware_items = list(middleware or ())
        if verify_proof:
            assert root is not None
            middleware_items.append(_ProofMiddleware(root))
        super().__init__(
            auth_token=aegis_api_key,
            base_url=normalize_gateway_url(gateway_url, openai=False),
            default_headers=headers,
            middleware=middleware_items,
            **kwargs,
        )


class AsyncAnthropic(anthropic.AsyncAnthropic):
    """Official ``anthropic.AsyncAnthropic`` routed through Aegis."""

    def __init__(
        self,
        *,
        aegis_api_key: str,
        gateway_url: str,
        tenant_id: str,
        session_id: str | None = None,
        trace_context: str | None = None,
        verify_proof: bool = False,
        trusted_mmr_root: str | None = None,
        default_headers: Mapping[str, str] | None = None,
        middleware: Sequence[Any] | None = None,
        **kwargs: Any,
    ) -> None:
        root = require_trusted_root(verify_proof, trusted_mmr_root)
        headers = build_headers(
            tenant_id=tenant_id,
            session_id=session_id,
            trace_context=trace_context,
            caller_headers=default_headers,
        )
        middleware_items = list(middleware or ())
        if verify_proof:
            assert root is not None
            middleware_items.append(_ProofMiddleware(root))
        super().__init__(
            auth_token=aegis_api_key,
            base_url=normalize_gateway_url(gateway_url, openai=False),
            default_headers=headers,
            middleware=middleware_items,
            **kwargs,
        )
