# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""Drop-in defaults for the official OpenAI Python clients."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

import httpx
import openai

from aegis_sdk._config import build_headers, normalize_gateway_url, require_trusted_root
from aegis_sdk.proof import verify_proof_headers


class OpenAI(openai.OpenAI):
    """Official ``openai.OpenAI`` routed through an Aegis gateway."""

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
        http_client: httpx.Client | None = None,
        **kwargs: Any,
    ) -> None:
        root = require_trusted_root(verify_proof, trusted_mmr_root)
        headers = build_headers(
            tenant_id=tenant_id,
            session_id=session_id,
            trace_context=trace_context,
            caller_headers=default_headers,
        )
        if verify_proof:
            assert root is not None

            def verify(response: httpx.Response) -> None:
                if response.headers.get("X-Aegis-Evidence-Status") == "pending-terminal":
                    return
                verify_proof_headers(response.headers, root)

            if http_client is None:
                http_client = httpx.Client(event_hooks={"response": [verify]})
            else:
                http_client.event_hooks.setdefault("response", []).append(verify)
        super().__init__(
            api_key=aegis_api_key,
            base_url=normalize_gateway_url(gateway_url, openai=True),
            default_headers=headers,
            http_client=http_client,
            **kwargs,
        )


class AsyncOpenAI(openai.AsyncOpenAI):
    """Official ``openai.AsyncOpenAI`` routed through an Aegis gateway."""

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
        http_client: httpx.AsyncClient | None = None,
        **kwargs: Any,
    ) -> None:
        root = require_trusted_root(verify_proof, trusted_mmr_root)
        headers = build_headers(
            tenant_id=tenant_id,
            session_id=session_id,
            trace_context=trace_context,
            caller_headers=default_headers,
        )
        if verify_proof:
            assert root is not None

            async def verify(response: httpx.Response) -> None:
                if response.headers.get("X-Aegis-Evidence-Status") == "pending-terminal":
                    return
                verify_proof_headers(response.headers, root)

            if http_client is None:
                http_client = httpx.AsyncClient(event_hooks={"response": [verify]})
            else:
                http_client.event_hooks.setdefault("response", []).append(verify)
        super().__init__(
            api_key=aegis_api_key,
            base_url=normalize_gateway_url(gateway_url, openai=True),
            default_headers=headers,
            http_client=http_client,
            **kwargs,
        )
