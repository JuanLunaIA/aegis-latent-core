# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.providers.openai_provider — Passthrough adapter for OpenAI and any
OpenAI-compatible endpoint (local vLLM, LM Studio, llama.cpp server, etc.).

No translation is performed; all requests and responses pass through
unchanged.  The only job of this adapter is to set the Authorization header.

Also contains OpenRouterAdapter which is structurally identical except it
adds the optional HTTP-Referer / X-Title headers that OpenRouter uses for
analytics and rate-limiting tier selection.

Dependencies: none (stdlib only).
"""
from __future__ import annotations

from typing import Any

from aegis.providers.base import ProviderAdapter


class OpenAIAdapter(ProviderAdapter):
    """Passthrough adapter for OpenAI and compatible endpoints."""

    @property
    def name(self) -> str:
        return "openai"

    # All other methods use the base class defaults (no-op translation).


class OpenRouterAdapter(ProviderAdapter):
    """
    Adapter for OpenRouter (https://openrouter.ai).

    OpenRouter speaks the OpenAI API natively.  The only difference is:
    - Base URL: https://openrouter.ai/api/v1
    - Optional headers: HTTP-Referer and X-Title for routing/analytics.

    Set AEGIS_OPENROUTER_SITE_URL and AEGIS_OPENROUTER_SITE_NAME in your
    .env for best-effort routing to the relevant tier.
    """

    _DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"

    def __init__(
        self,
        site_url: str = "",
        site_name: str = "",
        base_url: str = "",
    ) -> None:
        self._site_url = site_url
        self._site_name = site_name
        self._base_url = base_url or self._DEFAULT_BASE_URL

    @property
    def name(self) -> str:
        return "openrouter"

    @property
    def base_url_override(self) -> str | None:
        return self._base_url

    def build_headers(self, api_key: str) -> dict[str, str]:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
        if self._site_url:
            headers["HTTP-Referer"] = self._site_url
        if self._site_name:
            headers["X-Title"] = self._site_name
        return headers

    def translate_request(
        self,
        path: str,
        body: dict[str, Any],
        model_override: str | None = None,
    ) -> tuple[str, dict[str, Any]]:
        out = dict(body)
        if model_override:
            out["model"] = model_override
        return path, out
