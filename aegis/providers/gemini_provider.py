# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.providers.gemini_provider — Google Gemini adapter.

Uses Google's OpenAI-compatible endpoint:
    https://generativelanguage.googleapis.com/v1beta/openai/

This endpoint accepts the standard OpenAI /v1/chat/completions payload and
returns an OpenAI-compatible response, so no request/response translation
is required.  Authentication uses a query-param API key or Bearer token.

Logprobs support: partial (depends on model; handled gracefully).

References:
  https://ai.google.dev/gemini-api/docs/openai (Google AI for Developers)

Dependencies: stdlib only.
"""
from __future__ import annotations

from typing import Any

from aegis.providers.base import ProviderAdapter

_GEMINI_OPENAI_BASE = "https://generativelanguage.googleapis.com/v1beta/openai"


class GeminiAdapter(ProviderAdapter):
    """
    Adapter for Google Gemini via the OpenAI-compatible endpoint.

    Supported models (as of 2026-06):
        gemini-2.0-flash, gemini-2.0-pro, gemini-1.5-pro, gemini-1.5-flash

    Set AEGIS_BACKEND_API_KEY to your Google AI API key.
    Set AEGIS_PROVIDER_MODEL to override the model name (e.g. 'gemini-2.0-flash').

    Logprobs: Gemini supports logprobs for select models.  When not available,
    Aegis falls back to text-level entropy estimation.
    """

    def __init__(self, base_url: str = "") -> None:
        self._base_url = base_url.rstrip("/") if base_url else _GEMINI_OPENAI_BASE

    @property
    def name(self) -> str:
        return "gemini"

    @property
    def base_url_override(self) -> str | None:
        return self._base_url

    def build_headers(self, api_key: str) -> dict[str, str]:
        # Google AI accepts Bearer token same as OpenAI.
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"
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
        # Gemini's OpenAI-compat endpoint doesn't support all OpenAI params.
        # Strip unsupported fields to avoid 400 errors.
        _UNSUPPORTED = {"logit_bias", "suffix", "best_of", "echo"}
        for key in _UNSUPPORTED:
            out.pop(key, None)
        return path, out
