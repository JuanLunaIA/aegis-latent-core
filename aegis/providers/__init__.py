# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.providers — Multi-provider adapter registry.

Supported providers
-------------------
  openai       OpenAI API + any OpenAI-compatible endpoint (vLLM, llama.cpp, LM Studio)
  anthropic    Anthropic Claude — full bidirectional translation from OpenAI format
  gemini       Google Gemini via the OpenAI-compatible endpoint
  openrouter   OpenRouter.ai — routes to 300+ models; OpenAI-native with extra headers

Usage
-----
Set ``AEGIS_PROVIDER=anthropic`` (or openai/gemini/openrouter) in your ``.env``.
The forwarder picks up the adapter automatically on startup.

For models that need a base URL override (Anthropic, Gemini):
  - Anthropic: base URL is fixed to ``https://api.anthropic.com``
  - Gemini:    base URL is fixed to ``https://generativelanguage.googleapis.com/v1beta/openai``
  - OpenRouter: base URL is fixed to ``https://openrouter.ai/api/v1``
  - OpenAI:    base URL comes from ``AEGIS_BACKEND_URL``

To use a custom or self-hosted OpenAI-compatible endpoint (vLLM, Ollama, etc.):
  set ``AEGIS_PROVIDER=openai`` and ``AEGIS_BACKEND_URL=http://your-host:port``.
"""

from __future__ import annotations

import logging

from aegis.providers.anthropic_provider import AnthropicAdapter
from aegis.providers.base import ProviderAdapter
from aegis.providers.gemini_provider import GeminiAdapter
from aegis.providers.openai_provider import OpenAIAdapter, OpenRouterAdapter

logger = logging.getLogger(__name__)

# Public re-exports so callers can do `from aegis.providers import AnthropicAdapter`
__all__ = [
    "ProviderAdapter",
    "OpenAIAdapter",
    "OpenRouterAdapter",
    "GeminiAdapter",
    "AnthropicAdapter",
    "build_provider",
    "PROVIDER_NAMES",
]

# Canonical provider names → adapter classes.
_PROVIDER_REGISTRY: dict[str, type[ProviderAdapter]] = {
    "openai": OpenAIAdapter,
    "anthropic": AnthropicAdapter,
    "gemini": GeminiAdapter,
    "openrouter": OpenRouterAdapter,
}

# Public set of valid provider names for validation / help text.
PROVIDER_NAMES: frozenset[str] = frozenset(_PROVIDER_REGISTRY.keys())


def build_provider(
    name: str,
    *,
    # OpenRouter extras
    openrouter_site_url: str = "",
    openrouter_site_name: str = "",
    openrouter_base_url: str = "",
    # Anthropic extras
    anthropic_api_version: str = "2023-06-01",
    anthropic_base_url: str = "",
    # Gemini extras
    gemini_base_url: str = "",
) -> ProviderAdapter:
    """
    Instantiate a provider adapter by name with provider-specific options.

    Args:
        name:                   Provider identifier (see ``PROVIDER_NAMES``).
        openrouter_site_url:    HTTP-Referer for OpenRouter analytics.
        openrouter_site_name:   X-Title for OpenRouter analytics.
        openrouter_base_url:    Override OpenRouter base URL (testing only).
        anthropic_api_version:  Anthropic-Version header value.
        anthropic_base_url:     Override Anthropic base URL (testing only).
        gemini_base_url:        Override Gemini base URL (testing only).

    Returns:
        Configured ``ProviderAdapter`` instance.

    Raises:
        ValueError: If ``name`` is not in ``PROVIDER_NAMES``.
    """
    normalized = name.strip().lower()
    if normalized not in _PROVIDER_REGISTRY:
        raise ValueError(f"Unknown provider {name!r}. Valid options: {sorted(PROVIDER_NAMES)}")

    if normalized == "openrouter":
        adapter = OpenRouterAdapter(
            site_url=openrouter_site_url,
            site_name=openrouter_site_name,
            base_url=openrouter_base_url,
        )
    elif normalized == "anthropic":
        adapter = AnthropicAdapter(
            api_version=anthropic_api_version,
            base_url=anthropic_base_url,
        )
    elif normalized == "gemini":
        adapter = GeminiAdapter(base_url=gemini_base_url)
    else:
        adapter = OpenAIAdapter()

    logger.info(
        "aegis.providers: activated provider=%r base_url_override=%r logprobs=%s",
        adapter.name,
        adapter.base_url_override or "(from AEGIS_BACKEND_URL)",
        adapter.supports_logprobs,
    )
    return adapter
