# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis.providers.base — Abstract provider adapter interface.

Every supported LLM provider implements this ABC.  The proxy layer calls
these adapters to:
  1. Translate an incoming OpenAI-compatible request to the provider's
     native wire format.
  2. Build provider-specific HTTP headers (auth, versioning).
  3. Translate the provider's response back to the OpenAI wire format so
     the rest of the pipeline (forensic chain, audit ledger, streaming
     clients) is provider-agnostic.

For providers that speak OpenAI natively (openrouter, local vLLM, etc.)
the adapters are no-ops.  For providers with custom formats (Anthropic)
the adapters perform full bidirectional translation.

All async streaming translation helpers must yield bytes in the OpenAI
server-sent-events format:
    data: <json>\n\n
    data: [DONE]\n\n
"""
from __future__ import annotations

import abc
from collections.abc import AsyncIterator
from typing import Any


class ProviderAdapter(abc.ABC):
    """Bidirectional translator between OpenAI format and a provider's API."""

    # ── identity ──────────────────────────────────────────────────────────

    @property
    @abc.abstractmethod
    def name(self) -> str:
        """Short identifier, e.g. 'anthropic', 'openai', 'openrouter'."""

    @property
    def base_url_override(self) -> str | None:
        """Return a URL to use instead of the configured backend_url, or None."""
        return None

    # ── capabilities ─────────────────────────────────────────────────────

    @property
    def supports_logprobs(self) -> bool:
        """Whether this provider returns OpenAI-style logprobs.
        When False, force_logprobs injection is suppressed automatically.
        """
        return True

    @property
    def requires_stream_translation(self) -> bool:
        """Whether SSE streaming requires active translation.
        For providers that already stream in OpenAI format, return False.
        """
        return False

    # ── request / response translation ───────────────────────────────────

    def build_headers(self, api_key: str) -> dict[str, str]:
        """Return provider-specific HTTP headers.

        Args:
            api_key: The API key configured via AEGIS_BACKEND_API_KEY.

        Returns:
            Dict of HTTP headers to include in the upstream request.
            Subclasses should include Content-Type and any auth headers.
        """
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
        """Translate an OpenAI-format request to the provider's format.

        Args:
            path: Original request path, e.g. '/v1/chat/completions'.
            body: Parsed request body in OpenAI format.
            model_override: If set, replace the 'model' field in the
                request with this value before translation.

        Returns:
            Tuple of (provider_path, provider_body).
        """
        out = dict(body)
        if model_override:
            out["model"] = model_override
        return path, out

    def translate_response(
        self,
        response_bytes: bytes,
        original_model: str,
    ) -> bytes:
        """Translate a provider response to OpenAI format.

        Args:
            response_bytes: Raw response body bytes from the provider.
            original_model: The model name from the original client request.

        Returns:
            Response bytes in OpenAI format.
        """
        return response_bytes

    async def translate_stream(
        self,
        raw_lines: AsyncIterator[str],
        original_model: str,
        request_id: str,
        created: int,
    ) -> AsyncIterator[bytes]:
        """Translate a provider SSE stream to OpenAI SSE format.

        Only called when requires_stream_translation is True.

        Args:
            raw_lines: Async iterator of raw SSE lines from the provider.
            original_model: Model name from the original client request.
            request_id: UUID for the request (used as chunk ID).
            created: Unix timestamp for the response.

        Yields:
            Bytes in OpenAI SSE format ('data: {...}\\n\\n' or 'data: [DONE]\\n\\n').
        """
        raise NotImplementedError(
            f"Provider '{self.name}' has requires_stream_translation=True "
            "but did not implement translate_stream()"
        )
        # Required to make this an async generator at the type level:
        yield  # type: ignore[misc]  # pragma: no cover
