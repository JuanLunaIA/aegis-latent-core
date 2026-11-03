# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Report committed requests to the Aegis Cloud control plane for metering.

Enabled only when both ``AEGIS_CLOUD_URL`` and ``AEGIS_CLOUD_API_KEY`` are
set. The gateway calls :func:`report_usage` after a request's evidence is
durable, so only committed requests are billed. Reporting runs in the
background and never delays, alters or withholds the response: evidence
ordering stays the gateway's own fail-closed boundary, metering is downstream
of it.

``request_id`` is the idempotency key on the control plane, so a retried POST
is never counted twice. The API key is only ever sent over HTTPS (or to a
loopback address for local testing) and is never logged.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import os
from typing import Any
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)

# Mirrors the control-plane contract (aegis-cloud app/schemas.py).
MAX_TOKENS = 10_000_000
_MAX_MODEL = 120
_MAX_PROVIDER = 60
_MAX_TOOL_CALLS = 1000

_RETRY_DELAYS: tuple[float, ...] = (0.5, 2.0, 8.0)
_TIMEOUT = httpx.Timeout(5.0)
# Test seam; production uses the default network transport.
_TRANSPORT: httpx.AsyncBaseTransport | None = None
# The gateway's airgap EgressGuard, installed at startup. Metering must obey the
# same allowlist as the upstream forwarder: AEGIS_CLOUD_URL's host has to be in
# AEGIS_AIRGAP_ALLOWED_HOSTS when airgap mode is on.
# ponytail: process-global, last create_app() wins; fine for one app per process.
_EGRESS_GUARD: Any = None
# Strong references so scheduled reports are not garbage-collected mid-flight.
# ponytail: in-memory only; a crash loses unsent reports. Move to the terminal
# outbox if billing must survive process death.
_PENDING: set[asyncio.Task[bool]] = set()

Usage = tuple[int, int, int]  # (input_tokens, output_tokens, tool_calls)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def cloud_config() -> tuple[str, str] | None:
    """Return ``(base_url, api_key)`` or ``None`` when metering is off or unsafe."""
    url = os.environ.get("AEGIS_CLOUD_URL", "").strip().rstrip("/")
    key = os.environ.get("AEGIS_CLOUD_API_KEY", "").strip()
    if not url or not key:
        return None
    parts = urlsplit(url)
    host = parts.hostname or ""
    if parts.scheme == "https" and host:
        return url, key
    if parts.scheme == "http" and _is_loopback(host):
        return url, key
    logger.error("AEGIS_CLOUD_URL must be https (or loopback http); usage metering disabled")
    return None


def _count(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return min(value, MAX_TOKENS)


def usage_from_response(provider: str, response_json: object, request_bytes: bytes) -> Usage:
    """Billable counts from a provider response, estimating input when it is absent.

    The control plane bills on the input-size tier, so a missing ``usage`` block
    falls back to ~4 bytes per token of the request body rather than zero.
    """
    estimated_input = min(len(request_bytes) // 4, MAX_TOKENS)
    if not isinstance(response_json, dict):
        return estimated_input, 0, 0
    usage = response_json.get("usage")
    usage = usage if isinstance(usage, dict) else {}
    in_field, out_field = (
        ("input_tokens", "output_tokens")
        if provider == "anthropic"
        else ("prompt_tokens", "completion_tokens")
    )
    inp = _count(usage.get(in_field))
    out = _count(usage.get(out_field)) or 0
    tools = 0
    if provider == "anthropic":
        content = response_json.get("content")
        if isinstance(content, list):
            tools = sum(1 for b in content if isinstance(b, dict) and b.get("type") == "tool_use")
    else:
        choices = response_json.get("choices")
        if isinstance(choices, list):
            for choice in choices:
                message = choice.get("message") if isinstance(choice, dict) else None
                calls = message.get("tool_calls") if isinstance(message, dict) else None
                if isinstance(calls, list):
                    tools += len(calls)
    return (estimated_input if inp is None else inp), out, min(tools, _MAX_TOOL_CALLS)


async def send_usage(
    request_id: str,
    *,
    model: str,
    provider: str,
    usage: Usage,
    transport: httpx.AsyncBaseTransport | None = None,
) -> bool:
    """POST one usage event, retrying 5xx and network errors a bounded number of times."""
    cfg = cloud_config()
    if cfg is None:
        return False
    base_url, key = cfg
    if _EGRESS_GUARD is not None and not _EGRESS_GUARD.is_allowed(base_url):
        logger.error(
            "usage report blocked by airgap egress guard: request_id=%s "
            "(add the AEGIS_CLOUD_URL host to AEGIS_AIRGAP_ALLOWED_HOSTS)",
            request_id,
        )
        return False
    inp, out, tools = usage
    payload: dict[str, Any] = {
        "request_id": request_id,
        "model": (model or "unknown")[:_MAX_MODEL],
        "provider": (provider or "unknown")[:_MAX_PROVIDER],
        "input_tokens": inp,
        "output_tokens": out,
        "tool_calls": tools,
    }
    reason = "not attempted"
    async with httpx.AsyncClient(
        timeout=_TIMEOUT, transport=transport or _TRANSPORT, follow_redirects=False
    ) as client:
        for attempt in range(len(_RETRY_DELAYS) + 1):
            try:
                resp = await client.post(
                    f"{base_url}/v1/usage", json=payload, headers={"x-aegis-key": key}
                )
            except httpx.HTTPError as exc:
                reason = type(exc).__name__
            else:
                if resp.status_code < 300:
                    return True
                if resp.status_code < 500:
                    # 402 = plan limit or evaluation expired; 401/403 = bad key;
                    # 422 = contract mismatch. Retrying cannot change any of them.
                    logger.error(
                        "usage report rejected: request_id=%s status=%s",
                        request_id,
                        resp.status_code,
                    )
                    return False
                reason = f"HTTP {resp.status_code}"
            if attempt < len(_RETRY_DELAYS):
                await asyncio.sleep(_RETRY_DELAYS[attempt])
    logger.error("usage report lost after retries: request_id=%s last=%s", request_id, reason)
    return False


def report_usage(request_id: str, *, model: str, provider: str, usage: Usage) -> bool:
    """Schedule a background report. Returns False when metering is not configured."""
    if cloud_config() is None:
        return False
    task = asyncio.get_running_loop().create_task(
        send_usage(request_id, model=model, provider=provider, usage=usage)
    )
    _PENDING.add(task)
    task.add_done_callback(_finished)
    return True


def _finished(task: asyncio.Task[bool]) -> None:
    _PENDING.discard(task)
    if not task.cancelled() and (exc := task.exception()) is not None:
        logger.error("usage report crashed: %s", type(exc).__name__, exc_info=exc)


async def drain(timeout: float) -> None:
    """Wait for in-flight reports at shutdown, then cancel what is left."""
    if not _PENDING:
        return
    pending = set(_PENDING)
    _, still = await asyncio.wait(pending, timeout=timeout)
    for task in still:
        task.cancel()
    if still:
        logger.error("usage reports cancelled at shutdown: %d", len(still))
