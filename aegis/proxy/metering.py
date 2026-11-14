# Copyright (c) 2026 Juan Luna. All rights reserved.
# SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
# Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
"""Report committed requests to the Aegis Cloud control plane for metering.

Enabled only when ``AEGIS_CLOUD_URL`` and ``AEGIS_CLOUD_INTERNAL_HMAC`` are both
set. The gateway records an event after a request's evidence is durable, so only
committed requests are billed, and it never delays, alters or withholds the
response for metering.

Events go to an append-only JSONL outbox on disk, not to memory, so a process
restart does not lose them. A background task rotates the outbox into a segment,
groups its events by organisation and posts them to ``/v1/usage/batch`` over the
control plane's internal HMAC channel (timestamp, nonce, method, path and body
digest; see aegis-cloud ``app/internal_auth.py``). Retries are idempotent: the
batch id is a digest of the batch's request ids, and the control plane also
deduplicates each event by ``request_id``. A 4xx is final for that batch and is
moved to a ``.rejected`` file; a 5xx or network error keeps the segment for the
next pass.

The organisation is the authenticated principal's ``tenant_id``, never a request
header. A tenant id that is not a valid organisation slug is not reported.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import httpx

logger = logging.getLogger(__name__)

# Mirrors the control-plane contract (aegis-cloud app/schemas.py).
MAX_TOKENS = 10_000_000
MAX_BATCH_EVENTS = 100
_MAX_MODEL = 120
_MAX_PROVIDER = 60
_MAX_TOOL_CALLS = 1000
_SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,79}$")
_MIN_SECRET = 32
_BATCH_PATH = "/v1/usage/batch"
# The spool lives beside the evidence WAL: an unbounded backlog during a long
# Cloud outage could fill the volume and make evidence commits fail, so new
# events are dropped (and logged) once the spool reaches this size.
DEFAULT_MAX_SPOOL_BYTES = 64 * 1024 * 1024
_TIMEOUT = httpx.Timeout(5.0)

Usage = tuple[int, int, int]  # (input_tokens, output_tokens, tool_calls)


def _is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def cloud_config() -> tuple[str, str] | None:
    """Return ``(base_url, hmac_secret)`` or ``None`` when metering is off or unsafe."""
    url = os.environ.get("AEGIS_CLOUD_URL", "").strip().rstrip("/")
    secret = os.environ.get("AEGIS_CLOUD_INTERNAL_HMAC", "").strip()
    if not url or not secret:
        return None
    if len(secret) < _MIN_SECRET:
        logger.error("AEGIS_CLOUD_INTERNAL_HMAC is shorter than 32 characters; metering disabled")
        return None
    parts = urlsplit(url)
    host = parts.hostname or ""
    if (parts.scheme == "https" and host) or (parts.scheme == "http" and _is_loopback(host)):
        return url, secret
    logger.error("AEGIS_CLOUD_URL must be https (or loopback http); usage metering disabled")
    return None


def sign(secret: str, *, timestamp: str, nonce: str, method: str, path: str, body: bytes) -> str:
    """HMAC-SHA256 over the control plane's canonical request bytes."""
    message = (
        f"{timestamp}\n{nonce}\n{method.upper()}\n{path}\n{hashlib.sha256(body).hexdigest()}"
    ).encode()
    return hmac.new(secret.encode("utf-8"), message, hashlib.sha256).hexdigest()


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


class UsageOutbox:
    """Durable JSONL outbox plus the flusher that drains it to the control plane."""

    def __init__(
        self,
        path: Path,
        *,
        egress_guard: Any = None,
        transport: httpx.AsyncBaseTransport | None = None,
        max_spool_bytes: int = DEFAULT_MAX_SPOOL_BYTES,
    ) -> None:
        self.path = path
        self.rejected_path = path.with_name(path.name + ".rejected")
        self._egress_guard = egress_guard
        self._transport = transport
        self._max_bytes = max_spool_bytes
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        self._spool_bytes = self._measure()

    def _measure(self) -> int:
        """Bytes held by the outbox and its pending segments."""
        files = [self.path, *self._segments()]
        return sum(f.stat().st_size for f in files if f.exists())

    # ── write side (request path) ───────────────────────────────────────────
    def record(
        self, request_id: str, *, tenant_id: str, model: str, provider: str, usage: Usage
    ) -> bool:
        """Append one event. False when the tenant is not a reportable organisation."""
        if not _SLUG_RE.fullmatch(tenant_id or ""):
            logger.warning("usage not reported: tenant is not an organisation slug")
            return False
        inp, out, tools = usage
        line = json.dumps(
            {
                "org_slug": tenant_id,
                "request_id": request_id[:128],
                "model": (model or "unknown")[:_MAX_MODEL],
                "provider": (provider or "unknown")[:_MAX_PROVIDER],
                "input_tokens": inp,
                "output_tokens": out,
                "tool_calls": tools,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            },
            separators=(",", ":"),
        )
        data = line + "\n"
        # write+flush only, into the page cache: the flusher fsyncs the segment
        # it takes (outside this lock), so a process crash loses nothing and a
        # host crash loses at most one flush interval.
        with self._lock:
            if self._spool_bytes + len(data) > self._max_bytes:
                logger.error("usage not recorded: metering spool is full (Cloud unreachable?)")
                return False
            with self.path.open("a", encoding="utf-8") as handle:
                handle.write(data)
                handle.flush()
            self._spool_bytes += len(data)
        return True

    # ── read side (background) ──────────────────────────────────────────────
    def _rotate(self) -> None:
        segment = self.path.with_name(f"{self.path.name}.{time.time_ns()}.sending")
        with self._lock:
            if not (self.path.exists() and self.path.stat().st_size > 0):
                return
            os.replace(self.path, segment)
        # fsync after releasing the lock, so request-path appends never wait on disk.
        with segment.open("rb") as handle:
            os.fsync(handle.fileno())

    def _segments(self) -> list[Path]:
        return sorted(self.path.parent.glob(f"{self.path.name}.*.sending"))

    async def flush_once(self) -> int:
        """Send every pending segment once. Returns the number of events accepted."""
        cfg = cloud_config()
        if cfg is None:
            return 0
        base_url, secret = cfg
        if self._egress_guard is not None and not self._egress_guard.is_allowed(base_url):
            logger.error(
                "usage reports blocked by airgap egress guard "
                "(add the AEGIS_CLOUD_URL host to AEGIS_AIRGAP_ALLOWED_HOSTS)"
            )
            return 0
        await asyncio.to_thread(self._rotate)
        accepted = 0
        async with httpx.AsyncClient(
            timeout=_TIMEOUT, transport=self._transport, follow_redirects=False
        ) as client:
            for segment in self._segments():
                sent, remaining = await self._send_segment(client, base_url, secret, segment)
                accepted += sent
                await asyncio.to_thread(self._settle, segment, remaining)
        await asyncio.to_thread(self._remeasure)
        return accepted

    def _remeasure(self) -> None:
        with self._lock:
            self._spool_bytes = self._measure()

    @staticmethod
    def _settle(segment: Path, remaining: list[str]) -> None:
        """Drop a finished segment, or shrink it to the events still to retry."""
        if not remaining:
            segment.unlink(missing_ok=True)
            return
        tmp = segment.with_name(segment.name + ".tmp")
        with tmp.open("w", encoding="utf-8") as handle:
            handle.write("\n".join(remaining) + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp, segment)

    async def _send_segment(
        self, client: httpx.AsyncClient, base_url: str, secret: str, segment: Path
    ) -> tuple[int, list[str]]:
        by_org: dict[str, list[dict[str, Any]]] = {}
        for raw in segment.read_text(encoding="utf-8").splitlines():
            try:
                event = json.loads(raw)
                org = event.pop("org_slug")
            except (ValueError, KeyError, AttributeError):
                continue  # a torn final line from a crash mid-write
            by_org.setdefault(org, []).append(event)
        accepted = 0
        remaining: list[str] = []
        for org, events in by_org.items():
            for start in range(0, len(events), MAX_BATCH_EVENTS):
                chunk = events[start : start + MAX_BATCH_EVENTS]
                outcome = await self._post(client, base_url, secret, org, chunk)
                if outcome == "accepted":
                    accepted += len(chunk)
                elif outcome == "rejected":
                    await asyncio.to_thread(self._dead_letter, org, chunk)
                else:
                    remaining.extend(
                        json.dumps({"org_slug": org, **e}, separators=(",", ":")) for e in chunk
                    )
        return accepted, remaining

    async def _post(
        self,
        client: httpx.AsyncClient,
        base_url: str,
        secret: str,
        org: str,
        events: list[dict[str, Any]],
    ) -> str:
        ids = "\n".join(sorted(e["request_id"] for e in events))
        batch_id = hashlib.sha256(f"{org}\n{ids}".encode()).hexdigest()[:64]
        body = json.dumps(
            {"org_slug": org, "batch_id": batch_id, "events": events}, separators=(",", ":")
        ).encode()
        timestamp = str(int(time.time()))
        nonce = secrets.token_hex(16)
        headers = {
            "content-type": "application/json",
            "x-aegis-timestamp": timestamp,
            "x-aegis-nonce": nonce,
            "x-aegis-signature": sign(
                secret,
                timestamp=timestamp,
                nonce=nonce,
                method="POST",
                path=_BATCH_PATH,
                body=body,
            ),
        }
        try:
            resp = await client.post(f"{base_url}{_BATCH_PATH}", content=body, headers=headers)
        except httpx.HTTPError as exc:
            logger.warning("usage batch not sent: org=%s error=%s", org, type(exc).__name__)
            return "retry"
        if resp.status_code < 300:
            return "accepted"
        if resp.status_code in (401, 409, 429) or resp.status_code >= 500:
            # 401 can be clock skew, 409 a nonce collision, 429/5xx transient.
            logger.warning("usage batch deferred: org=%s status=%s", org, resp.status_code)
            return "retry"
        # 402 plan limit, 404 unknown org, 422 contract mismatch: retrying cannot help.
        logger.error("usage batch rejected: org=%s status=%s", org, resp.status_code)
        return "rejected"

    def _dead_letter(self, org: str, events: list[dict[str, Any]]) -> None:
        if self.rejected_path.exists() and self.rejected_path.stat().st_size >= self._max_bytes:
            logger.error("rejected usage dropped: %d events, rejected file is full", len(events))
            return
        with self.rejected_path.open("a", encoding="utf-8") as handle:
            for event in events:
                handle.write(json.dumps({"org_slug": org, **event}, separators=(",", ":")) + "\n")
            handle.flush()
            os.fsync(handle.fileno())

    async def run(self, interval_seconds: float = 5.0) -> None:
        """Flush forever; a failed pass is logged and retried on the next tick."""
        while True:
            try:
                await self.flush_once()
            except Exception:  # noqa: BLE001 - the loop must survive one bad pass
                logger.exception("usage flush pass failed")
            await asyncio.sleep(interval_seconds)
