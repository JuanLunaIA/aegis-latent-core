"""
aegis.embedded — in-process evidence engine for applications that hold the
provider client themselves.

The gateway in :mod:`aegis.proxy.app` sits between an application and a model
provider as a separate network hop. That is the right shape when the boundary
is organisational — several teams, several languages, one enforcement point —
and the wrong shape when the boundary is a single Python process that already
holds an ``openai`` or ``anthropic`` client and cannot add a hop, such as a
Lambda handler or a batch job.

This module runs the same controls in that process:

    import aegis, openai
    client = aegis.wrap(openai.OpenAI())
    reply = client.chat.completions.create(model=..., messages=[...])
    reply._aegis_evidence          # node hash, root, inclusion proof

**What is identical to the gateway.** The WAF (:class:`~aegis.proxy.waf.AegisWAF`),
the Safe Harbor scrubber, the bounded-holdback streaming redactor, and the
append-only signed Merkle ledger are the same classes the gateway uses, so a
record committed here verifies with the same tooling and the same proofs.

**What is different, and matters for a threat model.** The gateway is a
separate process that the application cannot bypass; this runs inside the
application, so it constrains the calls that go through the wrapped client and
nothing else. Code in the same process can call the provider directly, hold a
second unwrapped client, or edit the WAL. It is an evidence and policy layer
for cooperative code, not a containment boundary against the process it runs
in. Where the application itself is the thing being constrained, the gateway is
the correct deployment and this is not a substitute for it.

Provider SDKs are not imported here and are not dependencies of this package.
Clients are recognised by shape — an object exposing ``chat.completions.create``
or ``messages.create`` — so this module imports cleanly whether or not either
SDK is installed, and a compatible client of any origin works.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import inspect
import json
import logging
import os
import time
import uuid
from collections.abc import AsyncIterator, Iterator
from dataclasses import dataclass, field
from types import TracebackType
from typing import Any

from aegis.core.crypto_audit import AuditNode, CryptographicAuditLedger
from aegis.core.forensic import sha256_hex
from aegis.core.phi_deidentifier import PHIDeidentifier
from aegis.core.streaming_deidentifier import StreamingDeidentifier
from aegis.proxy.waf import AegisWAF

logger = logging.getLogger(__name__)

__all__ = [
    "AegisBlockedError",
    "AegisEmbedded",
    "AegisEmbeddedError",
    "EmbeddedEvidence",
    "wrap",
]

#: Where evidence goes when the caller names no path. Deliberately explicit and
#: inside the working directory rather than a temporary directory: evidence that
#: silently lands somewhere the operating system may clear is worse than
#: evidence that lands somewhere obvious.
DEFAULT_STORAGE_PATH = ".aegis/embedded-evidence.jsonl"

_ENFORCEMENT_MODES = ("strict", "shadow")


class AegisEmbeddedError(RuntimeError):
    """Base class for embedded-engine failures."""


class AegisBlockedError(AegisEmbeddedError):
    """The in-process WAF refused the request; it was never sent upstream.

    Carries the committed rejection identifier when the refusal was recorded
    durably, so the caller can cite the evidence for the block.
    """

    def __init__(self, reason: str, *, rejection_id: str | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.rejection_id = rejection_id


@dataclass(frozen=True)
class EmbeddedEvidence:
    """The evidence attached to a response as ``_aegis_evidence``.

    Every field is derived from a node already committed to the ledger. The
    inclusion proof is self-contained: it verifies against a separately trusted
    root with :meth:`~aegis.core.mmr.MerkleMountainRange.verify_portable_inclusion`
    and needs neither this process nor the ledger file.
    """

    state_id: str
    node_hash: str
    merkle_root: str
    request_hash: str
    response_hash: str
    signature_scheme: str
    status: str
    mmr_leaf_index: int
    mmr_leaf_count: int
    mmr_proof: dict[str, Any] | None = None
    redaction_hits: dict[str, int] = field(default_factory=dict)

    @classmethod
    def from_node(
        cls, node: AuditNode, *, redaction_hits: dict[str, int] | None = None
    ) -> EmbeddedEvidence:
        return cls(
            state_id=node.state_id,
            node_hash=node.node_hash,
            merkle_root=node.merkle_root,
            request_hash=node.request_hash,
            response_hash=node.response_hash,
            signature_scheme=node.signature_scheme,
            status=node.status,
            mmr_leaf_index=node.mmr_leaf_index,
            mmr_leaf_count=node.mmr_leaf_count,
            mmr_proof=node.mmr_proof,
            redaction_hits=dict(redaction_hits or {}),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "state_id": self.state_id,
            "node_hash": self.node_hash,
            "merkle_root": self.merkle_root,
            "request_hash": self.request_hash,
            "response_hash": self.response_hash,
            "signature_scheme": self.signature_scheme,
            "status": self.status,
            "mmr_leaf_index": self.mmr_leaf_index,
            "mmr_leaf_count": self.mmr_leaf_count,
            "mmr_proof": self.mmr_proof,
            "redaction_hits": dict(self.redaction_hits),
        }


def _canonical_request_bytes(payload: dict[str, Any]) -> bytes:
    """Deterministic bytes for a request payload, for hashing only."""
    try:
        return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode()
    except (TypeError, ValueError):
        return repr(payload).encode()


def _attach(response: object, evidence: EmbeddedEvidence) -> None:
    """Attach evidence to a provider response object without failing the call.

    Provider models are ordinarily mutable pydantic objects. A model that
    refuses the attribute still returns its content to the caller, and the
    evidence is committed either way — the ledger, not the response object, is
    the record. Losing the convenience accessor is not worth raising over.
    """
    try:
        object.__setattr__(response, "_aegis_evidence", evidence)
    except (AttributeError, TypeError):  # pragma: no cover - exotic response types
        logger.warning(
            "could not attach _aegis_evidence to a %s; the node is committed regardless",
            type(response).__name__,
        )


class AegisEmbedded:
    """In-process WAF, redaction and signed evidence ledger.

    Owns a :class:`~aegis.core.crypto_audit.CryptographicAuditLedger` writing to
    a local JSONL WAL. One instance holds one WAL path, and the ledger takes an
    exclusive advisory lock on it, so two engines cannot fork one evidence
    chain — construct one per process and share it.

    Args:
        storage_path: WAL path. Defaults to :data:`DEFAULT_STORAGE_PATH`.
        signing_key: HMAC-SHA256 key. Empty falls back to an ephemeral Ed25519
            key, which makes records self-consistent but not attributable
            across restarts; the ledger reports that as reduced admissibility.
        enforcement_mode: ``"strict"`` blocks on a WAF detection; ``"shadow"``
            records the detection and lets the request through.
        redact_requests: Apply Safe Harbor scrubbing to prompt text before it
            leaves the process.
        redact_responses: Apply bounded-holdback redaction to streamed output.
        tenant_id: Attribution recorded on every node.
        window_chars: Streaming holdback bound, in characters.
        mmr_fast_restore: Restore the accumulator from its peak checkpoint on
            open. See the ledger's own documentation for the trade-off.
    """

    def __init__(
        self,
        *,
        storage_path: str | None = None,
        signing_key: str = "",
        enforcement_mode: str = "strict",
        redact_requests: bool = True,
        redact_responses: bool = True,
        tenant_id: str = "embedded",
        window_chars: int = 128,
        mmr_fast_restore: bool = False,
    ) -> None:
        if enforcement_mode not in _ENFORCEMENT_MODES:
            raise ValueError(
                f"enforcement_mode must be one of {_ENFORCEMENT_MODES}, got {enforcement_mode!r}"
            )
        self.enforcement_mode = enforcement_mode
        self.tenant_id = tenant_id
        self.redact_requests = redact_requests
        self.redact_responses = redact_responses
        self.window_chars = window_chars

        self.storage_path = storage_path or DEFAULT_STORAGE_PATH
        parent = os.path.dirname(os.path.abspath(self.storage_path))
        os.makedirs(parent, exist_ok=True)

        self.ledger = CryptographicAuditLedger(
            self.storage_path,
            signing_key=signing_key,
            mmr_fast_restore=mmr_fast_restore,
        )
        # shadow_mode inverts the block, not the detection: the same pipeline
        # runs and the result still records what was found.
        self.waf = AegisWAF(strict_mode=True, shadow_mode=enforcement_mode == "shadow")
        self._scrubber = PHIDeidentifier()

    # ── lifecycle ──────────────────────────────────────────────────────────

    def close(self) -> None:
        """Flush and release the WAL. Safe to call more than once."""
        self.ledger.close()

    def __enter__(self) -> AegisEmbedded:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    # ── request path ───────────────────────────────────────────────────────

    def guard_request(self, payload: dict[str, Any], *, endpoint: str) -> dict[str, Any]:
        """Inspect and de-identify a request, or refuse it.

        A refusal is committed to the ledger before it is raised, so a blocked
        request leaves the same kind of signed, chain-linked trace as one that
        was served. Evidence failure never converts a block into a pass.

        Returns:
            The payload to send upstream — de-identified when
            ``redact_requests`` is set, otherwise the payload unchanged.

        Raises:
            AegisBlockedError: In ``strict`` mode, when the WAF detects.
        """
        result = self.waf.inspect_payload(payload)
        if not result.allowed:
            reason = result.reason or "payload rejected by WAF"
            rejection_id: str | None = None
            try:
                node = self.ledger.commit_rejection(
                    request_bytes=_canonical_request_bytes(payload),
                    rejection_code=403,
                    reason_category="waf_block",
                    tenant_id=self.tenant_id,
                    endpoint=endpoint,
                )
                rejection_id = node.state_id
            except Exception:
                logger.exception("rejection evidence commit failed; blocking regardless")
            raise AegisBlockedError(reason, rejection_id=rejection_id)
        if result.shadow_blocked:
            logger.warning("aegis embedded shadow mode: would have blocked (%s)", result.reason)

        if not self.redact_requests:
            return payload
        return self._scrub_payload(payload)

    def _scrub_payload(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Return a copy with Safe Harbor scrubbing applied to prompt text.

        Only the fields that carry model-visible prose are touched — message
        content and ``prompt`` — so scrubbing cannot corrupt tool schemas,
        identifiers, or numeric parameters that happen to match a pattern.
        """
        scrubbed = dict(payload)
        messages = scrubbed.get("messages")
        if isinstance(messages, list):
            new_messages: list[Any] = []
            for message in messages:
                if isinstance(message, dict) and isinstance(message.get("content"), str):
                    copy = dict(message)
                    copy["content"] = self._scrubber.scrub(message["content"]).text
                    new_messages.append(copy)
                else:
                    new_messages.append(message)
            scrubbed["messages"] = new_messages
        if isinstance(scrubbed.get("prompt"), str):
            scrubbed["prompt"] = self._scrubber.scrub(scrubbed["prompt"]).text
        if isinstance(scrubbed.get("system"), str):
            scrubbed["system"] = self._scrubber.scrub(scrubbed["system"]).text
        return scrubbed

    # ── evidence ───────────────────────────────────────────────────────────

    def commit_interaction(
        self,
        *,
        state_id: str,
        request_payload: dict[str, Any],
        response_bytes: bytes,
        model: str,
        endpoint: str,
    ) -> EmbeddedEvidence:
        """Commit a completed non-streaming interaction."""
        node = self.ledger.commit_forensic(
            state_id=state_id,
            request_bytes=_canonical_request_bytes(request_payload),
            response_bytes=response_bytes,
            tenant_id=self.tenant_id,
            model=model,
            endpoint=endpoint,
            phi_scrubbed=self.redact_requests,
            scrub_method="safe_harbor_regex" if self.redact_requests else "",
        )
        return EmbeddedEvidence.from_node(node)

    def commit_stream_terminal(
        self,
        *,
        state_id: str,
        request_payload: dict[str, Any],
        response_hash: str,
        response_size: int,
        response_preview: bytes,
        terminal_outcome: str,
        token_count: int,
        elapsed_seconds: float,
        redaction_hits: dict[str, int],
        model: str,
        endpoint: str,
    ) -> EmbeddedEvidence:
        """Commit the terminal summary of an incrementally hashed stream."""
        node = self.ledger.commit_forensic_summary(
            state_id=state_id,
            request_bytes=_canonical_request_bytes(request_payload),
            response_hash=response_hash,
            response_size=response_size,
            response_preview=response_preview,
            terminal_outcome=terminal_outcome,
            final_marker_included=terminal_outcome == "complete",
            token_count=token_count,
            elapsed_seconds=elapsed_seconds,
            redaction_hits=redaction_hits,
            tenant_id=self.tenant_id,
            model=model,
            endpoint=endpoint,
            phi_scrubbed=self.redact_responses,
            scrub_method="streaming_holdback" if self.redact_responses else "",
        )
        return EmbeddedEvidence.from_node(node, redaction_hits=redaction_hits)

    def new_stream_redactor(self) -> StreamingDeidentifier | None:
        """A fresh bounded-holdback redactor, or None when disabled."""
        if not self.redact_responses:
            return None
        return StreamingDeidentifier(window_chars=self.window_chars)


# ── chunk helpers ─────────────────────────────────────────────────────────────
#
# Read and rewrite the text carried by a streaming chunk without importing
# either provider SDK. Both shapes are handled explicitly; anything else yields
# no text, which is correct — a chunk with no text delta contributes nothing to
# the response hash and needs no redaction.


def _chunk_text(chunk: Any) -> str:
    """Extract the text delta from an OpenAI or Anthropic streaming chunk."""
    choices = getattr(chunk, "choices", None)
    if choices:
        delta = getattr(choices[0], "delta", None)
        content = getattr(delta, "content", None)
        if isinstance(content, str):
            return content
    delta = getattr(chunk, "delta", None)
    text = getattr(delta, "text", None)
    if isinstance(text, str):
        return text
    return ""


def _set_chunk_text(chunk: Any, text: str) -> bool:
    """Rewrite a chunk's text delta. Returns whether it took effect."""
    choices = getattr(chunk, "choices", None)
    if choices:
        delta = getattr(choices[0], "delta", None)
        if delta is not None and isinstance(getattr(delta, "content", None), str):
            try:
                delta.content = text
            except (AttributeError, TypeError, ValueError):
                return False
            return True
    delta = getattr(chunk, "delta", None)
    if delta is not None and isinstance(getattr(delta, "text", None), str):
        try:
            delta.text = text
        except (AttributeError, TypeError, ValueError):
            return False
        return True
    return False


@dataclass(frozen=True)
class _StreamSummary:
    """Terminal facts about a delivered stream, for the summary commit."""

    response_hash: str
    response_size: int
    response_preview: bytes
    token_count: int
    elapsed_seconds: float
    redaction_hits: dict[str, int]


class _StreamRecorder:
    """Hashes a stream incrementally and redacts it within a bounded holdback.

    The response hash is built from the text actually delivered to the caller,
    so the committed evidence describes what the application received rather
    than what the provider sent.
    """

    _PREVIEW_LIMIT = 4096

    def __init__(self, engine: AegisEmbedded) -> None:
        self._redactor = engine.new_stream_redactor()
        self._hasher_parts: list[bytes] = []
        self._size = 0
        self._tokens = 0
        self._preview = bytearray()
        self._started = time.perf_counter()

    def observe(self, chunk: Any) -> bool:
        """Account for one chunk, rewriting its text when redaction is on.

        Returns whether the chunk carried a text delta, which the stream
        wrappers need in order to find the chunk the held-back tail belongs to.
        """
        text = _chunk_text(chunk)
        if not text:
            return False
        self._tokens += 1
        if self._redactor is None:
            self._record(text)
            return True
        settled = self._redactor.feed(text)
        if not _set_chunk_text(chunk, settled):
            raise AegisEmbeddedError(
                "streaming redaction is enabled but this chunk's text could not be "
                "rewritten; refusing to emit unredacted output"
            )
        self._record(settled)
        return True

    def _record(self, text: str) -> None:
        encoded = text.encode("utf-8")
        self._hasher_parts.append(encoded)
        self._size += len(encoded)
        if len(self._preview) < self._PREVIEW_LIMIT:
            self._preview.extend(encoded[: self._PREVIEW_LIMIT - len(self._preview)])

    def finalize(self) -> tuple[_StreamSummary, str]:
        """Drain the holdback and return the summary plus the flushed tail.

        The tail is returned rather than merely hashed. A bounded holdback means
        the last ``window_chars`` of a response are still retained when the
        source ends — for a short response, all of it — so a wrapper that
        recorded the flush without delivering it would hash text the caller
        never saw and silently truncate the reply.
        """
        tail = self._redactor.flush() if self._redactor is not None else ""
        if tail:
            self._record(tail)
        hits = dict(self._redactor.stats.entity_hits) if self._redactor is not None else {}
        body = b"".join(self._hasher_parts)
        return (
            _StreamSummary(
                response_hash=sha256_hex(body),
                response_size=self._size,
                response_preview=bytes(self._preview),
                token_count=self._tokens,
                elapsed_seconds=time.perf_counter() - self._started,
                redaction_hits=hits,
            ),
            tail,
        )


def _wrap_sync_stream(
    engine: AegisEmbedded,
    stream: Any,
    *,
    state_id: str,
    request_payload: dict[str, Any],
    model: str,
    endpoint: str,
) -> Iterator[Any]:
    """Yield chunks, committing the terminal summary before the last of them.

    Chunks from the most recent text-bearing one onward are held rather than
    released. That serves two requirements at once. The commit lands before the
    consumer sees the final chunk, so a consumer holding the last chunk knows
    the evidence is already durable. And the held-back tail that ``flush``
    returns at the end has a text-bearing chunk to be appended to — the first
    entry in the buffer — instead of being hashed into evidence the caller was
    never given.
    """
    recorder = _StreamRecorder(engine)
    buffer: list[Any] = []
    try:
        for chunk in stream:
            if recorder.observe(chunk):
                # A new text chunk supersedes the previous tail candidate.
                yield from buffer
                buffer = [chunk]
            elif buffer:
                buffer.append(chunk)
            else:
                yield chunk
    except GeneratorExit:
        # The consumer stopped reading. Record the truncation, then re-raise:
        # a partially delivered stream is evidence too.
        _commit_stream(
            engine, recorder, "client_disconnect", state_id, request_payload, model, endpoint
        )
        raise
    except Exception:
        _commit_stream(
            engine, recorder, "upstream_error", state_id, request_payload, model, endpoint
        )
        raise

    evidence = _commit_stream(
        engine, recorder, "complete", state_id, request_payload, model, endpoint, buffer
    )
    if buffer:
        _attach(buffer[-1], evidence)
    yield from buffer


async def _wrap_async_stream(
    engine: AegisEmbedded,
    stream: Any,
    *,
    state_id: str,
    request_payload: dict[str, Any],
    model: str,
    endpoint: str,
) -> AsyncIterator[Any]:
    """Async twin of :func:`_wrap_sync_stream`, with the same ordering."""
    recorder = _StreamRecorder(engine)
    buffer: list[Any] = []
    try:
        async for chunk in stream:
            if recorder.observe(chunk):
                for held in buffer:
                    yield held
                buffer = [chunk]
            elif buffer:
                buffer.append(chunk)
            else:
                yield chunk
    except GeneratorExit:
        _commit_stream(
            engine, recorder, "client_disconnect", state_id, request_payload, model, endpoint
        )
        raise
    except Exception:
        _commit_stream(
            engine, recorder, "upstream_error", state_id, request_payload, model, endpoint
        )
        raise

    evidence = _commit_stream(
        engine, recorder, "complete", state_id, request_payload, model, endpoint, buffer
    )
    if buffer:
        _attach(buffer[-1], evidence)
    for held in buffer:
        yield held


def _commit_stream(
    engine: AegisEmbedded,
    recorder: _StreamRecorder,
    outcome: str,
    state_id: str,
    request_payload: dict[str, Any],
    model: str,
    endpoint: str,
    buffer: list[Any] | None = None,
) -> EmbeddedEvidence:
    """Drain the recorder, deliver the held-back tail, and commit the terminal node.

    ``buffer`` is the run of undelivered chunks headed by the last text-bearing
    one. The flushed tail is appended to that chunk so the caller receives the
    complete response; on a truncated stream there is no buffer to deliver it
    to, and the tail is recorded in the evidence only — which is the honest
    result, since the caller stopped reading.
    """
    summary, tail = recorder.finalize()
    if tail and buffer:
        head = buffer[0]
        if not _set_chunk_text(head, _chunk_text(head) + tail):  # pragma: no cover - defensive
            raise AegisEmbeddedError(
                "the held-back tail of a redacted stream could not be delivered; "
                "refusing to truncate the response silently"
            )
    return engine.commit_stream_terminal(
        state_id=state_id,
        request_payload=request_payload,
        response_hash=summary.response_hash,
        response_size=summary.response_size,
        response_preview=summary.response_preview,
        terminal_outcome=outcome,
        token_count=summary.token_count,
        elapsed_seconds=summary.elapsed_seconds,
        redaction_hits=summary.redaction_hits,
        model=model,
        endpoint=endpoint,
    )


def _response_bytes(response: Any) -> bytes:
    """Deterministic bytes for a non-streaming response, for hashing."""
    for attribute in ("model_dump_json", "json"):
        method = getattr(response, attribute, None)
        if callable(method):
            try:
                rendered = method()
            except (TypeError, ValueError):  # pragma: no cover - defensive
                continue
            if isinstance(rendered, str):
                return rendered.encode()
            if isinstance(rendered, bytes):
                return rendered
    dump = getattr(response, "model_dump", None)
    if callable(dump):
        try:
            return _canonical_request_bytes(dump())
        except (TypeError, ValueError):  # pragma: no cover - defensive
            pass
    if isinstance(response, dict):
        return _canonical_request_bytes(response)
    return repr(response).encode()


def _install(engine: AegisEmbedded, owner: Any, method_name: str, endpoint: str) -> None:
    """Replace one bound ``create`` with an instrumented version.

    The wrapper is installed on the client's own sub-object, so it affects that
    client instance only and leaves the SDK's classes untouched. Wrapping is
    idempotent: a client already wrapped is left alone rather than layered.
    """
    original = getattr(owner, method_name)
    if getattr(original, "_aegis_wrapped", False):
        return

    is_async = inspect.iscoroutinefunction(original)

    def _prepare(kwargs: dict[str, Any]) -> tuple[str, dict[str, Any], str]:
        state_id = f"emb-{uuid.uuid4().hex}"
        guarded = engine.guard_request(dict(kwargs), endpoint=endpoint)
        model = str(guarded.get("model", "unknown"))
        return state_id, guarded, model

    if is_async:

        async def async_create(*args: Any, **kwargs: Any) -> Any:
            state_id, guarded, model = _prepare(kwargs)
            streaming = bool(guarded.get("stream"))
            result = await original(*args, **guarded)
            if streaming:
                return _wrap_async_stream(
                    engine,
                    result,
                    state_id=state_id,
                    request_payload=guarded,
                    model=model,
                    endpoint=endpoint,
                )
            evidence = engine.commit_interaction(
                state_id=state_id,
                request_payload=guarded,
                response_bytes=_response_bytes(result),
                model=model,
                endpoint=endpoint,
            )
            _attach(result, evidence)
            return result

        async_create._aegis_wrapped = True  # type: ignore[attr-defined]
        setattr(owner, method_name, async_create)
        return

    def sync_create(*args: Any, **kwargs: Any) -> Any:
        state_id, guarded, model = _prepare(kwargs)
        streaming = bool(guarded.get("stream"))
        result = original(*args, **guarded)
        if streaming:
            return _wrap_sync_stream(
                engine,
                result,
                state_id=state_id,
                request_payload=guarded,
                model=model,
                endpoint=endpoint,
            )
        evidence = engine.commit_interaction(
            state_id=state_id,
            request_payload=guarded,
            response_bytes=_response_bytes(result),
            model=model,
            endpoint=endpoint,
        )
        _attach(result, evidence)
        return result

    sync_create._aegis_wrapped = True  # type: ignore[attr-defined]
    setattr(owner, method_name, sync_create)


def wrap(client: Any, *, engine: AegisEmbedded | None = None, **options: Any) -> Any:
    """Instrument a provider client in place and return it.

    ``client`` may be any object exposing ``chat.completions.create`` (the
    OpenAI shape) or ``messages.create`` (the Anthropic shape), synchronous or
    asynchronous. Both are instrumented when both are present. Recognition is
    by shape rather than by type, so neither SDK is imported or required.

    The wrapper is installed on the client instance's own sub-objects; other
    clients, and the SDK classes themselves, are unaffected. Calling ``wrap``
    twice on one client is a no-op.

    Args:
        client: The provider client to instrument.
        engine: An existing :class:`AegisEmbedded` to record into. Pass one to
            share a single ledger across several clients — each engine holds an
            exclusive lock on its WAL, so a second engine on the same path
            would be refused.
        **options: Forwarded to :class:`AegisEmbedded` when ``engine`` is not
            given — ``storage_path``, ``signing_key``, ``enforcement_mode`` and
            the rest.

    Returns:
        The same client object, instrumented. Its ``AegisEmbedded`` is reachable
        as ``client._aegis`` — hold it to close the ledger.

    Raises:
        TypeError: If the object exposes neither supported surface, which is
            reported rather than silently returning an unwrapped client.
    """
    active = engine or AegisEmbedded(**options)

    installed = False
    completions = getattr(getattr(client, "chat", None), "completions", None)
    if completions is not None and hasattr(completions, "create"):
        _install(active, completions, "create", "chat.completions")
        installed = True

    messages = getattr(client, "messages", None)
    if messages is not None and hasattr(messages, "create"):
        _install(active, messages, "create", "messages")
        installed = True

    if not installed:
        if engine is None:
            active.close()
        raise TypeError(
            f"{type(client).__name__} exposes neither chat.completions.create nor "
            "messages.create; aegis.wrap supports the OpenAI and Anthropic client shapes"
        )

    try:
        client._aegis = active
    except (AttributeError, TypeError):  # pragma: no cover - exotic clients
        logger.warning(
            "could not attach _aegis to a %s; hold the AegisEmbedded yourself to close it",
            type(client).__name__,
        )
    return client
