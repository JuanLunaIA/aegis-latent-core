# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import logging
import math
import time
import uuid
from collections import OrderedDict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
from secrets import randbelow
from threading import Lock
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.middleware.base import BaseHTTPMiddleware

import aegis
from aegis.anchoring.rfc3161 import (
    HTTPXTimestampTransport,
    OpenSSLRFC3161Verifier,
    RFC3161AnchorClient,
)
from aegis.auth.apikey import AuditKeyAuth, ProxyKeyAuth
from aegis.auth.mtls import MTLSVerificationConfig, MTLSVerifier
from aegis.auth.oidc import HTTPXJWKSTransport, OIDCConfig, OIDCManager
from aegis.auth.principal import Principal
from aegis.config import AegisSettings, get_settings
from aegis.core import observability
from aegis.core.circuit_breaker import CircuitOpenError
from aegis.core.crypto_audit import AuditNode, CryptographicAuditLedger
from aegis.core.hsm import HSMSigningBackend
from aegis.core.normalization import canonical_normalize
from aegis.core.pci_detector import PCIScrubber
from aegis.core.phi_deidentifier import PHIDeidentifier
from aegis.core.ratelimiter import RateLimitBackendUnavailable as LegacyRateLimitBackendUnavailable
from aegis.core.secrets import VaultManager
from aegis.core.session_manager import SessionLifecycleManager
from aegis.core.waf_session import WAFSessionTracker
from aegis.proxy.analyzer import ResponseAnalyzer
from aegis.proxy.attestation_api import build_attestation_router
from aegis.proxy.audit_api import build_audit_router
from aegis.proxy.dependencies import validate_audit_auth, validate_proxy_auth
from aegis.proxy.dmz_middleware import DMZSourceIPMiddleware
from aegis.proxy.forwarder import LLMForwarder
from aegis.proxy.rate_limiter import (
    DualRateLimiter,
    RateLimitBackendUnavailableError,
    RateLimitDecision,
    RedisRateLimitBackend,
    TokenReservation,
)
from aegis.proxy.schemas import AlertOut
from aegis.proxy.streaming import BoundedStreamProxy, StreamEvidenceSummary
from aegis.proxy.waf import AegisWAF
from aegis.storage.s3_worm import Boto3S3WormProvider, ObjectLockMode, S3WormArchiver
from aegis.storage.segment_manifest import archive_finalized_segment
from aegis.telemetry.events import EventKind, EventOutcome, SecurityEvent, Severity
from aegis.telemetry.siem import HTTPSIEMSink, SIEMExporter, SIEMFormat

logger = logging.getLogger(__name__)
_ALERT_BUFFER_SIZE = 10_000

# Strong references to fire-and-forget commit tasks. asyncio only holds a weak
# reference to tasks created with create_task; without this set a task can be
# garbage-collected mid-flight, silently dropping an audit commit. Tasks remove
# themselves via add_done_callback when they finish.
_BACKGROUND_TASKS: set[asyncio.Task[Any]] = set()


async def _with_jitter_measurement(coro: Any, enqueued_at: float) -> Any:
    """Wrap *coro* to record scheduling jitter as the first observable action."""
    observability.SCHEDULING_JITTER.observe(time.perf_counter() - enqueued_at)
    return await coro


def _spawn_background(coro: Any) -> asyncio.Task[Any]:
    """Schedule *coro* as a tracked background task that survives GC."""
    enqueued_at = time.perf_counter()
    task = asyncio.create_task(_with_jitter_measurement(coro, enqueued_at))
    _BACKGROUND_TASKS.add(task)
    observability.AUDIT_PENDING_COMMITS.set(len(_BACKGROUND_TASKS))

    def _on_done(t: asyncio.Task[Any]) -> None:
        _BACKGROUND_TASKS.discard(t)
        observability.AUDIT_PENDING_COMMITS.set(len(_BACKGROUND_TASKS))

    task.add_done_callback(_on_done)
    return task


# FIX-APP-01: Maximum concurrent analyzer instances.
# Mirrors the cap in SessionLifecycleManager to prevent unbounded memory growth
# when callers omit the x-session-id header (UUID-per-request path).
_MAX_ANALYZER_SESSIONS = 4_096


class RequestBodyLimitMiddleware(BaseHTTPMiddleware):
    """Reject oversized bodies before JSON parsing or provider forwarding."""

    def __init__(self, app: Any, max_body_bytes: int) -> None:
        super().__init__(app)
        self._max_body_bytes = max_body_bytes

    async def dispatch(self, request: Request, call_next: Any) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                declared = int(content_length)
            except ValueError:
                return JSONResponse(status_code=400, content={"detail": "Invalid Content-Length"})
            if declared < 0 or declared > self._max_body_bytes:
                return JSONResponse(status_code=413, content={"detail": "Request body too large"})
        received = 0
        original_receive = request.receive

        async def bounded_receive() -> dict[str, Any]:
            nonlocal received
            message = await original_receive()
            if message.get("type") == "http.request":
                chunk = message.get("body", b"")
                received += len(chunk)
                if received > self._max_body_bytes:
                    raise HTTPException(status_code=413, detail="Request body too large")
            return dict(message)

        request._receive = bounded_receive  # type: ignore[attr-defined]
        try:
            return await call_next(request)
        except HTTPException as exc:
            return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})


class RequestSmugglingProtectionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cl_headers = request.headers.getlist("content-length")
        if len(cl_headers) > 1:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "detail": "Multiple Content-Length headers detected. Potential smuggling attack."
                },
            )

        te_header = request.headers.get("transfer-encoding")
        cl_header = request.headers.get("content-length")
        if te_header and "chunked" in te_header.lower() and cl_header:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={
                    "detail": (
                        "Both Transfer-Encoding: chunked and Content-Length present. "
                        "Potential smuggling attack."
                    )
                },
            )

        if te_header and "chunked" not in te_header.lower():
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Unsupported or ambiguous Transfer-Encoding detected."},
            )

        return await call_next(request)


class _AlertStore:
    def __init__(self, maxsize: int = _ALERT_BUFFER_SIZE) -> None:
        from collections import deque

        self._buf: deque[AlertOut] = deque(maxlen=maxsize)
        self._lock = asyncio.Lock()

    async def append(self, alert: AlertOut) -> None:
        async with self._lock:
            self._buf.append(alert)

    async def recent(self, n: int = 100) -> list[AlertOut]:
        async with self._lock:
            items = list(self._buf)
        return items[-n:]


@dataclass(frozen=True)
class _AnalysisJob:
    request_id: str
    session_id: str
    model: str
    logprobs_data: list[Any]
    sampling_params: dict[str, Any]
    raw_body: bytes
    response_bytes: bytes
    tenant_id: str
    phi_scrubbed: bool
    scrub_method: str
    analysis_timeout_seconds: float


async def _analysis_worker(state: _AppState) -> None:
    """Run optional response enrichment outside the client-visible request path."""
    while True:
        job = await state.analysis_queue.get()
        try:
            analyzer = state.get_analyzer(job.session_id)
            analysis = await asyncio.wait_for(
                asyncio.to_thread(
                    analyzer.analyze,
                    request_id=job.request_id,
                    model=job.model,
                    logprobs_data=job.logprobs_data,
                    sampling_params=job.sampling_params,
                ),
                timeout=job.analysis_timeout_seconds,
            )
            enrichment_params = dict(analysis.sampling_params)
            enrichment_params.update(
                {
                    "analysis_of": job.request_id,
                    "alerts": len(analysis.alerts),
                    "analysis_status": "complete",
                }
            )
            await asyncio.to_thread(
                state.ledger.commit_state,
                state_id=f"{job.request_id}:analysis",
                entropy=analysis.mean_entropy,
                payload=job.response_bytes[:65_536],
                tenant_id=job.tenant_id,
                sampling_params=enrichment_params,
                phi_scrubbed=job.phi_scrubbed,
                scrub_method=job.scrub_method,
                signer_name=job.session_id,
                signature_meaning="analysis-enrichment",
            )
            for alert in analysis.alerts:
                await state.alert_store.append(alert)
        except asyncio.CancelledError:
            raise
        except Exception:
            observability.ANALYSIS_ERRORS.inc()
            logger.exception("asynchronous response analysis failed")
        finally:
            state.analysis_queue.task_done()
            # CPython 3.11 can retain a pending cancellation across a
            # wait_for(to_thread(...)) boundary.  Do not re-enter queue.get()
            # after shutdown requested cancellation, even if an inner await
            # consumed the first CancelledError delivery.
            current = asyncio.current_task()
            if current is not None and current.cancelling():
                raise asyncio.CancelledError


# FIX-APP-01: Bounded LRU cache for ResponseAnalyzer instances.
# The original dict[str, ResponseAnalyzer] had no eviction policy.
# Under no-session-id traffic (UUID-per-request), it grew without bound
# until OOM, identical to the BUG-05 pattern fixed in SessionLifecycleManager.
#
# Mechanism: OrderedDict preserves insertion order. On capacity hit the
# least-recently-used entry is popped from the front (last=False).
# Accessing an existing session moves it to the MRU end.
# Thread-safety: guarded by a Lock (sync, not async — get_analyzer is
# called in the request handler which is already running in an asyncio task;
# a threading.Lock here is sufficient to guard concurrent workers).
class _BoundedAnalyzerCache:
    """LRU-bounded cache for ResponseAnalyzer instances.

    Parameters
    ----------
    maxsize : int
        Maximum number of concurrent session analyzers held in memory.
        When the cap is reached the LRU entry is evicted.
    cfg : AegisSettings
        Application configuration. KL/JS/entropy thresholds are read here
        so that environment-variable overrides are respected at runtime.
        Note: Previously, ResponseAnalyzer was instantiated with hardcoded
        defaults, silently ignoring AegisSettings.kl_alert_threshold and siblings.
        This has been corrected to read thresholds from cfg when available.
    """

    def __init__(
        self, maxsize: int = _MAX_ANALYZER_SESSIONS, cfg: AegisSettings | None = None
    ) -> None:
        self._maxsize = maxsize
        self._cfg = cfg
        self._cache: OrderedDict[str, ResponseAnalyzer] = OrderedDict()
        self._lock = Lock()
        # Eviction telemetry for health checks
        self._eviction_count: int = 0
        self._total_gets: int = 0

    def get(self, session_id: str) -> ResponseAnalyzer:
        """Return the analyzer for *session_id*, creating it if absent.

        Accessing an existing entry moves it to the MRU position.
        """
        with self._lock:
            self._total_gets += 1
            if session_id in self._cache:
                self._cache.move_to_end(session_id)
                return self._cache[session_id]
            if len(self._cache) >= self._maxsize:
                evicted_id, _ = self._cache.popitem(last=False)
                self._eviction_count += 1
                logger.debug("_BoundedAnalyzerCache: evicted LRU session %s", evicted_id)
            # Read thresholds from cfg when available.
            if self._cfg is not None:
                analyzer = ResponseAnalyzer(
                    session_id=session_id,
                    kl_threshold=self._cfg.kl_alert_threshold,
                    js_threshold=self._cfg.js_alert_threshold,
                    entropy_alert_drop_bits=self._cfg.entropy_alert_threshold_bits,
                )
            else:
                analyzer = ResponseAnalyzer(session_id=session_id)
            self._cache[session_id] = analyzer
            return analyzer

    def remove(self, session_id: str) -> None:
        """Explicitly evict a session."""
        with self._lock:
            self._cache.pop(session_id, None)

    def size(self) -> int:
        with self._lock:
            return len(self._cache)

    def eviction_rate(self) -> float:
        """Fraction of gets that triggered an LRU eviction. Used by /health."""
        with self._lock:
            if self._total_gets == 0:
                return 0.0
            return self._eviction_count / self._total_gets


class _AppState:
    forwarder: LLMForwarder
    ledger: CryptographicAuditLedger
    sessions: SessionLifecycleManager
    ratelimiter: Any
    vault: VaultManager | None
    waf: AegisWAF
    # FIX-APP-01: replaced plain dict with bounded LRU cache.
    analyzers: _BoundedAnalyzerCache
    alert_store: _AlertStore
    analysis_queue: asyncio.Queue[_AnalysisJob]
    analysis_workers: list[asyncio.Task[Any]]
    proxy_auth: ProxyKeyAuth
    audit_auth: AuditKeyAuth
    settings: AegisSettings
    # mTLS authentication handler; None when mTLS is not configured.
    # Checked by dependencies.py via getattr(state, "mtls_auth", None).
    mtls_auth: Any
    # FIX-APP-02: entropy guard helpers instantiated once at startup,
    # not on every request (was: per-request allocation in hot path).
    _entropy_taint_engine: Any
    _entropy_analyzer: Any
    _entropy_segmenter: Any
    # PHI de-identification scrubber (None when phi_deidentify=False).
    _phi_scrubber: PHIDeidentifier | None
    # PCI-DSS cardholder-data scrubber (None when pci_scrub=False).
    _pci_scrubber: PCIScrubber | None
    # Multi-turn behavioral WAF session tracker (Domain 5.1).
    waf_session_tracker: WAFSessionTracker
    # Optional best-effort copy of terminal streaming frames. JSONL is authoritative.
    native_stream_wal: Any
    oidc_manager: OIDCManager | None
    enterprise_mtls_verifier: MTLSVerifier | None
    siem_exporter: SIEMExporter | None
    s3_archiver: S3WormArchiver | None
    rfc3161_client: RFC3161AnchorClient | None
    archive_task: asyncio.Task[None] | None

    def get_analyzer(self, session_id: str) -> ResponseAnalyzer:
        return self.analyzers.get(session_id)


def _extract_payload_text(body: dict) -> str:
    if "messages" in body:
        return " ".join(
            m.get("content", "") if isinstance(m, dict) else str(m) for m in body["messages"]
        )
    if "prompt" in body:
        prompt = body["prompt"]
        return " ".join(prompt) if isinstance(prompt, list) else str(prompt)
    return ""


def _apply_request_entropy_guard(request: Request, body: dict, state: _AppState) -> None:
    """Apply Shannon-entropy payload guard using pre-initialised state singletons.

    FIX-APP-02: TaintEngine, PayloadEntropyAnalyzer, and XDPDynamicSegmenter
    were previously instantiated on every request (a hot-path allocation for each
    call when request_entropy_guard=True).  They are now initialised once in the
    lifespan and reused from _AppState.  Both classes are stateless per-call, so
    sharing across requests is safe.
    """
    cfg = state.settings
    if not cfg.request_entropy_guard:
        return

    payload_text = _extract_payload_text(body)
    if not payload_text:
        return

    taint_engine = state._entropy_taint_engine
    analyzer = state._entropy_analyzer
    segmenter = state._entropy_segmenter

    tainted_payload = taint_engine.taint(payload_text, origin="CLIENT_REQUEST")
    allowed, entropy = analyzer.analyze_payload(payload_text)
    if not allowed:
        client_ip = request.client.host if request.client else "unknown"
        segmenter.block_ip_immediately(client_ip)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Payload rejected by entropy guard: entropy={entropy:.4f}",
        )
    if analyzer.detect_entropy_shift(payload_text):
        client_ip = request.client.host if request.client else "unknown"
        segmenter.block_ip_immediately(client_ip)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Payload rejected: abrupt entropy shift detected",
        )

    sanitized = taint_engine.sanitize_value(tainted_payload, "ENTROPY_WAF_PIPELINE")
    body["_sanitized_payload"] = sanitized.value


def _apply_phi_scrub_request(body: dict, state: _AppState) -> tuple[dict, bool, str]:
    """Scrub PHI from request message content when phi_deidentify is enabled.

    Returns ``(body, phi_scrubbed, scrub_method)``.  The original dict is not
    mutated; a shallow copy is returned only when scrubbing actually fires.
    """
    scrubber = state._phi_scrubber
    if scrubber is None:
        return body, False, ""
    messages = body.get("messages")
    if not messages:
        return body, False, ""
    scrubbed_msgs, hits = scrubber.scrub_messages(messages)
    if hits:
        logger.debug("PHI scrubbed from request (%d entities): %s", sum(hits.values()), hits)
        new_body = dict(body)
        new_body["messages"] = scrubbed_msgs
        return new_body, True, "safe_harbor_regex"
    return body, False, ""


def _apply_phi_scrub_response(resp_json: dict, state: _AppState) -> dict:
    """Scrub PHI from response choices[].message.content when phi_deidentify is enabled.

    Returns a (possibly modified) response dict.  The original is not mutated.
    """
    scrubber = state._phi_scrubber
    if scrubber is None:
        return resp_json
    choices = resp_json.get("choices")
    if not choices:
        return resp_json
    modified = False
    new_choices = []
    for choice in choices:
        msg = choice.get("message") if isinstance(choice, dict) else None
        if msg and isinstance(msg.get("content"), str):
            result = scrubber.scrub(msg["content"])
            if result.phi_detected:
                logger.debug(
                    "PHI scrubbed from response (%d entities): %s",
                    result.total_hits,
                    result.hits,
                )
                new_choice = dict(choice)
                new_choice["message"] = dict(msg)
                new_choice["message"]["content"] = result.text
                new_choices.append(new_choice)
                modified = True
                continue
        new_choices.append(choice)
    if modified:
        new_resp = dict(resp_json)
        new_resp["choices"] = new_choices
        return new_resp
    return resp_json


def _apply_pci_scrub_request(body: dict, state: _AppState) -> tuple[dict, bool]:
    """Scrub PCI cardholder data from request message content when pci_scrub is enabled.

    Returns ``(body, pci_scrubbed)``.  The original dict is not mutated; a shallow
    copy is returned only when scrubbing actually fires.
    """
    scrubber = state._pci_scrubber
    if scrubber is None:
        return body, False
    messages = body.get("messages")
    if not messages:
        return body, False
    modified = False
    new_messages = []
    for msg in messages:
        if isinstance(msg, dict) and isinstance(msg.get("content"), str):
            result = scrubber.scan(msg["content"])
            if result.chd_detected:
                logger.debug(
                    "PCI scrubbed from request (%d PAN, %d CVV, %d track): brands=%s",
                    result.pan_count,
                    result.cvv_count,
                    result.track_count,
                    [b.value for b in result.brands],
                )
                new_msg = dict(msg)
                new_msg["content"] = result.text
                new_messages.append(new_msg)
                modified = True
                continue
        new_messages.append(msg)
    if modified:
        new_body = dict(body)
        new_body["messages"] = new_messages
        return new_body, True
    return body, False


def _apply_pci_scrub_response(resp_json: dict, state: _AppState) -> dict:
    """Scrub PCI cardholder data from response choices[].message.content when pci_scrub is enabled.

    Returns a (possibly modified) response dict.  The original is not mutated.
    """
    scrubber = state._pci_scrubber
    if scrubber is None:
        return resp_json
    choices = resp_json.get("choices")
    if not choices:
        return resp_json
    modified = False
    new_choices = []
    for choice in choices:
        msg = choice.get("message") if isinstance(choice, dict) else None
        if msg and isinstance(msg.get("content"), str):
            result = scrubber.scan(msg["content"])
            if result.chd_detected:
                logger.debug(
                    "PCI scrubbed from response (%d PAN, %d CVV, %d track)",
                    result.pan_count,
                    result.cvv_count,
                    result.track_count,
                )
                new_choice = dict(choice)
                new_choice["message"] = dict(msg)
                new_choice["message"]["content"] = result.text
                new_choices.append(new_choice)
                modified = True
                continue
        new_choices.append(choice)
    if modified:
        new_resp = dict(resp_json)
        new_resp["choices"] = new_choices
        return new_resp
    return resp_json


def _scrub_anthropic_payload(
    payload: dict[str, Any], state: _AppState
) -> tuple[dict[str, Any], bool, str]:
    """Scrub native Anthropic text/content/system fields without changing shape."""
    changed = False
    methods: set[str] = set()

    def scrub_text(text: str) -> str:
        nonlocal changed
        result = text
        if state._phi_scrubber is not None:
            phi = state._phi_scrubber.scrub(result)
            if phi.phi_detected:
                result = phi.text
                changed = True
                methods.add("safe_harbor_regex")
        if state._pci_scrubber is not None:
            pci = state._pci_scrubber.scan(result)
            if pci.chd_detected:
                result = pci.text
                changed = True
                methods.add("pci_pan_mask")
        return result

    def visit(value: Any, key: str = "") -> Any:
        if isinstance(value, dict):
            return {child_key: visit(child, child_key) for child_key, child in value.items()}
        if isinstance(value, list):
            return [visit(child, key) for child in value]
        if isinstance(value, str) and key in {"content", "system", "text"}:
            return scrub_text(value)
        return value

    result = visit(payload)
    assert isinstance(result, dict)
    return result, changed, "+".join(sorted(methods))


def _extract_logprobs(resp_json: dict) -> list:
    try:
        return resp_json.get("choices", [])[0].get("logprobs", {}).get("content", [])
    except (IndexError, AttributeError):
        return []


def create_proxy_app(settings: AegisSettings | None = None) -> FastAPI:
    """Factory entry point documented in README for ``uvicorn --factory``."""
    return create_app(settings)


def create_app(settings: AegisSettings | None = None) -> FastAPI:
    cfg = settings or get_settings()

    # Publish enforcement posture on /metrics, not /health: the health contract
    # is that it never leaks config values. This is a single posture bit, so a
    # governed deployment can alert on a runtime that came up in development
    # mode. Set before any other construction so the gauge reflects the config
    # this process actually loaded.
    observability.SECURITY_ENFORCEMENT_MODE.set(
        1 if cfg.security_enforcement_mode == "strict" else 0
    )

    state = _AppState()
    state.settings = cfg
    state.mtls_auth = None  # populated in lifespan when mtls_required or ssl_ca_certs is set
    # Bounded LRU cache instead of unbounded plain dict.
    # cfg injected so ResponseAnalyzer reads thresholds from config.
    state.analyzers = _BoundedAnalyzerCache(maxsize=_MAX_ANALYZER_SESSIONS, cfg=cfg)
    state.alert_store = _AlertStore()
    state.analysis_queue = asyncio.Queue(maxsize=cfg.analysis_queue_size)
    state.analysis_workers = []
    state.proxy_auth = ProxyKeyAuth(cfg)
    state.audit_auth = AuditKeyAuth(cfg)
    state.waf = AegisWAF(strict_mode=cfg.waf_strict_mode)
    state.waf_session_tracker = WAFSessionTracker(
        max_sessions=4_096,
        window=cfg.waf_session_window,
        cumulative_threshold=cfg.waf_session_cumulative_threshold,
        crescendo_turns=cfg.waf_session_crescendo_turns,
    )
    state._phi_scrubber = PHIDeidentifier() if cfg.phi_deidentify else None
    state._pci_scrubber = PCIScrubber() if cfg.pci_scrub else None

    # HSM/PKCS#11 signing backend (optional; degrades gracefully when unavailable).
    _hsm_backend: HSMSigningBackend | None = None
    if cfg.pkcs11_library_path:
        _hsm_backend = HSMSigningBackend(
            library_path=cfg.pkcs11_library_path,
            slot_id=cfg.pkcs11_slot_id,
            pin=cfg.pkcs11_pin,
            key_label=cfg.pkcs11_key_label,
            token_label=cfg.pkcs11_token_label,
        )
        if _hsm_backend.available:
            logger.info("HSM/PKCS#11 signing enabled (library=%s)", cfg.pkcs11_library_path)
        else:
            if cfg.security_enforcement_mode == "strict":
                raise RuntimeError(
                    "strict runtime cannot fall back from configured PKCS#11 signing backend"
                )
            logger.warning(
                "HSM/PKCS#11 library configured (%s) but backend not available in development mode",
                cfg.pkcs11_library_path,
            )

    _signing_key = cfg.signing_key
    if not _signing_key and not cfg.auth_disabled:
        import logging as _log

        _log.getLogger(__name__).warning(
            "AEGIS_SIGNING_KEY is not set. "
            "The audit chain will use an empty signing key — signatures are NOT cryptographically valid. "
            "Generate one with: python -c 'import secrets; print(secrets.token_hex(32))'"
        )
    state.ledger = CryptographicAuditLedger(
        persistence_path=str(cfg.wal_path),
        signing_key=_signing_key,
        max_memory_nodes=cfg.max_memory_nodes,
        max_wal_bytes=cfg.max_wal_bytes,
        hsm_backend=_hsm_backend,
        require_strong_signing=cfg.security_enforcement_mode == "strict",
    )
    state.native_stream_wal = None
    try:
        import aegis_rust  # type: ignore[import]

        native_path = f"{cfg.wal_path}.stream.rwal"
        state.native_stream_wal = aegis_rust.RustWal.open(native_path, 256 * 1024 * 1024)
        logger.info("Native Rust streaming WAL enabled: %s", native_path)
    except (ImportError, OSError, RuntimeError, ValueError) as exc:
        logger.warning(
            "Native Rust streaming WAL unavailable; JSONL WAL remains authoritative: %s", exc
        )

    def _commit_stream_evidence(**kwargs: Any) -> Any:
        """Commit once to the ledger and append one CRC-framed native WAL record."""
        node = state.ledger.commit_forensic_summary(**kwargs)
        native_stream_wal = state.native_stream_wal
        if native_stream_wal is not None:
            frame = {
                "frame_type": "aegis-stream-terminal-v1",
                "node": node.to_dict(),
                "node_hash": node.node_hash,
            }
            try:
                native_stream_wal.append(
                    json.dumps(frame, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
                )
            except Exception:
                observability.NATIVE_STREAM_WAL_ERRORS.inc()
                logger.exception(
                    "Auxiliary Rust streaming WAL append failed; disabling the auxiliary "
                    "segment while preserving the authoritative JSONL terminal commit"
                )
                state.native_stream_wal = None
        return node

    rate_backend = (
        RedisRateLimitBackend(cfg.redis_url) if cfg.rate_limit_backend == "redis" else None
    )
    state.ratelimiter = DualRateLimiter(
        request_capacity=cfg.rate_limit_burst,
        request_refill_per_second=cfg.rate_limit_requests_per_minute / 60.0,
        token_capacity=cfg.rate_limit_token_capacity,
        token_refill_per_second=cfg.rate_limit_tokens_per_minute / 60.0,
        backend=rate_backend,
        max_buckets=cfg.rate_limit_max_buckets,
    )
    state.oidc_manager = None
    if cfg.auth_mode in {"oidc", "oidc_mtls"}:
        state.oidc_manager = OIDCManager(
            OIDCConfig(
                issuer=cfg.oidc_issuer,
                audience=cfg.oidc_audience,
                algorithms=cfg.get_oidc_algorithms(),
                tenant_claim=cfg.oidc_tenant_claim,
                roles_claim=cfg.oidc_roles_claim,
                leeway_seconds=cfg.oidc_leeway_seconds,
            ),
            HTTPXJWKSTransport(
                cfg.oidc_jwks_url,
                timeout=cfg.oidc_http_timeout_seconds,
            ),
        )
    state.enterprise_mtls_verifier = None
    if cfg.auth_mode in {"mtls", "api_key_mtls", "oidc_mtls"}:
        state.enterprise_mtls_verifier = MTLSVerifier(
            MTLSVerificationConfig(
                trusted_proxy_cidrs=cfg.get_mtls_proxy_cidrs(),
                allowed_sha256_fingerprints=cfg.get_mtls_fingerprints(),
                san_allowlist=cfg.get_mtls_san_allowlist(),
                tenant_san_prefix=cfg.mtls_tenant_san_prefix,
            )
        )
    state.siem_exporter = None
    if cfg.siem_url:
        state.siem_exporter = SIEMExporter(
            HTTPSIEMSink(
                cfg.siem_url,
                bearer_token=cfg.siem_bearer_token,
                timeout=cfg.webhook_timeout_seconds,
            ),
            cfg.siem_spool_path,
            output_format=SIEMFormat(cfg.siem_format),
            max_spool_rows=cfg.siem_spool_max_rows,
            max_spool_bytes=cfg.siem_spool_max_bytes,
            max_payload_bytes=cfg.siem_max_payload_bytes,
        )
    state.s3_archiver = None
    if cfg.s3_archive_enabled:
        state.s3_archiver = S3WormArchiver(
            Boto3S3WormProvider(region_name=cfg.s3_archive_region or None),
            bucket=cfg.s3_archive_bucket,
            journal_path=cfg.s3_archive_journal_path,
            spool_dir=cfg.s3_archive_spool_dir,
            retention=timedelta(days=cfg.s3_archive_retention_days),
            object_lock_mode=ObjectLockMode(cfg.s3_archive_lock_mode),
            max_spool_bytes=cfg.s3_archive_max_spool_bytes,
        )
    state.rfc3161_client = None
    if cfg.tsa_url:
        state.rfc3161_client = RFC3161AnchorClient(
            url=cfg.tsa_url,
            transport=HTTPXTimestampTransport(),
            verifier=OpenSSLRFC3161Verifier(ca_file=cfg.tsa_ca_file),
            evidence_dir=cfg.tsa_evidence_dir,
        )
    state.archive_task = None

    # FIX-APP-02: pre-initialise entropy guard singletons.
    # These objects are stateless across requests; constructing them once avoids
    # repeated import + __init__ overhead on every guarded request.
    # If the imports fail (optional deps not installed), guard is a no-op at runtime.
    try:
        from aegis.core.entropy_analysis import PayloadEntropyAnalyzer
        from aegis.core.taint_analysis import TaintEngine
        from aegis.core.xdp_dynamic_segmentation import XDPDynamicSegmenter

        state._entropy_taint_engine = TaintEngine()
        state._entropy_analyzer = PayloadEntropyAnalyzer()
        state._entropy_segmenter = XDPDynamicSegmenter()
    except ImportError:
        state._entropy_taint_engine = None
        state._entropy_analyzer = None
        state._entropy_segmenter = None

    async def _archive_finalized_segments_worker() -> None:
        assert state.s3_archiver is not None
        while True:
            for segment_path in state.ledger.archived_segments:
                try:
                    await archive_finalized_segment(
                        segment_path,
                        archiver=state.s3_archiver,
                        prefix=cfg.s3_archive_prefix,
                        receipt_dir=cfg.s3_archive_spool_dir / "anchor-receipts",
                        anchor_client=state.rfc3161_client,
                    )
                except asyncio.CancelledError:
                    raise
                except Exception:
                    logger.exception(
                        "finalized WAL archival is degraded; local authoritative segment retained"
                    )
            await asyncio.sleep(5.0)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        cfg.validate_runtime_invariants()
        logging.basicConfig(
            level=getattr(logging, cfg.log_level),
            format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        )
        observability.setup_otel(service_name="aegis-proxy")
        if state.siem_exporter is not None:
            state.siem_exporter.start()
        if state.s3_archiver is not None:
            await state.s3_archiver.start()
            state.archive_task = asyncio.create_task(
                _archive_finalized_segments_worker(),
                name="aegis-finalized-segment-archive",
            )

        # NOTE: the seccomp filter is applied LAST in this startup sequence
        # (just before `yield`), NOT here.  The async Rust forwarder's Tokio
        # runtime must spawn its worker threads and load the TLS trust store
        # while clone()/openat() are still permitted; once every subsystem has
        # initialised its threads and file descriptors we lock the process down.
        # See the "Seccomp lockdown" block below and seccomp_guard.py.

        lsm = None
        try:
            from aegis.core.lsm_guard import LSMGuard

            lsm = LSMGuard()
            if cfg.security_enforcement_mode == "strict" and cfg.require_lsm:
                lsm.assert_enforcing()
            if not lsm.verify_confinement():
                if cfg.security_enforcement_mode == "strict" and cfg.require_lsm:
                    raise RuntimeError(
                        "strict runtime requires active AppArmor/SELinux confinement"
                    )
                logger.warning("LSM confinement unavailable; development runtime continues")
            else:
                logger.info("LSM confinement verified — AppArmor/SELinux profile active.")
        except Exception as exc:
            if cfg.security_enforcement_mode == "strict" and cfg.require_lsm:
                raise RuntimeError(f"LSM enforcement required but unavailable: {exc}") from exc
            logger.warning("LSM module unavailable in development runtime: %s", exc)

        cfg.wal_path.parent.mkdir(parents=True, exist_ok=True)

        state.vault = None
        if cfg.vault_url:
            state.vault = VaultManager(
                vault_url=cfg.vault_url,
                role_id=cfg.vault_role_id,
                secret_id=cfg.vault_secret_id,
            )
            await state.vault.authenticate()

        backend_key = cfg.backend_api_key
        if state.vault and not backend_key:
            backend_key = (
                await state.vault.get_secret(cfg.vault_backend_secret_path, "api_key") or ""
            )

        forwarder_cfg = cfg.model_copy(update={"backend_api_key": backend_key})

        from aegis.providers import build_provider

        provider = build_provider(
            cfg.provider,
            openrouter_site_url=cfg.openrouter_site_url,
            openrouter_site_name=cfg.openrouter_site_name,
            anthropic_api_version=cfg.anthropic_api_version,
        )

        egress_guard = cfg.get_egress_guard()
        state.forwarder = LLMForwarder(forwarder_cfg, provider=provider, egress_guard=egress_guard)
        await state.forwarder.start()
        state.sessions = SessionLifecycleManager(max_sessions=4_096)
        state.analysis_workers = [
            asyncio.create_task(_analysis_worker(state), name=f"aegis-analysis-{index}")
            for index in range(cfg.analysis_worker_count)
        ]

        # Legacy SPIFFE header authentication is intentionally not activated.
        # Principal-first mTLS accepts direct TLS state or headers from an
        # explicitly allowlisted immediate proxy only.

        # ── Seccomp lockdown (applied LAST, after all subsystems init) ──────
        # Warm the Rust async runtime so its worker pool exists before we forbid
        # clone()/clone3(); then apply the strict syscall filter.  At this point
        # the forwarder's threads, the WAL file descriptors, and the TLS trust
        # store are all initialised, so the steady-state request path needs no
        # thread/process creation or new file opens.
        from aegis.core.rust_integration import warmup_rust_runtime

        warmup_rust_runtime()

        guard = None
        try:
            from aegis.core.seccomp_guard import SeccompGuard

            guard = SeccompGuard()
            if not guard.apply_filter():
                if cfg.security_enforcement_mode == "strict" and cfg.require_seccomp:
                    raise RuntimeError("strict runtime requires an active seccomp filter")
                logger.warning("Seccomp unavailable; development runtime continues")
        except Exception as exc:
            if cfg.security_enforcement_mode == "strict" and cfg.require_seccomp:
                raise RuntimeError(f"Seccomp enforcement required but unavailable: {exc}") from exc
            logger.warning("Seccomp unavailable in development runtime: %s", exc)

        app.state.aegis = state
        yield

        for worker in state.analysis_workers:
            worker.cancel()
        if state.archive_task is not None:
            state.archive_task.cancel()
            await asyncio.gather(state.archive_task, return_exceptions=True)
        if state.analysis_workers:
            try:
                async with asyncio.timeout(cfg.analysis_shutdown_timeout_seconds):
                    await asyncio.gather(*state.analysis_workers, return_exceptions=True)
            except TimeoutError:
                pending_workers = [
                    worker.get_name() for worker in state.analysis_workers if not worker.done()
                ]
                logger.error(
                    "analysis worker shutdown exceeded %.3fs; pending=%s",
                    cfg.analysis_shutdown_timeout_seconds,
                    pending_workers,
                )
        await state.forwarder.stop()
        if state.siem_exporter is not None:
            try:
                await asyncio.to_thread(state.siem_exporter.shutdown, 5.0, drain=False)
            except TimeoutError:
                logger.error("SIEM exporter did not stop before shutdown deadline")
        if state.s3_archiver is not None:
            await state.s3_archiver.close(drain=True)
        await state.ratelimiter.close()
        state.sessions.close()
        state.ledger.close()
        if _hsm_backend is not None:
            _hsm_backend.close()

    app = FastAPI(
        title="Aegis Latent Core",
        description=(
            "Forensic telemetry proxy for LLM inference pipelines. "
            "OpenAI-compatible drop-in with Merkle chain-of-custody."
        ),
        version=aegis.__version__,
        docs_url="/docs" if cfg.debug_mode else None,
        redoc_url="/redoc" if cfg.debug_mode else None,
        openapi_url="/openapi.json" if cfg.debug_mode else None,
        lifespan=lifespan,
    )
    app.state.aegis = state

    cors_origins = cfg.get_cors_origins()
    if cors_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
            expose_headers=[
                "Link",
                "X-Aegis-Analysis-Status",
                "X-Aegis-Evidence-Status",
                "X-Aegis-MMR-Format",
                "X-Aegis-MMR-Leaf",
                "X-Aegis-MMR-Leaf-Count",
                "X-Aegis-MMR-Leaf-Index",
                "X-Aegis-MMR-Proof",
                "X-Aegis-MMR-Root",
                "X-Aegis-Proof-Status",
                "X-Aegis-Request-ID",
                "X-Aegis-Session-ID",
                "X-RateLimit-Limit-Requests",
                "X-RateLimit-Remaining-Requests",
                "X-RateLimit-Limit-Tokens",
                "X-RateLimit-Remaining-Tokens",
                "Retry-After",
            ],
        )

    app.add_middleware(RequestBodyLimitMiddleware, max_body_bytes=cfg.max_request_body_bytes)
    app.add_middleware(RequestSmugglingProtectionMiddleware)

    dmz_networks = cfg.get_dmz_networks()
    if dmz_networks:
        app.add_middleware(
            DMZSourceIPMiddleware,
            allowed_networks=dmz_networks,
            trust_proxy_headers=cfg.dmz_trust_proxy_headers,
        )

    app.include_router(build_audit_router(state.ledger, validate_audit_auth), prefix="/v1/audit")
    app.include_router(build_attestation_router(), prefix="/v1/attestation")

    if observability.prometheus_available():
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        @app.get("/metrics", include_in_schema=False)
        async def metrics() -> Response:
            """Prometheus metrics endpoint. Available when prometheus-client is installed."""
            return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    async def _commit_evidence(
        rid: str,
        sid: str,
        raw_body: bytes,
        response_bytes: bytes,
        model: str,
        request_start: float,
        response_complete: bool,
        phi_scrubbed: bool = False,
        scrub_method: str = "",
        endpoint: str = "chat.completions",
        tenant_id: str | None = None,
    ) -> AuditNode:
        """Commit mandatory request-response evidence before any terminal response."""
        # PII redaction: replace tenant_id with a one-way hash prefix when
        # the operator has enabled it. The full session_id is retained in
        # memory for analysis; only the durable WAL record is pseudonymous.
        audit_identity = tenant_id or sid
        if cfg.pii_redact_tenant_id:
            audit_sid = hashlib.sha256(audit_identity.encode()).hexdigest()[:16]
        else:
            audit_sid = audit_identity

        commit_start = time.perf_counter()
        try:
            # The ledger remains synchronous by design; to_thread preserves
            # event-loop availability while this durability gate is awaited.
            node = await asyncio.to_thread(
                state.ledger.commit_forensic,
                state_id=rid,
                request_bytes=raw_body,
                response_bytes=response_bytes,
                entropy=0.0,
                tenant_id=audit_sid,
                model=model,
                endpoint=endpoint,
                sampling_params={
                    "evidence_status": "durable",
                    "response_complete": response_complete,
                },
                phi_scrubbed=phi_scrubbed,
                scrub_method=scrub_method,
                signer_name="",
                signature_meaning="request-response-evidence",
            )
            commit_elapsed = time.perf_counter() - commit_start
            observability.AUDIT_COMMIT_DURATION.observe(commit_elapsed)
            observability.AUDIT_CHAIN_NODES.set(len(state.ledger.chain))
            observability.AUDIT_COMMIT_LAG.observe(time.perf_counter() - request_start)
            return node
        except Exception as exc:
            observability.AUDIT_COMMIT_ERRORS.inc()
            logger.exception("mandatory durable evidence commit failed")
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Durable evidence unavailable; governed request rejected",
            ) from exc

    def _proof_headers(node: AuditNode) -> dict[str, str]:
        if node.mmr_proof is None or not node.mmr_leaf_hash:
            return {}
        proof_json = json.dumps(
            node.mmr_proof, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        proof_value = base64.urlsafe_b64encode(proof_json).decode("ascii").rstrip("=")
        return {
            "X-Aegis-MMR-Format": "aegis-mmr-inclusion-v1",
            "X-Aegis-MMR-Leaf": node.mmr_leaf_hash,
            "X-Aegis-MMR-Leaf-Index": str(node.mmr_leaf_index),
            "X-Aegis-MMR-Leaf-Count": str(node.mmr_leaf_count),
            "X-Aegis-MMR-Proof": proof_value,
            "X-Aegis-MMR-Root": node.merkle_root,
            "Link": (
                f'</v1/audit/proofs/{node.state_id}>; rel="aegis-inclusion-proof"; '
                'type="application/json"'
            ),
        }

    def _requested_output_tokens(body: dict[str, Any]) -> int:
        value = body.get("max_completion_tokens", body.get("max_tokens"))
        if value is None:
            return cfg.rate_limit_default_output_tokens
        if isinstance(value, bool) or not isinstance(value, int) or value < 1:
            raise HTTPException(
                status_code=422, detail="output token limit must be a positive integer"
            )
        if value > cfg.rate_limit_max_output_tokens:
            raise HTTPException(
                status_code=422,
                detail="requested output token limit exceeds the configured maximum",
            )
        return value

    def _rate_headers(decision: RateLimitDecision) -> dict[str, str]:
        return {
            # The generic fields represent the request bucket. Dimension-specific
            # fields remain authoritative for clients that also reserve tokens.
            "X-RateLimit-Limit": str(cfg.rate_limit_burst),
            "X-RateLimit-Remaining": str(decision.request_remaining),
            "X-RateLimit-Limit-Requests": str(cfg.rate_limit_burst),
            "X-RateLimit-Remaining-Requests": str(decision.request_remaining),
            "X-RateLimit-Limit-Tokens": str(cfg.rate_limit_token_capacity),
            "X-RateLimit-Remaining-Tokens": str(decision.token_remaining),
        }

    async def _reserve_budget(
        principal: Principal,
        body: dict[str, Any],
    ) -> tuple[RateLimitDecision, TokenReservation]:
        try:
            decision = await state.ratelimiter.reserve(
                principal.tenant_id,
                principal.credential_id,
                _requested_output_tokens(body),
            )
        except (RateLimitBackendUnavailableError, LegacyRateLimitBackendUnavailable) as exc:
            observability.RATELIMIT_BACKEND_ERRORS.inc()
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Rate-limit backend unavailable; request rejected",
            ) from exc
        if not decision.allowed or decision.reservation is None:
            observability.RATELIMIT_REJECTIONS.inc()
            headers = _rate_headers(decision)
            if math.isfinite(decision.retry_after):
                headers["Retry-After"] = str(max(1, math.ceil(decision.retry_after)))
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Request or generated-token quota exceeded",
                headers=headers,
            )
        return decision, decision.reservation

    async def _settle_budget(
        reservation: TokenReservation,
        response_json: object,
        *,
        provider: str,
    ) -> RateLimitDecision | None:
        if not isinstance(response_json, dict):
            return await reservation.finalize(reservation.reserved)
        usage = response_json.get("usage")
        if not isinstance(usage, dict):
            return await reservation.finalize(reservation.reserved)
        field = "output_tokens" if provider == "anthropic" else "completion_tokens"
        actual = usage.get(field)
        if isinstance(actual, bool) or not isinstance(actual, int) or actual < 0:
            return await reservation.finalize(reservation.reserved)
        return await reservation.finalize(actual)

    def _emit_security_event(
        request_id: str,
        *,
        outcome: EventOutcome,
        duration_seconds: float,
        item_count: int = 1,
    ) -> None:
        exporter = state.siem_exporter
        if exporter is None:
            return
        event = SecurityEvent(
            kind=EventKind.REQUEST_COMPLETED,
            outcome=outcome,
            correlation_id=request_id,
            severity=Severity.INFO if outcome is EventOutcome.SUCCEEDED else Severity.WARNING,
            item_count=item_count,
            duration_ms=max(0.0, duration_seconds * 1000.0),
        )
        _spawn_background(asyncio.to_thread(exporter.submit, event))

    async def _durable_error_response(
        *,
        request_id: str,
        session_id: str,
        raw_body: bytes,
        model: str,
        request_start: float,
        status_code: int,
        content: bytes,
        endpoint: str = "chat.completions",
        tenant_id: str | None = None,
    ) -> Response:
        """Persist an error response before exposing it to the caller."""
        node = await _commit_evidence(
            request_id,
            session_id,
            raw_body,
            content,
            model,
            request_start,
            response_complete=True,
            endpoint=endpoint,
            tenant_id=tenant_id,
        )
        error_response = Response(
            content=content,
            status_code=status_code,
            media_type="application/json",
        )
        error_response.headers.update(
            {
                "X-Aegis-Request-ID": request_id,
                "X-Aegis-Session-ID": session_id,
                "X-Aegis-Evidence-Status": "durable",
                "X-Aegis-Analysis-Status": "not-applicable",
            }
        )
        error_response.headers.update(_proof_headers(node))
        return error_response

    def _enqueue_analysis(
        rid: str,
        sid: str,
        model: str,
        logprobs_data: list[Any],
        sampling_params: dict[str, Any],
        raw_body: bytes,
        response_bytes: bytes,
        phi_scrubbed: bool,
        scrub_method: str,
    ) -> bool:
        """Submit optional response enrichment without weakening evidence integrity."""
        if (
            cfg.analysis_sample_rate <= 0.0
            or randbelow(1_000_000) / 1_000_000 > cfg.analysis_sample_rate
        ):
            return False
        try:
            state.analysis_queue.put_nowait(
                _AnalysisJob(
                    request_id=rid,
                    session_id=sid,
                    model=model,
                    logprobs_data=logprobs_data,
                    sampling_params=sampling_params,
                    raw_body=raw_body,
                    response_bytes=response_bytes,
                    tenant_id=hashlib.sha256(sid.encode()).hexdigest()[:16]
                    if cfg.pii_redact_tenant_id
                    else sid,
                    phi_scrubbed=phi_scrubbed,
                    scrub_method=scrub_method,
                    analysis_timeout_seconds=cfg.analysis_timeout_seconds,
                )
            )
            return True
        except asyncio.QueueFull:
            observability.ANALYSIS_QUEUE_REJECTIONS.inc()
            logger.warning("response analysis queue full; durable evidence remains complete")
            return False

    @app.get("/health")
    async def health() -> JSONResponse:
        """Deep health check: ledger + analyzer cache pressure.

        Returns 200 when all subsystems are operational, 503 when any
        subsystem is degraded.  This endpoint is safe to expose to a
        load-balancer; it never leaks config values or key material.
        """
        ledger_nodes = len(state.ledger.chain)
        ledger_fault = getattr(state.ledger, "_fault_state", "healthy")
        ledger_healthy = ledger_fault == "healthy"

        eviction_rate = state.analyzers.eviction_rate()
        cache_size = state.analyzers.size()

        # LRU pressure threshold: >30% eviction rate signals the session cap
        # is too small for current traffic — increase _MAX_ANALYZER_SESSIONS.
        cache_healthy = eviction_rate < 0.30

        # Provider name: guard against mock objects during testing and
        # against the lifespan not yet having completed (startup race).
        _fwd = getattr(state, "forwarder", None)
        try:
            provider_name = str(_fwd.provider.name) if _fwd is not None else "unavailable"
        except Exception:
            provider_name = "unavailable"

        status_code = 200 if (ledger_healthy and cache_healthy) else 503
        overall = "healthy" if status_code == 200 else "degraded"

        return JSONResponse(
            status_code=status_code,
            content={
                "status": overall,
                "ledger": {
                    "nodes": ledger_nodes,
                    "fault_state": ledger_fault,
                    "healthy": ledger_healthy,
                },
                "analyzer_cache": {
                    "size": cache_size,
                    "capacity": _MAX_ANALYZER_SESSIONS,
                    "eviction_rate": round(eviction_rate, 4),
                    "healthy": cache_healthy,
                },
                "provider": provider_name,
                "version": aegis.__version__,
            },
        )

    @app.get("/ready")
    async def ready() -> JSONResponse:
        """Readiness probe: confirms the forwarder client is initialised.

        Returns 200 once the lifespan startup has completed and the upstream
        httpx client is open.  Returns 503 before that window (edge case in
        slow-start environments).
        """
        forwarder_ready = (
            getattr(state, "forwarder", None) is not None and state.forwarder._client is not None
        )
        status_code = 200 if forwarder_ready else 503
        return JSONResponse(
            status_code=status_code,
            content={"status": "ready" if forwarder_ready else "starting"},
        )

    @app.post("/v1/chat/completions")
    async def chat_completions(
        request: Request,
        principal: Annotated[Principal, Depends(validate_proxy_auth)],
    ):
        request_start = time.perf_counter()
        raw_body = await request.body()
        try:
            body = canonical_normalize(json.loads(raw_body))
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON") from exc

        with observability.record_span("aegis.waf.check") as sp:
            waf_result = state.waf.inspect_payload(body)
            if sp:
                sp.set_attribute("waf.allowed", str(waf_result.allowed))
        if not waf_result.allowed:
            layer = "layer1" if "Layer-1" in (waf_result.reason or "") else "layer2"
            observability.WAF_BLOCKS.labels(layer=layer).inc()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Payload rejected by WAF: {waf_result.reason}",
            )

        # FIX-APP-02: pass state instead of cfg so the function uses the cached singletons.
        _apply_request_entropy_guard(request, body, state)

        # Best-effort PHI identifier redaction on the hot request path.
        # Scrubs 18 HIPAA identifier categories from message content before forwarding.
        # raw_body (used for audit) retains the original; body is the scrubbed copy.
        body, _phi_scrubbed, _scrub_method = _apply_phi_scrub_request(body, state)

        # PCI-DSS cardholder-data scrubbing (PAN/CVV/Track) before forwarding.
        body, _pci_scrubbed = _apply_pci_scrub_request(body, state)
        if _pci_scrubbed:
            _scrub_method = (_scrub_method + "+pci_pan_mask").lstrip("+")

        session_id = (
            request.headers.get("x-aegis-session-id")
            or request.headers.get("x-session-id")
            or body.get("user")
            or str(uuid.uuid4())
        )
        tenant_id = principal.tenant_id
        request_id = str(uuid.uuid4())

        # Multi-turn behavioral WAF check (Domain 5.1): accumulate per-session WAF
        # scores and detect escalation patterns (cumulative score / crescendo attack).
        # Runs only on requests that passed the per-turn WAF check above.
        session_waf = state.waf_session_tracker.record_and_check(
            session_id=session_id,
            score=waf_result.score,
            allowed=waf_result.allowed,
            reason=waf_result.reason or "",
        )
        if session_waf.escalated:
            observability.WAF_BLOCKS.labels(layer="session").inc()
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Behavioral WAF: {session_waf.reason}",
            )

        rate_decision, reservation = await _reserve_budget(principal, body)

        if not hasattr(state, "forwarder") or state.forwarder is None:
            await reservation.refund(0)
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Proxy not ready: forwarder has not been initialized. "
                "Ensure the server lifespan completed before sending requests.",
            )
        if (
            cfg.force_logprobs
            and state.forwarder.provider.supports_logprobs
            and not body.get("logprobs", False)
        ):
            body["logprobs"] = True
            body["top_logprobs"] = cfg.top_logprobs

        if body.get("stream", False):
            stream = state.forwarder.stream_sse("/v1/chat/completions", body)

            async def _commit_stream_terminal(summary: StreamEvidenceSummary) -> None:
                audit_sid = (
                    hashlib.sha256(tenant_id.encode()).hexdigest()[:16]
                    if cfg.pii_redact_tenant_id
                    else tenant_id
                )
                commit_start = time.perf_counter()
                try:
                    await asyncio.to_thread(
                        _commit_stream_evidence,
                        state_id=request_id,
                        request_bytes=raw_body,
                        response_hash=summary.response_hash,
                        response_size=summary.response_size,
                        response_preview=summary.response_preview,
                        terminal_outcome=summary.terminal_outcome,
                        final_marker_included=summary.final_marker_included,
                        token_count=summary.token_count,
                        elapsed_seconds=summary.elapsed_seconds,
                        redaction_hits=summary.redaction_hits,
                        tenant_id=audit_sid,
                        model=body.get("model", "unknown"),
                        endpoint="chat.completions",
                        phi_scrubbed=_phi_scrubbed or bool(summary.redaction_hits),
                        scrub_method=(
                            (_scrub_method + "+stream_window_regex").lstrip("+")
                            if summary.redaction_hits
                            else _scrub_method
                        ),
                        signer_name=principal.subject,
                        signature_meaning="stream-terminal-evidence",
                    )
                    observability.STREAM_DURATION.labels(
                        provider="openai", outcome=summary.terminal_outcome
                    ).observe(summary.elapsed_seconds)
                    observability.STREAM_TOKENS.labels(provider="openai").inc(summary.token_count)
                    for entity, count in summary.redaction_hits.items():
                        observability.STREAM_REDACTIONS.labels(
                            provider="openai", entity=entity
                        ).inc(count)
                    observability.AUDIT_COMMIT_DURATION.observe(time.perf_counter() - commit_start)
                    observability.AUDIT_CHAIN_NODES.set(len(state.ledger.chain))
                    observability.AUDIT_COMMIT_LAG.observe(time.perf_counter() - request_start)
                    await reservation.finalize(reservation.reserved)
                    _emit_security_event(
                        request_id,
                        outcome=(
                            EventOutcome.SUCCEEDED
                            if summary.terminal_outcome == "complete"
                            else EventOutcome.FAILED
                        ),
                        duration_seconds=summary.elapsed_seconds,
                    )
                except Exception:
                    observability.AUDIT_COMMIT_ERRORS.inc()
                    raise

            bounded_stream = BoundedStreamProxy(
                stream,
                terminal_commit=_commit_stream_terminal,
                max_response_bytes=cfg.max_stream_response_bytes,
                max_duration_seconds=cfg.max_stream_duration_seconds,
                max_event_bytes=cfg.max_stream_event_bytes,
                queue_max_items=cfg.stream_queue_max_items,
                queue_max_bytes=cfg.stream_queue_max_bytes,
                deidentifier_window_chars=cfg.stream_deidentifier_window_chars,
                enable_phi=state._phi_scrubber is not None,
                enable_pci=state._pci_scrubber is not None,
            )
            return StreamingResponse(
                bounded_stream,
                media_type="text/event-stream",
                headers={
                    "X-Aegis-Request-ID": request_id,
                    "X-Aegis-Session-ID": session_id,
                    "X-Aegis-Evidence-Status": "pending-terminal",
                    "X-Aegis-Analysis-Status": "not-sampled",
                    "X-Aegis-Proof-Status": "pending-terminal",
                    **_rate_headers(rate_decision),
                    "Link": (
                        f"</v1/audit/proofs/{request_id}>; "
                        'rel="aegis-inclusion-proof"; type="application/json"'
                    ),
                },
            )

        forward_timer = observability.StageTimer()
        try:
            with observability.record_span(
                "aegis.forward", provider=cfg.provider, endpoint="chat.completions"
            ):
                upstream = await state.forwarder.forward_json("/v1/chat/completions", body)
        except CircuitOpenError:
            observability.FORWARD_ERRORS.labels(stage="circuit_open").inc()
            await reservation.refund(0)
            return await _durable_error_response(
                request_id=request_id,
                session_id=session_id,
                raw_body=raw_body,
                model=body.get("model", "unknown"),
                request_start=request_start,
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content=b'{"detail":"Upstream temporarily unavailable (circuit breaker OPEN)"}',
            )
        except Exception:
            observability.FORWARD_ERRORS.labels(stage="network").inc()
            logger.exception("upstream forwarding failed")
            await reservation.refund(0)
            return await _durable_error_response(
                request_id=request_id,
                session_id=session_id,
                raw_body=raw_body,
                model=body.get("model", "unknown"),
                request_start=request_start,
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content=b'{"detail":"Upstream forwarding failed"}',
            )
        forward_timer.record("forward")

        if upstream.status_code != 200:
            observability.REQUEST_TOTAL.labels(
                method="POST",
                endpoint="chat_completions",
                status_class=f"{upstream.status_code // 100}xx",
            ).inc()
            await reservation.refund(0)
            return await _durable_error_response(
                request_id=request_id,
                session_id=session_id,
                raw_body=raw_body,
                model=body.get("model", "unknown"),
                request_start=request_start,
                status_code=upstream.status_code,
                content=upstream.content,
            )

        resp_json = upstream.json()
        settled = await _settle_budget(reservation, resp_json, provider="openai")
        response_rate_decision = settled or rate_decision
        # PHI de-identification on the hot response path: scrub before returning to client.
        resp_json = _apply_phi_scrub_response(resp_json, state)
        # PCI-DSS cardholder-data scrubbing on the hot response path.
        resp_json = _apply_pci_scrub_response(resp_json, state)
        resp_content = (
            json.dumps(resp_json).encode()
            if (state._phi_scrubber or state._pci_scrubber)
            else upstream.content
        )
        evidence_node = await _commit_evidence(
            request_id,
            session_id,
            raw_body,
            resp_content,
            body.get("model", "unknown"),
            request_start,
            response_complete=True,
            phi_scrubbed=_phi_scrubbed,
            scrub_method=_scrub_method,
            tenant_id=tenant_id,
        )
        queued = _enqueue_analysis(
            request_id,
            session_id,
            body.get("model", "unknown"),
            _extract_logprobs(resp_json),
            {"temperature": body.get("temperature")},
            raw_body,
            resp_content,
            _phi_scrubbed,
            _scrub_method,
        )

        observability.REQUEST_TOTAL.labels(
            method="POST", endpoint="chat_completions", status_class="2xx"
        ).inc()
        # Total end-to-end latency includes the mandatory evidence gate.
        observability.REQUEST_DURATION.labels(stage="total").observe(
            time.perf_counter() - request_start
        )

        trace_id = observability.current_trace_id()
        resp = Response(content=resp_content, status_code=200)
        resp.headers.update(
            {
                "X-Aegis-Request-ID": request_id,
                "X-Aegis-Session-ID": session_id,
                "X-Aegis-Alert-Count": "0",
                "X-Aegis-Evidence-Status": "durable",
                "X-Aegis-Analysis-Status": "queued" if queued else "not-sampled",
            }
        )
        resp.headers.update(_proof_headers(evidence_node))
        resp.headers.update(_rate_headers(response_rate_decision))
        _emit_security_event(
            request_id,
            outcome=EventOutcome.SUCCEEDED,
            duration_seconds=time.perf_counter() - request_start,
        )
        if trace_id:
            resp.headers["X-Trace-ID"] = trace_id
        return resp

    @app.post("/v1/messages")
    async def anthropic_messages(
        request: Request,
        principal: Annotated[Principal, Depends(validate_proxy_auth)],
    ) -> Response:
        request_start = time.perf_counter()
        raw_body = await request.body()
        try:
            parsed = canonical_normalize(json.loads(raw_body))
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON") from exc
        if not isinstance(parsed, dict):
            raise HTTPException(status_code=400, detail="Anthropic request must be an object")
        body: dict[str, Any] = parsed
        if not isinstance(body.get("model"), str) or not isinstance(body.get("messages"), list):
            raise HTTPException(status_code=422, detail="model and messages are required")
        max_tokens = body.get("max_tokens")
        if not isinstance(max_tokens, int) or isinstance(max_tokens, bool) or max_tokens < 1:
            raise HTTPException(status_code=422, detail="max_tokens must be a positive integer")

        waf_result = state.waf.inspect_payload(body)
        if not waf_result.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Payload rejected by WAF: {waf_result.reason}",
            )
        _apply_request_entropy_guard(request, body, state)
        body, request_scrubbed, scrub_method = _scrub_anthropic_payload(body, state)

        session_id = (
            request.headers.get("x-aegis-session-id")
            or request.headers.get("x-session-id")
            or str(uuid.uuid4())
        )
        tenant_id = principal.tenant_id
        request_id = str(uuid.uuid4())
        rate_decision, reservation = await _reserve_budget(principal, body)
        if state.forwarder.provider.name != "anthropic":
            await reservation.refund(0)
            return await _durable_error_response(
                request_id=request_id,
                session_id=session_id,
                raw_body=raw_body,
                model=body["model"],
                request_start=request_start,
                status_code=status.HTTP_409_CONFLICT,
                content=b'{"detail":"Native Anthropic ingress requires AEGIS_PROVIDER=anthropic"}',
                endpoint="anthropic.messages",
                tenant_id=tenant_id,
            )

        if body.get("stream") is True:
            upstream_stream = state.forwarder.stream_native_anthropic(body)
            terminal_marker = b'event: message_stop\ndata: {"type":"message_stop"}\n\n'

            async def _commit_anthropic_terminal(summary: StreamEvidenceSummary) -> None:
                audit_tenant = (
                    hashlib.sha256(tenant_id.encode()).hexdigest()[:16]
                    if cfg.pii_redact_tenant_id
                    else tenant_id
                )
                await asyncio.to_thread(
                    _commit_stream_evidence,
                    state_id=request_id,
                    request_bytes=raw_body,
                    response_hash=summary.response_hash,
                    response_size=summary.response_size,
                    response_preview=summary.response_preview,
                    terminal_outcome=summary.terminal_outcome,
                    final_marker_included=summary.final_marker_included,
                    token_count=summary.token_count,
                    elapsed_seconds=summary.elapsed_seconds,
                    redaction_hits=summary.redaction_hits,
                    tenant_id=audit_tenant,
                    model=body["model"],
                    endpoint="anthropic.messages",
                    phi_scrubbed=request_scrubbed or bool(summary.redaction_hits),
                    scrub_method=scrub_method,
                    signer_name=principal.subject,
                    signature_meaning="stream-terminal-evidence",
                )
                observability.STREAM_DURATION.labels(
                    provider="anthropic", outcome=summary.terminal_outcome
                ).observe(summary.elapsed_seconds)
                observability.STREAM_TOKENS.labels(provider="anthropic").inc(summary.token_count)
                for entity, count in summary.redaction_hits.items():
                    observability.STREAM_REDACTIONS.labels(provider="anthropic", entity=entity).inc(
                        count
                    )
                await reservation.finalize(reservation.reserved)
                _emit_security_event(
                    request_id,
                    outcome=(
                        EventOutcome.SUCCEEDED
                        if summary.terminal_outcome == "complete"
                        else EventOutcome.FAILED
                    ),
                    duration_seconds=summary.elapsed_seconds,
                )

            bounded = BoundedStreamProxy(
                upstream_stream,
                terminal_commit=_commit_anthropic_terminal,
                max_response_bytes=cfg.max_stream_response_bytes,
                max_duration_seconds=cfg.max_stream_duration_seconds,
                max_event_bytes=cfg.max_stream_event_bytes,
                queue_max_items=cfg.stream_queue_max_items,
                queue_max_bytes=cfg.stream_queue_max_bytes,
                deidentifier_window_chars=cfg.stream_deidentifier_window_chars,
                enable_phi=state._phi_scrubber is not None,
                enable_pci=state._pci_scrubber is not None,
                protocol="anthropic",
                terminal_predicate=lambda _raw, event: (
                    isinstance(event, dict) and event.get("type") == "message_stop"
                ),
                terminal_marker=terminal_marker,
            )
            return StreamingResponse(
                bounded,
                media_type="text/event-stream",
                headers={
                    "X-Aegis-Request-ID": request_id,
                    "X-Aegis-Session-ID": session_id,
                    "X-Aegis-Evidence-Status": "pending-terminal",
                    "X-Aegis-Proof-Status": "pending-terminal",
                    **_rate_headers(rate_decision),
                    "Link": (
                        f"</v1/audit/proofs/{request_id}>; "
                        'rel="aegis-inclusion-proof"; type="application/json"'
                    ),
                },
            )

        try:
            upstream = await state.forwarder.forward_native_anthropic(body)
        except CircuitOpenError:
            await reservation.refund(0)
            return await _durable_error_response(
                request_id=request_id,
                session_id=session_id,
                raw_body=raw_body,
                model=body["model"],
                request_start=request_start,
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content=b'{"type":"error","error":{"type":"overloaded_error","message":"Upstream temporarily unavailable"}}',
                endpoint="anthropic.messages",
                tenant_id=tenant_id,
            )
        except Exception:
            logger.exception("native Anthropic forwarding failed")
            await reservation.refund(0)
            return await _durable_error_response(
                request_id=request_id,
                session_id=session_id,
                raw_body=raw_body,
                model=body["model"],
                request_start=request_start,
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content=b'{"type":"error","error":{"type":"api_error","message":"Upstream forwarding failed"}}',
                endpoint="anthropic.messages",
                tenant_id=tenant_id,
            )
        response_json = upstream.json()
        if upstream.status_code < 200 or upstream.status_code >= 300:
            await reservation.refund(0)
            return await _durable_error_response(
                request_id=request_id,
                session_id=session_id,
                raw_body=raw_body,
                model=body["model"],
                request_start=request_start,
                status_code=upstream.status_code,
                content=upstream.content,
                endpoint="anthropic.messages",
                tenant_id=tenant_id,
            )
        settled = await _settle_budget(reservation, response_json, provider="anthropic")
        response_rate_decision = settled or rate_decision
        response_json, response_scrubbed, response_scrub_method = _scrub_anthropic_payload(
            response_json, state
        )
        response_content = json.dumps(
            response_json, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        evidence_node = await _commit_evidence(
            request_id,
            session_id,
            raw_body,
            response_content,
            body["model"],
            request_start,
            response_complete=True,
            phi_scrubbed=request_scrubbed or response_scrubbed,
            scrub_method="+".join(part for part in (scrub_method, response_scrub_method) if part),
            endpoint="anthropic.messages",
            tenant_id=tenant_id,
        )
        response = Response(
            content=response_content,
            status_code=upstream.status_code,
            media_type="application/json",
            headers={
                "X-Aegis-Request-ID": request_id,
                "X-Aegis-Session-ID": session_id,
                "X-Aegis-Evidence-Status": "durable",
                "X-Aegis-Analysis-Status": "not-sampled",
            },
        )
        response.headers.update(_proof_headers(evidence_node))
        response.headers.update(_rate_headers(response_rate_decision))
        _emit_security_event(
            request_id,
            outcome=EventOutcome.SUCCEEDED,
            duration_seconds=time.perf_counter() - request_start,
        )
        return response

    @app.post("/v1/completions")
    async def completions(
        request: Request,
        principal: Annotated[Principal, Depends(validate_proxy_auth)],
    ):
        raw_body = await request.body()
        try:
            body = canonical_normalize(json.loads(raw_body))
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON") from exc

        waf_result = state.waf.inspect_payload(body)
        if not waf_result.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"WAF rejected: {waf_result.reason}",
            )

        _apply_request_entropy_guard(request, body, state)

        if not hasattr(state, "forwarder") or state.forwarder is None:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Proxy not ready: forwarder has not been initialized.",
            )
        session_id = (
            request.headers.get("x-aegis-session-id")
            or request.headers.get("x-session-id")
            or str(uuid.uuid4())
        )
        tenant_id = principal.tenant_id
        request_id = str(uuid.uuid4())

        session_waf = state.waf_session_tracker.record_and_check(
            session_id=session_id,
            score=waf_result.score,
            allowed=waf_result.allowed,
            reason=waf_result.reason or "",
        )
        if session_waf.escalated:
            observability.WAF_BLOCKS.labels(layer="session").inc()
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Behavioral WAF: {session_waf.reason}",
            )

        rate_decision, reservation = await _reserve_budget(principal, body)

        completions_start = time.perf_counter()
        try:
            upstream = await state.forwarder.forward_json("/v1/completions", body)
        except CircuitOpenError:
            observability.FORWARD_ERRORS.labels(stage="circuit_open").inc()
            await reservation.refund(0)
            return await _durable_error_response(
                request_id=request_id,
                session_id=session_id,
                raw_body=raw_body,
                model=body.get("model", "unknown"),
                request_start=completions_start,
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content=b'{"detail":"Upstream temporarily unavailable (circuit breaker OPEN)"}',
                endpoint="completions",
            )
        except Exception:
            observability.FORWARD_ERRORS.labels(stage="network").inc()
            logger.exception("upstream completions forwarding failed")
            await reservation.refund(0)
            return await _durable_error_response(
                request_id=request_id,
                session_id=session_id,
                raw_body=raw_body,
                model=body.get("model", "unknown"),
                request_start=completions_start,
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content=b'{"detail":"Upstream forwarding failed"}',
                endpoint="completions",
            )
        if upstream.status_code != 200:
            await reservation.refund(0)
            return await _durable_error_response(
                request_id=request_id,
                session_id=session_id,
                raw_body=raw_body,
                model=body.get("model", "unknown"),
                request_start=completions_start,
                status_code=upstream.status_code,
                content=upstream.content,
                endpoint="completions",
            )

        try:
            response_json = upstream.json()
        except Exception:
            response_json = None
        settled = await _settle_budget(reservation, response_json, provider="openai")
        response_rate_decision = settled or rate_decision
        evidence_node = await _commit_evidence(
            request_id,
            session_id,
            raw_body,
            upstream.content,
            body.get("model", "unknown"),
            completions_start,
            response_complete=True,
            endpoint="completions",
            tenant_id=tenant_id,
        )
        queued = _enqueue_analysis(
            request_id,
            session_id,
            body.get("model", "unknown"),
            [],
            {"endpoint": "completions", "model": body.get("model")},
            raw_body,
            upstream.content,
            False,
            "",
        )

        resp = Response(content=upstream.content, status_code=200)
        resp.headers["X-Aegis-Request-ID"] = request_id
        resp.headers["X-Aegis-Session-ID"] = session_id
        resp.headers["X-Aegis-Evidence-Status"] = "durable"
        resp.headers["X-Aegis-Analysis-Status"] = "queued" if queued else "not-sampled"
        resp.headers.update(_proof_headers(evidence_node))
        resp.headers.update(_rate_headers(response_rate_decision))
        _emit_security_event(
            request_id,
            outcome=EventOutcome.SUCCEEDED,
            duration_seconds=time.perf_counter() - completions_start,
        )
        return resp

    return app


def main() -> None:
    """CLI entry point: ``aegis`` / ``aegis-server``."""
    import uvicorn

    cfg = get_settings()

    # FIX-BLOCKER-03 (server side): pass SSL/mTLS config to uvicorn.
    # ssl_certfile + ssl_keyfile: TLS for the Aegis server itself.
    # ssl_ca_certs + mtls_required: require and verify client certificates.
    uvicorn_kwargs: dict = {
        "host": cfg.host,
        "port": cfg.port,
        "workers": cfg.workers,
        "log_level": cfg.log_level.lower(),
    }

    if cfg.ssl_certfile is not None:
        uvicorn_kwargs["ssl_certfile"] = str(cfg.ssl_certfile)
    if cfg.ssl_keyfile is not None:
        uvicorn_kwargs["ssl_keyfile"] = str(cfg.ssl_keyfile)
    if cfg.ssl_ca_certs is not None:
        uvicorn_kwargs["ssl_ca_certs"] = str(cfg.ssl_ca_certs)
    if cfg.mtls_required:
        # ssl_cert_reqs=2 → ssl.CERT_REQUIRED: client certificate is mandatory.
        uvicorn_kwargs["ssl_cert_reqs"] = 2
        logger.info(
            "mTLS enforced: client certificate required (ssl_ca_certs=%s)",
            cfg.ssl_ca_certs,
        )

    uvicorn.run("aegis.proxy.app:app", **uvicorn_kwargs)


app = create_app()
