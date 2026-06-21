# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import time
import uuid
from collections import OrderedDict
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from threading import Lock
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.middleware.base import BaseHTTPMiddleware

import aegis
from aegis.auth.apikey import AuditKeyAuth, ProxyKeyAuth
from aegis.config import AegisSettings, get_settings
from aegis.proxy.dmz_middleware import DMZSourceIPMiddleware
from aegis.core import observability
from aegis.core.circuit_breaker import CircuitOpenError
from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.hsm import HSMSigningBackend
from aegis.core.normalization import canonical_normalize
from aegis.core.phi_deidentifier import PHIDeidentifier
from aegis.core.ratelimiter import create_rate_limiter
from aegis.core.secrets import VaultManager
from aegis.core.session_manager import SessionLifecycleManager
from aegis.core.waf_session import WAFSessionTracker
from aegis.proxy.analyzer import ResponseAnalysis, ResponseAnalyzer
from aegis.proxy.audit_api import build_audit_router
from aegis.proxy.dependencies import validate_proxy_auth
from aegis.proxy.forwarder import LLMForwarder
from aegis.proxy.schemas import AlertOut
from aegis.proxy.waf import AegisWAF

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
        FIX-BLOCKER-02: previously, ResponseAnalyzer was instantiated with
        hardcoded defaults (kl_threshold=2.0, js_threshold=0.5, etc.),
        silently ignoring AegisSettings.kl_alert_threshold and siblings.
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
            # FIX-BLOCKER-02: read thresholds from cfg when available.
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
    # Multi-turn behavioral WAF session tracker (Domain 5.1).
    waf_session_tracker: WAFSessionTracker

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

    state = _AppState()
    state.settings = cfg
    state.mtls_auth = None  # populated in lifespan when mtls_required or ssl_ca_certs is set
    # FIX-APP-01: bounded LRU cache instead of unbounded plain dict.
    # FIX-BLOCKER-02: cfg injected so ResponseAnalyzer reads thresholds from config.
    state.analyzers = _BoundedAnalyzerCache(maxsize=_MAX_ANALYZER_SESSIONS, cfg=cfg)
    state.alert_store = _AlertStore()
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
            logger.warning(
                "HSM/PKCS#11 library configured (%s) but backend not available; "
                "falling back to HMAC-SHA256 signing.",
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
    )
    state.ratelimiter = create_rate_limiter(cfg)

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

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logging.basicConfig(
            level=getattr(logging, cfg.log_level),
            format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        )
        observability.setup_otel(service_name="aegis-proxy")

        # NOTE: the seccomp filter is applied LAST in this startup sequence
        # (just before `yield`), NOT here.  The async Rust forwarder's Tokio
        # runtime must spawn its worker threads and load the TLS trust store
        # while clone()/openat() are still permitted; once every subsystem has
        # initialised its threads and file descriptors we lock the process down.
        # See the "Seccomp lockdown" block below and seccomp_guard.py.

        # FIX-BLOCKER-01: LSM guard runs in advisory mode — a missing or
        # inactive LSM profile is logged as a WARNING, never a fatal error.
        # Rationale: most container, cloud, and development environments do not
        # have AppArmor/SELinux profiles loaded for arbitrary Python processes.
        # Crashing on startup prevents deployment in any such environment.
        # Operators who require hard LSM enforcement MUST validate the profile
        # externally (e.g. `aa-status`, `getenforce`) before starting Aegis.
        lsm = None
        try:
            from aegis.core.lsm_guard import LSMGuard

            lsm = LSMGuard()
            if not lsm.verify_confinement():
                logger.warning(
                    "LSM confinement NOT detected (AppArmor/SELinux profile absent or inactive). "
                    "Aegis is running in DAC-only mode. "
                    "For hardened deployments, load an LSM profile before starting the server."
                )
            else:
                logger.info("LSM confinement verified — AppArmor/SELinux profile active.")
        except Exception as exc:
            logger.warning("LSM module unavailable (%s). Continuing in degraded mode.", exc)

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

        state.forwarder = LLMForwarder(forwarder_cfg, provider=provider)
        await state.forwarder.start()
        state.sessions = SessionLifecycleManager(max_sessions=4_096)

        # I-05: wire mTLS identity validation when the operator enables it.
        # Without this block state.mtls_auth stays None and the mTLS code path
        # in dependencies.py is silently skipped, making mtls_required a no-op.
        if cfg.mtls_required or cfg.ssl_ca_certs:
            try:
                from aegis.core.identity import SpiffeIdentityManager
                from aegis.proxy.mtls import mTLSAuth

                state.mtls_auth = mTLSAuth(SpiffeIdentityManager())
                logger.info("mTLS authentication enabled (SPIFFE via SPIRE agent).")
            except Exception as exc:
                logger.warning("mTLS initialization failed: %s", exc)
                if cfg.mtls_required:
                    raise RuntimeError(
                        "mtls_required=True but mTLS could not be initialized"
                    ) from exc

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
                if not guard.is_sandbox:
                    raise RuntimeError(
                        "CRITICAL: Seccomp enforcement failed in non-sandbox environment."
                    )
                logger.warning(
                    "Seccomp filter could not be applied (degraded mode - sandbox detected)"
                )
        except Exception as exc:
            if guard is not None and not guard.is_sandbox:
                raise RuntimeError(f"CRITICAL: Seccomp initialization failed: {exc}") from exc
            logger.warning("Seccomp enforcement skipped: %s", exc)

        app.state.aegis = state
        yield

        await state.forwarder.stop()
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
        )

    app.add_middleware(RequestSmugglingProtectionMiddleware)

    dmz_networks = cfg.get_dmz_networks()
    if dmz_networks:
        app.add_middleware(
            DMZSourceIPMiddleware,
            allowed_networks=dmz_networks,
            trust_proxy_headers=cfg.dmz_trust_proxy_headers,
        )

    app.include_router(build_audit_router(state.ledger, state.audit_auth), prefix="/v1/audit")

    if observability.prometheus_available():
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest

        @app.get("/metrics", include_in_schema=False)
        async def metrics() -> Response:
            """Prometheus metrics endpoint. Available when prometheus-client is installed."""
            return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)

    async def _commit_and_alert(
        rid: str,
        sid: str,
        analysis: ResponseAnalysis,
        raw_body: bytes,
        request_start: float = 0.0,
        phi_scrubbed: bool = False,
        scrub_method: str = "",
        signer_name: str = "",
        signature_meaning: str = "",
    ) -> None:
        """Commit one audit node and fire alerts.

        Fail-open policy: audit storage failures are logged as ERROR and
        counted (aegis_audit_commit_errors_total) but do NOT propagate to
        the caller. The proxy continues serving. Callers must monitor the
        error counter; /health reflects ledger._fault_state for degraded
        posture detection.

        Privacy: when cfg.pii_redact_tenant_id is True the session/user
        identifier is replaced with its SHA-256 prefix before being written
        to the WAL. This makes the WAL GDPR-pseudonymous for tenant IDs.
        """
        # PII redaction: replace tenant_id with a one-way hash prefix when
        # the operator has enabled it. The full session_id is retained in
        # memory for analysis; only the durable WAL record is pseudonymous.
        if cfg.pii_redact_tenant_id:
            audit_sid = hashlib.sha256(sid.encode()).hexdigest()[:16]
        else:
            audit_sid = sid

        commit_start = time.perf_counter()
        try:
            # Run the synchronous ledger commit (which calls os.fsync) in a
            # thread pool so the event loop is not stalled during disk I/O.
            # The ledger's internal threading.Lock makes this thread-safe.
            await asyncio.to_thread(
                state.ledger.commit_state,
                state_id=rid,
                entropy=analysis.mean_entropy,
                payload=raw_body[:65536],
                tenant_id=audit_sid,
                sampling_params=analysis.sampling_params,
                phi_scrubbed=phi_scrubbed,
                scrub_method=scrub_method,
                signer_name=signer_name,
                signature_meaning=signature_meaning,
            )
            commit_elapsed = time.perf_counter() - commit_start
            observability.AUDIT_COMMIT_DURATION.observe(commit_elapsed)
            observability.AUDIT_CHAIN_NODES.set(len(state.ledger.chain))
            if request_start > 0.0:
                observability.AUDIT_COMMIT_LAG.observe(time.perf_counter() - request_start)
            for alert in analysis.alerts:
                await state.alert_store.append(alert)
        except Exception as exc:
            observability.AUDIT_COMMIT_ERRORS.inc()
            logger.error(
                "Audit commit failed (fail-open: proxy continues serving). "
                "Monitor aegis_audit_commit_errors_total and /health. Error: %s",
                exc,
            )

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
        _key: Annotated[str, Depends(validate_proxy_auth)],
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

        # PHI de-identification on the hot request path (NIST SP 800-188 Safe Harbor).
        # Scrubs 18 HIPAA identifier categories from message content before forwarding.
        # raw_body (used for audit) retains the original; body is the scrubbed copy.
        body, _phi_scrubbed, _scrub_method = _apply_phi_scrub_request(body, state)

        session_id = request.headers.get("x-session-id") or body.get("user") or str(uuid.uuid4())
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

        if not await state.ratelimiter.check_limit(session_id):
            observability.RATELIMIT_REJECTIONS.inc()
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for this session",
            )

        analyzer = state.get_analyzer(session_id)

        if not hasattr(state, "forwarder") or state.forwarder is None:
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

            async def _stream_chat() -> AsyncIterator[bytes]:
                accumulated: list = []
                upstream_done = False
                try:
                    async for raw, parsed in state.forwarder.stream_sse(
                        "/v1/chat/completions", body
                    ):
                        if raw.strip() == b"data: [DONE]":
                            upstream_done = True
                            yield b"data: [DONE]\n\n"
                            continue
                        if raw.startswith(b"data:"):
                            yield raw if raw.endswith(b"\n") else raw + b"\n"
                        elif raw.strip():
                            yield b"data: " + raw + b"\n"

                        if parsed:
                            lp = parsed.get("choices", [{}])[0].get("logprobs")
                            if lp and lp.get("content"):
                                accumulated.extend(lp["content"])

                    if not upstream_done:
                        yield b"data: [DONE]\n\n"
                finally:
                    # Commit the audit node even when the client disconnects
                    # mid-stream: asyncio raises GeneratorExit/CancelledError at
                    # the yield above, so any post-loop commit would be skipped,
                    # leaving partially-delivered responses out of the audit
                    # chain. The commit covers exactly what was accumulated.
                    # Scheduled via _spawn_background so it survives cancellation
                    # of this generator's task on disconnect.
                    logprobs = (
                        _extract_logprobs({"choices": [{"logprobs": {"content": accumulated}}]})
                        if accumulated
                        else None
                    )
                    analysis = analyzer.analyze(
                        request_id=request_id,
                        model=body.get("model", "unknown"),
                        logprobs_data=logprobs,
                        sampling_params={"temperature": body.get("temperature")},
                    )
                    _spawn_background(
                        _commit_and_alert(
                            request_id, session_id, analysis, raw_body, request_start,
                            phi_scrubbed=_phi_scrubbed, scrub_method=_scrub_method,
                            signer_name=session_id, signature_meaning="authored",
                        )
                    )

            return StreamingResponse(_stream_chat(), media_type="text/event-stream")

        forward_timer = observability.StageTimer()
        try:
            with observability.record_span(
                "aegis.forward", provider=cfg.provider, endpoint="chat.completions"
            ):
                upstream = await state.forwarder.forward_json("/v1/chat/completions", body)
        except CircuitOpenError as exc:
            observability.FORWARD_ERRORS.labels(stage="circuit_open").inc()
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Upstream temporarily unavailable (circuit breaker OPEN)",
            ) from exc
        except Exception:
            observability.FORWARD_ERRORS.labels(stage="network").inc()
            raise
        forward_timer.record("forward")

        if upstream.status_code != 200:
            observability.REQUEST_TOTAL.labels(
                method="POST",
                endpoint="chat_completions",
                status_class=f"{upstream.status_code // 100}xx",
            ).inc()
            return Response(content=upstream.content, status_code=upstream.status_code)

        resp_json = upstream.json()
        # PHI de-identification on the hot response path: scrub before returning to client.
        resp_json = _apply_phi_scrub_response(resp_json, state)
        analysis = analyzer.analyze(
            request_id=request_id,
            model=body.get("model", "unknown"),
            logprobs_data=_extract_logprobs(resp_json),
            sampling_params={"temperature": body.get("temperature")},
        )

        _spawn_background(
            _commit_and_alert(
                request_id, session_id, analysis, raw_body, request_start,
                phi_scrubbed=_phi_scrubbed, scrub_method=_scrub_method,
                signer_name=session_id, signature_meaning="authored",
            )
        )

        observability.REQUEST_TOTAL.labels(
            method="POST", endpoint="chat_completions", status_class="2xx"
        ).inc()
        # Total end-to-end latency (client-visible). Background commit is NOT
        # included here — it runs after the response is returned, proving the
        # "zero forensic latency" claim is measurable via separate metrics.
        observability.REQUEST_DURATION.labels(stage="total").observe(
            time.perf_counter() - request_start
        )

        trace_id = observability.current_trace_id()
        resp_content = json.dumps(resp_json).encode() if state._phi_scrubber else upstream.content
        resp = Response(content=resp_content, status_code=200)
        resp.headers.update(
            {
                "X-Aegis-Request-ID": request_id,
                "X-Aegis-Session-ID": session_id,
                "X-Aegis-Alert-Count": str(len(analysis.alerts)),
            }
        )
        if trace_id:
            resp.headers["X-Trace-ID"] = trace_id
        return resp

    @app.post("/v1/completions")
    async def completions(
        request: Request,
        _key: Annotated[str, Depends(validate_proxy_auth)],
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
        session_id = request.headers.get("x-session-id", str(uuid.uuid4()))
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

        if not await state.ratelimiter.check_limit(session_id):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for this session",
            )

        completions_start = time.perf_counter()
        try:
            upstream = await state.forwarder.forward_json("/v1/completions", body)
        except CircuitOpenError as exc:
            observability.FORWARD_ERRORS.labels(stage="circuit_open").inc()
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Upstream temporarily unavailable (circuit breaker OPEN)",
            ) from exc
        if upstream.status_code != 200:
            return Response(content=upstream.content, status_code=upstream.status_code)

        analyzer = state.get_analyzer(session_id)
        analysis = analyzer.analyze(
            request_id=request_id,
            model=body.get("model", "unknown"),
            logprobs_data=None,
            sampling_params={"endpoint": "completions", "model": body.get("model")},
        )
        _spawn_background(
            _commit_and_alert(request_id, session_id, analysis, raw_body, completions_start)
        )

        resp = Response(content=upstream.content, status_code=200)
        resp.headers["X-Aegis-Request-ID"] = request_id
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
