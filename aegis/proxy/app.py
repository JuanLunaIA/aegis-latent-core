# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

import asyncio
import json
import logging
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
from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.normalization import canonical_normalize
from aegis.core.ratelimiter import create_rate_limiter
from aegis.core.secrets import VaultManager
from aegis.core.session_manager import SessionLifecycleManager
from aegis.proxy.analyzer import ResponseAnalysis, ResponseAnalyzer
from aegis.proxy.audit_api import build_audit_router
from aegis.proxy.dependencies import validate_proxy_auth
from aegis.proxy.forwarder import LLMForwarder
from aegis.proxy.schemas import AlertOut
from aegis.proxy.waf import AegisWAF

logger = logging.getLogger(__name__)
_ALERT_BUFFER_SIZE = 10_000

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
    # FIX-APP-02: entropy guard helpers instantiated once at startup,
    # not on every request (was: per-request allocation in hot path).
    _entropy_taint_engine: Any
    _entropy_analyzer: Any
    _entropy_segmenter: Any

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
    # FIX-APP-01: bounded LRU cache instead of unbounded plain dict.
    # FIX-BLOCKER-02: cfg injected so ResponseAnalyzer reads thresholds from config.
    state.analyzers = _BoundedAnalyzerCache(maxsize=_MAX_ANALYZER_SESSIONS, cfg=cfg)
    state.alert_store = _AlertStore()
    state.proxy_auth = ProxyKeyAuth(cfg)
    state.audit_auth = AuditKeyAuth(cfg)
    state.waf = AegisWAF(strict_mode=cfg.waf_strict_mode)
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

        app.state.aegis = state
        yield

        await state.forwarder.stop()
        await state.ratelimiter.close()
        state.sessions.close()
        state.ledger.close()

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
    app.include_router(build_audit_router(state.ledger, state.audit_auth), prefix="/v1/audit")

    async def _commit_and_alert(
        rid: str, sid: str, analysis: ResponseAnalysis, raw_body: bytes
    ) -> None:
        try:
            # Run the synchronous ledger commit (which calls os.fsync) in a
            # thread pool so the event loop is not stalled during disk I/O.
            # The ledger's internal threading.Lock makes this thread-safe.
            await asyncio.to_thread(
                state.ledger.commit_state,
                state_id=rid,
                entropy=analysis.mean_entropy,
                payload=raw_body[:65536],
                tenant_id=sid,
                sampling_params=analysis.sampling_params,
            )
            for alert in analysis.alerts:
                await state.alert_store.append(alert)
        except Exception as exc:
            logger.error("Failed to commit analysis to ledger: %s", exc)

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
        raw_body = await request.body()
        try:
            body = canonical_normalize(json.loads(raw_body))
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=400, detail="Invalid JSON") from exc

        waf_result = state.waf.inspect_payload(body)
        if not waf_result.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Payload rejected by WAF: {waf_result.reason}",
            )

        # FIX-APP-02: pass state instead of cfg so the function uses the cached singletons.
        _apply_request_entropy_guard(request, body, state)

        session_id = request.headers.get("x-session-id") or body.get("user") or str(uuid.uuid4())
        request_id = str(uuid.uuid4())

        if not await state.ratelimiter.check_limit(session_id):
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
                async for raw, parsed in state.forwarder.stream_sse("/v1/chat/completions", body):
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
                await _commit_and_alert(request_id, session_id, analysis, raw_body)

            return StreamingResponse(_stream_chat(), media_type="text/event-stream")

        upstream = await state.forwarder.forward_json("/v1/chat/completions", body)
        if upstream.status_code != 200:
            return Response(content=upstream.content, status_code=upstream.status_code)

        resp_json = upstream.json()
        analysis = analyzer.analyze(
            request_id=request_id,
            model=body.get("model", "unknown"),
            logprobs_data=_extract_logprobs(resp_json),
            sampling_params={"temperature": body.get("temperature")},
        )

        asyncio.create_task(_commit_and_alert(request_id, session_id, analysis, raw_body))

        resp = Response(content=upstream.content, status_code=200)
        resp.headers.update(
            {
                "X-Aegis-Request-ID": request_id,
                "X-Aegis-Session-ID": session_id,
                "X-Aegis-Alert-Count": str(len(analysis.alerts)),
            }
        )
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

        if not await state.ratelimiter.check_limit(session_id):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for this session",
            )

        upstream = await state.forwarder.forward_json("/v1/completions", body)
        if upstream.status_code != 200:
            return Response(content=upstream.content, status_code=upstream.status_code)

        analyzer = state.get_analyzer(session_id)
        analysis = analyzer.analyze(
            request_id=request_id,
            model=body.get("model", "unknown"),
            logprobs_data=None,
            sampling_params={"endpoint": "completions", "model": body.get("model")},
        )
        asyncio.create_task(_commit_and_alert(request_id, session_id, analysis, raw_body))

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
