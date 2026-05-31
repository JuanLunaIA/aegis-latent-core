from __future__ import annotations

import asyncio
import json
import logging
import uuid
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Annotated, Any

from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.middleware.base import BaseHTTPMiddleware

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


class _AppState:
    forwarder: LLMForwarder
    ledger: CryptographicAuditLedger
    sessions: SessionLifecycleManager
    ratelimiter: Any
    vault: VaultManager | None
    waf: AegisWAF
    analyzers: dict[str, ResponseAnalyzer]
    alert_store: _AlertStore
    proxy_auth: ProxyKeyAuth
    audit_auth: AuditKeyAuth
    settings: AegisSettings

    def get_analyzer(self, session_id: str) -> ResponseAnalyzer:
        if session_id not in self.analyzers:
            self.analyzers[session_id] = ResponseAnalyzer(session_id=session_id)
        return self.analyzers[session_id]


def _extract_payload_text(body: dict) -> str:
    if "messages" in body:
        return " ".join(
            m.get("content", "") if isinstance(m, dict) else str(m) for m in body["messages"]
        )
    if "prompt" in body:
        prompt = body["prompt"]
        return " ".join(prompt) if isinstance(prompt, list) else str(prompt)
    return ""


def _apply_request_entropy_guard(request: Request, body: dict, cfg: AegisSettings) -> None:
    if not cfg.request_entropy_guard:
        return

    payload_text = _extract_payload_text(body)
    if not payload_text:
        return

    from aegis.core.entropy_analysis import PayloadEntropyAnalyzer
    from aegis.core.taint_analysis import TaintEngine
    from aegis.core.xdp_dynamic_segmentation import XDPDynamicSegmenter

    taint_engine = TaintEngine()
    tainted_payload = taint_engine.taint(payload_text, origin="CLIENT_REQUEST")
    analyzer = PayloadEntropyAnalyzer()
    segmenter = XDPDynamicSegmenter()

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


def create_app(settings: AegisSettings | None = None) -> FastAPI:
    cfg = settings or get_settings()

    state = _AppState()
    state.settings = cfg
    state.analyzers = {}
    state.alert_store = _AlertStore()
    state.proxy_auth = ProxyKeyAuth(cfg)
    state.audit_auth = AuditKeyAuth(cfg)
    state.waf = AegisWAF(strict_mode=cfg.waf_strict_mode)
    state.ledger = CryptographicAuditLedger(
        persistence_path=str(cfg.wal_path),
        max_memory_nodes=cfg.max_memory_nodes,
    )
    state.ratelimiter = create_rate_limiter(cfg)

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logging.basicConfig(
            level=getattr(logging, cfg.log_level),
            format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        )

        try:
            from aegis.core.seccomp_guard import SeccompGuard

            guard = SeccompGuard()
            if not guard.apply_filter():
                logger.warning("Seccomp filter could not be applied (degraded mode)")
        except Exception as exc:
            logger.warning("Seccomp enforcement skipped: %s", exc)

        try:
            from aegis.core.lsm_guard import LSMGuard

            lsm = LSMGuard()
            if not lsm.verify_confinement():
                logger.warning("LSM confinement not detected (degraded mode)")
        except Exception as exc:
            logger.warning("LSM verification skipped: %s", exc)

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
        state.forwarder = LLMForwarder(forwarder_cfg)
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
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
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
            state.ledger.commit_state(
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
    async def health() -> dict[str, str]:
        return {"status": "healthy"}

    @app.get("/ready")
    async def ready() -> dict[str, str]:
        return {"status": "ready"}

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

        _apply_request_entropy_guard(request, body, cfg)

        session_id = request.headers.get("x-session-id") or body.get("user") or str(uuid.uuid4())
        request_id = str(uuid.uuid4())

        if not await state.ratelimiter.check_limit(session_id):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for this session",
            )

        analyzer = state.get_analyzer(session_id)

        if cfg.force_logprobs and not body.get("logprobs", False):
            body["logprobs"] = True
            body["top_logprobs"] = cfg.top_logprobs

        if body.get("stream", False):

            async def _stream_chat() -> AsyncIterator[bytes]:
                accumulated: list = []
                async for raw, parsed in state.forwarder.stream_sse("/v1/chat/completions", body):
                    if raw.startswith(b"data:"):
                        yield raw if raw.endswith(b"\n") else raw + b"\n"
                    else:
                        yield b"data: " + raw if not raw.startswith(b"data:") else raw

                    if parsed:
                        lp = parsed.get("choices", [{}])[0].get("logprobs")
                        if lp and lp.get("content"):
                            accumulated.extend(lp["content"])

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

        _apply_request_entropy_guard(request, body, cfg)

        session_id = request.headers.get("x-session-id", str(uuid.uuid4()))
        request_id = str(uuid.uuid4())

        if not await state.ratelimiter.check_limit(session_id):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for this session",
            )

        state.ledger.commit_state(
            state_id=request_id,
            entropy=0.0,
            payload=raw_body[:65536],
            tenant_id=session_id,
            sampling_params={"endpoint": "completions", "model": body.get("model")},
        )

        upstream = await state.forwarder.forward_json("/v1/completions", body)
        if upstream.status_code != 200:
            return Response(content=upstream.content, status_code=upstream.status_code)

        resp = Response(content=upstream.content, status_code=200)
        resp.headers["X-Aegis-Request-ID"] = request_id
        return resp

    return app


def main() -> None:
    """CLI entry point: ``aegis`` / ``aegis-server``."""
    import uvicorn

    cfg = get_settings()
    uvicorn.run(
        "aegis.proxy.app:app",
        host=cfg.host,
        port=cfg.port,
        workers=cfg.workers,
        log_level=cfg.log_level.lower(),
    )


app = create_app()
