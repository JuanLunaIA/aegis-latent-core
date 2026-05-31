from __future__ import annotations
import asyncio
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Annotated, Any, AsyncIterator

import httpx
import numpy as np
from fastapi import Depends, FastAPI, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, StreamingResponse
from starlette.middleware.base import BaseHTTPMiddleware

from aegis.auth.apikey import AuditKeyAuth, ProxyKeyAuth, build_audit_auth, build_proxy_auth
from aegis.config import AegisSettings, get_settings
from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.core.session_manager import SessionLifecycleManager
from aegis.core.ratelimiter import DistributedRateLimiter
from aegis.core.identity import SpiffeIdentityManager
from aegis.core.secrets import VaultManager
from aegis.core.sandbox import enable_hardened_sandbox
from aegis.core.memory import memory_manager
from aegis.core.ebpf_monitor import ebpf_monitor
from aegis.proxy.analyzer import ResponseAnalyzer
from aegis.proxy.audit_api import build_audit_router
from aegis.proxy.forwarder import LLMForwarder
from aegis.proxy.dependencies import validate_audit_auth, validate_proxy_auth
from aegis.proxy.waf import AegisWAF
from aegis.core.normalization import canonical_normalize
from aegis.proxy.mtls import mTLSAuth
from aegis.proxy.schemas import (
    AlertOut,
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChoiceLogprobs,
    CompletionRequest,
    EmbeddingRequest,
    TokenLogprob,
    TopLogprob,
)

# --- HARDENING: Request Smuggling Protection ---
class RequestSmugglingProtectionMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        cl_headers = request.headers.getlist("content-length")
        if len(cl_headers) > 1:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Multiple Content-Length headers detected. Potential smuggling attack."}
            )
        
        te_header = request.headers.get("transfer-encoding")
        cl_header = request.headers.get("content-length")
        if te_header and "chunked" in te_header.lower() and cl_header:
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Both Transfer-Encoding: chunked and Content-Length headers present. Potential smuggling attack."}
            )
        
        if te_header and "chunked" not in te_header.lower():
            return JSONResponse(
                status_code=status.HTTP_400_BAD_REQUEST,
                content={"detail": "Unsupported or ambiguous Transfer-Encoding detected."}
            )
        
        return await call_next(request)

logger = logging.getLogger(__name__)
_ALERT_BUFFER_SIZE = 10_000

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
    ratelimiter: DistributedRateLimiter
    identity: SpiffeIdentityManager
    vault: VaultManager
    waf: AegisWAF
    analyzers: dict[str, ResponseAnalyzer]
    alert_store: _AlertStore
    proxy_auth: ProxyKeyAuth
    audit_auth: AuditKeyAuth
    settings: AegisSettings
    mtls_auth: mTLSAuth | None = None

    def _get_analyzer(self, session_id: str) -> ResponseAnalyzer:
        if session_id not in self.analyzers:
            self.analyzers[session_id] = ResponseAnalyzer(session_id=session_id)
        return self.analyzers[session_id]

def create_app(settings: AegisSettings | None = None) -> FastAPI:
    cfg = settings or get_settings()
    
    app = FastAPI(
        title="Aegis Latent Core",
        description=(
            "Forensic telemetry proxy for LLM inference pipelines. "
            "OpenAI-compatible drop-in with Merkle chain-of-custody."
        ),
        version="2.0.0",
        docs_url="/docs",
        redoc_url="/redoc",
    )
    
    @app.get("/health")
    async def health():
        return {"status": "healthy"}

    @app.get("/ready")
    async def ready():
        return {"status": "ready"}

    app.add_middleware(RequestSmugglingProtectionMiddleware)
    
    # --- STATE INITIALIZATION ---
    state = _AppState()
    state.settings = cfg
    state.analyzers = {}
    state.alert_store = _AlertStore()
    state.proxy_auth = ProxyKeyAuth(cfg)
    state.audit_auth = AuditKeyAuth(cfg)
    state.waf = AegisWAF(cfg)
    state.ledger = CryptographicAuditLedger(
        persistence_path=str(cfg.wal_path),
        max_memory_nodes=cfg.max_memory_nodes,
    )
    app.state.aegis = state

    # --- AUDIT ROUTER ---
    app.include_router(build_audit_router(state.ledger, state.audit_auth), prefix="/v1/audit")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        logging.basicConfig(
            level=getattr(logging, cfg.log_level),
            format="%(asctime)s %(levelname)s %(name)s — %(message)s",
        )
        
        # --- HARDENING: Seccomp-BPF Enforcement ---
        try:
            from aegis.core.seccomp_guard import SeccompGuard
            guard = SeccompGuard()
            if not guard.apply_filter():
                logger.warning("Seccomp filter could not be applied. Continuing in degraded mode.")
        except Exception as e:
            logger.warning(f"Seccomp enforcement failed: {e}")
        
        # --- HARDENING: LSM Confinement Verification ---
        try:
            from aegis.core.lsm_guard import LSMGuard
            lsm = LSMGuard()
            if not lsm.verify_confinement():
                logger.warning("System is running without LSM confinement. Integrity degraded.")
        except Exception as e:
            logger.warning(f"LSM verification failed: {e}")
        
        # --- COMPONENT STARTUP ---
        cfg.wal_path.parent.mkdir(parents=True, exist_ok=True)
        
        state.vault = None
        if cfg.vault_url:
            state.vault = VaultManager(
                vault_url=cfg.vault_url,
                role_id=cfg.vault_role_id,
                secret_id=cfg.vault_secret_id
            )
            await state.vault.authenticate()
        
        backend_key = cfg.backend_api_key
        if state.vault and not backend_key:
            backend_key = await state.vault.get_secret(cfg.vault_backend_secret_path, "api_key") or ""
        
        forwarder_cfg = cfg.model_copy(update={"backend_api_key": backend_key})
        state.forwarder = LLMForwarder(forwarder_cfg)
        await state.forwarder.start()
        
        state.sessions = SessionLifecycleManager(max_sessions=4_096)
        state.ratelimiter = DistributedRateLimiter(
            redis_url=cfg.redis_url or "redis://localhost:6379",
            requests_per_minute=cfg.rate_limit_threshold,
            burst=cfg.rate_limit_burst,
        )
        
        yield
        
        await state.forwarder.stop()
        state.sessions.close()
        state.ledger.close()

    app.router.lifespan_context = lifespan

    @app.post("/v1/chat/completions")
    async def chat_completions(
        request: Request, 
        _key: Annotated[str, Depends(validate_proxy_auth)]
    ):
        raw_body = await request.body()
        try: 
            body = json.loads(raw_body)
            body = canonical_normalize(body)
        except json.JSONDecodeError: 
            raise HTTPException(status_code=400, detail="Invalid JSON")

        # 1. WAF INSPECTION
        waf_result = state.waf.inspect_payload(body)
        if not waf_result.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Payload rejected by WAF: {waf_result.reason}"
            )
        
        # 2. ENTROPY ANALYSIS
        payload_text = ""
        if "messages" in body:
            payload_text = " ".join([m.get("content", "") if isinstance(m, dict) else str(m) for m in body["messages"]])
        elif "prompt" in body:
            prompt = body["prompt"]
            payload_text = " ".join(prompt) if isinstance(prompt, list) else str(prompt)
            
        if payload_text:
            from aegis.core.entropy_analysis import PayloadEntropyAnalyzer
            from aegis.core.xdp_dynamic_segmentation import XDPDynamicSegmenter
            from aegis.core.taint_analysis import TaintEngine
            
            taint_engine = TaintEngine()
            tainted_payload = taint_engine.taint(payload_text, origin="CLIENT_REQUEST")
            
            analyzer = PayloadEntropyAnalyzer()
            segmenter = XDPDynamicSegmenter()
            
            allowed, entropy = analyzer.analyze_payload(payload_text)
            if not allowed:
                client_ip = request.client.host
                segmenter.block_ip_immediately(client_ip)
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Payload rejected by Entropy Analysis: entropy={entropy:.4f}. IP BLACKHOLED."
                )
            if analyzer.detect_entropy_shift(payload_text):
                client_ip = request.client.host
                segmenter.block_ip_immediately(client_ip)
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Payload rejected: Abrupt entropy shift detected. IP BLACKHOLED."
                )
            
            sanitized_payload = taint_engine.sanitize_value(tainted_payload, "ENTROPY_WAF_PIPELINE")
            body["_sanitized_payload"] = sanitized_payload.value
        
        session_id = request.headers.get("x-session-id") or body.get("user") or str(uuid.uuid4())
        request_id = str(uuid.uuid4())
        
        if not await state.ratelimiter.check_limit(session_id):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded for this session. Please slow down."
            )
        
        analyzer = state._get_analyzer(session_id)
        
        if not body.get("logprobs", False):
            body["logprobs"] = True
            body["top_logprobs"] = cfg.top_logprobs
            body["top_logprobs"] = cfg.top_logprobs
        
        if body.get("stream", False):
            async def _stream_chat(b, sid, rid, anz, rebuild):
                accumulated = []
                async for raw, parsed in state.forwarder.stream_sse("/v1/chat/completions", b):
                    yield b"data: " + raw if not raw.startswith(b"data:") else raw
                    if parsed:
                        lp = parsed["choices"][0].get("logprobs")
                        if lp and lp.get("content"): 
                            accumulated.extend(lp["content"])
                
                yield b"data: [DONE]\n\n"
                
                logprobs = _extract_logprobs({"choices": [{"logprobs": {"content": accumulated}}]}) if accumulated else None
                analysis = anz.analyze(
                    request_id=rid, 
                    model=b.get("model", "unknown"), 
                    logprobs_data=logprobs, 
                    sampling_params={"temperature": b.get("temperature")}
                )
                await _commit_and_alert(rid, sid, analysis, rebuild)
            return StreamingResponse(
                _stream_chat(body, session_id, request_id, analyzer, raw_body), 
                media_type="text/event-stream"
            )
        
        upstream = await state.forwarder.forward_json("/v1/chat/completions", body)
        if upstream.status_code != 200: 
            return Response(content=upstream.content, status_code=upstream.status_code)
            
        resp_json = upstream.json()
        analysis = analyzer.analyze(
            request_id=request_id, 
            model=body.get("model", "unknown"), 
            logprobs_data=_extract_logprobs(resp_json), 
            sampling_params={"temperature": body.get("temperature")}
        )
        
        asyncio.create_task(_commit_and_alert(request_id, session_id, analysis, raw_body))
        
        resp = Response(content=upstream.content, status_code=200)
        resp.headers.update({
            "X-Aegis-Request-ID": request_id, 
            "X-Aegis-Session-ID": session_id, 
            "X-Aegis-Alert-Count": str(len(analysis.alerts))
        })
        return resp

    @app.post("/v1/completions")
    async def completions(
        request: Request, 
        _key: Annotated[str, Depends(validate_proxy_auth)]
    ):
        raw_body = await request.body()
        try: 
            body = json.loads(raw_body)
            body = canonical_normalize(body)
        except json.JSONDecodeError: 
            raise HTTPException(status_code=400, detail="Invalid JSON")
            
        waf_result = state.waf.inspect_payload(body)
        if not waf_result.allowed:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"WAF rejected: {waf_result.reason}"
            )
        
        payload_text = ""
        if "messages" in body:
            payload_text = " ".join([m.get("content", "") if isinstance(m, dict) else str(m) for m in body["messages"]])
        elif "prompt" in body:
            prompt = body["prompt"]
            payload_text = " ".join(prompt) if isinstance(prompt, list) else str(prompt)
        
        if payload_text:
            from aegis.core.entropy_analysis import PayloadEntropyAnalyzer
            from aegis.core.xdp_dynamic_segmentation import XDPDynamicSegmenter
            from aegis.core.taint_analysis import TaintEngine
            
            taint_engine = TaintEngine()
            tainted_payload = taint_engine.taint(payload_text, origin="CLIENT_REQUEST")
            
            analyzer = PayloadEntropyAnalyzer()
            segmenter = XDPDynamicSegmenter()
            
            allowed, entropy = analyzer.analyze_payload(payload_text)
            if not allowed:
                client_ip = request.client.host
                segmenter.block_ip_immediately(client_ip)
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Payload rejected by Entropy Analysis: entropy={entropy:.4f}. IP BLACKHOLED."
                )
            if analyzer.detect_entropy_shift(payload_text):
                client_ip = request.client.host
                segmenter.block_ip_immediately(client_ip)
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Payload rejected: Abrupt entropy shift detected. IP BLACKHOLED."
                )
            
            sanitized_payload = taint_engine.sanitize_value(tainted_payload, "ENTROPY_WAF_PIPELINE")
            body["_sanitized_payload"] = sanitized_payload.value
        
        session_id = request.headers.get("x-session-id", str(uuid.uuid4()))
        request_id = str(uuid.uuid4())
        
        state.ledger.commit_state(
            state_id=request_id, 
            entropy=0.0, 
            payload=raw_body[:65536], 
            tenant_id=session_id, 
            sampling_params={"endpoint": "completions", "model": body.get("model")}
        )
        
        upstream = await state.forwarder.forward_json("/v1/completions", body)
        if upstream.status_code != 200: 
            return Response(content=upstream.content, status_code=upstream.status_code)
            
        resp = Response(content=upstream.content, status_code=200)
        resp.headers["X-Aegis-Request-ID"] = request_id
        return resp

    def _extract_logprobs(resp_json: dict) -> list:
        try:
            return resp_json.get("choices", [])[0].get("logprobs", {}).get("content", [])
        except (IndexError, AttributeError):
            return []
    
    async def _commit_and_alert(rid: str, sid: str, analysis: ResponseAnalyzer, raw_body: bytes):
        try:
            # Use a safe fallback for attributes if they are missing in the current ResponseAnalyzer version
            entropy = getattr(analysis, "mean_entropy", 0.0)
            params = getattr(analysis, "params", {})
            alerts = getattr(analysis, "alerts", [])
            
            state.ledger.commit_state(
                state_id=rid, 
                entropy=entropy, 
                payload=raw_body[:65536], 
                tenant_id=sid, 
                sampling_params=params
            )
            for alert in alerts:
                await state.alert_store.append(alert)
        except Exception as e:
            logger.error(f"Failed to commit analysis to ledger: {e}")

    return app

app = create_app()