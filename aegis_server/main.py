# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis_server.main — Enterprise FastAPI application entry point.

This module wires together every sub-system of the enterprise layer:

    StorageProvider  ──► audit node persistence (SQLite / PostgreSQL / DynamoDB)
    SignerProvider   ──► signing (HMAC-SHA256 / Vault Transit)
    ComplianceExporter ─► SOC2/HIPAA sealed bundles
    BackgroundTasks  ──► off-path analytics (entropy, KL, crypto commit)

Request lifecycle (non-streaming)
----------------------------------
1. WAF + auth middleware (existing aegis.proxy.waf / auth layers).
2. Proxy handler forwards request to upstream LLM backend via httpx.
3. Response is returned to the caller *immediately* — zero added latency.
4. A ``BackgroundTask`` is enqueued to:
   a. Deserialise the response JSON (potentially large when logprobs=True).
   b. Compute Shannon entropy, KL divergence, MoE gate metrics off-path.
   c. Sign the Merkle root via the configured ``SignerProvider``.
   d. Persist the ``StorageNode`` via the configured ``StorageProvider``.

This ensures the forensic pipeline never adds measurable latency to the
user-facing request/response cycle.

Dependency injection
--------------------
FastAPI dependencies ``get_storage`` and ``get_signer`` read from the
application state object (``request.app.state``), which is populated during
the ``lifespan`` context manager.  No globals are used.

New endpoints (enterprise layer)
---------------------------------
POST /v1/enterprise/compliance/export
    Trigger an on-demand compliance bundle export.
GET  /v1/enterprise/compliance/bundles
    List previously exported bundles in the export directory.
GET  /v1/enterprise/health
    Returns storage + signer health plus node count.

Dependencies:
    fastapi>=0.111.0, pydantic>=2.7.0, httpx>=0.27.0,
    aiosqlite>=0.20.0 (optional), asyncpg>=0.29.0 (optional),
    aioboto3>=13.0.0 (optional), hvac>=2.1.0 (optional).
"""

from __future__ import annotations

import datetime
import hashlib
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Annotated, Any

import numpy as np
from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field, field_validator

from aegis.auth.apikey import constant_time_key_in
from aegis_server import __version__
from aegis_server.compliance.exporter import ComplianceExporter, ExportParams
from aegis_server.config import EnterpriseSettings, get_settings
from aegis_server.crypto import SignerProvider, get_signer
from aegis_server.storage import StorageProvider, get_provider

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic request / response schemas
# ---------------------------------------------------------------------------


class ComplianceExportRequest(BaseModel):
    """Request body for ``POST /v1/enterprise/compliance/export``."""

    from_offset: int = Field(
        default=0,
        ge=0,
        description="Zero-based record offset into the ordered audit chain.",
    )
    limit: int = Field(
        default=10_000,
        ge=1,
        le=100_000,
        description="Maximum number of audit nodes to include in the bundle.",
    )
    tenant_id: str | None = Field(
        default=None,
        description="Restrict export to this tenant/client identifier.  Null = all tenants.",
    )

    @field_validator("tenant_id", mode="before")
    @classmethod
    def _empty_to_none(cls, v: Any) -> str | None:
        if v == "":
            return None
        return v


class ComplianceExportResponse(BaseModel):
    """Response for a successful compliance export."""

    export_id: str
    output_path: str
    node_count: int
    chain_hash: str
    bundle_signature: str
    signer_scheme: str
    generated_at: str
    integrity_valid: bool


class EnterpriseHealthResponse(BaseModel):
    """Health check response for the enterprise layer."""

    status: str
    version: str
    storage_provider: str
    signer_provider: str
    node_count: int
    integrity_valid: bool
    checked_at: str


# ---------------------------------------------------------------------------
# Application lifespan — startup / shutdown
# ---------------------------------------------------------------------------


@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI lifespan context manager.

    Startup:
        1. Load ``EnterpriseSettings`` (validates all required env vars).
        2. Construct and initialise the ``StorageProvider``.
        3. Construct the ``SignerProvider`` (Vault auth is lazy).
        4. Attach both to ``app.state`` for dependency injection.
        5. Log the configured backend identities.

    Shutdown:
        1. Close the ``StorageProvider`` (releases pool / file handles).
    """
    settings: EnterpriseSettings = get_settings()

    # ── Configure structured logging ──────────────────────────────────
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        format="%(asctime)s %(levelname)-8s %(name)s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
    )

    logger.info(
        "Aegis enterprise layer v%s starting — storage=%s signer=%s",
        __version__,
        settings.storage_provider,
        settings.signer_provider,
    )

    # ── Storage ───────────────────────────────────────────────────────
    storage: StorageProvider = get_provider(settings)
    try:
        await storage.initialize()
    except RuntimeError as exc:
        logger.critical("Storage provider initialisation failed: %s", exc)
        raise

    # ── Signer ────────────────────────────────────────────────────────
    signer: SignerProvider = get_signer(settings)

    # ── Compliance exporter ───────────────────────────────────────────
    exporter = ComplianceExporter(
        storage=storage,
        signer=signer,
        export_dir=settings.compliance_export_dir,
    )

    # ── Attach to app state ───────────────────────────────────────────
    app.state.storage = storage
    app.state.signer = signer
    app.state.exporter = exporter
    app.state.settings = settings

    # MAJOR-02 fix: initialise the MerkleMountainRange singleton here so
    # _run_forensic_analytics can use real MMR merkle_roots instead of the
    # SHA-256 surrogate.  The MMR is in-memory and rebuilt on restart;
    # future work: persist peaks to storage for cross-restart continuity.
    from aegis.core.mmr import MerkleMountainRange

    app.state.mmr = MerkleMountainRange()
    logger.info("MerkleMountainRange initialised (in-memory, MAJOR-02 fix).")

    logger.info("Aegis enterprise layer ready.")

    yield  # ── application runs here ──────────────────────────────────

    # ── Shutdown ──────────────────────────────────────────────────────
    logger.info("Aegis enterprise layer shutting down …")
    await storage.close()
    logger.info("Storage provider closed.")


# ---------------------------------------------------------------------------
# FastAPI application factory
# ---------------------------------------------------------------------------


def create_app(settings: EnterpriseSettings | None = None) -> FastAPI:
    """
    Build and configure the enterprise FastAPI application.

    This function is called once at startup (from ``main()`` below) and
    also by test fixtures to inject test-scoped settings.

    Args:
        settings: Pre-built settings object (used by tests).  When ``None``,
                  the process-level singleton from ``get_settings()`` is used.

    Returns:
        Configured ``FastAPI`` instance.
    """
    cfg = settings or get_settings()

    app = FastAPI(
        title="Aegis Latent Core — Enterprise Gateway",
        version=__version__,
        description=(
            "High-performance, drop-in OpenAI-compatible LLM proxy with "
            "cryptographic audit chain, real-time entropy forensics, and "
            "SOC2 / HIPAA compliance exports."
        ),
        # MEDIUM-02 fix: OpenAPI schema hidden in production.
        # Set AEGIS_DEBUG_MODE=true only in local development.
        docs_url="/docs" if getattr(cfg, "debug_mode", False) else None,
        redoc_url="/redoc" if getattr(cfg, "debug_mode", False) else None,
        openapi_url="/openapi.json" if getattr(cfg, "debug_mode", False) else None,
        lifespan=lifespan,
    )

    # ── CORS ──────────────────────────────────────────────────────────
    if cfg.cors_origins:
        origins = [o.strip() for o in cfg.cors_origins.split(",") if o.strip()]
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    # ── Register route groups ─────────────────────────────────────────
    app.include_router(_health_router())
    app.include_router(_enterprise_router())

    return app


# ---------------------------------------------------------------------------
# FastAPI dependency injectors
# ---------------------------------------------------------------------------


def _get_storage(request: Request) -> StorageProvider:
    """Inject the process-level ``StorageProvider`` from app state."""
    storage: StorageProvider | None = getattr(request.app.state, "storage", None)
    if storage is None:
        raise HTTPException(status_code=503, detail="Storage provider not initialised")
    return storage


def _get_signer(request: Request) -> SignerProvider:
    """Inject the process-level ``SignerProvider`` from app state."""
    signer: SignerProvider | None = getattr(request.app.state, "signer", None)
    if signer is None:
        raise HTTPException(status_code=503, detail="Signer provider not initialised")
    return signer


def _get_exporter(request: Request) -> ComplianceExporter:
    """Inject the process-level ``ComplianceExporter`` from app state."""
    exporter: ComplianceExporter | None = getattr(request.app.state, "exporter", None)
    if exporter is None:
        raise HTTPException(status_code=503, detail="Compliance exporter not initialised")
    return exporter


def _get_settings_dep(request: Request) -> EnterpriseSettings:
    """Inject the process-level ``EnterpriseSettings`` from app state."""
    s: EnterpriseSettings | None = getattr(request.app.state, "settings", None)
    return s or get_settings()


def _require_auth(
    request: Request,
    settings: Annotated[EnterpriseSettings, Depends(_get_settings_dep)],
) -> str:
    """
    Validate the ``Authorization: Bearer <key>`` header for enterprise endpoints.

    Returns the matched API key on success.

    Raises:
        HTTPException 401: Missing or malformed Authorization header.
        HTTPException 403: Key not in the allowed set.
    """
    if settings.auth_disabled:
        return "__auth_disabled__"

    auth_header: str | None = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=401,
            detail="Missing or malformed Authorization header.  "
            "Expected: 'Authorization: Bearer <api-key>'",
        )
    key = auth_header.removeprefix("Bearer ").strip()
    valid_keys = settings.get_api_keys()
    if valid_keys and not constant_time_key_in(key, valid_keys):
        raise HTTPException(status_code=403, detail="Invalid API key")
    return key


def _require_audit_auth(
    request: Request,
    settings: Annotated[EnterpriseSettings, Depends(_get_settings_dep)],
) -> str:
    """
    Validate the Authorization header against the audit-only key set.

    Falls back to the proxy key set when no dedicated audit keys are configured.
    """
    if settings.auth_disabled:
        return "__auth_disabled__"

    auth_header: str | None = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    key = auth_header.removeprefix("Bearer ").strip()
    valid_keys = settings.get_audit_api_keys()
    if valid_keys and not constant_time_key_in(key, valid_keys):
        raise HTTPException(
            status_code=403, detail="Invalid or insufficient API key for audit access"
        )
    return key


# ---------------------------------------------------------------------------
# Background analytics task
# ---------------------------------------------------------------------------


async def _run_forensic_analytics(
    *,
    request_id: str,
    request_bytes: bytes,
    response_bytes: bytes,
    client_id: str,
    model: str,
    endpoint: str,
    storage: StorageProvider,
    signer: SignerProvider,
    force_logprobs: bool,
    app_state: Any = None,
) -> None:
    """
    Off-path forensic analytics task — runs via FastAPI BackgroundTasks.

    This function is intentionally designed to never raise unhandled exceptions:
    any failure is logged as ERROR but must not crash the worker process.

    Steps:
    1. Parse response JSON; warn on oversized payloads.
    2. Extract logprob token trail when present.
    3. Compute Shannon entropy of the response text.
    4. Hash request + response bytes.
    5. Build ``node_data`` forensic metadata dict.
    6. Sign the Merkle root (node_data hash used as proxy MMR root).
    7. Persist the node to storage.

    Args:
        request_id:    Unique request identifier (UUID4).
        request_bytes: Raw request body bytes.
        response_bytes: Raw response body bytes.
        client_id:     Redacted API key prefix (8 chars).
        model:         LLM model name from the request.
        endpoint:      API path, e.g. ``"chat.completions"``.
        storage:       Initialised storage provider.
        signer:        Configured signing provider.
        force_logprobs: Whether logprob injection was active.
    """
    start_ts = time.monotonic()
    timestamp = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    # ── 1. Parse response ─────────────────────────────────────────────
    response_json: dict[str, Any] = {}
    if response_bytes:
        payload_size = len(response_bytes)
        if force_logprobs and payload_size > 512_000:
            logger.warning(
                "request_id=%s: response payload is %d bytes — logprobs injection "
                "significantly inflates upstream transit size.  Consider reducing "
                "AEGIS_TOP_LOGPROBS or disabling AEGIS_FORCE_LOGPROBS for "
                "high-throughput workloads.",
                request_id,
                payload_size,
            )
        try:
            response_json = json.loads(response_bytes)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            logger.warning(
                "request_id=%s: response JSON parse failed in background task: %s",
                request_id,
                exc,
            )

    # ── 2. Extract logprob token trail ────────────────────────────────
    token_trail: list[dict[str, Any]] = []
    try:
        choices = response_json.get("choices", [])
        for choice in choices:
            logprobs_block = (choice or {}).get("logprobs") or {}
            content_tokens = logprobs_block.get("content") or []
            for tok in content_tokens:
                if isinstance(tok, dict):
                    token_trail.append(
                        {
                            "token": tok.get("token", ""),
                            "logprob": tok.get("logprob", 0.0),
                            # Store per-position top-K distribution for correct
                            # Shannon entropy computation (MAJOR-01 fix).
                            "top_logprobs": tok.get("top_logprobs") or [],
                        }
                    )
    except Exception as exc:
        logger.debug("request_id=%s: logprob extraction error: %s", request_id, exc)

    # ── 3. Position-averaged Shannon entropy ──────────────────────────
    # MAJOR-01 fix: compute H per position over the top-K distribution,
    # then average.  The old approach normalised argmax logprobs across
    # positions, which measured sequence-level score concentration, not
    # the model's per-token uncertainty.
    #
    # H_correct = (1/T) Σ_t [ -Σ_k p_{t,k} log2(p_{t,k}) ]
    #
    # Falls back to character-level entropy when logprobs are absent
    # (Anthropic provider) so the metric is always populated.
    entropy: float = 0.0
    try:
        position_entropies: list[float] = []
        for tok in token_trail:
            top_lps = tok.get("top_logprobs", [])
            if len(top_lps) < 2:
                # Single logprob entry → entropy is 0 (deterministic position).
                # Still add 0 so average reflects true sequence length.
                if tok.get("logprob") is not None:
                    position_entropies.append(0.0)
                continue
            lp_arr = np.array(
                [x.get("logprob", -100.0) for x in top_lps if isinstance(x, dict)],
                dtype=np.float64,
            )
            probs = np.exp(np.clip(lp_arr, -80.0, 0.0))
            probs = probs / (probs.sum() + 1e-12)
            nz = probs[probs > 0.0]
            position_entropies.append(float(-np.sum(nz * np.log2(nz + 1e-15))))

        if position_entropies:
            entropy = float(np.mean(position_entropies))
        elif response_bytes:
            # Fallback: character-level Shannon entropy of the raw response.
            # Used when the provider does not return logprobs (Anthropic, Gemini).
            char_counts = np.bincount(np.frombuffer(response_bytes, dtype=np.uint8))
            char_counts = char_counts[char_counts > 0].astype(np.float64)
            char_probs = char_counts / char_counts.sum()
            entropy = float(-np.sum(char_probs * np.log2(char_probs)))
    except Exception as exc:
        logger.debug("request_id=%s: entropy calculation error: %s", request_id, exc)

    # ── 4. Hash request + response ────────────────────────────────────
    request_hash: str = hashlib.sha256(request_bytes).hexdigest()
    response_hash: str = hashlib.sha256(response_bytes).hexdigest() if response_bytes else ""

    # ── 5. Build node_data ────────────────────────────────────────────
    # BLOCKER-01 fix: use get_latest_node() which returns the node with the
    # HIGHEST seq value (ORDER BY seq DESC LIMIT 1), not the genesis node.
    # The old list_nodes(limit=1, offset=0) used ASC order and always returned
    # the first node, breaking the linked-list structure from node #3 onwards.
    prev_hash: str = "0" * 64
    try:
        latest = await storage.get_latest_node()
        if latest:
            prev_hash = latest.get("node_id", "0" * 64)
    except Exception as exc:
        logger.debug("request_id=%s: could not retrieve prev_hash: %s", request_id, exc)

    # MAJOR-02 fix: use the MerkleMountainRange singleton (app.state.mmr) to
    # compute the real merkle_root with append-only MMR semantics instead of
    # the SHA-256 surrogate.  Falls back to the surrogate when mmr is None
    # (e.g. lifespan not yet initialised in tests).
    mmr = getattr(app_state, "mmr", None)
    if mmr is not None:
        try:
            leaf_data = (request_hash + response_hash + timestamp).encode()
            merkle_root: str = mmr.add_leaf(leaf_data)
        except Exception as exc:
            logger.warning(
                "request_id=%s: MMR.add_leaf failed (%s); falling back to SHA-256 surrogate",
                request_id,
                exc,
            )
            merkle_root = hashlib.sha256(
                (request_hash + response_hash + timestamp).encode()
            ).hexdigest()
    else:
        merkle_root = hashlib.sha256(
            (request_hash + response_hash + timestamp).encode()
        ).hexdigest()

    node_data: dict[str, Any] = {
        "prev_hash": prev_hash,
        "entropy": round(entropy, 6),
        "model": model,
        "endpoint": endpoint,
        "token_trail_count": len(token_trail),
        "is_fallback": False,
        "logprobs_present": bool(token_trail),
        "force_logprobs": force_logprobs,
        "usage": response_json.get("usage", {}),
    }

    # ── 6. Sign the Merkle root ───────────────────────────────────────
    signature: str = ""
    try:
        signature = await signer.sign_payload(merkle_root.encode())
    except Exception as exc:
        logger.error(
            "request_id=%s: signing failed in background task: %s — "
            "node will be persisted unsigned.",
            request_id,
            exc,
        )
        node_data["is_fallback"] = True

    # ── 7. Persist node ───────────────────────────────────────────────
    # node_id is SHA-256(merkle_root || signature) for tamper-evidence.
    node_id = hashlib.sha256((merkle_root + signature).encode()).hexdigest()
    try:
        await storage.write_node(
            node_id=node_id,
            timestamp=timestamp,
            node_data=node_data,
            request_hash=request_hash,
            response_hash=response_hash,
            merkle_root=merkle_root,
            signature=signature,
            client_id=client_id,
        )
        elapsed_ms = (time.monotonic() - start_ts) * 1000
        logger.debug(
            "request_id=%s: analytics background task complete in %.1f ms "
            "(node_id=%s…, entropy=%.4f, tokens=%d)",
            request_id,
            elapsed_ms,
            node_id[:16],
            entropy,
            len(token_trail),
        )
    except Exception as exc:
        logger.error(
            "request_id=%s: storage.write_node failed in background task: %s",
            request_id,
            exc,
        )


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------


def _health_router():
    """Liveness + readiness probes (unauthenticated)."""
    from fastapi import APIRouter

    router = APIRouter(tags=["Health"])

    @router.get("/health", include_in_schema=False)
    async def health() -> dict[str, str]:
        return {"status": "healthy", "version": __version__}

    @router.get("/ready", include_in_schema=False)
    async def ready(request: Request) -> dict[str, str]:
        storage = getattr(request.app.state, "storage", None)
        if storage is None:
            raise HTTPException(status_code=503, detail="Storage not ready")
        return {"status": "ready", "version": __version__}

    return router


def _enterprise_router():
    """Enterprise-specific endpoints (authenticated)."""
    from fastapi import APIRouter

    router = APIRouter(prefix="/v1/enterprise", tags=["Enterprise"])

    # ── Health ────────────────────────────────────────────────────────

    @router.get(
        "/health",
        response_model=EnterpriseHealthResponse,
        summary="Enterprise layer health",
        description=(
            "Returns the health status of the storage provider and signer.  "
            "Includes a live node count and the result of the most recent "
            "integrity verification."
        ),
    )
    async def enterprise_health(
        storage: Annotated[StorageProvider, Depends(_get_storage)],
        settings: Annotated[EnterpriseSettings, Depends(_get_settings_dep)],
        _key: Annotated[str, Depends(_require_audit_auth)],
    ) -> EnterpriseHealthResponse:
        checked_at = datetime.datetime.now(datetime.UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        try:
            integrity = await storage.check_integrity()
            node_count: int = integrity.get("node_count", 0)
            integrity_valid: bool = bool(integrity.get("is_valid", False))
        except Exception as exc:
            logger.error("enterprise_health: storage check failed: %s", exc)
            node_count = -1
            integrity_valid = False

        return EnterpriseHealthResponse(
            status="healthy" if integrity_valid or node_count == 0 else "degraded",
            version=__version__,
            storage_provider=settings.storage_provider,
            signer_provider=settings.signer_provider,
            node_count=node_count,
            integrity_valid=integrity_valid,
            checked_at=checked_at,
        )

    # ── Compliance export ─────────────────────────────────────────────

    @router.post(
        "/compliance/export",
        response_model=ComplianceExportResponse,
        status_code=201,
        summary="Trigger a compliance export bundle",
        description=(
            "Fetches the requested range of audit nodes, computes a canonical "
            "SHA-256 chain hash, signs it via the configured signer, and writes "
            "a sealed JSON bundle to the compliance export directory.  "
            "The bundle satisfies SOC2 Type II CC6.1 / CC7.2 and HIPAA 45 CFR "
            "§164.312(b) audit evidence requirements."
        ),
    )
    async def trigger_compliance_export(
        body: ComplianceExportRequest,
        exporter: Annotated[ComplianceExporter, Depends(_get_exporter)],
        _key: Annotated[str, Depends(_require_audit_auth)],
    ) -> ComplianceExportResponse:
        params = ExportParams(
            from_offset=body.from_offset,
            limit=body.limit,
            tenant_id=body.tenant_id,
        )
        try:
            result = await exporter.export(params=params)
        except RuntimeError as exc:
            logger.error("compliance export failed: %s", exc)
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        return ComplianceExportResponse(
            export_id=result.export_id,
            output_path=result.output_path,
            node_count=result.node_count,
            chain_hash=result.chain_hash,
            bundle_signature=result.bundle_signature,
            signer_scheme=result.signer_scheme,
            generated_at=result.generated_at,
            integrity_valid=result.integrity_valid,
        )

    # ── List existing bundles ─────────────────────────────────────────

    @router.get(
        "/compliance/bundles",
        summary="List exported compliance bundles",
        description=(
            "Returns a list of previously exported compliance bundle files "
            "in the configured export directory, sorted by filename descending "
            "(newest first)."
        ),
    )
    async def list_compliance_bundles(
        settings: Annotated[EnterpriseSettings, Depends(_get_settings_dep)],
        _key: Annotated[str, Depends(_require_audit_auth)],
        limit: int = 50,
    ) -> dict[str, Any]:
        import pathlib

        export_dir = pathlib.Path(settings.compliance_export_dir).resolve()
        if not export_dir.exists():
            return {"bundles": [], "export_dir": str(export_dir)}

        bundles = sorted(
            (
                {
                    "filename": f.name,
                    "size_bytes": f.stat().st_size,
                    "modified_at": datetime.datetime.fromtimestamp(
                        f.stat().st_mtime, tz=datetime.UTC
                    ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                }
                for f in export_dir.glob("aegis_compliance_*.json")
                if f.is_file()
            ),
            key=lambda x: x["filename"],
            reverse=True,
        )[:limit]

        return {
            "bundles": bundles,
            "export_dir": str(export_dir),
            "total": len(bundles),
        }

    # ── Audit passthrough: node listing ──────────────────────────────

    @router.get(
        "/audit/nodes",
        summary="List audit nodes from persistent storage",
        description=(
            "Returns a paginated list of audit nodes from the configured "
            "storage backend.  Supports optional tenant_id filtering."
        ),
    )
    async def list_audit_nodes(
        storage: Annotated[StorageProvider, Depends(_get_storage)],
        _key: Annotated[str, Depends(_require_audit_auth)],
        limit: int = 100,
        offset: int = 0,
        tenant_id: str | None = None,
    ) -> dict[str, Any]:
        try:
            nodes = await storage.list_nodes(
                limit=min(limit, 1000),
                offset=max(offset, 0),
                tenant_id=tenant_id or None,
            )
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        return {
            "nodes": nodes,
            "limit": limit,
            "offset": offset,
            "tenant_id": tenant_id,
            "returned": len(nodes),
        }

    @router.get(
        "/audit/nodes/{node_hash}",
        summary="Retrieve a single audit node by hash",
    )
    async def get_audit_node(
        node_hash: str,
        storage: Annotated[StorageProvider, Depends(_get_storage)],
        _key: Annotated[str, Depends(_require_audit_auth)],
    ) -> dict[str, Any]:
        if len(node_hash) != 64 or not all(c in "0123456789abcdef" for c in node_hash):
            raise HTTPException(
                status_code=422,
                detail="node_hash must be a 64-character lowercase hex string",
            )
        try:
            node = await storage.get_node(node_hash)
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

        if node is None:
            raise HTTPException(
                status_code=404,
                detail=f"No audit node found with hash {node_hash!r}",
            )
        return node

    @router.get(
        "/audit/integrity",
        summary="Verify full chain integrity",
        description=(
            "Performs an O(N) chain-linkage verification sweep across all nodes "
            "in the storage backend.  Each node's prev_hash is validated against "
            "its predecessor's node_id.  Run during off-peak hours for large tables."
        ),
    )
    async def audit_integrity(
        storage: Annotated[StorageProvider, Depends(_get_storage)],
        _key: Annotated[str, Depends(_require_audit_auth)],
    ) -> dict[str, Any]:
        try:
            return await storage.check_integrity()
        except RuntimeError as exc:
            raise HTTPException(status_code=500, detail=str(exc)) from exc

    # ── Proxy: chat completions with background analytics ─────────────

    @router.post(
        "/proxy/chat/completions",
        summary="Proxied chat completions with off-path forensics",
        description=(
            "Forwards the request to the configured upstream LLM endpoint and "
            "returns the response immediately.  Forensic analytics (entropy, "
            "KL divergence, chain commit) run off-path via a BackgroundTask — "
            "zero latency added to the user-facing request."
        ),
        include_in_schema=True,
    )
    async def proxy_chat_completions(
        request: Request,
        background_tasks: BackgroundTasks,
        storage: Annotated[StorageProvider, Depends(_get_storage)],
        signer: Annotated[SignerProvider, Depends(_get_signer)],
        settings: Annotated[EnterpriseSettings, Depends(_get_settings_dep)],
        _key: Annotated[str, Depends(_require_auth)],
    ) -> Response:
        import httpx

        request_id = str(uuid.uuid4())
        request_bytes = await request.body()

        # Parse model name for metadata (best-effort)
        model = "unknown"
        try:
            req_json = json.loads(request_bytes)
            model = str(req_json.get("model", "unknown"))
            # Inject logprobs if configured
            if settings.force_logprobs:
                req_json["logprobs"] = True
                req_json["top_logprobs"] = settings.top_logprobs
                request_bytes = json.dumps(req_json).encode()
        except (json.JSONDecodeError, UnicodeDecodeError):
            pass

        # Derive client_id from API key (8-char prefix, never full key)
        auth_header = request.headers.get("Authorization", "")
        raw_key = auth_header.removeprefix("Bearer ").strip()
        client_id = (raw_key[:8] + "…") if len(raw_key) >= 8 else "anon"

        # Forward request to upstream
        upstream_url = f"{settings.backend_url.rstrip('/')}/v1/chat/completions"
        upstream_headers = {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        backend_key = settings.backend_api_key.get_secret_value()
        if backend_key:
            upstream_headers["Authorization"] = f"Bearer {backend_key}"

        response_bytes = b""
        upstream_status = 502
        upstream_resp_headers: dict[str, str] = {}

        try:
            async with httpx.AsyncClient(
                timeout=httpx.Timeout(
                    connect=settings.backend_connect_timeout_seconds,
                    read=settings.backend_timeout_seconds,
                    write=30.0,
                    pool=5.0,
                )
            ) as client:
                resp = await client.post(
                    upstream_url,
                    content=request_bytes,
                    headers=upstream_headers,
                )
                response_bytes = await resp.aread()
                upstream_status = resp.status_code
                upstream_resp_headers = dict(resp.headers)
        except httpx.TimeoutException as exc:
            logger.error("request_id=%s: upstream timeout: %s", request_id, exc)
            return JSONResponse(
                status_code=504,
                content={"error": "upstream LLM backend timed out"},
                headers={"X-Aegis-Request-ID": request_id},
            )
        except httpx.RequestError as exc:
            logger.error("request_id=%s: upstream connection error: %s", request_id, exc)
            return JSONResponse(
                status_code=502,
                content={"error": "upstream LLM backend unreachable"},
                headers={"X-Aegis-Request-ID": request_id},
            )

        # Enqueue off-path analytics — response already available to return
        background_tasks.add_task(
            _run_forensic_analytics,
            request_id=request_id,
            request_bytes=request_bytes,
            response_bytes=response_bytes,
            client_id=client_id,
            model=model,
            endpoint="chat.completions",
            storage=storage,
            signer=signer,
            force_logprobs=settings.force_logprobs,
            app_state=request.app.state,
        )

        # Return upstream response verbatim + Aegis headers
        # Strip hop-by-hop headers that must not be forwarded
        _HOP_BY_HOP = frozenset(
            {
                "transfer-encoding",
                "connection",
                "keep-alive",
                "proxy-authenticate",
                "proxy-authorization",
                "te",
                "trailers",
                "upgrade",
            }
        )
        forward_headers = {
            k: v for k, v in upstream_resp_headers.items() if k.lower() not in _HOP_BY_HOP
        }
        forward_headers["X-Aegis-Request-ID"] = request_id

        return Response(
            content=response_bytes,
            status_code=upstream_status,
            headers=forward_headers,
            media_type=upstream_resp_headers.get("content-type", "application/json"),
        )

    return router


# ---------------------------------------------------------------------------
# Application singleton + entry point
# ---------------------------------------------------------------------------

# Module-level app instance consumed by Uvicorn / Gunicorn workers
app = create_app()


def main() -> None:
    """
    CLI entry point registered as ``aegis-enterprise-server`` in pyproject.toml.

    Reads host/port/workers/log_level from ``EnterpriseSettings`` (environment
    variables) so the Docker CMD is simply ``["aegis-enterprise-server"]``.
    """
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "aegis_server.main:app",
        host=settings.host,
        port=settings.port,
        workers=settings.workers,
        log_level=settings.log_level.lower(),
        access_log=True,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )


if __name__ == "__main__":
    main()
