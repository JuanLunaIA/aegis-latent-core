"""
aegis.config — Centralized configuration via environment variables.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import AnyHttpUrl, Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AegisSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── Backend ──────────────────────────────────────────────────────────
    backend_url: AnyHttpUrl = Field(
        default="http://localhost:11434",
        description="URL of the upstream LLM backend (OpenAI-compatible).",
    )
    backend_api_key: str = Field(
        default="",
        description="API key forwarded to the upstream backend. If empty, will be fetched from Vault.",
    )
    backend_timeout_seconds: float = Field(
        default=120.0,
        ge=1.0,
        le=600.0,
        description="Total timeout for upstream requests (seconds).",
    )
    backend_connect_timeout_seconds: float = Field(
        default=10.0,
        ge=0.5,
        le=30.0,
    )

    # ── Vault Integration ────────────────────────────────────────────────
    vault_url: str = Field(
        default="",
        description="URL of the HashiCorp Vault server.",
    )
    vault_role_id: str = Field(
        default="",
        description="AppRole RoleID for Vault authentication.",
    )
    vault_secret_id: str = Field(
        default="",
        description="AppRole SecretID for Vault authentication.",
    )
    vault_backend_secret_path: str = Field(
        default="secret/data/aegis/backend",
        description="Vault path for the LLM backend API key.",
    )

    # ── Auth ─────────────────────────────────────────────────────────────
    api_keys: str = Field(
        default="",
        description=(
            "Comma-separated list of allowed API keys for proxy access. "
            "Leave empty to disable auth (NOT recommended for production)."
        ),
    )
    audit_api_keys: str = Field(
        default="",
        description="Comma-separated API keys for the /audit/* read endpoints.",
    )
    auth_disabled: bool = Field(
        default=False,
        description="Set True only for local development. Never in production.",
    )

    # ── mTLS / SSL Hardening ──────────────────────────────────────────────
    ssl_certfile: Path | None = Field(
        default=None,
        description="Path to the server SSL certificate file.",
    )
    ssl_keyfile: Path | None = Field(
        default=None,
        description="Path to the server SSL private key file.",
    )
    ssl_ca_certs: Path | None = Field(
        default=None,
        description="Path to the CA bundle used to verify client certificates (mTLS).",
    )
    mtls_required: bool = Field(
        default=False,
        description="If True, the server will require and verify a client certificate.",
    )

    # ── Storage ───────────────────────────────────────────────────────────
    wal_path: Path = Field(
        default=Path("./aegis.wal.jsonl"),
        description="Path to the Write-Ahead Log for the Merkle audit chain.",
    )
    max_memory_nodes: int = Field(
        default=100_000,
        ge=1_000,
        description="In-memory Merkle chain cap (deque sliding window).",
    )

    # ── Telemetry ─────────────────────────────────────────────────────────
    force_logprobs: bool = Field(
        default=True,
        description=(
            "Inject logprobs=True and top_logprobs=20 into every chat request "
            "so entropy analysis is always available."
        ),
    )
    top_logprobs: int = Field(
        default=20,
        ge=1,
        le=20,
        description="Number of top logprobs to request (max 20, OpenAI limit).",
    )
    entropy_alert_threshold_bits: float = Field(
        default=1.0,
        ge=0.0,
        description="Shannon entropy drop (bits) below baseline that triggers ALERT.",
    )
    kl_alert_threshold: float = Field(
        default=2.0,
        ge=0.0,
        description="KL divergence above which an ALERT is emitted.",
    )
    js_alert_threshold: float = Field(
        default=0.5,
        ge=0.0,
        le=1.0,
        description="JS divergence above which an ALERT is emitted.",
    )

    # ── Rate Limiting ─────────────────────────────────────────────────────
    rate_limit_requests_per_minute: int = Field(
        default=60,
        ge=1,
        le=10_000,
        description="Default request limit per minute per tenant/session.",
    )
    rate_limit_threshold: int = Field(
        default=60,
        ge=1,
        le=10_000,
        description="Rate limit threshold (requests per minute).",
    )
    rate_limit_window: int = Field(
        default=60,
        ge=1,
        le=3600,
        description="Rate limit window in seconds.",
    )
    rate_limit_burst: int = Field(
        default=10,
        ge=1,
        le=100,
        description="Maximum burst capacity for the token bucket.",
    )
    redis_url: str = Field(
        default="redis://localhost:6379",
        description="Redis connection URL for distributed rate limiting.",
    )
    rate_limit_backend: str = Field(
        default="memory",
        description="Rate limiter backend: 'memory' (default, no Redis) or 'redis'.",
    )
    request_entropy_guard: bool = Field(
        default=False,
        description="Block requests failing Shannon-entropy heuristics (enable in hardened mode).",
    )
    waf_strict_mode: bool = Field(
        default=True,
        description="Reject payloads that match known prompt-injection patterns.",
    )


    # ── Server ────────────────────────────────────────────────────────────
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8080, ge=1, le=65535)
    workers: int = Field(default=1, ge=1, le=64)
    log_level: str = Field(default="INFO")
    cors_origins: str = Field(
        default="",
        description="Comma-separated CORS allowed origins. Empty = no CORS headers.",
    )

    # ── Alerting ──────────────────────────────────────────────────────────
    webhook_url: str = Field(
        default="",
        description="HTTP(S) URL to POST alert payloads to (Slack, Teams, custom SIEM).",
    )
    webhook_timeout_seconds: float = Field(default=5.0, ge=0.5, le=30.0)

    @field_validator("rate_limit_backend")
    @classmethod
    def _validate_rate_limit_backend(cls, v: str) -> str:
        allowed = {"memory", "redis"}
        v_lower = v.lower()
        if v_lower not in allowed:
            raise ValueError(f"rate_limit_backend must be one of {allowed}")
        return v_lower

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, v: str) -> str:
        allowed = {"DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"}
        v_upper = v.upper()
        if v_upper not in allowed:
            raise ValueError(f"log_level must be one of {allowed}")
        return v_upper

    def get_api_keys(self) -> frozenset[str]:
        if not self.api_keys:
            return frozenset()
        return frozenset(k.strip() for k in self.api_keys.split(",") if k.strip())

    def get_audit_api_keys(self) -> frozenset[str]:
        if not self.audit_api_keys:
            return self.get_api_keys()
        return frozenset(k.strip() for k in self.audit_api_keys.split(",") if k.strip())

    def get_cors_origins(self) -> list[str]:
        if not self.cors_origins:
            return []
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def backend_url_str(self) -> str:
        return str(self.backend_url).rstrip("/")

@lru_cache(maxsize=1)
def get_settings() -> AegisSettings:
    return AegisSettings()
