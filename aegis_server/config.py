# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
"""
aegis_server.config — Enterprise configuration via environment variables.

All settings are read from the environment (or a .env file).  No secrets are
stored in code; defaults are safe for local development only.

Environment prefix: ``AEGIS_``

Dependency: pydantic-settings>=2.3.0
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class EnterpriseSettings(BaseSettings):
    """
    Enterprise-layer configuration.

    Storage provider, crypto signer, and upstream proxy settings are all
    controlled here.  The existing ``aegis.config.AegisSettings`` handles
    WAF, rate-limiter, and per-request forensics thresholds; this class
    extends it with persistence and signing backends.
    """

    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ------------------------------------------------------------------
    # Shared runtime enforcement
    # ------------------------------------------------------------------
    security_enforcement_mode: Literal["strict", "development"] = Field(default="strict")
    require_durable_evidence: bool = Field(default=True)

    # ------------------------------------------------------------------
    # Server
    # ------------------------------------------------------------------
    host: str = Field(default="0.0.0.0", description="Bind address.")
    port: int = Field(default=8080, ge=1, le=65535, description="Bind port.")
    workers: int = Field(default=1, ge=1, le=64, description="Uvicorn worker count.")
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(default="INFO")
    cors_origins: str = Field(
        default="",
        description="Comma-separated allowed CORS origins. Empty = no CORS.",
    )

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------
    api_keys: str = Field(
        default="",
        description=(
            "Comma-separated proxy API keys.  At least one is required in "
            "production.  Empty disables authentication (development only)."
        ),
    )
    audit_api_keys: str = Field(
        default="",
        description=(
            "Comma-separated read-only keys for /v1/audit/*.  Inherits api_keys when empty."
        ),
    )
    auth_disabled: bool = Field(
        default=False,
        description="Disable all authentication.  Never set True in production.",
    )

    # ------------------------------------------------------------------
    # Upstream backend
    # ------------------------------------------------------------------
    backend_url: str = Field(
        default="http://localhost:11434",
        description="OpenAI-compatible upstream LLM endpoint.",
    )
    backend_api_key: SecretStr = Field(
        default=SecretStr(""),
        description="API key forwarded to the upstream backend.",
    )
    backend_timeout_seconds: float = Field(default=120.0, gt=0)
    backend_connect_timeout_seconds: float = Field(default=10.0, gt=0)

    # ------------------------------------------------------------------
    # Forensics
    # ------------------------------------------------------------------
    force_logprobs: bool = Field(
        default=True,
        description=(
            "Inject logprobs=true, top_logprobs=N into every request.  "
            "Increases upstream payload size by ~3–8× for long completions."
        ),
    )
    top_logprobs: int = Field(default=20, ge=1, le=20)
    kl_alert_threshold: float = Field(default=2.0, gt=0)
    js_alert_threshold: float = Field(default=0.5, gt=0, le=1)
    entropy_alert_threshold_bits: float = Field(default=1.0, gt=0)
    request_entropy_guard: bool = Field(
        default=False,
        description="Block requests whose payload entropy is below the minimum band.",
    )
    webhook_url: str = Field(
        default="",
        description="POST alert payloads here (Slack, PagerDuty, SIEM ingest).",
    )

    # ------------------------------------------------------------------
    # Storage provider
    # ------------------------------------------------------------------
    storage_provider: Literal["sqlite", "postgres", "dynamodb"] = Field(
        default="sqlite",
        description=(
            "Persistence backend for the audit chain.  "
            "sqlite = local WAL-mode file; "
            "postgres = asyncpg connection pool; "
            "dynamodb = AWS DynamoDB via aioboto3."
        ),
    )

    # SQLite
    sqlite_path: str = Field(
        default="./aegis_audit.db",
        description="Path to the SQLite audit database file.",
    )

    # PostgreSQL
    postgres_dsn: str = Field(
        default="",
        description=(
            "asyncpg DSN, e.g. "
            "postgresql://user:pass@host:5432/aegis_audit.  "
            "Required when storage_provider=postgres."
        ),
    )
    postgres_min_pool_size: int = Field(default=2, ge=1, le=64)
    postgres_max_pool_size: int = Field(default=10, ge=1, le=256)

    # DynamoDB
    dynamodb_table: str = Field(
        default="aegis-audit-nodes",
        description="DynamoDB table name.  Table + GSI must be pre-created.",
    )
    dynamodb_region: str = Field(
        default="us-east-1",
        description="AWS region for DynamoDB.",
    )
    dynamodb_endpoint_url: str = Field(
        default="",
        description=(
            "Override DynamoDB endpoint (e.g. http://localhost:8000 for "
            "DynamoDB Local).  Empty = use AWS default."
        ),
    )

    # ------------------------------------------------------------------
    # Cryptographic signing provider
    # ------------------------------------------------------------------
    signer_provider: Literal["hmac", "vault"] = Field(
        default="hmac",
        description=(
            "Signing backend.  hmac = local HMAC-SHA256 (development / "
            "self-hosted); vault = HashiCorp Vault Transit Engine (enterprise)."
        ),
    )

    # HMAC signer
    hmac_signing_key: SecretStr = Field(
        default=SecretStr(""),
        description=(
            "HMAC signing key.  Required when signer_provider=hmac and no keyring "
            "path is configured.  Minimum 32 bytes of entropy.  Never use the default."
        ),
    )
    hmac_keyring_path: str = Field(
        default="",
        description=(
            "Optional owner-readable JSON keyring for zero-restart HMAC rotation. "
            "When set, it takes precedence over hmac_signing_key."
        ),
    )
    hmac_keyring_reload_interval_s: float = Field(
        default=1.0,
        ge=0.0,
        le=300.0,
        description="Minimum interval between keyring metadata reload attempts.",
    )

    # HashiCorp Vault Transit
    vault_url: str = Field(
        default="",
        description=(
            "Vault server URL, e.g. https://vault.corp.example.com.  "
            "Required when signer_provider=vault."
        ),
    )
    vault_token: SecretStr = Field(
        default=SecretStr(""),
        description="Vault token (short-lived; prefer AppRole in production).",
    )
    vault_role_id: str = Field(
        default="",
        description="Vault AppRole RoleID (takes precedence over token).",
    )
    vault_secret_id: SecretStr = Field(
        default=SecretStr(""),
        description="Vault AppRole SecretID.",
    )
    vault_transit_key: str = Field(
        default="aegis-signing-key",
        description="Name of the Transit secrets engine key used for signing.",
    )
    vault_transit_mount: str = Field(
        default="transit",
        description="Mount path for the Transit secrets engine.",
    )
    vault_max_retries: int = Field(
        default=3,
        ge=0,
        le=10,
        description="Maximum retry attempts on transient Vault failures.",
    )
    vault_retry_base_delay_s: float = Field(
        default=0.25,
        gt=0,
        description="Base delay (seconds) for exponential retry backoff.",
    )
    vault_namespace: str = Field(
        default="",
        description="Vault Enterprise namespace (empty = root namespace).",
    )

    # ------------------------------------------------------------------
    # Compliance exporter
    # ------------------------------------------------------------------
    compliance_export_dir: str = Field(
        default="./aegis_exports",
        description="Directory where compliance export bundles are written.",
    )

    # ------------------------------------------------------------------
    # Validators
    # ------------------------------------------------------------------

    @field_validator("api_keys", "audit_api_keys", mode="before")
    @classmethod
    def _strip_keys(cls, v: str) -> str:
        return v.strip() if isinstance(v, str) else v

    @model_validator(mode="after")
    def _check_required_settings(self) -> EnterpriseSettings:
        if self.storage_provider == "postgres" and not self.postgres_dsn:
            raise ValueError("AEGIS_POSTGRES_DSN is required when AEGIS_STORAGE_PROVIDER=postgres")
        if self.signer_provider == "vault" and not self.vault_url:
            raise ValueError("AEGIS_VAULT_URL is required when AEGIS_SIGNER_PROVIDER=vault")
        if self.signer_provider == "vault":
            has_token = bool(self.vault_token.get_secret_value())
            has_approle = bool(self.vault_role_id and self.vault_secret_id.get_secret_value())
            if not has_token and not has_approle:
                raise ValueError(
                    "When AEGIS_SIGNER_PROVIDER=vault, provide either "
                    "AEGIS_VAULT_TOKEN or both AEGIS_VAULT_ROLE_ID + "
                    "AEGIS_VAULT_SECRET_ID"
                )
        return self

    # ------------------------------------------------------------------
    # Convenience
    # ------------------------------------------------------------------

    def validate_runtime_invariants(self) -> None:
        """Fail before serving when enterprise evidence controls are incomplete."""
        if self.security_enforcement_mode != "strict":
            return
        if self.auth_disabled:
            raise ValueError("strict runtime cannot disable authentication")
        if not self.require_durable_evidence:
            raise ValueError("strict runtime requires durable evidence")
        if not self.get_api_keys():
            raise ValueError("strict runtime requires at least one API key")
        if self.signer_provider == "hmac":
            if self.hmac_keyring_path:
                return
            key = self.hmac_signing_key.get_secret_value()
            if len(key.encode("utf-8")) < 32:
                raise ValueError("strict runtime requires an HMAC key with at least 32 bytes")
        if self.signer_provider == "vault" and not self.vault_url:
            raise ValueError("strict runtime requires Vault signer URL")

    def get_api_keys(self) -> set[str]:
        """Return the set of valid proxy API keys (stripped, non-empty)."""
        if not self.api_keys:
            return set()
        return {k.strip() for k in self.api_keys.split(",") if k.strip()}

    def get_audit_api_keys(self) -> set[str]:
        """Return the set of valid audit-only API keys."""
        raw = self.audit_api_keys or self.api_keys
        if not raw:
            return set()
        return {k.strip() for k in raw.split(",") if k.strip()}


@lru_cache(maxsize=1)
def get_settings() -> EnterpriseSettings:
    """Return a process-level singleton of EnterpriseSettings."""
    return EnterpriseSettings()
