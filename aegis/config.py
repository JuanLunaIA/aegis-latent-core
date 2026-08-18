"""
aegis.config — Centralized configuration via environment variables.
"""

# Copyright (c) 2026 Juan Luna. All rights reserved.
# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
from __future__ import annotations

from functools import lru_cache
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

from pydantic import AnyHttpUrl, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class AegisSettings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # ── Provider ─────────────────────────────────────────────────────────
    provider: str = Field(
        default="openai",
        description=(
            "LLM provider adapter to use. "
            "Valid values: openai, anthropic, gemini, openrouter. "
            "Controls request/response translation and auth header format. "
            "Set to 'openai' for any OpenAI-compatible endpoint (vLLM, Ollama, LM Studio)."
        ),
    )
    provider_model: str = Field(
        default="",
        description=(
            "Override the model name sent to the upstream provider. "
            "When set, replaces the 'model' field in every request. "
            "Useful for routing all traffic through a single backend model "
            "regardless of what the client requests."
        ),
    )

    # ── OpenRouter extras ─────────────────────────────────────────────
    openrouter_site_url: str = Field(
        default="",
        description="HTTP-Referer header for OpenRouter analytics (optional).",
    )
    openrouter_site_name: str = Field(
        default="",
        description="X-Title header for OpenRouter analytics (optional).",
    )

    # ── Anthropic extras ──────────────────────────────────────────────
    anthropic_api_version: str = Field(
        default="2023-06-01",
        description="anthropic-version header value. Change only when targeting a beta API version.",
    )

    # ── Backend ──────────────────────────────────────────────────────────
    backend_url: AnyHttpUrl = Field(
        default="http://localhost:11434",
        description=(
            "URL of the upstream LLM backend (OpenAI-compatible). "
            "Ignored for providers with a fixed base URL "
            "(anthropic: api.anthropic.com, gemini: generativelanguage.googleapis.com, "
            "openrouter: openrouter.ai/api/v1)."
        ),
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
    api_key_scopes: str = Field(
        default="",
        description=(
            "Semicolon-separated HIPAA minimum-necessary scope restrictions per API key. "
            "Format: 'key1:scope1,scope2;key2:scope3'. "
            "Valid scopes: proxy:completions, audit:read, audit:export, audit:analytics. "
            "Keys not listed here receive all scopes (backward-compatible default). "
            "Example: 'read-only-key:audit:read;export-key:audit:read,audit:export'. "
            "Set via AEGIS_API_KEY_SCOPES environment variable."
        ),
    )
    signing_key: str = Field(
        default="",
        description=(
            "Dedicated HMAC-SHA256 signing key for the Merkle audit chain. "
            "MUST be separate from AEGIS_API_KEYS. "
            "Generate with: python -c 'import secrets; print(secrets.token_hex(32))' "
            "If empty and auth is not disabled, a warning is emitted at startup."
        ),
    )

    # ── LDAP / Active Directory ───────────────────────────────────────────────
    ldap_url: str = Field(
        default="",
        description=(
            "LDAP server URL for multi-factor identity assertion. "
            "Use 'ldaps://' for direct TLS (recommended) or 'ldap://' with "
            "AEGIS_LDAP_USE_START_TLS=true for StartTLS. "
            "Example: ldaps://dc.corp.example.com:636. "
            "Leave empty to disable LDAP authentication."
        ),
    )
    ldap_base_dn: str = Field(
        default="",
        description=(
            "LDAP base Distinguished Name for user and group searches. "
            "Example: DC=corp,DC=example,DC=com"
        ),
    )
    ldap_bind_dn: str = Field(
        default="",
        description=(
            "Service-account DN for the initial directory search bind (least-privilege read). "
            "Example: CN=svc-aegis,OU=ServiceAccounts,DC=corp,DC=example,DC=com. "
            "Provide via AEGIS_LDAP_BIND_DN environment variable or Vault."
        ),
    )
    ldap_bind_password: str = Field(
        default="",
        description=(
            "Password for the LDAP service account. "
            "Provide via AEGIS_LDAP_BIND_PASSWORD or Vault; never hard-code."
        ),
    )
    ldap_user_search_filter: str = Field(
        default="(|(sAMAccountName={username})(userPrincipalName={username}))",
        description=(
            "LDAP search filter template for user lookup. {username} is substituted "
            "with the RFC 4515-escaped login name. "
            "AD default covers sAMAccountName and UPN formats. "
            "POSIX LDAP alternative: (uid={username})"
        ),
    )
    ldap_user_search_base: str = Field(
        default="",
        description=(
            "DN subtree for user searches. Defaults to ldap_base_dn when empty. "
            "Example: OU=Users,DC=corp,DC=example,DC=com"
        ),
    )
    ldap_required_groups: str = Field(
        default="",
        description=(
            "Comma-separated CN or DN values of LDAP groups the authenticated user "
            "must belong to (at least one). Empty string disables group check. "
            "Example: AegisUsers,AegisAdmins"
        ),
    )
    ldap_ad_mode: bool = Field(
        default=True,
        description=(
            "Enable Active Directory extensions: nested group OID "
            "(1.2.840.113556.1.4.1941), memberOf enumeration, sAMAccountName lookup. "
            "Set False for plain RFC 4519 LDAP directories."
        ),
    )
    ldap_use_start_tls: bool = Field(
        default=False,
        description="Upgrade plain ldap:// to TLS via StartTLS before bind.",
    )
    ldap_ca_certs_file: str = Field(
        default="",
        description=(
            "Path to PEM CA bundle for LDAP TLS peer verification. "
            "Empty string uses the system default trust store."
        ),
    )
    ldap_timeout_seconds: float = Field(
        default=10.0,
        ge=1.0,
        le=60.0,
        description="Socket-level timeout (seconds) for LDAP connect and operations.",
    )

    def get_ldap_required_groups(self) -> frozenset[str]:
        if not self.ldap_required_groups:
            return frozenset()
        return frozenset(g.strip() for g in self.ldap_required_groups.split(",") if g.strip())

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
    phi_master_key: str = Field(
        default="",
        description=(
            "Hex-encoded 32-byte master key for AES-256-GCM PHI payload encryption. "
            "When set, audit node payload bytes are encrypted at rest under a per-tenant "
            "HKDF-SHA256 DEK before being written to the WAL. "
            "Generate with: python -c 'import secrets; print(secrets.token_hex(32))' "
            "MUST be separate from AEGIS_SIGNING_KEY. Required when AEGIS_PHI_DEIDENTIFY=true "
            "in HIPAA-regulated deployments."
        ),
    )
    cac_piv_required: bool = Field(
        default=False,
        description=(
            "When True, mTLS client certificates must carry a recognized DoD CAC or GSA PIV "
            "certificate policy OID (DoDI 8520.02 / NIST SP 800-73-4 / GSA FPKI) and the "
            "Client Authentication EKU.  EDIPI (CAC) or UUID (PIV-I) is extracted and logged. "
            "Requires ssl_ca_certs to be configured for proper chain validation."
        ),
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
    max_wal_bytes: int = Field(
        default=0,
        ge=0,
        description=(
            "Rotate the active WAL into an archived, immutable segment once it "
            "reaches this many bytes. 0 disables rotation (single unbounded WAL). "
            "Archived segments (named '<wal_path>.NNNNNN', mode 0o600) are "
            "retained for forensic completeness and replayed on startup; the "
            "audit chain is never truncated."
        ),
    )

    # ── Runtime enforcement and bounded resources ─────────────────────────
    security_enforcement_mode: Literal["strict", "development"] = Field(
        default="strict",
        description=(
            "strict is the only production mode: required auth, durable signed evidence, "
            "distributed rate limiting, and privileged kernel controls. development is for "
            "isolated tests/local work and must never be used for a production claim."
        ),
    )
    require_durable_evidence: bool = Field(
        default=True,
        description="Reject governed requests when signed durable evidence cannot be committed.",
    )
    require_lsm: bool = Field(
        default=True,
        description="Require active AppArmor/SELinux confinement in strict runtime mode.",
    )
    require_seccomp: bool = Field(
        default=True,
        description="Require an active seccomp filter in strict runtime mode.",
    )
    max_request_body_bytes: int = Field(
        default=1_048_576,
        ge=1_024,
        le=16_777_216,
        description="Streaming HTTP body limit enforced before JSON parsing.",
    )
    analysis_queue_size: int = Field(
        default=2_048,
        ge=1,
        le=100_000,
        description="Bounded asynchronous response-analysis queue capacity.",
    )
    analysis_worker_count: int = Field(
        default=2,
        ge=1,
        le=64,
        description="Number of bounded response-analysis workers.",
    )
    analysis_sample_rate: float = Field(
        default=1.0,
        ge=0.0,
        le=1.0,
        description="Fraction of successful responses submitted for asynchronous analysis.",
    )
    analysis_timeout_seconds: float = Field(
        default=5.0,
        ge=0.1,
        le=60.0,
        description="Maximum wall time for one asynchronous response analysis job.",
    )

    # ── Telemetry ─────────────────────────────────────────────────────────
    force_logprobs: bool = Field(
        default=False,
        description=(
            "Inject logprobs=True and top_logprobs=N into every chat request "
            "for entropy analysis. Disabled by default because it inflates response "
            "size 5-10x and is unsupported by Anthropic/Gemini providers. "
            "Enable explicitly when using an OpenAI-compatible backend that supports it."
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
    waf_session_window: int = Field(
        default=10,
        ge=2,
        le=100,
        description=(
            "Sliding-window size (number of recent turns) examined by the multi-turn "
            "behavioral WAF.  Older turns are evicted automatically."
        ),
    )
    waf_session_cumulative_threshold: float = Field(
        default=2.0,
        ge=0.1,
        description=(
            "Sum of per-turn WAF scores within the session window that triggers "
            "a session-level block.  Score per turn is in [0, 1]; default 2.0 "
            "requires at least two full-weight soft hits in the window."
        ),
    )
    waf_session_crescendo_turns: int = Field(
        default=3,
        ge=2,
        le=20,
        description=(
            "Number of consecutive turns each producing a non-zero WAF score "
            "before a crescendo (gradual constraint erosion) block is triggered."
        ),
    )

    # ── Server ────────────────────────────────────────────────────────────
    debug_mode: bool = Field(
        default=False,
        description=(
            "Enable /docs and /redoc OpenAPI endpoints. "
            "NEVER enable in production — exposes full API schema. "
            "Automatically forces auth_disabled=False check at startup."
        ),
    )
    host: str = Field(default="0.0.0.0")
    port: int = Field(default=8080, ge=1, le=65535)
    workers: int = Field(default=1, ge=1, le=64)
    log_level: str = Field(default="INFO")
    cors_origins: str = Field(
        default="",
        description="Comma-separated CORS allowed origins. Empty = no CORS headers.",
    )
    dmz_allowed_source_ips: str = Field(
        default="",
        description=(
            "DMZ-mode: comma-separated list of IPv4/IPv6 addresses or CIDR networks "
            "that are allowed to reach the proxy. When non-empty, every request whose "
            "client IP is not in the allowlist is rejected with 403 Forbidden before "
            "any authentication is attempted. Supports exact addresses (e.g. 10.0.0.1) "
            "and prefix notation (e.g. 10.0.0.0/24, ::1/128). Empty string (default) "
            "disables DMZ mode — all source IPs are permitted. "
            "Configure via AEGIS_DMZ_ALLOWED_SOURCE_IPS."
        ),
    )
    dmz_trust_proxy_headers: bool = Field(
        default=False,
        description=(
            "When True, DMZ-mode reads the real client IP from X-Forwarded-For or "
            "X-Real-IP headers (trusted reverse-proxy scenario). "
            "Never set this when the proxy is internet-facing — it allows IP spoofing. "
            "Only enable behind a trusted load balancer or nginx ingress."
        ),
    )

    # ── Air-gap egress enforcement ────────────────────────────────────────
    airgap_mode: bool = Field(
        default=False,
        description=(
            "When True, the proxy blocks all outbound HTTP connections except to hosts "
            "listed in AEGIS_AIRGAP_ALLOWED_HOSTS plus the configured upstream backend. "
            "Provides application-layer OT network zone enforcement "
            "(IEC 62443 Zone and Conduit model). "
            "Pair with kernel-level controls (nftables, network namespaces) for defense-in-depth. "
            "Configure via AEGIS_AIRGAP_MODE."
        ),
    )
    airgap_allowed_hosts: str = Field(
        default="",
        description=(
            "Comma-separated list of allowed outbound hostnames or host:port pairs "
            "when AEGIS_AIRGAP_MODE=true. The upstream backend host is always implicitly "
            "allowed. Example: 'internal-llm.corp.example.com,10.0.0.5:8080'. "
            "An empty value (with airgap_mode=true) only permits the upstream backend. "
            "Configure via AEGIS_AIRGAP_ALLOWED_HOSTS."
        ),
    )

    # ── HSM / PKCS#11 signing ─────────────────────────────────────────────
    pkcs11_library_path: str = Field(
        default="",
        description=(
            "Filesystem path to the PKCS#11 shared library. Empty string disables HSM signing. "
            "Examples: /usr/lib/softhsm/libsofthsm2.so (SoftHSM2), "
            "/opt/cloudhsm/lib/libcloudhsm_pkcs11.so (AWS CloudHSM). "
            "Requires python-pkcs11 to be installed (pip install python-pkcs11). "
            "When configured, audit nodes are signed by the HSM-resident key instead of the "
            "in-memory AEGIS_SIGNING_KEY; the private key NEVER enters application memory."
        ),
    )
    pkcs11_slot_id: int = Field(
        default=0,
        ge=0,
        description="PKCS#11 slot index (0-based). Ignored when AEGIS_PKCS11_TOKEN_LABEL is set.",
    )
    pkcs11_pin: str = Field(
        default="",
        description=(
            "PKCS#11 User PIN for C_Login. Provide via environment variable "
            "AEGIS_PKCS11_PIN or Vault; never hard-code in config files."
        ),
    )
    pkcs11_key_label: str = Field(
        default="aegis-signing-key",
        description="CKA_LABEL of the private signing key stored in the PKCS#11 token.",
    )
    pkcs11_token_label: str = Field(
        default="",
        description=(
            "When non-empty, resolve the slot by token label rather than pkcs11_slot_id. "
            "Useful when slot numbering is dynamic (e.g. AWS CloudHSM)."
        ),
    )

    # ── Reliability: circuit breaker ──────────────────────────────────────
    circuit_breaker_failure_threshold: int = Field(
        default=5,
        ge=1,
        le=100,
        description=(
            "Consecutive upstream failures before the circuit opens. "
            "While OPEN all requests return 503 immediately (fail-fast). "
            "After circuit_breaker_recovery_timeout seconds one probe is allowed."
        ),
    )
    circuit_breaker_recovery_timeout: float = Field(
        default=30.0,
        ge=1.0,
        le=600.0,
        description="Seconds the circuit stays OPEN before allowing a recovery probe.",
    )
    circuit_breaker_success_threshold: int = Field(
        default=2,
        ge=1,
        le=20,
        description="Consecutive probe successes in HALF_OPEN required to re-close the circuit.",
    )

    # ── Privacy / PII redaction ────────────────────────────────────────────
    phi_deidentify: bool = Field(
        default=False,
        description=(
            "When True, apply real-time PHI de-identification (NIST SP 800-188 Safe Harbor) "
            "to request message content before forwarding to the upstream LLM, and to response "
            "content before returning to the client. Scrubs 18 HIPAA identifier categories via "
            "regex (names, DOB, SSN, MRN, phone, email, IP, URL, etc.). Does not require an "
            "NLP model. Enable for HIPAA-regulated deployments."
        ),
    )
    pci_scrub: bool = Field(
        default=False,
        description=(
            "When True, apply real-time PCI-DSS v4.0 cardholder-data detection and masking "
            "to request message content before forwarding to the upstream LLM, and to response "
            "content before returning to the client. Detects PANs (Luhn + IIN gate), "
            "CVV/CVC security codes (in context), and Track 1/2 magnetic-stripe data. "
            "PANs are masked to last-4 per PCI-DSS §3.4; CVV and track data are fully redacted. "
            "Enable for PCI-DSS-scoped deployments (payments, e-commerce, financial services)."
        ),
    )
    pii_redact_tenant_id: bool = Field(
        default=False,
        description=(
            "When True, replace tenant_id (session/user identifier) in the WAL with "
            "a one-way SHA-256 prefix before committing to the audit chain. "
            "Enables GDPR/CCPA compliance for deployments where session IDs are "
            "considered personal data. Does not affect in-flight analysis — only "
            "the durable WAL record. Cannot be reversed without the original ID."
        ),
    )

    # ── Alerting ──────────────────────────────────────────────────────────
    webhook_url: str = Field(
        default="",
        description="HTTP(S) URL to POST alert payloads to (Slack, Teams, custom SIEM).",
    )
    webhook_timeout_seconds: float = Field(default=5.0, ge=0.5, le=30.0)

    @field_validator("provider")
    @classmethod
    def _validate_provider(cls, v: str) -> str:
        allowed = {"openai", "anthropic", "gemini", "openrouter"}
        v_lower = v.strip().lower()
        if v_lower not in allowed:
            raise ValueError(f"AEGIS_PROVIDER must be one of {sorted(allowed)}, got {v!r}")
        return v_lower

    @field_validator("security_enforcement_mode")
    @classmethod
    def _validate_security_enforcement_mode(cls, v: str) -> str:
        value = v.strip().lower()
        if value not in {"strict", "development"}:
            raise ValueError("security_enforcement_mode must be 'strict' or 'development'")
        return value

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

    @model_validator(mode="after")
    def _enforce_auth_posture(self) -> AegisSettings:
        """Validate backend URL and refuse authentication disablement in production.

        The ``debug_mode`` field documents that auth cannot be silently disabled
        in production. This makes that promise enforceable: ``auth_disabled`` is
        only honoured when ``debug_mode`` is also set. Without this check a stray
        ``AEGIS_AUTH_DISABLED=true`` in a production environment would open both
        the proxy and the ``/v1/audit/*`` endpoints with no credential check —
        a silent, config-only privilege escalation that no code path guards.
        """
        parsed_backend = urlparse(str(self.backend_url))
        if parsed_backend.scheme not in {"http", "https"} or not parsed_backend.hostname:
            raise ValueError("backend_url must be an absolute http/https URL with a hostname")
        if parsed_backend.username is not None or parsed_backend.password is not None:
            raise ValueError("backend_url must not contain URL userinfo")
        if self.auth_disabled and not self.debug_mode:
            raise ValueError(
                "auth_disabled=True requires debug_mode=True. Refusing to start "
                "with authentication disabled outside debug mode. Set "
                "AEGIS_DEBUG_MODE=true for local development, or remove "
                "AEGIS_AUTH_DISABLED and configure AEGIS_API_KEYS for production."
            )
        return self

    def validate_runtime_invariants(self) -> None:
        """Raise before binding sockets when strict runtime invariants are absent."""
        if self.security_enforcement_mode != "strict":
            return
        if self.debug_mode:
            raise ValueError("strict runtime cannot enable debug_mode")
        if self.auth_disabled:
            raise ValueError("strict runtime cannot disable authentication")
        if not self.require_durable_evidence:
            raise ValueError("strict runtime requires require_durable_evidence=True")
        if self.rate_limit_backend != "redis":
            raise ValueError("strict runtime requires rate_limit_backend='redis'")
        if not self.get_api_keys():
            raise ValueError("strict runtime requires at least one AEGIS_API_KEYS value")
        if not self.signing_key and not self.pkcs11_library_path:
            raise ValueError("strict runtime requires signing_key or pkcs11_library_path")
        if self.mtls_required and not self.ssl_ca_certs:
            raise ValueError("mtls_required=True requires ssl_ca_certs")

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

    def get_dmz_networks(self) -> list[Any]:
        """Parse AEGIS_DMZ_ALLOWED_SOURCE_IPS into ipaddress network objects."""
        import ipaddress

        if not self.dmz_allowed_source_ips:
            return []
        networks = []
        for entry in self.dmz_allowed_source_ips.split(","):
            entry = entry.strip()
            if not entry:
                continue
            try:
                # Accept bare IPs (treat as /32 or /128) or CIDR notation
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError as exc:
                raise ValueError(
                    f"AEGIS_DMZ_ALLOWED_SOURCE_IPS: invalid address or network {entry!r}: {exc}"
                ) from exc
        return networks

    def get_egress_guard(self) -> Any:
        """Build an EgressGuard from airgap_mode + airgap_allowed_hosts."""
        from aegis.proxy.egress_guard import build_egress_guard

        return build_egress_guard(
            airgap_mode=self.airgap_mode,
            allowed_hosts_csv=self.airgap_allowed_hosts,
            upstream_url=self.backend_url_str,
        )

    @property
    def backend_url_str(self) -> str:
        return str(self.backend_url).rstrip("/")


@lru_cache(maxsize=1)
def get_settings() -> AegisSettings:
    return AegisSettings()
