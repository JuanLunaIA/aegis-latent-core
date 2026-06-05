
# Security Policy

## Supported Versions

| Version | Supported          |
| :------ | :----------------- |
| 2.3.x   | ✅ Active           |
| 2.2.x   | ⚠️ Security patches only |
| 2.1.x   | ❌ End of life      |
| 2.0.x   | ❌ End of life      |
| < 2.0   | ❌ End of life      |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Use [GitHub Security Advisories](https://github.com/JuanLunaIA/aegis-latent-core/security/advisories/new) on the **JuanLunaIA/aegis-latent-core** repository. For sensitive disclosures, contact the maintainer through GitHub private channels.

### Response Timeline

| Milestone              | Target           |
| :--------------------- | :--------------- |
| Acknowledgment         | 48 hours         |
| Severity assessment    | 5 business days  |
| Mitigation or plan     | 14 days (critical: 7 days) |
| Public disclosure      | After patch ships |

We follow coordinated disclosure. Reports may be credited in the changelog unless the reporter requests anonymity.

---

## Deployment Security Checklist

### Authentication

- Always set `AEGIS_API_KEYS` in production. Never set `AEGIS_AUTH_DISABLED=true` outside local development.
- Use a high-entropy signing key: `python -c 'import secrets; print(secrets.token_hex(32))'` and store the output in `AEGIS_SIGNING_KEY`. An empty or missing signing key causes audit nodes to fall back to ephemeral Ed25519 keys, reducing legal admissibility to `"Compromised"`.
- Restrict audit API access with separate `AEGIS_AUDIT_API_KEYS` (read-only principals should not share keys with write paths).

### TLS / mTLS (v2.3.0+)

- Enable TLS termination at the Aegis layer for any deployment that does not place it behind a TLS-terminating proxy:
  ```env
  AEGIS_SSL_CERTFILE=/etc/certs/server.crt
  AEGIS_SSL_KEYFILE=/etc/certs/server.key
  ```
- To enforce mutual TLS (require a client certificate from callers):
  ```env
  AEGIS_MTLS_REQUIRED=true
  AEGIS_SSL_CA_CERTS=/etc/certs/client-ca.crt
  ```
- To use a custom CA bundle when connecting to an upstream LLM provider:
  ```env
  AEGIS_SSL_CA_CERTS=/etc/certs/upstream-ca.crt
  ```
  If `AEGIS_MTLS_REQUIRED=true` but `AEGIS_SSL_CERTFILE` and `AEGIS_SSL_KEYFILE` are not set, Aegis logs a `WARNING` and proceeds without a client certificate.

### Secrets Management

- Never commit `.env`, PEM files, or any `*.wal.jsonl` file containing real audit data to version control.
- Rotate `AEGIS_SIGNING_KEY` using a documented key-rotation procedure; an unannounced rotation will break the HMAC chain. Document the rotation event in your chain-of-custody notes.
- Use `AEGIS_DEBUG_MODE=false` (default) in all non-development environments. Debug mode exposes `/docs`, `/redoc`, and `/openapi.json`.

### LSM Hardening (v2.3.0+)

As of v2.3.0, the LSM guard runs in **advisory mode**: missing AppArmor or SELinux profiles emit a `WARNING` but do not crash the server. For hardened deployments requiring hard LSM enforcement:

1. Load an AppArmor or SELinux profile before starting Aegis.
2. Verify confinement externally: `aa-status` (AppArmor) or `getenforce` (SELinux).
3. Use a process supervisor or init system that fails the unit on non-zero exit if enforcement is mandatory for your threat model.

### Entropy & WAF Tuning

- Tune `AEGIS_ENTROPY_ALERT_THRESHOLD_BITS` to match your model's expected entropy range before deploying alerting integrations.
- In high-security environments, set `AEGIS_WAF_STRICT_MODE=true`. In strict mode, the WAF applies hard blocks on critical injection patterns regardless of score threshold.
- KL divergence and Jensen-Shannon divergence thresholds (`AEGIS_KL_ALERT_THRESHOLD`, `AEGIS_JS_ALERT_THRESHOLD`) are now respected at runtime via `AegisSettings` (fixed in v2.3.0); verify your values if upgrading from v2.2.0.

### Network Exposure

- Bind to `127.0.0.1` or a private interface unless a load balancer or ingress controller handles public-facing TLS termination.
- Restrict `/v1/audit/*` endpoints to trusted internal networks or require `AEGIS_AUDIT_API_KEYS`.
- The visualizer server (`tools/visualizer/`) is a local development tool. Never expose it to public networks.

---

## Known Security-Relevant Fixes

| Version | Fix | Severity |
| :------ | :-- | :------- |
| 2.3.0 | mTLS settings were defined in `AegisSettings` but never applied to the uvicorn listener or the upstream `httpx` client | High |
| 2.3.0 | `ResponseAnalyzer` thresholds were hardcoded, ignoring `AegisSettings`; alerting could not be tuned at runtime | Medium |
| 2.2.0 | Audit chain signing key derived from the first sorted API key; unannounced rotation silently invalidated the chain | High |
| 2.2.0 | `/docs` and `/redoc` exposed unconditionally in all deployment modes | Medium |
| 2.2.0 | `prev_hash` always pointed to the genesis node due to wrong `ORDER BY` direction in `list_nodes()` | Critical |
| 2.2.0 | Concurrent `BackgroundTask` writes could fork the audit chain (no chain lock) | Critical |

# Política de seguridad

## Versiones soportadas

| Versión | Soportada |
| :--- | :--- |
| 2.x | Sí |
| 1.x | No |

## Reportar una vulnerabilidad

**No abras un issue público** para vulnerabilidades de seguridad.

Usa [GitHub Security Advisories](https://github.com/JuanLunaIA/aegis-latent-core/security/advisories/new) en el repositorio **JuanLunaIA/aegis-latent-core**, o contacta al mantenedor por los canales privados de GitHub.

Objetivo de respuesta:

- Acuse de recibo en **48 horas**
- Mitigación o plan en **14 días** (según gravedad)

Seguimos divulgación coordinada. Los reportes pueden acreditarse en el changelog salvo que pidan anonimato.

## Buenas prácticas al desplegar

- Define siempre `AEGIS_API_KEYS` en producción; no uses `AEGIS_AUTH_DISABLED`.
- No versiones `.env`, claves PEM ni el archivo `*.wal.jsonl` con datos reales.
- Restringe el acceso a `/v1/audit/*` con claves de solo lectura (`AEGIS_AUDIT_API_KEYS`).
