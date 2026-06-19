# Aegis Data Retention & Privacy Reference

> scope: what Aegis persists, where, and under which privacy regime
> ref: GDPR Art. 30 (Records of Processing), HIPAA 45 CFR §164.312(b)

---

## What Aegis Persists

### WAL (Write-Ahead Log) — durable, per-node

Each committed audit node is written as one JSON line to the WAL file
(`aegis.wal.jsonl` by default, configurable via `AEGIS_WAL_PATH`).

| Field | Type | Content | PII risk |
|---|---|---|---|
| `state_id` | string | UUID generated per request (not user-visible) | None |
| `timestamp` | float | UNIX epoch seconds at commit time | Minimal (timing only) |
| `entropy` | float | Shannon entropy of response logprobs | None |
| `tenant_id` | string | Session or user identifier from `X-Session-ID` header or `user` field | **Medium** — may be set to a user ID by the caller |
| `sampling_params` | object | `model`, `temperature`, `endpoint` from the request | None |
| `prev_hash` | string | SHA-256 of the predecessor node's hash fields | None |
| `merkle_root` | string | SHA-256 root of the Merkle Mountain Range at commit time | None |
| `signature` | string | HMAC-SHA256 or PQC-ML-DSA hex signature | None |
| `signature_scheme` | string | `hmac-sha256`, `pqc-ml-dsa`, or `ed25519-fallback` | None |
| `public_key` | string | Hex public key (PQC/ed25519 paths only; empty for HMAC) | None |
| `request_hash` | string | SHA-256 of the raw HTTP request body | None — hash only |
| `response_hash` | string | SHA-256 of the raw HTTP response body | None — hash only |
| `model` | string | LLM model name from the request | None |
| `endpoint` | string | API endpoint slug (e.g. `chat.completions`) | None |
| `token_trail_count` | int | Number of per-token logprob records included in the MMR leaf | None |
| `is_fallback` | bool | True when the ephemeral Ed25519 fallback signer was used | None |

**Critical: request/response bodies are NOT stored.** They are hashed into
SHA-256 digests (`request_hash` / `response_hash`) and hashed into the MMR
leaf (which is itself hashed, not persisted). The WAL contains no plaintext
prompt or completion content.

### In-Memory Only (not persisted to WAL)

| Data | Where | Lifetime |
|---|---|---|
| Raw request body | `raw_body` variable in `_commit_and_alert` | Until the background task completes |
| MMR leaf bytes | `leaf` variable in `commit_forensic` | Until `add_leaf()` returns |
| Per-token logprobs | `accumulated` list in `_stream_chat` | Until `analysis = analyzer.analyze()` returns |
| HMAC signing key | `AegisSettings.signing_key` (env var) | Process lifetime; never logged |

---

## PII Analysis

### tenant_id — the primary PII risk

`tenant_id` is the only WAL field that may carry personal data. It originates
from:
1. `X-Session-ID` request header (caller-controlled string)
2. `user` field in the OpenAI request body (caller-controlled string)
3. A random UUID generated per request when neither is present (no PII)

When callers set `X-Session-ID` or `user` to a persistent user identifier
(e.g. a user UUID or email address hash), `tenant_id` becomes pseudonymous
personal data under GDPR Art. 4(1).

### Mitigation: `AEGIS_PII_REDACT_TENANT_ID=true`

When this environment variable is set, `_commit_and_alert` replaces
`tenant_id` with the first 16 hex characters of
`SHA-256(session_id.encode())` before writing to the WAL:

```
audit_sid = hashlib.sha256(sid.encode()).hexdigest()[:16]
```

This makes the WAL **pseudonymous** (GDPR Art. 4(5) / Recital 26) rather
than directly identifiable. The original session_id is retained in memory
for analysis but never reaches disk.

---

## GDPR Compliance Posture

| GDPR requirement | Aegis behavior |
|---|---|
| Art. 5(1)(b) purpose limitation | WAL contains only audit/forensic fields; no marketing/analytics use |
| Art. 5(1)(c) data minimisation | Request/response bodies are hashed, not stored |
| Art. 5(1)(e) storage limitation | No built-in WAL rotation; operators must configure log rotation (e.g. `logrotate`) |
| Art. 5(1)(f) integrity & confidentiality | WAL created with `0o600` (owner-only); HMAC-signed chain detects tampering |
| Art. 17 right to erasure | WAL is append-only by design (forensic integrity); deletion requires WAL file replacement and chain rebuild |
| Art. 25 data protection by design | `pii_redact_tenant_id` provides pseudonymisation at the storage layer |
| Art. 30 records of processing | This document |

### Recommended GDPR operator controls

1. Set `AEGIS_PII_REDACT_TENANT_ID=true` when `X-Session-ID` or `user`
   carries user-identifiable values.
2. Configure WAL rotation with a retention period matching your data
   retention policy (e.g. 30/90/365 days).
3. Store `AEGIS_SIGNING_KEY` in a secrets manager (Vault, AWS SSM, etc.),
   not in the WAL or environment file.
4. Deploy Aegis with the WAL on an encrypted volume (LUKS, AWS EBS encryption).

---

## HIPAA Compliance Posture

| HIPAA safeguard | Aegis behavior |
|---|---|
| §164.312(a)(2)(iv) Encryption | WAL contains hashes, not PHI; TLS for in-transit data via `ssl_certfile` |
| §164.312(b) Audit controls | WAL is the audit log; `verify_integrity()` detects tampering |
| §164.312(c)(1) Integrity | HMAC-SHA256 chain; `0o600` WAL permissions |
| §164.312(e)(2)(ii) Encryption in transit | `AEGIS_SSL_CERTFILE` + `AEGIS_MTLS_REQUIRED` |

**HIPAA note:** Aegis does not log prompt/response content. If LLM prompts
contain PHI (e.g. clinical notes), the `request_hash` in the WAL is a
SHA-256 digest — not reversible to PHI without the original. This meets
§164.312(b) audit trail requirements without storing PHI at rest.

---

## Retention Recommendations

| WAL retention | Use case |
|---|---|
| 90 days | Standard enterprise security audit |
| 365 days | Financial services / SOC 2 Type II |
| 7 years | HIPAA-covered healthcare |
| Indefinite | Legal / regulatory hold |

Implement retention by rotating the WAL file (rename + create new) and
archiving or deleting the rotated file per your policy. Aegis will
reconstruct the in-memory chain from the active WAL on restart.
