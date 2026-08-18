<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core — Threat Model

**Method:** STRIDE-oriented data-flow review with explicit residual risk
**Scope:** Aegis gateway, signer/keyring, WAL/storage, ingress, and operator controls
**Status:** Repository design baseline; target deployment review remains required

## Assets

The main assets are provider credentials, caller credentials, request and response metadata, evidence hashes, chain linkage, signatures, key IDs, WAL segments, storage records, configuration, and release artifacts. Raw prompt/response content may be sensitive and must be minimized or redacted according to the customer’s data policy.

## Trust boundaries

| Boundary | Threat | Control | Residual risk |
|---|---|---|---|
| Client → ingress | Spoofing, replay, oversized body, malformed protocol | TLS/mTLS, authentication, request-size bounds, trusted proxy configuration, request IDs | Forwarded-header and ingress parser mistakes remain deployment risks. |
| Ingress → gateway | Parser differential, HTTP/2 fragmentation, duplicate headers, normalization bypass | Explicit termination owner, canonicalization, WAF corpus, integration testing at actual ingress | Current local corpus does not prove HTTP/2 boundary coverage. |
| Gateway → upstream | Credential disclosure, SSRF, egress abuse, provider confusion | Canonical endpoint validation, allowlist, TLS, timeout/circuit controls, secret redaction | Network/firewall/namespace policy remains outside application code. |
| Gateway → WAL/storage | Evidence loss, reorder, tamper, partial write, storage stall | Append-only WAL, fsync/transaction commit, chain verification, owner-only permissions, replay | Filesystem/controller/backup semantics require target acceptance testing. |
| Gateway → signer | Key disclosure, weak key, wrong key, unavailable signer, rotation race | HSM/Vault or versioned keyring, atomic snapshot validation, key ID metadata, no secret logging | Secret-manager, HSM, clock, propagation, and destruction controls are external. |
| Three replicas → shared control plane | Stale key, split-brain activation, duplicate ordering, partial rollout | One active key, overlap verify keys, atomic reload, per-record key ID, replica-specific evidence | A real three-replica run remains unverified. |
| Gateway → enrichment | Queue exhaustion, task loss, analysis failure | Bounded queue, explicit status/metrics, authoritative evidence before enrichment | Analysis may be delayed or rejected; this is acceptable only if evidence is durable. |
| Operator → deployment | Privilege abuse, unsafe config, unreviewed release | Least privilege, branch rules, signed release/tag, SBOM/provenance, rollback, audit events | Human access governance and change review remain organizational. |

## STRIDE summary

### Spoofing

Bearer-token authentication uses constant-time comparison. Optional mTLS can bind callers to a configured CA and client-certificate policy. Key rotation and revocation remain operator responsibilities; a client key and signing key must remain separate.

### Tampering

Audit nodes bind predecessor, request hash, response hash, Merkle root, signature, and scheme metadata. WAL replay and `verify_integrity()` detect chain changes within the retained evidence. Root or host compromise can still delete or replace the storage path; immutable backup and external custody are required for stronger claims.

### Repudiation

The evidence record includes request identifiers, timestamps, signer scheme, and non-secret key ID where a versioned keyring is used. HMAC is symmetric; a verifier holding the secret can also sign. Any stronger non-repudiation claim requires an asymmetric custody model and independent review.

### Information disclosure

The core ledger persists hashes and metadata rather than raw request/response bodies by default, but payloads exist transiently in process memory before hashing. Secrets must not appear in code, logs, commits, bundles, sample dashboards, or benchmark artifacts. PHI/PII redaction and retention remain finite, configuration-dependent controls.

### Denial of service

Request-size limits, structural-depth guards, rate limiting, upstream timeouts/circuit breakers, bounded enrichment, and WAL backpressure reduce local resource exhaustion. Network-layer volumetric DDoS and provider-side saturation remain outside the application boundary. Under storage stall, the authoritative path may block or reject; it must not silently drop evidence.

### Elevation of privilege

Strict mode can require Seccomp and LSM/AppArmor/SELinux controls, owner-only WAL permissions, read-only runtime paths, and scoped API keys. Missing enforcement must fail or report unavailable according to the declared runtime mode. A root/host compromise remains outside the protection of application DAC and process-level checks.

## Abuse cases and failure behavior

| Abuse case | Expected behavior | Release gate |
|---|---|---|
| Caller sends a critical prompt-injection pattern | WAF blocks before upstream forwarding and emits an observable decision/evidence according to the governed path. | No critical bypass in the pinned corpus. |
| Redis limiter is unavailable | Strict path rejects rather than silently allowing traffic through. | Failure-path regression passes. |
| WAL/fsync stalls | Hot path blocks or rejects according to bounds; authoritative evidence is not silently dropped. | Zero missing/duplicate IDs and valid chain in declared test scope. |
| Keyring replacement is malformed | Previous valid snapshot remains active or startup fails closed. | No unsigned/unverifiable records; reload failure observable without secret leakage. |
| Signer backend is unavailable | Configured policy determines fail-closed behavior; no fake signature is returned. | No claim of PQC availability when backend is absent. |
| Upstream returns non-2xx or network error | Durable error evidence path is used when storage is available; response includes evidence status. | Error-path tests and release artifact. |
| WAL is edited or reordered | Integrity verification fails at the first invalid node. | Replay/integrity test passes. |

## Assumptions

The customer controls the ingress, network, secret manager, storage, backup, host kernel, container runtime, provider contract, operator identity, and retention policy. Aegis assumes those controls are configured as documented and does not treat an application-level check as proof that an external subsystem remains healthy indefinitely.

## Detection and incident response

Alert on evidence-commit failures, chain verification failures, missing or duplicate request IDs, keyring reload failures, key ID anomalies, signer unavailability, WAF critical bypasses, Redis backend failures, queue saturation, upstream circuit opening, and runtime-control rejection. Preserve raw logs, WAL segments, configuration hashes, benchmark artifacts, and release hashes under read-only access. Use NIST SP 800-61 incident handling and the customer’s legal/privacy process for notification decisions.

## Non-defenses

Aegis does not claim protection against upstream provider compromise, signing-key exfiltration, process-memory reads before hashing, a compromised CA bundle, cold-boot or DMA extraction, novel jailbreak techniques outside the named corpus, network-layer volumetric DDoS, or a compromised host root account. Hardware TEE attestation, FIPS 140 module validation, and ZK-proof privacy remain open assurance items.

## Cross-references

- [`../../README.md`](../../README.md) — product boundary and operational contract.
- [`../CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md) — public claim controls.
- [`../operations/BACKPRESSURE_RUNBOOK.md`](../operations/BACKPRESSURE_RUNBOOK.md) — I/O stall and recovery.
- [`../operations/KEY_ROTATION_RUNBOOK.md`](../operations/KEY_ROTATION_RUNBOOK.md) — keyring rotation.
- [`../SECURITY_ASSURANCE_ROADMAP.md`](../SECURITY_ASSURANCE_ROADMAP.md) — independent assurance sequence.
