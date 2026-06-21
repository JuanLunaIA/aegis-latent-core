<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core — Threat Model

> STRIDE analysis · mTLS · secret-leakage mitigation.
> One of the system "laws" referenced by [`README.md`](../../README.md). Defenses
> listed here correspond to **implemented, tested** code. Residual risks and explicit
> non-defenses are stated plainly — Aegis does not claim protections it does not have.

---

## 1. Assets and Trust Zones

| Asset | Sensitivity | Where it lives |
|---|---|---|
| `AEGIS_SIGNING_KEY` (audit signing) | **Critical** | process memory only |
| `AEGIS_API_KEYS` (client auth) | High | process memory; **distinct** from signing key |
| Audit hash chain | High (integrity) | memory + WAL `0o600` |
| Request/response payloads | High (confidentiality) | transient memory; only **digests** persisted |
| WAL segments | High (integrity) | disk, owner-only `0o600`, append-only |

```
 Client Zone (authenticated, content UNTRUSTED)
        │  Bearer token + optional mTLS
        ▼
 ┌─────────────── Aegis Trusted Process ───────────────┐
 │ signing key · API keys · audit chain (in memory)    │
 │ WAL writer (0o600, append-only)                     │
 └───────┬──────────────────────────────┬──────────────┘
         │ TLS-verified (content opaque) │ sealed bundle (offline-verifiable)
         ▼                               ▼
 Upstream Provider Zone           Auditor Zone (read-only)
```

---

## 2. STRIDE Analysis

### S — Spoofing (identity)

| Vector | Control | Residual |
|---|---|---|
| Forged client identity | Bearer-token auth, `hmac.compare_digest()` constant-time compare | Key rotation/revocation is operator responsibility |
| Client cert impersonation | **mTLS** with CAC/PIV (DoD CAC / GSA PIV) policy-OID verification, EDIPI/UUID extraction (`AEGIS_MTLS_REQUIRED`) | Trusts configured CA bundle |
| Directory identity spoof | LDAP/AD service-bind → user-bind → group-assert; RFC 4515 injection escaping; `ldaps://`/StartTLS | Trusts directory TLS chain |
| `auth_disabled` bypass in prod | `auth_disabled=True` is **only honored when `debug_mode=True`** | — |

### T — Tampering (integrity)

| Vector | Control | Residual |
|---|---|---|
| Post-hoc audit edit | SHA-256 hash chain + signature; `verify_integrity()` cascade detection | Requires signing key to stay confidential |
| WAL byte edit | CRC32 framing → `wal_corrupt` fault state; append-only, `0o600` | Root/host compromise can still delete files |
| Reorder/insert/delete nodes | `prev_hash` is first hash input → detectable cascade | — |
| Export tampering | Operator seal + m-of-n witness co-sign + tamper-evident export log | — |

### R — Repudiation (non-deniability)

| Vector | Control | Residual |
|---|---|---|
| "I never exported that" | Tamper-evident export log (independent HMAC, `0o600`), custody-transfer log | — |
| "The timestamp is fabricated" | RFC 3161 TSA token bound to bundle imprint | Trusts the TSA |
| "That signature isn't mine" | ML-DSA-65 / HMAC over chain seal; witness co-signing for multi-party authorization | Ephemeral Ed25519 fallback is repudiable by design |

### I — Information Disclosure (confidentiality)

| Vector | Control | Residual |
|---|---|---|
| Payloads in audit nodes | Only **SHA-256 digests** persisted, never raw bodies | In-memory payloads readable if process compromised pre-commit |
| PHI/PII leakage | Real-time de-identification (NIST SP 800-188 Safe Harbor), field-level AES-256-GCM PHI encryption (per-tenant HKDF DEK), differential-privacy analytics | De-id pattern coverage is finite |
| Data-at-rest (IL6) | AES-256-GCM per-node envelope, per-tenant DEK; master key distinct from signing & PHI keys | Key management is operator responsibility |
| Classified data egress | SCI/SAP marker detector blocks pre-forwarding (34 DoD/IC patterns) | Novel/coded markings need pattern updates |
| **Secret leakage in artifacts** | Signing key/API keys **never** written to code, logs, commits, or bundles; secrets read from env/Vault only | Operator must not echo env into logs |

### D — Denial of Service (availability)

| Vector | Control | Residual |
|---|---|---|
| Per-tenant request flood | CAS token bucket / Redis GCRA, per-tenant isolation | Network-layer volumetric DDoS out of scope |
| Payload-depth bomb | structural depth guard (>10 → reject) before WAF scan | Semantic complexity not checked |
| Upstream stall | per-provider circuit breaker → fail-fast 503, auto-recovery | — |
| WAL disk exhaustion | backpressure gauge + graceful in-memory-only degradation + `CRITICAL` log | Sustained exhaustion needs operator action |
| Event-loop saturation | measured: graceful degradation, 0 errors under 6-min overload ([BENCHMARKS](../BENCHMARKS.md#endurance--stability-run)) | Single-worker throughput bounded — scale horizontally |

### E — Elevation of Privilege

| Vector | Control | Residual |
|---|---|---|
| Post-exploit syscall abuse | **seccomp BPF allowlist**: `clone`/`clone3` denied post-startup; `execve`, `ptrace`, `process_vm_readv/writev`, `mount`, `reboot` permanently denied | Degrades (warns) where the runtime blocks nested BPF |
| Lateral file access | WAL `0o600`; WORM `0o400` sealed segments; read-only rootfs option | Root compromise bypasses DAC |
| Over-broad API keys | HIPAA minimum-necessary scoped keys (`AEGIS_API_KEY_SCOPES`), RBAC + Zero-Trust constraints, ABAC Bell-LaPadula for IL5/IL6 | Scope config is operator-defined |

---

## 3. mTLS Posture

- **Mutual TLS** terminates at Aegis with client-certificate verification.
- **CAC/PIV**: validates DoD CAC (DoDI 8520.02) and GSA PIV (NIST SP 800-73-4) policy
  OIDs; extracts EDIPI / UUID subject identity; `cac_piv_required` enforces presence.
- **Upstream TLS**: connections to the LLM provider are TLS-verified against the
  configured CA bundle; in air-gap mode (`AEGIS_AIRGAP_MODE`) egress is restricted to
  `AEGIS_AIRGAP_ALLOWED_HOSTS`.
- **CNSA/Suite B negotiation**: `CNSANegotiator` selects P-384 ECDH / AES-256-GCM /
  SHA-384 where mandated and refuses downgrade.

> **Residual:** Aegis trusts whatever CA bundle it is configured with. A compromised or
> mis-issued CA can MITM the upstream leg. Pin roots and host an enclave-local trust
> store for high-assurance deployments (see SCALING_GUIDE → TLS).

---

## 4. Secret-Leakage Mitigation (explicit)

This project treats secret hygiene as a hard invariant:

1. `AEGIS_SIGNING_KEY` is **separate** from `AEGIS_API_KEYS` — compromise of a client
   key cannot forge audit signatures, and vice-versa.
2. Secrets are sourced from environment or **Vault/AppRole** (`hvac`), never hard-coded.
3. No secret, key, or credential is ever written into source, comments, commit messages,
   PR text, logs, or exported bundles.
4. Audit nodes persist **digests only** — raw prompts/responses never hit disk.
5. The `usedforsecurity=False` MD5 in `dfir_export.py` is a **format checksum** for
   EWF/E01 compatibility, not a security hash (integrity comes from the parallel SHA-256).

---

## 5. Non-Defenses (what Aegis does NOT protect against)

These are stated so operators do not over-rely on the system:

| Threat | Why out of scope |
|---|---|
| Upstream provider compromise | Aegis is a transparent proxy; provider-side processing is opaque |
| `AEGIS_SIGNING_KEY` exfiltration | Key in process memory; theft allows forging valid-looking chains |
| Process-memory read before commit | In-flight payloads are plaintext in RAM until digested |
| TLS CA compromise | Trusts configured CA bundle |
| Cold-boot / DMA DRAM extraction | No hardware memory encryption (SEV-SNP/TDX/SGX are roadmap, not implemented) |
| Novel jailbreak techniques | WAF covers documented patterns; unknown techniques may pass |
| Network-layer volumetric DDoS | Needs upstream/network mitigation |

Hardware-TEE attestation, FIPS 140-3 Level-3 boundary, and ZK-proof privacy are tracked
as **open** items in [`../ROADMAP.md`](../ROADMAP.md) and must not be assumed present.

---

## 6. Cross-References

- Crypto flow & chain internals: [`../architecture/DEEP_DIVE.md`](../architecture/DEEP_DIVE.md)
- Scaling, WAL tuning, Redis TLS: [`../performance/SCALING_GUIDE.md`](../performance/SCALING_GUIDE.md)
- Measured resilience numbers: [`../BENCHMARKS.md`](../BENCHMARKS.md)
