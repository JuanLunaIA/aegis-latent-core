# Repository Map — Aegis Latent Core v3.1.0

This map is the shortest route through the Aegis Latent Core repository. Read the root README first, then select the path that matches the review. Paths in this map describe the current source tree; release evidence artifacts may be retained outside the source tree and attached to the GitHub release.

**Last verified:** 2026-08-22 UTC
**Release baseline:** `v3.1.0`
**Root entry point:** [`README.md`](../README.md)

## Runtime surfaces

| Path | Role | Review focus |
|---|---|---|
| `aegis/proxy/app.py` | Core FastAPI gateway and request lifecycle | Authentication, evidence gate, streaming, error paths, headers and bounded enrichment |
| `aegis/proxy/waf.py` | Application-layer WAF | Normalization, critical patterns, structure guard and shadow mode |
| `aegis/proxy/egress_guard.py` | Endpoint and air-gap guard | URL canonicalization, scheme restrictions, allowlists and SSRF boundary |
| `aegis/core/crypto_audit.py` | Hash chain and WAL | Canonical record, signature, `fsync`, rotation, replay and integrity |
| `aegis/proxy/streaming.py` | Incremental SSE transformation and terminal evidence ordering | Per-stream queue/event/byte/window/output/duration limits and backpressure; aggregate concurrency remains deployment-dependent |
| `aegis/core/mmr.py` | MMR state and portable inclusion-proof generation | Versioned proof contract, retained-state availability, and trusted-root boundary |
| `aegis/core/forensic_bundle.py` | Bounded retained-window forensic ZIP export | Contract contents, digest verification, acquisition bounds, and no legal/custody conclusion |
| `sdk/python/` and `sdk/typescript/` | Tested gateway clients and stateless proof verifiers | Provider/version test scope, shared vectors, package builds, and current-main post-v3.1.0 status |
| `dashboard/` | Read-only audit, proof, metrics, and export UI | Server-side credential boundary, real-data-only states, accessibility regressions, and no availability/capacity claim |
| `aegis/core/ratelimiter.py` | Rate-limit providers | Redis failure semantics and development-only fallback |
| `aegis/core/seccomp_guard.py` | Seccomp capability/enforcement | Startup requirements and sandbox boundary |
| `aegis/core/lsm_guard.py` | AppArmor/SELinux checks | Runtime enforcement and deployment prerequisites |
| `aegis_server/` | Enterprise storage, analytics and compliance API | Provider contracts, authentication, export evidence and signer integration |
| `aegis_server/crypto/keyring.py` | Versioned HMAC keyring | Atomic reload, overlap verification, expiry, key IDs and fail-closed startup |

## Tests and harnesses

| Path | Role |
|---|---|
| `tests/test_p0_release_gates.py` | Blocking P0/P1 regression gates |
| `tests/test_enterprise_durable_evidence.py` | Governed success and durable failure-path tests |
| `tests/test_market_hardening_gates.py` | WAF corpus and `fsync`-injection regressions |
| `tests/test_proxy_streaming.py` | Bounded SSE transformation, backpressure, failure, closure, and terminal-evidence regressions |
| `tests/test_mmr_portable.py` | Portable MMR proof generation, all leaf ordinals, tampering, and schema rejection |
| `tests/test_forensic_bundle.py` | Bounded bundle contract, digests, and rejection of empty/unbounded requests |
| `sdk/python/tests/`, `sdk/typescript/tests/`, `dashboard/tests/` | SDK provider/proof contracts and dashboard no-fabrication/state regressions |
| `tests/test_keyring_rotation.py` | Keyring schema, reload, overlap, expiry and invalid-snapshot behavior |
| `tests/data/waf_corpus_v1.json` | Pinned local WAF cases; not a universal threat corpus |
| `tools/security/run_waf_corpus.py` | WAF metrics and Wilson interval report generator |
| `tools/benchmarks/run_backpressure_stall.py` | `fsync`-stall workload and evidence-correlation report generator |
| `tools/benchmarks/run_key_rotation.py` | Local multi-instance key-rotation exercise |
| `tools/benchmarks/run_pqc_timing.py` | Native ML-DSA timing experiment with raw-sample retention |

## Documentation by audience

| Audience | Entry point |
|---|---|
| Developer | [`docs/DEVELOPER_QUICKSTART.md`](DEVELOPER_QUICKSTART.md), [`CONTRIBUTING.md`](../CONTRIBUTING.md) |
| Platform/SRE | [`docs/PLATFORM_OPERATOR_GUIDE.md`](PLATFORM_OPERATOR_GUIDE.md), [`DEPLOYMENT_GUIDE.md`](../DEPLOYMENT_GUIDE.md), `docs/operations/` |
| AppSec | [`SECURITY.md`](../SECURITY.md), [`docs/security/THREAT_MODEL.md`](security/THREAT_MODEL.md), [`docs/security/WAF_TESTING.md`](security/WAF_TESTING.md) |
| Cryptography reviewer | `aegis_server/crypto/`, [`docs/security/PQC_CONSTANT_TIME.md`](security/PQC_CONSTANT_TIME.md), [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md) |
| Compliance/privacy | [`docs/compliance/COMPLIANCE_MAPPING.md`](compliance/COMPLIANCE_MAPPING.md), [`docs/privacy/DATA_RETENTION.md`](privacy/DATA_RETENTION.md) |
| Buyer/procurement | [`docs/PRODUCT_BRIEF_US.md`](PRODUCT_BRIEF_US.md), [`docs/BUYER_GUIDE_US.md`](BUYER_GUIDE_US.md), [`docs/FAQ_PROCUREMENT.md`](FAQ_PROCUREMENT.md), [`docs/COMMERCIAL_STRATEGY_US.md`](COMMERCIAL_STRATEGY_US.md) |
| Release owner | [`CHANGELOG.md`](../CHANGELOG.md), release workflows, SBOM/provenance assets, benchmark artifacts and gate records |

## Architecture and claims

| Question | Document |
|---|---|
| How does the request and evidence lifecycle work? | [`docs/architecture/ARCHITECTURE.md`](architecture/ARCHITECTURE.md) |
| Why this product category? | [`docs/architecture/ADR-001-AI-GOVERNANCE-EVIDENCE-GATEWAY.md`](architecture/ADR-001-AI-GOVERNANCE-EVIDENCE-GATEWAY.md) |
| Which public claims are permitted? | [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md) |
| What was measured? | [`docs/benchmarks/BENCHMARK_RESULTS.md`](benchmarks/BENCHMARK_RESULTS.md) |
| What is the scaling boundary? | [`docs/performance/SCALING_GUIDE.md`](performance/SCALING_GUIDE.md) |

## Configuration and deployment

Runtime configuration is defined in the settings modules and deployment manifests. Read the environment-variable descriptions next to the code, then validate the actual container, kernel, storage, TLS, Redis, signer and ingress environment. Static manifests do not prove that the target cluster enforces the declared profile.

## Evidence path

A reproducible evidence chain should retain the source commit, command, environment, raw output, canonical JSON, artifact hashes, release tag and reviewer decision. The current public release stores SBOM, provenance, release gate, repository manifest, asset hashes and publication records as release assets. New benchmark outputs must state their boundary and must not overwrite immutable evidence.

## Change-impact checklist

A change touching `aegis/proxy/app.py`, `aegis/core/crypto_audit.py`, signer code, WAF code, configuration, deployment manifests or public claims requires a regression review. Update tests and the claim matrix, rerun affected harnesses, regenerate SBOM/provenance when the release changes, inspect the diff for secrets and stale versions, and update rollback notes before publishing.

## Related documents

- [`README.md`](../README.md)
- [`docs/architecture/ARCHITECTURE.md`](architecture/ARCHITECTURE.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
- [`docs/DEVELOPER_QUICKSTART.md`](DEVELOPER_QUICKSTART.md)
- [`docs/PLATFORM_OPERATOR_GUIDE.md`](PLATFORM_OPERATOR_GUIDE.md)
- [`docs/FAQ_TECHNICAL.md`](FAQ_TECHNICAL.md)
