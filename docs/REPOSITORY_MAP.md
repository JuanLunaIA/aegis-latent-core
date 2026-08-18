# Repository Map

This map is the shortest route through the Aegis Latent Core repository. Read the root README first, then select the path that matches the review.

## Runtime surfaces

| Path | Role | Review focus |
|---|---|---|
| `aegis/proxy/app.py` | Core FastAPI gateway and request lifecycle | Authentication, evidence gate, streaming, error paths, headers, bounded enrichment. |
| `aegis/proxy/waf.py` | Application-layer WAF | Normalization, critical patterns, structure guard, shadow mode, hot reload. |
| `aegis/proxy/egress_guard.py` | Endpoint and air-gap guard | URL canonicalization, scheme restrictions, allowlists, SSRF boundary. |
| `aegis/core/crypto_audit.py` | Hash chain and WAL | Canonical record, signature, fsync, rotation, replay, integrity. |
| `aegis/core/ratelimiter.py` | Rate-limit providers | Redis failure semantics and development-only fallback. |
| `aegis/core/seccomp_guard.py` | Seccomp capability/enforcement | Startup requirements and sandbox boundary. |
| `aegis/core/lsm_guard.py` | AppArmor/SELinux checks | Runtime enforcement and deployment prerequisites. |
| `aegis_server/` | Enterprise storage, analytics, compliance | Provider contracts, authentication, export evidence, signer integration. |
| `aegis_server/crypto/keyring.py` | Versioned HMAC keyring | Atomic reload, overlap verification, expiry, key IDs, fail-closed startup. |

## Tests and harnesses

| Path | Role |
|---|---|
| `tests/test_p0_release_gates.py` | Blocking P0/P1 regression gates. |
| `tests/test_market_hardening_gates.py` | WAF corpus and fsync-injection regressions. |
| `tests/test_keyring_rotation.py` | Keyring schema, reload, overlap, expiry, and invalid-snapshot behavior. |
| `tests/data/waf_corpus_v1.json` | Pinned local WAF cases; not a universal threat corpus. |
| `tools/security/run_waf_corpus.py` | WAF metrics and Wilson interval report generator. |
| `tools/benchmarks/run_backpressure_stall.py` | Fsync-stall workload and evidence-correlation report generator. |

## Documentation by audience

| Audience | Entry point |
|---|---|
| Developer | `README.md`, `CONTRIBUTING.md`, `docs/REPOSITORY_MAP.md` |
| Platform/SRE | `DEPLOYMENT_GUIDE.md`, `docs/operations/`, `docs/performance/` |
| AppSec | `SECURITY.md`, `docs/security/THREAT_MODEL.md`, `docs/security/WAF_TESTING.md` |
| Crypto reviewer | `aegis_server/crypto/`, `docs/security/PQC_CONSTANT_TIME.md`, `docs/CLAIMS_MATRIX.md` |
| Buyer/procurement | `docs/PRODUCT_BRIEF_US.md`, `docs/BUYER_GUIDE_US.md`, `docs/COMMERCIAL_STRATEGY_US.md`, `COMMERCIAL.md` |
| Release owner | `CHANGELOG.md`, release workflows, SBOM/provenance artifacts, gate records |

## Configuration and deployment

The runtime configuration is defined in the settings modules and deployment manifests. Read the environment-variable descriptions next to the code, then validate the actual container, kernel, storage, TLS, Redis, signer, and ingress environment. Static manifests do not prove that the target cluster enforces the declared profile.

## Evidence path

A reproducible evidence chain should retain the source commit, command, environment, raw output, canonical JSON, artifact hashes, release tag, and reviewer decision. The current public release stores SBOM, provenance, release gate, repository manifest, asset hashes, and publication record as release assets. New benchmark outputs must state their boundary and must not overwrite the immutable v3.0.1 evidence.

## Change impact checklist

A change touching `aegis/proxy/app.py`, `aegis/core/crypto_audit.py`, signer code, WAF code, configuration, deployment manifests, or public claims requires a regression review. Update tests and the claim matrix, rerun affected harnesses, regenerate SBOM/provenance when the release changes, inspect the diff for secrets and stale versions, and update rollback notes before publishing.
