# Release Epistemic Statement

**Review date:** 2026-09-15 UTC
**Source baseline:** `5.0.1`, fourteen synchronized anchors — **published 2026-09-24 on every surface except PyPI `aegis-latent-core`**, read back the same day ([RELEASE_STATUS.md](RELEASE_STATUS.md) §1.0a). The previous release is `v5.0.0`, published 2026-09-16 on every surface except PyPI `aegis-latent-core` (see [RELEASE_STATUS.md](RELEASE_STATUS.md) §1.0)
**Purpose:** a single index of what this release's evidence actually establishes, organized by epistemic status rather than by subsystem. This document adds no new claims; every row links to the document that carries the underlying evidence. Where this document and a linked one disagree, the linked one is authoritative — this is an index, not a second ledger.

## 1. What IS verified, with evidence locators

"Verified" here means: code exists, a test exercises it, and the test passed in this environment on the date recorded. It does not mean externally audited, certified, or production-proven — see §4.

| Area | Evidence |
|---|---|
| Signature-assurance lattice does not launder fallback-signed history | `CLM-090`, `tests/test_crypto_audit_branch.py::test_signature_assurance_does_not_launder_historical_fallback_nodes` |
| WAF homoglyph normalization closes the documented NFKC gap | `CLM-091`, `tests/test_waf_hardening.py`, `tests/test_homoglyph_normalizer.py` |
| `forwarded_allow_ips` wildcard is refused in strict mode | `CLM-092`, `tests/test_enterprise_config_new.py` |
| ZK inclusion circuit (Spartan, feature-gated) proves a recorded WAF-pass leaf under a public MMR root | `CLM-089`, `docs/institutional/DOC-08_ZERO_KNOWLEDGE_INCLUSION.md`, `aegis_rust_v2/tests/zk_mmr_end_to_end.rs` |
| Coalesced group-commit WAL durability and ordering | `CLM-082`, `tests/test_coalesced_commit.py` |
| SQLite storage-provider fork prevention | `CLM-081`, `tests/storage/test_chain_fork_prevention.py` (SQLite path only — see §2) |
| Block-buffer panic safety under Miri | `CLM-085`, CI job `Miri Undefined Behaviour` |
| Full test suite, Linux/glibc, Python 3.11–3.13 | CI jobs `Test (Python 3.11/3.12/3.13)`; see [PLATFORM_COMPATIBILITY.md](PLATFORM_COMPATIBILITY.md) |
| Fourteen release-contract version anchors agree at `5.0.0` | `python scripts/verify_release_contract.py --root .` → `READY` |
| Import reachability: every module is either reached from a real entrypoint or on a declared exception list | `scripts/verify_import_reachability.py`, `scripts/import_reachability_allowlist.txt` |

The full, per-claim register is [CLAIMS_MATRIX.md](CLAIMS_MATRIX.md); this table is a curated entry point, not a substitute for it.

## 2. What is NOT verified, and why

| Area | Why not | Evidence |
|---|---|---|
| Global ordering across multiple gateway replicas | The single-writer lock is process-local by design; storage providers use non-atomic read-then-write chain operations | `UC-005`, [PLATFORM_COMPATIBILITY.md](PLATFORM_COMPATIBILITY.md) §"Multi-pod" |
| PostgreSQL and DynamoDB storage providers | Written against documented backend primitives, but no live PostgreSQL server, no `asyncpg`, and no `moto` are installed in this environment | `CLM-081` |
| S3-with-Object-Lock provider (`aegis/storage/s3_worm.py`) | Wired into the real gateway path and locally testable, but its `moto`-mocked tests were not executed this pass (`moto` absent) | [PLATFORM_COMPATIBILITY.md](PLATFORM_COMPATIBILITY.md) §"Storage backend" |
| `storage-s3` pyproject extra as a chain-storage backend | The extra declares `boto3` but no corresponding provider module exists under `aegis_server/storage/` | [PLATFORM_COMPATIBILITY.md](PLATFORM_COMPATIBILITY.md) §"Storage backend" |
| Windows beyond the single-writer WAL lock; macOS; Linux/musl; arm64 execution | No CI job runs the full suite, or any suite, on these targets | [PLATFORM_COMPATIBILITY.md](PLATFORM_COMPATIBILITY.md) |
| Helm chart installed into a live cluster | `helm lint` runs in CI; no job installs the chart and sends it a request | [PLATFORM_COMPATIBILITY.md](PLATFORM_COMPATIBILITY.md) §"Deployment mode" |
| Constant-time behavior of either PQC signing backend | No timing claim is made or lifted for PQClean or the pure-Rust `ml-dsa` backend | `CLM-084`, `CLM-019`, `docs/security/PQC_CONSTANT_TIME.md` |
| ~78 modules under `aegis/` and `integrations/` not reachable from any real entrypoint | Disclosed, not individually adjudicated, by this session's reachability audit | `scripts/import_reachability_allowlist.txt` |

The full disposition register for claims that were supplied, found unsupported, and downgraded or blocked is [UNSUPPORTED_CLAIMS.md](institutional/UNSUPPORTED_CLAIMS.md).

## 3. What CANNOT be verified in this environment

Tools, services, or hardware this session confirmed absent, listed so a reader does not mistake their absence for a negative finding:

| Missing | Blocks | Evidence |
|---|---|---|
| `moto` (Python package) | Mocked S3/DynamoDB provider tests | `python -c "import moto"` → `ModuleNotFoundError`, checked this pass |
| A live PostgreSQL server, `asyncpg` | PostgreSQL storage-provider execution | `CLM-081` |
| A live DynamoDB endpoint | DynamoDB storage-provider execution against a real (non-mocked) backend | `CLM-081` |
| `cosign` execution against `v4.1.2` images | Cryptographic verification of the image signature (the signature *object's presence* was confirmed; the verification command was not run) | `RELEASE_STATUS.md` §2.7 |
| `gh attestation verify` execution | Build-provenance verification for the `4.1.2` release wheel | `RELEASE_STATUS.md` §2.8 |
| A full `sha256sum --check --strict` sweep over all 31 `v4.1.2` release assets | Complete integrity confirmation of that release's asset set (three of thirty-one were checked individually) | `RELEASE_STATUS.md` §2.8 |
| `helm` CLI | A rendered/templated check of the chart beyond `helm lint`'s own CI run | noted during this session's PR #178 verification pass |
| A live Kubernetes cluster (kind/k3d or managed) | An actual chart install and request/response smoke test | [PLATFORM_COMPATIBILITY.md](PLATFORM_COMPATIBILITY.md) §"Deployment mode" |
| macOS hardware or CI runner | Any macOS-specific behavior claim | [PLATFORM_COMPATIBILITY.md](PLATFORM_COMPATIBILITY.md) |
| Real arm64 hardware (as opposed to QEMU cross-build) | Execution testing of the published arm64 container image | [PLATFORM_COMPATIBILITY.md](PLATFORM_COMPATIBILITY.md) |
| A FIPS validation lab | Any FIPS 140-3 conformance statement for either PQC backend | `CLM-084` |
| An independent cryptographer or circuit auditor | Third-party review of the Spartan ZK circuit's soundness | `CLM-089`: "no third party has reviewed the circuit" |

A tool's absence here is a statement about this session's environment, not about whether the underlying capability works. Where a claim depends on one of these, its row in §1/§2 says so explicitly; do not infer a negative result from an absent tool.

## 4. What requires external validation

Independent penetration testing, SOC 2/ISO 27001 attestation, FIPS 140-3 module validation, and any claim of legal or regulatory compliance are commercial/organizational actions this repository's own evidence cannot substitute for, whatever internal testing shows. The full accounting of what is ready to deploy as a technical artifact versus what still needs an external actor — including the single-maintainer bus-factor and no-independent-assurance findings — is [Enterprise Readiness](enterprise/ENTERPRISE_READINESS.md) §7; this document stops at verification, that one covers deployment and procurement readiness.

---

**Related:** [Claims Matrix](CLAIMS_MATRIX.md) · [Unsupported Claims](institutional/UNSUPPORTED_CLAIMS.md) · [Platform Compatibility](PLATFORM_COMPATIBILITY.md) · [Release Status](RELEASE_STATUS.md) · [Enterprise Readiness](enterprise/ENTERPRISE_READINESS.md)
