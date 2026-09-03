# Changelog

All notable changes to **Aegis Latent Core** are documented in this file.

**Last verified:** 2026-08-27 UTC
**Release baseline:** `v4.0.2` checked-out source release target; source metadata does not establish external lifecycle state, which requires independent readback.
**Historical GitHub baseline:** `v4.0.1`, a lightweight tag targeting `6469904380218584ae0b5221334bc9a46500f5ba`
**Immutable source baseline:** `fdace8844568eb788216740b2cb5daf187d99d3b` (fourteen `4.0.0` anchors)
**Source release target:** `v4.0.2` (fourteen synchronized `4.0.2` anchors; tag, release, registry, image, signature, and attestation state remain external readback facts)
**Documentation verification baseline:** Public claims remain controlled by `docs/CLAIMS_MATRIX.md`; framework references are contribution mappings, not certifications.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

Source-only changes after the `v4.0.2` release target. None alters the release
target, and none is published; registry, image and release state remain
external readback facts recorded in `docs/RELEASE_STATUS.md`.

### Added

- Single-writer enforcement on the JSONL WAL: `CryptographicAuditLedger` takes a POSIX advisory lock before publishing the handle, so a second writer raises `WalWriterConflictError` at startup rather than forking the evidence chain silently.
- `aegis_security_enforcement_mode` gauge reporting the loaded enforcement posture as `1` (strict) or `0` (development), set before dependent construction and exposed on `/metrics` rather than `/health`.
- Helm chart renders a `StatefulSet` with per-replica `volumeClaimTemplates`, a headless governing Service, and a default-deny `NetworkPolicy`; `values.schema.json` pins `aegis.workers` to `"1"` and constrains `persistence.accessMode`.
- Post-build check asserting no server-only secret reaches browser-served dashboard output, wired into CI after the dashboard build.
- Documentation corpus: claim-control foundations (`docs/STYLE_GUIDE.md`, `docs/DOCUMENTATION_GOVERNANCE.md`, `docs/INDEX.md`), security volume, operations runbooks, API references, four framework technical-input documents, privacy boundaries, enterprise and corporate volumes, assurance index, and root governance files.
- Four documentation gates run in CI: `scripts/verify_docs.py`, `scripts/verify_claims.py`, `scripts/verify_links.sh`, and the pre-existing `tools/docs/verify_documentation.py`.
- Eleven claims-matrix rows covering the `fsync` durability boundary, trusted-root independence, the native WAL's auxiliary role, `pending-terminal` semantics, redaction as best-effort, registry publication state, the `bad_cert` explanation, and explicit denials for production SLO, WORM and immutability; stable `CLM-NNN` identifiers on all 53 rows.
- `MerkleMountainRange.checkpoint()` and `rollback_to()`: an O(log n) rollback token that records the append-only lengths and the live peak nodes, replacing a whole-structure snapshot on the commit path.
- Regression coverage for MMR append rollback (`tests/test_mmr_rollback.py`) and for chain integrity across memory-window rollover (`tests/test_crypto_audit_rollover.py`), including a `slow`-marked 100,000-node sweep through a 512-node window. Both the rollback path and the window anchor were previously unasserted.
- Rust↔Python MMR parity extended beyond root equality: Python-generated portable proofs are verified against the Rust-reported root, `RustBackedMMR` is checked end to end, and the `sha256-asciihex` wire literal is pinned to the digest both implementations actually compute.

### Changed

- Least-privilege `GITHUB_TOKEN`: read-only workflow-level floor in `ci.yml` and `forensic.yml`, and `security-events: write` moved from workflow scope to the four SARIF-uploading jobs in `security.yml`.
- `README.md` restructured and reduced from roughly 33 KB to 13 KB, stating release status once and routing to `docs/RELEASE_STATUS.md`.
- `docs/RELEASE_STATUS.md` records a 2026-09-02 readback of every publication surface, with per-surface commands and a publication-state table.
- `CryptographicAuditLedger` reverts a failed commit through the MMR checkpoint instead of `copy.deepcopy`. The deep copy ran on every commit and copied the whole accumulator, so per-commit cost grew with the length of the chain. Failure semantics are unchanged: a signing or WAL-persistence failure still leaves the MMR exactly as it was.

### Fixed

- Release-artifact verification instruction corrected: assets carry attestations and `SHA256SUMS`, not detached signatures, so the check is `gh attestation verify`, not `cosign verify-blob`; `cosign verify` applies to the OCI images.
- `DOC04-CLM-011` corrected: the proxy does attach `/metrics` whenever `prometheus-client` is importable.
- DNS egress in the Helm `NetworkPolicy` scoped to resolver pods via a `podSelector`; a namespace-only peer permitted port 53 to every pod in `kube-system` while the comment claimed otherwise.
- Three stale heading anchors in `docs/architecture/DEEP_DIVE.md` pointing at `docs/BENCHMARKS.md` sections that no longer exist.
- Stale `rollout status` commands in `docs/institutional/DOC-04_OPERATIONS_PLAYBOOK.md` naming `deployment/` and omitting the release prefix.
- Streaming redaction aborted ordinary text. `StreamingDeidentifier` rejected an open track-data candidate whenever a semicolon was followed by more than `window_chars` of text containing no `?`, and an open email candidate whenever an `@` appeared anywhere in the holdback window rather than in the trailing whitespace-free token. Prose containing a semicolon, a mentioned email address, or a Python decorator therefore raised `StreamingDeidentificationError`, which the proxy reports to the client as a `privacy_failure` terminal outcome. Each guard now tests whether the candidate is a viable prefix of the detector that would redact it.
- Open-candidate marker searches are now case-insensitive, matching the URL and track-1 detectors. An unterminated `HTTPS://` or `%b` candidate previously passed the guard entirely, which was a fail-open on the exact grammar the guard exists to catch.

## [4.0.2] — 2026-08-27

- Added trusted-proxy support for the documented `X-SSL-Client-SHA256` mTLS fingerprint assertion while preserving the historical `X-Client-Cert-SHA256` alias; conflicting assertions now fail closed.
- Added generic request-bucket `X-RateLimit-Limit` and `X-RateLimit-Remaining` response headers alongside the existing request/token dimension-specific fields.
- Added an all-targets, all-features Clippy gate with warnings denied to the Rust CI job and documented the reproducible source-development SDK contract in `docs/DEVELOPER_SDK_GUIDE.md`.
- Corrected the SDK documentation to acknowledge the public `aegis-latent-sdk` 4.0.0 registry objects without attributing them to the failed tag-triggered publication workflows.
- Clarified the audited immutable-source, external-object, registry-observation, and source-release-target layers after the v4 source merge and migrated shared coding-agent guidance from legacy `.cursorrules` to `AGENTS.md` with thin tool adapters.
- Added a deterministic, source-derived `.aegis_ai_context` manifest, progressive context router, component/workflow matrix, command/CI matrix, evidence index, and freshness tests. These are advisory repository aids, not hidden model instructions or release evidence.
- Recorded the current `main` policy of eight exact required GitHub Actions contexts, strict freshness, required signatures, linear history, disabled force pushes/deletions, and administrator enforcement disabled. Remote check results remain per-commit GitHub evidence and are not inferred from source metadata.
- Added a protected, manually dispatched GitHub Actions path that creates a Sigstore keyless signed annotated tag from the exact `main` head, verifies its workflow identity and ancestry, rejects tag replacement, and dispatches release, SDK publication, and signed OCI publication workflows against that immutable tag.
- Expanded GitHub Release assets to include the core package, Python SDK wheel/sdist, TypeScript SDK tarball, supported Rust wheels, SPDX JSON SBOM, per-file SHA-256 sidecars, a canonical release-asset manifest, and `SHA256SUMS`; release creation now rejects missing, unexpected, or byte-mismatched assets.
- Synchronized all fourteen governed version anchors—core, runtimes, both SDKs and locks, dashboard and lock, Rust metadata and lock, and Helm chart/app/image—to `4.0.2`.
- Included `aegis_server` in the core wheel, aligned active operator/Compose/airgap defaults to `4.0.2`, pinned multiarch Python and Node container bases by digest, and made the versioned installer verify the release-wheel SHA-256 sidecar before installation.
- Refreshed the hash-locked runtime closure and made its CI drift check seed `pip-compile` from the reviewed lock, so compatible transitive releases appearing later do not make identical source fail nondeterministically.
- Configured OCI publication for gateway and dashboard multiarch images with digest attestations and keyless Cosign signatures. PyPI/npm trusted publishing remains environment- and registry-controlled, and no release, package, image, signature, attestation, or provenance claim is made without successful external readback.

## [4.0.0 source candidate] — merged 2026-08-24

This historical candidate section describes the reviewed source tree merged as `2050a310ec295afc61d033ff842c9a535a4f3105`. Its fourteen version anchors are synchronized at `4.0.0`; that synchronization is source metadata, not publication evidence. No `v4.0.0` tag, GitHub Release, PyPI package, npm package, or OCI image publication is claimed.

### Bounded enterprise-maturation follow-up

- Added source-only release-readiness gates covering 14 synchronized version anchors, exact tag/version binding, pinned Python build backends, signed annotated tag ancestry, exact non-empty changelog extraction, deterministic release-asset preparation, and a create-only GitHub Release command. The OCI workflow now validates both declared architectures without registry login, push, signing, or publication. These controls do not establish external environment, signer, registry, Sigstore, architecture-runtime, or release acceptance.
- Restored Python 3.11 compatibility of the hash-locked dependency set by constraining NumPy below 2.5, and removed all 22 errors from the repository's configured `mypy-ci.ini` gate. The broader `mypy --strict` surface remains separate and is not claimed clean.
- Restricted forensic JCS manifests to ASCII keys, Unicode scalar strings, and I-JSON safe integers; bounded DAG-CBOR integers, rejected non-finite values and negative zero, and encoded accepted floats as 64-bit. `VERIFY.sh` now states that it checks only its embedded file-byte SHA-256 values and is not archive authentication, semantic verification, signature verification, or trusted-root verification.
- Hardened auxiliary RustWal recovery by flushing a zero-frame terminator at the recovered prefix and after each append, preventing same-size replacement of a corrupt frame from resurrecting a stale valid suffix. Tests cover contiguous concurrent offsets, readback, corruption, reopen, replacement, and reopen again; durability remains filesystem/device dependent and single-process scoped.
- Added a truthful `aegis.crypto` capability facade that reports optional PQC runtime availability, the explicit ZK stub state, logarithmic portable-MMR proof growth, and the absence of FIPS validation without changing cryptographic behavior.
- Added a dependency-free, metadata-only forensic query helper over fixed tuples of retained-node references. It neither copies nor makes referenced nodes immutable, uses bounded exact predicates and pagination, is not wired as a global/WAL search service, and carries no scale claim.
- Hardened finalized-segment timestamp receipt reuse, requiring exact schema and current-manifest bindings, trusted-CMS status, and non-empty timestamp evidence files; metadata gossip now surfaces equal-length divergent WAL heads without transferring WAL bytes.
- Made unmapped legacy API-key authority an explicit development-only compatibility opt-in while preserving strict-mode principal mapping requirements.
- Added content-free SIEM exporter counters for acceptance, rejection, acknowledgement, retry, and pending spool rows.
- Added hardened Helm defaults and a restricted source template for installing the operator controller with namespaced RBAC. Operator-generated Aegis workloads still require persistent-storage and target-cluster acceptance; the controller deployment intentionally references an invalid placeholder image until a reviewed immutable image is supplied.
- Added an advisory `.aegis_ai_context` pack, `llms.txt`, and legacy `.cursorrules` with offline structural tests and explicit release, proof, compliance, and external-acceptance boundaries. The rules were later migrated to canonical `AGENTS.md`; this bullet preserves the candidate history.
- Added strict documentation claim validation for configured high-risk assurance, performance, readiness, and publication language, including affirmative claims embedded in tables.
- Corrected TEE capability reporting so device-node visibility remains discovery-only; legacy caller-authored attestation reports are rejected, while an injected verifier may supply authenticated normalized claims for exact policy evaluation. No enclave loader or vendor quote verifier is implemented.
- Removed the unaccounted differential-privacy HTTP analytics route and reduced the module to an internal CSPRNG-backed Laplace count primitive with a one-release, add/remove adjacency boundary. No privacy accountant, repeated-release protection, or universal anonymization claim is provided.
- Made the legacy HSM manager fail closed when PKCS#11 is unavailable, removed its predictable software-HMAC fallback, rejected duplicate key labels, and required a unique exportable public key for asymmetric evidence metadata. Unit mocks are not hardware or FIPS validation.
- Replaced Cargo-only fuzzing capability detection and constant coverage/bug figures with exact executable, private-workspace, bounded-manifest, and confined target-file readiness checks, bounded execution states, explicit timeouts, and unavailable measured coverage. No cargo-fuzz target or Kani proof is claimed until source and tool evidence exist.

### Commercial expansion Phase 2/3

- Replaced whole-response SSE buffering with an incremental, byte-bounded streaming proxy that applies bounded-window PHI/PCI redaction, hashes forwarded bytes online, propagates backpressure, attempts one terminal-evidence commit per in-process stream invocation, and supports native Anthropic `/v1/messages` ingress. This is not exactly-once behavior across retries or process restarts.
- Added portable MMR inclusion proofs, corrected leaf-ordinal mapping for multi-peak trees, exposed authenticated proof retrieval and non-streaming proof headers, and added deterministic cross-language golden vectors plus the `aegis-mmr-inclusion-v1` protocol specification.
- Added standalone Python and TypeScript SDKs with gateway-compatible OpenAI and Anthropic client integration and stateless MMR proof verification while preserving provider-native request and response types.
- Added a read-only Next.js 16 and React 19 forensic dashboard with server-side credential isolation, explicit unavailable/error/empty states, real gateway data only, accessible ledger views, browser-side proof verification, and Prometheus-backed metrics visualization.
- Added a scoped forensic export workflow producing bounded ZIP bundles with RFC 8785 JCS manifests, deterministic RFC 8949 DAG-CBOR ledger slices, CIDv1 identifiers, portable MMR proofs, a technical PDF certificate, and an offline `VERIFY.sh`; the output explicitly does not claim certification or legal admissibility.
- Added provider-native RustWal terminal frames, streaming duration/token/redaction telemetry, a local MMR verification sandbox, raw canonical evidence inspection, and server-side ledger filters for tenant, model, endpoint, policy events, failures, and latency.
- Made post-commit failures in the auxiliary `RustWal` non-authoritative: Aegis now records `aegis_native_stream_wal_errors_total`, disables the failed auxiliary segment, and preserves the JSONL-bound terminal marker instead of creating contradictory terminal evidence.
- Added the bounded-stream Z3 model, streaming and portable-proof regression suites, SDK and dashboard CI jobs, production builds, accessibility checks, and real-backend visual QA evidence.
- Added and executed a seven-round, 1,000-event in-process SSE benchmark with retained JSON evidence and explicit exclusion of network and durable-WAL latency.

### CI reliability and supply-chain hardening

- Hardened asynchronous analysis-worker cancellation and bounded lifespan shutdown after reproducing the Python 3.11 `TestClient` teardown hang.
- Added per-response byte and total-duration limits to buffered SSE handling, with durable 502/504 failure evidence and upstream-generator closure tests.
- Replaced all 76 remote GitHub Action references with full 40-character commit SHAs and added a CI gate that rejects mutable Action references.
- Removed the mutable TLA+ `v1.8.0` release-asset URL from the formal trust path after the upstream lightweight tag and JAR changed in place; CI now builds from verified source commit `0894c3407f4717fec7cc18bde3bf3c857fa47333` and checks the embedded revision.
- Replaced repository-owned `datetime.utcnow()` test calls with UTC-aware timestamps and narrowly filtered three identified third-party transition warnings.
- Added explicit CI job timeouts and faulthandler stack dumps so a future non-progress condition terminates with diagnostic evidence.
- Corrected the source-SBOM job to catalog an extracted deterministic archive, validated SPDX generation on pull requests, and verified the post-merge Sigstore attestation for the exact source digest.
- Enabled repository-level SHA enforcement and a selected allowlist of 31 direct and observed transitive Action paths; active reruns of CI, Security, and Forensic CI pass under the hardened policy.
- Expanded `main` branch protection to 13 required CI contexts, including Python 3.11 and source SBOM, and enabled signed-commit and administrator enforcement.

### Final remediation verification

- Merged PR #95 as signed squash commit `8907a6db75cff2a3bd6a551ef7983f53bda17027` and the SBOM correction PR #96 as signed squash commit `43677edca6d39a2b4078187d3676d5a286627846`.
- Final GitHub Python 3.11.16 execution: `5,392 passed, 83 skipped in 64.34s`, `92%` line coverage, followed by a clean locked-runtime dependency audit.
- Remediation-baseline `main` CI passed all 14 jobs, including Python 3.11/3.12/3.13, formal verification, Market Hardening, source SBOM, Docker provenance/SBOM, and keyless image signing.
- Final Security workflow passed CodeQL, Bandit, dependency audit, Trivy, OSV Scanner, and Cargo Audit; Forensic CI also passed under the selected-action policy.
- Private Dependabot, code-scanning, and secret-scanning alert inventories remain unenumerated because the active integration token returns HTTP 403; this is recorded as missing authority rather than a zero-alert result.

### Institutional documentation and claim controls

- Added a six-volume institutional suite covering mechanistic architecture, cryptography and forensics, threat modeling, operations, regulatory review, and commercial procurement, plus a claim-evidence graph, unsupported-claims report, document-control record, and deterministic corpus audit.
- Corrected positive regulatory and evidentiary wording in code documentation: regex PHI handling is best-effort redaction, application sealed segments are not regulatory WORM, GxP objects are support hooks rather than validation, and software-generated integrity labels do not determine legal admissibility.
- Superseded the interim whole-response streaming buffer with the incremental bounded streaming contract documented above; aggregate concurrent memory remains deployment-dependent on configured per-stream queue/window limits and active stream count.
- Added `cbor2>=5.9.0` to runtime dependencies for deterministic DAG-CBOR evidence export after local dependency auditing detected advisories in the previously installed generation-only version.

### Formal and native WAL hardening

- Added bounded Z3, Lean, and TLC artifacts with pinned reproducible execution and explicit non-refinement boundaries.
- Serialized native WAL reserve/write/flush publication, added checked arithmetic and recovery CRC validation, and added concurrent/rejected-append regressions.

## [3.1.0] — 2026-08-18

### Product and documentation

- Repositioned the public product as an AI Governance and Evidence Gateway with a complete US-English README, repository map, buyer guide, product brief, commercial strategy, and explicit claim boundaries.
- Replaced stale v2.x security and commercial language with a current support policy, disclosure path, deployment boundary, licensing summary, procurement blockers, and assurance roadmap.
- Marked `Samples/` dashboards as static demo-only artifacts with synthetic telemetry; sample values are not runtime, customer, cryptographic, compliance, or capacity evidence.

### Security and evidence

- Added a versioned HMAC keyring with atomic reload, one active key, overlap verification keys, expiry, non-secret `key_id` metadata, and fail-closed initial loading.
- Added exporter metadata for the signing key ID used for compliance bundles.
- Added an injectable `fsync_fn` seam to the WAL ledger for deterministic authorized fault injection while retaining `os.fsync` as the production default.
- Expanded WAF critical coverage for persona overrides and added a pinned local corpus with observed bypass and false-positive metrics.

### Verification harnesses

- Added a backpressure/fsync-stall harness for offered 10k requests/s, durable request correlation, missing/duplicate evidence detection, latency percentiles, and WAL integrity. The retained run offered traffic for 0.25 seconds and committed 2,500 of 2,500 requests with zero failures, zero missing/duplicate IDs, valid chain integrity, and 836.3514210795984 ms p99 commit latency; accepted capacity is not claimed.
- Added WAF corpus reporting with corpus SHA-256, per-case verdicts, Wilson 95% interval, zero observed bypasses, zero false positives, and explicit HTTP/2/Nuclei non-execution boundaries.
- Added a three-instance local key-rotation exercise; 2,239 signatures were recorded with zero failed commits and zero unverifiable records. Secret-manager, orchestrator, and clock-skew acceptance remain open.
- Added a native ML-DSA timing harness with 1,000,000 samples per operation. `sign` met the declared non-detection threshold (`p=0.8521504207157158`); `verify` did not (`p=0.0`), so no constant-time claim is approved.
- Added regression tests for key rotation, WAF corpus behavior, and fsync fault injection.
- Documented that a local result is not a production SLO, accepted-capacity claim, universal WAF guarantee, constant-time proof, or certification.

### Final verification

- Final release checkout: `5,442 passed, 37 skipped, 47 warnings` in 68.08 s with `93.91%` line coverage; pytest exit status 0.
- Documentation reconstruction added the US-English developer quickstart, platform operator guide, architecture document, benchmark result record, rollback runbook, privacy boundary, compliance contribution map, and technical/security/procurement FAQs.
- Blocking static and supply-chain gates: Ruff check, Ruff format, Bandit, pip-audit requirements, pip-audit environment, `git diff --check`, Helm lint, and Cargo tests all exited status 0.
- The ML-DSA timing gate remains intentionally non-green for `verify` (`p=0.0`); the release blocks any constant-time verification claim and retains the residual risk in the public security documentation.

### Documentation boundary

- Framework references use NIST, W3C, CISA, IETF, HHS, ISO, EUR-Lex and AICPA sources as review lenses. The repository does not claim SOC 2, HIPAA, FedRAMP, EU AI Act conformity, GDPR legal basis, FIPS 140 validation or court admissibility.

### Versioning

- Bumped active Python, Rust, package, Docker, Helm, and script version anchors to `3.1.0`.

## [3.0.1] — 2026-08-17

### Security and evidence

- Upstream non-200 responses, circuit-open responses, and forwarding exceptions now commit signed durable request-response evidence before the terminal error is returned.
- Successful, streaming, and terminal error responses expose `X-Aegis-Evidence-Status: durable` together with request/session identifiers for external verification.
- Added regression coverage for chat and completions upstream errors, circuit-open behavior, and network forwarding faults.

### Performance and verification

- Added a live TCP workload harness covering mixed chat/health traffic, bounded concurrency, induced upstream latency, periodic 503 faults, and circuit-breaker opening.
- Validated 400-request steady traffic, 1000-request burst traffic, periodic 503 faults, and ten-request breaker opening against the local checkout with zero missing evidence-status headers in the valid runs.
- Bumped the Python package, Python entrypoints, Helm chart, Docker metadata, Rust crate, and maturin package to `3.0.1`.

### Verification

- Final checkout gate: `5374 passed, 80 skipped, 47 warnings`; Ruff lint/format, Bandit, pip-audit, and Helm lint exited with status 0.
- Coverage gate: `93%` line coverage measured by `pytest-cov`; residual warnings remain documented telemetry.

## 3.0.0 — 2026-08-14

This is a historical changelog entry; no corresponding public GitHub Release or tag is currently available.

### Security and evidence

- Production mode is now explicitly `strict` by default and rejects missing authentication, durable evidence, strong signing, request bounds, required kernel controls, or distributed rate limiting.
- Redis rate-limit failures raise `RateLimitBackendUnavailable` and are rejected at the HTTP boundary instead of failing open.
- Non-sandbox Seccomp failures raise; LSM exposes a fail-closed assertion for strict startup.
- The forensic ledger accepts `require_strong_signing` and rejects the ephemeral Ed25519 fallback when enabled. The proxy persists and fsyncs request/response evidence before returning a successful governed response.

### Performance and concurrency

- Response analysis is dispatched through a bounded worker queue and is no longer executed synchronously on the client-visible request path.
- Per-session analyzer state is serialized to prevent races in baseline, EMA, and previous-logit state.
- Streaming responses are bounded and committed before SSE emission.

### Configuration and supply chain

- Backend URLs and air-gap allowlist entries reject unsupported schemes, userinfo, malformed ports, and non-canonical entries.
- Enterprise lifespan uses the injected settings instance consistently.
- `cryptography` is constrained to `>=50.0.0,<51.0.0`; `requirements.lock` pins `50.0.0` with official PyPI hashes to remediate the audited `CVE-2026-69247` / `PYSEC-2026-3552` affected range.
- README, `.env.example`, and `DEPLOYMENT_GUIDE.md` now describe implemented behavior and residual risk instead of certification claims.

### Verification

- Isolated Python 3.12 baseline: `5373 passed, 80 skipped, 47 warnings in 24.17s`.


## [2.4.1] — 2026-06-24

### Summary

Commercial deployment release. Closes all remaining P0 security-theater items
identified in the 2026-06-24 roadmap audit; ships the complete cross-platform
abi3 wheel matrix; upgrades Helm chart to v2.4.1; introduces the enterprise
multi-vertical Docker Compose; and restructures COMMERCIAL.md with concrete
SLA tiers and AGPL §13 enforcement mechanics.

**Audit baseline at release:** 5,451 tests · 5 skipped · 95.18% branch
coverage · `ruff`/`mypy`/`bandit` clean · `cargo test` 26 passing · pyo3 0.29
/ `edition = "2021"` · 8-target abi3 wheel matrix (manylinux2014 + musllinux ×
x86_64/aarch64/armv7, macOS Intel/ARM, Windows MSVC) · all simulation-debt
entries driven to zero (`tests/test_no_simulation_markers.py` asserts 0).

### Security

- **De-simulated `CFIManager`** (ROADMAP P0.2). `aegis/core/cfi_manager.py`
  previously hardcoded `is_cfi_enabled = True  # Simulation result`, always
  returning a positive CFI attestation regardless of the binary under inspection.
  Rewritten with three real ELF detection tiers: LLVM CFI (`__cfi_check` /
  `__cfi_prototype` symbols via `pyelftools`), GCC/LLVM unwind tables
  (`.eh_frame` / `.eh_frame_hdr` sections), and Intel CET IBT + Shadow Stack
  (`GNU_PROPERTY_X86_FEATURE_1_AND` in `.note.gnu.property`). Falls back to
  `readelf`/`nm` subprocess if `pyelftools` is not installed. 18 tests including
  KAT against the real Rust `.so` binary and malformed-file edge cases
  (`tests/test_cfi_manager.py`).

- **De-simulated `MTEGuard`** (ROADMAP P0.2). `aegis/core/mte_guard.py`
  previously fabricated ARM MTE support on every platform (`self._hardware_support
  = True`) and simulated `PR_SET_TAGGED_ADDR_CTRL` success without issuing the
  syscall. Rewritten with real `/proc/cpuinfo` `mte` flag parsing, `AT_HWCAP2`
  bit 18 (`HWCAP2_MTE`) auxiliary-vector check, and a real `prctl(55, 1)` call
  via `ctypes.CDLL("libc.so.6")`. Returns `False` on x86/non-ARM hosts. 14 tests
  cover the no-hardware path and monkeypatched hardware paths; 2 ARM integration
  tests skip cleanly on CI (`tests/test_mte_guard.py`).

- **De-simulated `DependencyAuditor`** (ROADMAP P0.4). `aegis/core/dependency_audit.py`
  previously calculated `SHA-256(f"{name}_{version}_AUDITED")` as the audit hash
  and re-computed the exact same string for verification — always passing. Replaced
  with a real `pip-audit -f json` invocation (`DependencyAuditor.scan()` returning
  `VulnerabilityFinding` dataclasses) and real `importlib.metadata` RECORD hash
  verification using URL-safe base64 (PEP 658). `DependencyInternalizer.verify_supply_chain()`
  now delegates to both. 24 tests including tamper detection and real certifi hash
  match (`tests/test_dependency_audit.py`). Also registered `slow` pytest mark.

- **De-simulated `XDPDynamicSegmenter`** (ROADMAP P0.3). `aegis/core/xdp_dynamic_segmentation.py`
  previously added IPs only to an in-memory Python `set` and logged
  `# Simulation: eBPF_map_update(...DROP)` — no packet was ever dropped at the
  kernel level. Replaced with `_FirewallBackend` that auto-detects nftables (`nft`)
  → iptables → NONE and issues real kernel rules (`nft add/delete element` or
  `iptables -I/-D INPUT -s <ip> -j DROP`). `block_ip_immediately()` returns `True`
  only when a kernel rule is installed; the application-layer-only fallback path logs
  an explicit "APPLICATION-LAYER ONLY" advisory. 27 tests cover backend detection,
  idempotency, kernel failure fallback, and zone blackhole/active transitions
  (`tests/test_xdp_dynamic_segmentation.py`).

- **Hardened `DependencyAuditor` against B607 partial-path subprocess start**.
  `pip-audit` is now resolved via `shutil.which()` in `__init__`; a `DependencyAuditorError`
  is raised immediately if the tool is absent — no partial-path fallback. `subprocess.run`
  annotated `# noqa: S603`. Test updated to patch `shutil.which`.

- **De-simulated `sandbox_l1.py`** (ROADMAP P0.2). Previously skipped the
  entire rule-addition step ("we simulate the rule addition") and called
  `seccomp_load` with zero allowlist rules and `SCMP_ACT_KILL` — any loaded
  filter would have immediately killed the process. Rewritten with real
  `seccomp_syscall_resolve_name` + `seccomp_rule_add` calls via ctypes for
  every syscall in the allowlist; default action changed to
  `SCMP_ACT_ERRNO(EPERM)` (safe); `apply_filter()` returns `True` only when
  `seccomp_load()` succeeds; `build_filter_without_loading()` validates the
  filter safely in tests. 18 tests including real subprocess filter load and
  mocked-library failure paths (`tests/test_sandbox_l1.py`).

- **De-simulated `panic_mode.py`** (ROADMAP P0.2). `_zeroize_critical_memory` previously only
  logged "Zeroizing..." and "complete" with a `# Simulation` comment and no actual write.
  Replaced with real `ctypes.memset` over registered ``bytearray``/``memoryview`` buffers;
  ``register_sensitive_buffer()`` added so callers can enlist secret-bearing buffers.
  `_isolate_network` previously only logged with `# Simulation: calls XDPDynamicSegmenter...`.
  Replaced with real subprocess calls to `nft add rule ... drop` or `iptables -P INPUT/OUTPUT/FORWARD DROP`;
  returns `False` and logs a CRITICAL advisory when no kernel firewall tool is available.

- **De-simulated `root_ca_gateway.py`** (ROADMAP P0.2). `import_signed_certificate`
  had a `# Simulation of decoding the physical transfer` comment despite doing real
  JSON decoding. Comment removed. `fetch_certificate(request_id)` previously ignored
  the `request_id` parameter ("In a real system, we would match the request_id");
  now iterates `_inbound_buffer` and matches by `cert.ca_serial == request_id`.

- **De-simulated `memory.py`** (ROADMAP P0.2). `HardenedMemoryManager.initialize_hardened_allocator`
  previously set `_allocator_type = "mimalloc"` via a "Simulation mode" comment
  even when neither `libmimalloc.so` nor `libhardened_malloc.so` appeared in
  `/proc/self/maps`. Now logs a warning and sets `_allocator_type = "standard"`
  honestly when no hardened allocator is detected.

- **De-simulated `memory_invariants.py`** (ROADMAP P0.2). Previously computed
  golden hashes from a `f"STATE_{start}_{end}"` string (always matching itself,
  never detecting any modification). Rewritten with `_read_range()` reading the
  actual bytes from the process's own virtual address space via `/proc/self/mem`,
  and `_hash_range()` computing real SHA-256 digests. `register_invariant()`
  returns `False` when the range is unreadable. `verify_invariants()` re-reads
  each range and detects real modifications; unmapped pages after registration
  are logged as CRITICAL. 16 tests including real ctypes buffer tampering
  detection, unmapped-address handling, and mock-based unreadable-after-register
  coverage (`tests/test_memory_invariants.py`).

- `tests/test_no_simulation_markers.py` — `KNOWN_SIMULATION_DEBT` shrunk from
  23 → 16 as `cfi_manager.py`, `mte_guard.py`, `dependency_audit.py`,
  `xdp_dynamic_segmentation.py`, `sandbox_l1.py`, `memory.py`, and
  `memory_invariants.py` are removed. Debt-count assertion updated to `== 16`.

- **Removed two fake post-quantum modules that manufactured false cryptographic
  assurance** (ROADMAP P0.1). `aegis/core/pqc.py` advertised "ML-DSA (Dilithium)"
  signatures but computed HMAC-SHA512 padded with random bytes; `aegis/core/
  pqc_provider.py` was a SHAKE-256 "simulation" whose `verify()` accepted **any**
  128-byte signature regardless of message. Both are deleted.

### Added

- `aegis/core/pqc_signer.py` — the single real `PQCSigner` over genuine ML-DSA-65
  (FIPS 204) via the Rust `pqcrypto-mldsa` backend: real keypair (pk 1952 / sk
  4032 / sig 3309 bytes), `sign`/`verify`, honest `backend` reporting (never a
  simulation label), `require_real` mode, and no simulated fallback. 20 KAT-style
  tests prove forgery, tamper, wrong-key, and truncation rejection
  (`tests/test_pqc_signer.py`).

### Changed

- `aegis/core/pqc_tls.py` rewritten as a **real** hybrid post-quantum key
  exchange: X25519 ECDH (`cryptography`) composed with ML-KEM-1024
  (`aegis.core.mlkem_session`) via `HKDF-SHA256`, TLS-1.3-style initiator/
  responder protocol. The previous module's "X25519" and "Kyber" secrets were
  both `sha256(priv ‖ pub)` — not a Diffie-Hellman and not post-quantum. The new
  module refuses to downgrade to classical-only when ML-KEM is unavailable. 14
  tests prove key agreement and tamper-breaks-agreement (`tests/test_pqc_tls.py`).
- `aegis/core/artifact_signing.py` rewritten with two honestly-labelled **real**
  schemes — `HMAC_SHA512` and real `ML_DSA_65` (via `PQCSigner`) — fixing a
  comment that labelled HMAC as ML-DSA and a verify path that re-signed instead
  of doing asymmetric verification with the published public key. 10 tests
  (`tests/test_artifact_signing.py`).
- `tests/test_no_simulation_markers.py` — a **ratchet** CI guard: no new `aegis/`
  module may introduce a `# SIMULATION` marker, and de-simulated modules must be
  removed from the 23-entry `KNOWN_SIMULATION_DEBT` allowlist (shrink-only).

### Fixed

- `tests/test_determinism.py::test_no_outlier_exceeds_500us` now skips on shared
  CI runners (`HERMES_SANDBOX`/`CI`), where multi-tenant kernel-scheduler
  preemption produces millisecond-scale dispatch outliers unrelated to the code
  under test (a 90 ms outlier was observed). The hard <500 µs bound remains
  enforced on dedicated CPU-isolated hardware.

## [2.4.1] - 2026-06-24

Release-hardening and capability-expansion release. Twenty roadmap controls were
implemented and tested across all five target domains (Defense, Healthcare,
Industrial, Enterprise HA, Forensics), advancing the roadmap scorecard to
151/193 (~78%). All 4,575 tests pass (3 skipped) at 94.79% coverage.

### Added

**Defense & Government (Domain 1)**
- ML-KEM-1024 (FIPS 203) session-key bootstrap (`aegis/core/mlkem_session.py`).
- Cross-domain solution (CDS) guard with classification-domain transfer
  sanitization (`aegis/core/cds_guard.py`).
- Offline license validation — HMAC-SHA256 over canonical JSON, no phone-home,
  enforced key separation (`aegis/core/offline_license.py`).
- Pinned CA bundle for air-gapped signature verification, SHA-256 DER
  fingerprints, no runtime CA fetch (`aegis/core/pinned_ca_bundle.py`).
- LSM confinement guard — AppArmor/SELinux detection and advisory enforcement
  (`aegis/core/lsm_guard.py`, `deploy/apparmor/aegis.profile`).
- Hardware-bound session tokens (TPM 2.0 / software backends, HMAC-SHA256
  binding) (`aegis/core/hardware_token.py`).
- Rust build hardening — full RELRO, noexecstack, embedded size profile
  (`aegis_rust_v2/.cargo/config.toml`).
- **Fully air-gapped Docker image** — `deploy/docker/Dockerfile.airgap` with
  sha256-pinned base, `pip install --no-index --find-links /wheels`, vendored
  wheel workflow (`scripts/vendor_wheels.sh`), and `make docker-airgap`.

**Healthcare & Life Sciences (Domain 2)**
- GxP Installation/Operational Qualification (IQ/OQ) protocols with JSON evidence
  artifacts (`tools/qualification/iq_checks.py`, `oq_checks.py`).

**Industrial Automation & OT (Domain 3)**
- Real-time scheduling via `sched_setscheduler` (FIFO/RR/DEADLINE)
  (`aegis/core/rt_scheduler.py`).
- CPU affinity pinning via `sched_setaffinity` (`aegis/core/cpu_affinity.py`).
- Gossip-protocol WAL synchronization for disconnected edge nodes
  (`aegis/core/gossip_wal_sync.py`).
- CRDT audit-node ordering with vector clocks for deterministic distributed
  ordering (`aegis/core/crdt_ordering.py`).

**Enterprise Hyperscale & HA (Domain 4)**
- Raft consensus state machine (Ongaro & Ousterhout 2014) — leader election,
  log replication, SHA-256 entry-hash tamper detection (`aegis/core/raft_consensus.py`).
- Split-brain prevention via monotonic fencing tokens (Kleppmann 2016),
  gating every WAL write (`aegis/core/split_brain.py`).
- Kubernetes operator — `AegisProxy` CRD + kopf controller
  (`deploy/k8s/aegis-operator/`).

**Advanced Forensics & WAF (Domain 5)**
- Semantic similarity clustering of jailbreak families (SimHash + Hamming)
  (`aegis/core/semantic_sim_clustering.py`).
- Token-split reassembly WAF detector for boundary-split attack patterns
  (`aegis/core/token_split_detector.py`).
- Court-ready forensic PDF report with SHA-256 seal, no external PDF dependency
  (`aegis/core/forensic_pdf_report.py`).
- Anonymized threat-intelligence sharing with STIX 2.1 indicator export
  (`aegis/core/ti_sharing.py`).

**Tooling & Benchmarks**
- New `benchmarks/bench_crypto_audit.py` — measures HMAC signing, durable
  `commit_forensic()`, and `verify_integrity()` throughput (documented as
  Claim 4 in `docs/BENCHMARKS.md`).

### Changed

- Bumped version to 2.4.1 across `pyproject.toml`, `aegis`, `aegis_server`,
  Docker images, README, and deployment guide.
- README test evidence and badges refreshed to 4,575 passing tests.

### Fixed

- **Rust extension test linking:** `aegis_rust_v2/Cargo.toml` had
  `default = ["extension-module"]`, which made `cargo test` omit the libpython
  link and fail with undefined `Py*` symbols. Changed to `default = []`;
  maturin still enables `pyo3/extension-module` via `[tool.maturin] features`,
  so production wheels are unaffected. (`cargo test --release` → 23 passed.)
- **Version drift:** `aegis_server.__version__` and the standard
  `deploy/docker/Dockerfile` were stale at 2.3.0; the `aegis_server` `/health`
  and `/ready` endpoints now report the correct release version.
- **Forensic tool environment bug:** `tools/forensic/forensic_checks.py` invoked
  `cargo test` with an empty environment (no `PATH`), which prevented the Rust
  toolchain from resolving; it now inherits the process environment.
- Resolved 30 lint findings across recently added consensus, qualification, and
  test modules (import ordering, unused imports, `StrEnum` migration, ambiguous
  identifiers); full repository is now `ruff` lint- and format-clean.
- Skipped a flaky concurrent-load scheduling-jitter test on shared CI runners
  (`tests/test_determinism.py`), which require dedicated real-time hosts.

### Security

- `aegis_server.crypto` previously imported `hvac` eagerly at package level,
  breaking the HMAC-only compliance-export path on installs without the optional
  `vault` extra; `VaultSigner` is now lazy-imported. (Carried from 2.4.0.)

## [2.4.0] - 2026-06-21

### Added

- Broad roadmap expansion across Defense, Healthcare, Industrial, Enterprise,
  and Forensics domains (SCIM 2.0, RBAC/ABAC zero-trust, LDAP/AD, WORM ledger,
  RAG injection scanning, SLO burn-rate alerting, DFIR export formats, and more).

### Fixed

- `aegis_server.crypto` eagerly imported `hvac` at package level, breaking the
  HMAC-only compliance export path on installs without the optional `vault`
  extra; `VaultSigner` is now lazy-imported. *(Severity: Low)*

## 2.3.0 - 2026-06

This is a historical changelog entry; no corresponding public GitHub Release or tag is currently available.

### Fixed

- mTLS settings were defined in `AegisSettings` but never applied to the uvicorn
  listener or the upstream `httpx` client. *(Severity: High)*
- `ResponseAnalyzer` thresholds were hardcoded, ignoring `AegisSettings`;
  alerting could not be tuned at runtime. *(Severity: Medium)*

## [2.2.0] - 2026-05

### Fixed

- Audit chain signing key was derived from the first sorted API key; unannounced
  rotation silently invalidated the chain. *(Severity: High)*
- `/docs` and `/redoc` were exposed unconditionally in all deployment modes.
  *(Severity: Medium)*
- `prev_hash` always pointed to the genesis node due to a wrong `ORDER BY`
  direction in `list_nodes()`. *(Severity: Critical)*
- Concurrent `BackgroundTask` writes could fork the audit chain (no chain lock).
  *(Severity: Critical)*

[3.0.1]: https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v3.0.1
[2.4.1]: https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v2.4.1
[2.4.0]: https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v2.4.0
[2.2.0]: https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v2.2.0

## Related documents

- [`README.md`](README.md)
- [`docs/CLAIMS_MATRIX.md`](docs/CLAIMS_MATRIX.md)
- [`docs/benchmarks/BENCHMARK_RESULTS.md`](docs/benchmarks/BENCHMARK_RESULTS.md)
- [`docs/SECURITY_ASSURANCE_ROADMAP.md`](docs/SECURITY_ASSURANCE_ROADMAP.md)
- [`SECURITY.md`](SECURITY.md)
