<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core — Engineering and Market Roadmap

**Status:** checked-out source baseline `v5.0.0` has 14 synchronized anchors and was published 2026-09-16 on every surface except PyPI `aegis-latent-core`; source metadata does not establish external lifecycle or target-acceptance state
**Last verified:** 2026-09-15 UTC (register reviewed against the `5.0.0` source tree; external readback values are unchanged from their recorded dates)
**Release baseline:** checked-out source baseline `v5.0.0` with 14 synchronized anchors, published 2026-09-16 except PyPI `aegis-latent-core`, plus historical external observations
**Source baseline:** fourteen synchronized `5.0.0` anchors; immutable parent comparison `fdace8844568eb788216740b2cb5daf187d99d3b` has fourteen `4.0.0` anchors
**External baseline:** `v4.1.2` published and read back 2026-09-04 — signed annotated tag at `860f14177d94c194e5ae7156017d6fa74264e429`, GitHub Release, PyPI `aegis-latent-core` and `aegis-latent-sdk` `4.1.2`, npm `aegis-latent-sdk` `4.1.2`, GHCR gateway/dashboard images. Prior lightweight `v4.0.1` tag at `6469904380218584ae0b5221334bc9a46500f5ba` had failed tag workflows, and the `4.0.0` registry objects carry no attributed provenance from them
**Purpose:** Single source of truth for work that is implemented, measured, deployment-dependent, or still open.

## Status rules

| Mark | Meaning |
|---|---|
| `[x]` | Implemented and covered by a named test or artifact under declared conditions. |
| `[m]` | Measured by a reproducible artifact; not a universal capacity or assurance claim. |
| `[d]` | Deployment-dependent; source support exists but target infrastructure evidence is required. |
| `[ ]` | Open work, incomplete, unmeasured, or intentionally not claimed. |
| `[l]` | Requires legal, regulatory, contractual, or independent-assurance review. |

A checkbox may not be changed to `[x]` because a stub, dashboard sample, docstring, vendor statement, or favorable benchmark exists. Every change requires a locator, test or artifact, boundary, and falsification condition in [`CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md).

## Two-baseline current state

The current **source baseline** is `5.0.0` with fourteen synchronized anchors, published 2026-09-16 on every surface except PyPI `aegis-latent-core`. `4.1.2` remains the most recent version published on *every* surface. Readback on 2026-09-04 confirmed the signed annotated tag `v4.1.2` at `860f14177d94c194e5ae7156017d6fa74264e429`, its GitHub Release with 31 assets, PyPI `aegis-latent-core` `4.1.2`, PyPI `aegis-latent-sdk` `4.1.2`, npm `aegis-latent-sdk` `4.1.2`, and the GHCR gateway and dashboard images. Its immutable parent/source comparison `fdace8844568eb788216740b2cb5daf187d99d3b` has fourteen `4.0.0` anchors. The previous published GitHub baseline is signed annotated tag `v4.0.2` at `a6eb58dcc03f8b638c8f3e35f0300f5443a926ca`; before it, lightweight tag `v4.0.1` targeted `6469904380218584ae0b5221334bc9a46500f5ba` with failed tag workflows, and observed PyPI/npm `4.0.0` objects have no attributed provenance from those runs. Source metadata never establishes an external tag, release, registry artifact, deployed service, SLO, compliance result, or acceptance; every claim above rests on the readback, not on the version in the tree.

Historical v3.1.0 benchmark, security, remediation, and release records retain their original values and scope. They are not superseded as historical observations, but they must not be presented as measurements of the v4 source baseline without rerunning the named workload. See [`evidence/INDEX.md`](../evidence/INDEX.md).

## Completed core controls

- [x] Strict runtime mode requires authentication, durable evidence, strong signing, request-size bounds, distributed rate limiting, and configured kernel controls.
- [x] Governed successful, streaming, and terminal-error paths expose durable evidence status and use the durable error-evidence path where storage is available.
- [x] The ledger canonicalizes hashes, binds chain links, signs records, persists WAL segments, synchronizes the WAL before the governed success path, and verifies integrity.
- [x] Redis rate-limit failure is observable and fail-closed at the HTTP boundary.
- [x] Egress endpoint validation rejects malformed, unsupported, userinfo-bearing, and non-approved endpoints.
- [x] Seccomp and LSM/AppArmor/SELinux guards distinguish required enforcement from explicit sandbox/development operation.
- [x] Response analysis uses bounded workers and per-session serialization; enrichment is not required for authoritative evidence.
- [x] Native ML-DSA and other hardware-dependent controls refuse to fabricate success when their real backend is unavailable.
- [x] Dependency, SBOM, release provenance, and security disclosure surfaces exist and are tied to release artifacts.

Historical implementation detail remains in [`CHANGELOG.md`](../CHANGELOG.md), git history, module docs, and release assets. This file tracks current decision status rather than repeating every historical patch.

## v4 source baseline — Phase 2/3 modules A–D (not in the v3.1.0 distribution)

- [x] **Module A — bounded SSE:** incremental event transformation uses byte/event queue limits, event/output/window/preview/duration bounds, online hashing, and terminal evidence ordering. Locators: `aegis/proxy/streaming.py`, `tests/test_proxy_streaming.py`, and `specs/aegis_stream_buffer.smt2`. Limits are per admitted stream; aggregate memory and throughput remain concurrency- and deployment-dependent.
- [x] **Module B — portable MMR proof and SDKs:** the core emits the versioned inclusion-proof contract, shared vectors verify in Python and TypeScript, and tested OpenAI/Anthropic integration surfaces exist. Locators: `aegis/core/mmr.py`, `tests/test_mmr_portable.py`, `sdk/shared/mmr-inclusion-v1.json`, `sdk/python/tests/`, and `sdk/typescript/tests/`. A verifier still needs an independently trusted root; provider compatibility is bounded to tested surfaces and dependency ranges.
- [x] **Module B addendum — `aegis-mmr-inclusion-v2` domain separation.** v1 tags neither hash input, so a leaf payload equal to the concatenation of two child digests hashes to exactly the interior node over them — the RFC 6962 §2.1 type-confusion weakness, reachable through `verify_portable_inclusion`, which accepts caller-supplied leaf bytes. v2 prefixes each input with a domain tag and consumes raw 32-byte digests. Locators: `aegis/core/mmr.py` (`v2_leaf_hash`, `v2_node_hash`, `v2_bagged_root`), `tests/test_mmr_domain_separation.py`, `sdk/typescript/tests/mmrV2.test.ts`, `CLM-064`. **Wired into the ledger; `AEGIS_MMR_HASH_SCHEME` defaults to `auto`, so a new chain starts on v2 and an existing chain reopens under the scheme its WAL recorded.**
- [x] Wire `aegis-mmr-inclusion-v2` into `CryptographicAuditLedger`. Both prerequisites are met: `aegis_rust_v2/src/mmr.rs` implements each scheme under the same names, with Rust↔Python root agreement asserted across a 37-leaf rollover for both, and the migration rule is that **a scheme belongs to a chain**. There is no in-place upgrade and cannot be one — a root cannot be recomputed under a new construction without rewriting the history it already committed to — so the ledger reads the scheme its WAL recorded and refuses to reopen a chain under the other one with fault state `mmr_scheme_mismatch`. `AEGIS_MMR_HASH_SCHEME=auto` (the default) starts a new chain on v2 and leaves every chain in the field on v1. **Wire boundary:** a v2 receipt does not verify against an SDK build predating `4.3.0`, including published `4.1.2`.
- [x] **Module C — bounded forensic export:** retained-window export produces the contract-tested ZIP and rejects empty or unbounded acquisition requests. Locators: `aegis/core/forensic_bundle.py`, `tests/test_forensic_bundle.py`, and `tests/test_audit_api_new.py::test_forensic_export_returns_verifiable_zip`. It does not establish authorship, complete custody, certification, legal admissibility, or external immutability.
- [x] **Module D — forensic dashboard:** the read-only dashboard uses real gateway responses, server-side credential handling, explicit empty/unavailable/error states, and tested proof/contract parsing. Locators: `dashboard/src/`, `dashboard/tests/`, `.github/workflows/ci.yml` job `dashboard`, and `evidence/commercial_phase2_dashboard_qa.md`. A local visual-QA artifact is not customer telemetry, production availability, capacity, or independent assurance.
- [m] The seven-round, 1,000-event local SSE artifact is retained at `evidence/commercial_phase2_streaming_benchmark.json`; it excludes network and durable-WAL latency and is not an end-to-end capacity result.
- [x] Release contracts now require 14 synchronized version anchors, a signed-tag plus full-target dispatch boundary, pinned Python build backends, protected-main ancestry verification, exact release-note extraction, deterministic asset preparation, and a create-only GitHub Release command. The v4.0.2 run published gateway and dashboard multiarch images, attested their digests, and keyless-signed those digests; GitHub Release and GHCR readbacks passed, while PyPI/npm publication jobs were skipped.
- [ ] Establish and independently verify release-environment reviewers, trusted signer roots, immutable release settings, registry privileges/immutability, OIDC/Sigstore verification, SBOM attachment policy, architecture runtime smoke tests, and trusted-root distribution before any future publication claim.
- External lifecycle claims are bounded by independent readback. For `v4.1.2`: the signed tag, the GitHub Release and its 31 assets, PyPI `aegis-latent-core`, PyPI `aegis-latent-sdk`, npm `aegis-latent-sdk`, and both GHCR images passed on 2026-09-04 — the first version at which the gateway itself reached PyPI — while `cosign verify`, `gh attestation verify` and the full `SHA256SUMS` sweep were not run, and the PyPI gateway artifacts are byte-different from the release assets of the same name. For `v4.1.1`: the signed tag, GitHub Release assets, PyPI SDK and GHCR manifests passed on 2026-09-03, npm did not. For `v4.0.2`: the signed tag, GitHub Release assets, GHCR manifests, GitHub attestations, and OCI signatures passed, while both SDK registries remained at `4.0.0`. For `v5.0.0`: the signed tag, the GitHub Release and its 31 assets, PyPI `aegis-latent-sdk`, npm `aegis-latent-sdk`, and both GHCR images with cosign signature objects present were read back on 2026-09-16, while **PyPI `aegis-latent-core` was not published** and `cosign verify`, `gh attestation verify` and the `SHA256SUMS` sweep were not run. Modules A–D still require deployment acceptance before being described as production capabilities.
- [x] Add `CausalMmr`, a join-semilattice over domain-separated MMRs, as the data structure a reconciliation layer would need: `join` is idempotent, commutative and associative, so replicas exchanging leaf sets converge on one root whatever order they merge in. Locators: `aegis_rust_v2/src/crdt_mmr.rs`; `tests/test_crdt_mmr.py`; `CLM-066`. It is **unwired** — see the open item below.
- [ ] Provide cross-replica global ordering and multi-region failover/recovery evidence; current implementation does not establish multi-region HA. `CausalMmr` supplies the accumulator but not the system: there is no membership protocol or persistence, so each replica remains an independent chain (`CLM-012`) — wiring v2 into the ledger changed the construction each chain records, not the fact that there is one chain per replica. A gossip transport over mutual TLS does now run behind an off-by-default opt-in, but it reconciles the accumulator, not the ledger (`CLM-080`). Convergence is also not agreement about truth — `join` reconciles replicas that disagree about ordering, not replicas that lie, so Byzantine resistance is a separate and unaddressed problem.
- [ ] Publish the storage-growth boundary for the retained window: no module compacts WAL segments or tiers records to cheaper storage (`REG-019`, DOCUMENTED) - segments grow with the retained window, and capacity is the operator's dimension.
- [ ] Complete independent security, cryptographic, deployment, accessibility, and forensic-process assurance appropriate to the claimed scope. Repository tests and local QA are not external assurance.

## v3.1.0 market-hardening release

### Documentation and claim governance

- [x] Restore a complete US-English README as the primary product, architecture, operation, buyer, and repository index.
- [x] Add `docs/PRODUCT_BRIEF_US.md`, `docs/BUYER_GUIDE_US.md`, and `docs/COMMERCIAL_STRATEGY_US.md` with an explicit non-binding pricing hypothesis and no fabricated customer proof.
- [x] Replace stale security and commercial documents with current support, disclosure, license, procurement, and assurance boundaries.
- [x] Add `docs/REPOSITORY_MAP.md`, `docs/security/THREAT_MODEL.md`, `docs/security/WAF_TESTING.md`, `docs/security/PQC_CONSTANT_TIME.md`, and `docs/SECURITY_ASSURANCE_ROADMAP.md`.
- [x] Mark all `Samples/` dashboards as static demo-only and add explicit provenance metadata; sample numbers are not runtime evidence.
- [x] Update `CLAIMS_MATRIX.md` with evidence locators, falsification conditions, and prohibited wording.

### Backpressure and WAL

- [x] Add an injectable `fsync_fn` seam while keeping `os.fsync` as the production default.
- [x] Add a deterministic 10k RPS offered-load / injected-fsync-stall harness with missing/duplicate ID checks, chain verification, latency percentiles, and WAL hash.
- [m] Local result: 2,500 offered requests at 10k RPS offered, 2,500 durable commits, zero failures, zero missing IDs, zero duplicate IDs, and valid chain integrity under a 2 ms injected fsync delay; observed p99 commit latency was 836.3514210795984 ms (`evidence/execution_2026-08-20/backpressure_stall_report.json`). The 10,000-request / p99 1,189.89 ms pair previously recorded here is retracted (`UC-018`).
- [ ] Run the equivalent test against a disposable, loop-backed `dm-delay` block device only when root/capability, device ownership, cleanup, and isolation are proven.
- [ ] Add customer-target storage acceptance for filesystem, CSI/cloud volume, backup, restore, crash recovery, and external immutable retention.
- [ ] Revisit group commit or a Rust WAL path only after preserving the per-request durability contract and proving ordering semantics.

### WAF and ingress

- [x] Add a critical persona-override rule and regression coverage.
- [x] Add a pinned application-layer corpus with benign, critical, Unicode, structural, and nested cases.
- [m] Local result: 0 observed bypasses and 0 false positives across 15 malicious and 8 benign cases; Wilson interval remains wide because the corpus is small.
- [ ] Pin and execute HTTP/2 fragmentation and parser-differential tests at the actual authorized ingress boundary.
- [ ] Pin a reviewed `nuclei-templates` revision and run only against a disposable, owned local target; retain raw artifacts and minimize every finding into a safe regression test.
- [ ] Expand corpus by language, encoding, multimodal boundary, provider parameter, and parser normalization class with measured false-positive review.

### Key rotation

- [x] Add a versioned HMAC keyring with one active key, verify-key overlap, expiry, atomic snapshot validation, reload failure counter, and no-secret logging.
- [x] Add signer metadata so compliance exports persist the non-secret key ID used for sealing.
- [x] Add unit tests for rotation, overlap, expiry, invalid snapshot, weak key, duplicate ID, and initial-load failure.
- [ ] Run the full three-replica deployment test with staggered reload, secret-manager propagation, one delayed replica, restart/replay, rollback, and per-record key ID correlation.
- [ ] Add HSM/Vault rotation evidence and compare behavior with file-backed keyring under network failure.

### ML-DSA timing and assurance

- [m] Run separate native `sign()` and `verify()` timing experiments with 1,000,000 balanced interleaved samples per operation, release build, raw sample retention, and a declared Python-to-Rust boundary. `sign` met the non-detection threshold (`p=0.8521504207157158`); `verify` did not (`p=0.0`).
- [ ] Repeat across isolated CPU runs/seeds and report effect size, outliers, noise, run divergence, and implementation-boundary review before any stronger claim.
- [ ] Use only “no statistically significant timing leakage detected under the named experiment” after a passing run; never use “constant-time” without qualified review and the required evidence.
- [ ] Track algorithm conformance, compiler/build reproducibility, key custody, module boundary, and any FIPS 140 review separately.

## P0/P1 open work

- [ ] Replace the honest `zk_proof` stub with a reviewed real proving system or remove the public feature surface; `require_real=True` must continue to fail closed until then.
- [ ] Add an external transparency-log or timestamp anchoring backend with verifiable third-party evidence; never fabricate transaction IDs or proofs.
- [ ] Complete actual ingress, storage, secret-manager, kernel, TLS, Redis, backup, restore, and crash-recovery acceptance for each supported deployment profile.
- [ ] Keep dependency and action exceptions bounded, owned, time-limited, and documented; no silent advisory ignore.
- [ ] Complete an independent threat-model and code review before any certification, court-admissibility, or high-assurance procurement language.

## Additional v4 source capabilities and open acceptance work

- [x] Add immutable principal, OIDC, explicit mTLS leaf-pin, tenant confinement, scope enforcement, and dual request/token quota source modules with deterministic tests.
- [x] Compare tenant identifiers over UTF-8 bytes so the comparison is defined for every string. `hmac.compare_digest` raises `TypeError` on non-ASCII `str`, so a client-supplied `tenant_id` carrying non-ASCII surfaced an authorization denial as an unhandled 500 instead of the intended 403, and two credentials naming one internationalized tenant failed to combine at all. Locators: `aegis/proxy/dependencies.py` (`_same_tenant`), `aegis/auth/mtls.py`, `tests/security/test_tenant_isolation.py`, `CLM-065`. No cross-tenant read was possible in either case — the request failed closed throughout — so this corrected the shape of a failure and the availability of internationalized tenants, not an isolation boundary. Identifiers are deliberately not Unicode-normalized; normalizing would let two codepoint sequences resolve to one tenant.
- [x] Remove caller session/tenant values from primary-gateway quota identity and durable tenant selection.
- [x] Add finalized WAL segment manifests, durable S3 archival journal/spool, Object Lock metadata verification, and optional RFC 3161 trust verification against an explicit CA file.
- [x] Add closed-schema OTel/SIEM primitives, bounded SIEM spool controls, and privacy sentinel tests.
- [x] Add LangChain/LlamaIndex SDK callback source adapters and isolated SDK publishing workflow candidates.
- [d] Validate OIDC issuer/JWKS rotation and revocation behavior against the target IdP; source tests are not IdP acceptance.
- [d] Validate the TLS terminator, forwarded-certificate header stripping, leaf-pin rotation, and target PKI/revocation policy. Current source must not be described as universal mTLS chain validation.
- [d] Validate Redis atomic quota behavior, outage handling, latency, and key lifecycle on the target topology.
- [d] Validate S3 versioning/Object Lock bucket creation, permissions, retention/legal-hold behavior, reconciliation, restore, cost, and deletion resistance. GCS and Azure adapters are not implemented.
- [d] Validate the approved TSA, trust/revocation/policy configuration, renewal, offline verification, and evidence retention.
- [d] Validate SIEM/OTel authentication, egress, downstream parsing, quotas, outage recovery, retention, and operational ownership.
- [ ] Migrate or retire the alternate `aegis_server` HTTP surface so it cannot be mistaken for having the primary gateway's new tenant/RBAC contract.
- [x] Add an isolated gateway/dashboard multi-architecture OCI build, SBOM, provenance, and keyless digest-signing workflow candidate.
- [x] Add a truthful crypto capability facade that reports optional runtime availability, the non-real ZK stub, O(log n) portable-MMR proof growth, and absent external validation without changing the underlying primitives.
- [x] Add an exact metadata-only query helper over fixed tuples of retained-node references. It neither copies nor makes referenced nodes immutable, remains unwired to the audit HTTP API, and is not a durable, archived-WAL, full-text, or scale-qualified search engine.
- [x] Fail closed on stale/malformed timestamp-receipt reuse and expose same-length WAL-head divergence in the metadata-only gossip detector.
- [x] Add a deterministic advisory AI context pack with offline schema/link/claim-boundary checks; context files remain non-authoritative.
- [d] Add hardened Helm defaults and a restricted source template for installing the AegisProxy operator controller with namespaced RBAC. A reviewed immutable controller image, persistent storage for generated Aegis workloads, cluster reconciliation tests, readiness/status observation, and target acceptance remain open.
- [x] Treat TEE device nodes as discovery-only, reject unauthenticated legacy reports, and provide fail-closed policy evaluation for normalized claims from an injected verifier. Enclave loading, vendor quote/collateral verification, hardware execution, and FIPS 140-3 evidence remain open.
- [x] Withdraw the unaccounted DP analytics endpoint and retain only an internal one-release Laplace count primitive with exact sensitivity and CSPRNG boundaries. A durable privacy accountant, stable query/dataset identity, memoization, contribution bounds, and reviewed publication policy remain open.
- [x] Remove the legacy HSM manager's predictable software-signing fallback and reject ambiguous PKCS#11 key selection. Vendor-token interoperability, cloud KMS adapters, key-policy/IAM acceptance, and certification evidence remain open.
- [x] Require exact cargo-fuzz executables, a private workspace, bounded parseable manifest, and confined regular target files; distinguish clean/crash/tool-error/timeout states; and remove synthetic coverage/bug metrics. Git provenance, retained campaign artifacts, measured coverage, and bounded Kani harnesses remain open.
- [d] Validate OCI execution, package permissions, registry policy, signature/provenance verification, architecture smoke tests, and rollback on the target GHCR environment.
- [ ] Configure protected immutable signed tags, GitHub environments, and exact PyPI/npm trusted-publisher bindings. Publication remains disabled unless `AEGIS_TRUSTED_PUBLISHING_ENABLED=true` is configured externally.
- [ ] Complete full CI, security, formal, documentation, dependency, packaging, and target-environment acceptance gates plus mandatory domain approvals before any future tag, release, registry publication, or deployment-readiness claim.

## P2 performance and operations

- [ ] Ledger compaction and cold tiering. The JSONL WAL has no mechanism to compact old segments or move them to a cheaper storage tier — `docs/operations/STORAGE_REQUIREMENTS.md` only advises provisioning enough headroom for the retention window. Any compaction scheme must preserve hash-chain and MMR-inclusion-proof reachability for every leaf it moves or rewrites, which is nontrivial design work, not a bounded bug fix. `REG-019`.
- [ ] Measure end-to-end proxy latency with a real or explicitly bounded upstream, including evidence durability, streaming, WAF, rate limiting, and provider failure paths.
- [ ] Measure multi-worker or multi-process topology with the actual container/seccomp policy; document worker count, GIL/event-loop boundary, storage, and rejected traffic.
- [d] The Phase 2 SSE queue is explicitly byte/event bounded and instrumented; continue bounding and testing every other cache and queue, including aggregate concurrency, eviction, age, saturation, and memory pressure.
- [ ] Add memory-pressure, disk-exhaustion, WAL rotation, and recovery tests that preserve evidence correlation.
- [ ] Publish an SLO only after an owner, target, error budget, telemetry, and rollback path exist.

## Market and assurance work

- [x] Define one initial ICP: private-deployment B2B SaaS, fintech, and regulated-enterprise platform/security teams operating multiple model providers.
- [x] Define the sales sequence: local evaluation, evidence replay, controlled pilot, security review, procurement package, production rollout.
- [x] Define non-binding package hypotheses and support boundaries.
- [ ] Validate pricing with at least three buyer interviews, cost-to-serve modeling, comparable quotes, and a paid pilot.
- [ ] Build a support operation before promising contractual response targets, 24/7 coverage, or mission-critical SLA.
- [ ] Create a customer data/retention/deletion statement and have counsel review AGPL/commercial terms before external sale.
- [ ] Obtain independent security, cryptographic, and deployment assurance appropriate to the target buyer segment.

## Release gate

The historical v3.1.0 distribution passed its declared publication gate, but it does not contain the later Phase 2/3 modules in the v4 source baseline. The `v4.0.2` source, signed tag, GitHub Release asset envelope, and GHCR OCI objects passed their recorded release gates.

**The registry blockage recorded here previously is closed, and this entry no longer claims otherwise.** At `4.0.2` both SDK publish jobs were skipped, so neither registry received it; that was true of `4.0.2` and is not true now. `4.1.2` published to PyPI (`aegis-latent-core` and `aegis-latent-sdk`) and to npm (`aegis-latent-sdk`), read back on 2026-09-04 — see [Release Status §1.1](RELEASE_STATUS.md). What replaces it is narrower: the publication workflows are dispatch-only and are not verified by readback as part of the release, so a partial publication reports success and is discovered afterwards by reading the registry.

Nothing is published for the current `5.0.0` source baseline. Deployment acceptance remains open until the affected source and tests, target-environment controls, architecture smoke/rollback evidence, SBOM/dependency review, and qualified residual-risk review are complete.

## Audit backlog — v5.0.1-prep (2026-09-21)

A deep audit of this baseline (forensic scan of the code surface, claims and quantitative cross-reference across every `.md`/`.txt`, regulator/article verification, governance coverage; full record with per-finding verification in [`AUDIT_REPORT_v5.0.1_PREP.md`](../AUDIT_REPORT_v5.0.1_PREP.md)) produced **94 findings**. Of those, 26 require engineering or documentation work beyond a wording fix and are ticketed here; each ticket is also a registry row (`REG-D05`–`REG-D30`, state `OPEN`, [Registry](REGISTRY.md) §4.6) and, where it is a boundary rather than a bug, an unsupported-claims entry (`UC-050`–`UC-058`, [Unsupported Claims](institutional/UNSUPPORTED_CLAIMS.md)). The audit did **not** fix these items — nothing here is reported as done.

- [x] **AUD-01 [P1] — Audit evidence endpoint returns HTTP 500 for every node (JCS projection)**
  - **Affected files:** aegis/proxy/audit_api.py (handler at :233-234; canonicalizer in aegis/core/forensic_bundle.py)
  - **Root cause:** AuditNode.to_dict() always carries float fields (timestamp, entropy, sampling_params.elapsed_seconds); canonical_jcs_bytes rejects floats by design, the ForensicBundleError is uncaught, and no exception handler is registered, so the documented byte-exact RFC 8785 projection 500s on 100% of nodes. Reproduced first-hand (parent probe: GET /nodes/{hash} -> 200; /evidence -> 500).
  - **Proposed solution:** Either route the JCS projection through a float-safe form (project floats as strings per the register's own JCS scope) or catch ForensicBundleError and return a documented 4xx/501 with an explanatory body; add a regression test that exercises the endpoint against a real committed node (every existing test mocks the ledger).
  - **Estimated effort:** S (0.5-1 day)
  - **Closed 2026-09-21 (`REG-D12`):** `chain_snapshot()` added and used at every read site (one snapshot per handler, so a count and a tail hash can no longer describe different chains in the same response); `wal_backup.py` and `iso27037_evidence.py` moved to the accessor. The endpoint-level probe shows 45 non-200 of 150 under the old path and 0 of 150 after, and the new control test reproduces the deque interleaving on this host. Evidence: `evidence/registry/reg-d12_fixed.txt`.
  - **Closed 2026-09-21:** the JCS companion serves real nodes through the documented evidence projection (`project_jcs_evidence`), and out-of-domain records return 422 instead of an unhandled 500; two real-ledger regression tests added. See `REG-D05`.
- [x] **AUD-02 [P1] — Signature verification is dispatched on a self-declared, hash-unbound field**
  - **Affected files:** aegis/core/crypto_audit.py (_verify dispatch :1442; node_hash :562-574; _build_signed_payload; node_signature_assurance :432)
  - **Root cause:** signature_scheme is not an input to node_hash nor to the signed payload; verify_integrity() verifies HMAC only when the label says hmac-sha256, and node_signature_assurance maps the same unauthenticated label to an assurance tier. Reproduced first-hand: rewriting only the label on all WAL lines yields verify_integrity=(True,None) with signature_assurance=ASYMMETRIC_HARDWARE_ATTESTED and every per-node status 'unverified'.
  - **Proposed solution:** Bind the scheme into the chain: add signature_scheme to the hashed material and the signed payload under a chain-version bump, verify each declared scheme against an allowlist with a real verifier (or mark 'unverified' explicitly in verify_integrity's result), and add a tamper test (edit label -> integrity fails or status is 'unverified' and assurance is floored).
  - **Estimated effort:** M (2-4 days, touches node_hash compatibility + migration note)
  - **Closed 2026-09-21 (`REG-D06`):** fixed with a narrower mechanism than the ticket's literal wording — the label is fenced by a shape-only allowlist (`scheme_material_inconsistency`), `signature_status` reports `invalid` for fenced material, `verify_integrity()` dispatches every node through that verifier, and `node_signature_assurance` floors inconsistent nodes to `UNSIGNED`; `node_hash` is untouched, so no chain break. Tests: `tests/test_crypto_audit_scheme_binding.py` (7, including the audit's reproduced WAL-relabel attack); evidence `evidence/registry/reg-d06_fixed.txt`. The payload-binding half moved to `AUD-27`.
- [x] **AUD-03 [P1] — Terminal evidence is not committed on the teardown styles the ASGI stack actually delivers**
  - **Affected files:** aegis/proxy/streaming.py (_iterate CancelledError handler :357-365; _cancel_producer :567-570; aclose)
  - **Root cause:** Under anyio-delivered cancellation (the real Starlette/uvicorn path) the first await inside the CancelledError handler re-raises, so the shielded _finalize never runs; aclose()/GeneratorExit cannot await at all. Reproduced first-hand: real-app send-failure run -> wal_terminal_nodes=0; controls T1_aclose=0, T2_cancel=1, T3_complete=1. Response headers advertise pending-terminal with no landing proof.
  - **Proposed solution:** Commit terminal evidence on every teardown style: wrap the finalize in a shielded, cancellation-proof task created before the generator is abandoned (e.g. spawn the terminal commit as a task the response object owns, committed in the server-side task group), and add teardown tests for all three styles (cancel, aclose/GeneratorExit, send failure) counting terminal nodes.
  - **Estimated effort:** M (1-3 days + tests)
  - **Closed 2026-09-21 (`REG-D07`):** `_freeze_summary()` is now synchronous (the once-only guard survives a cancelled scope), the `CancelledError` and `aclose()` teardown paths hand the commit off without awaiting, the app owns a `TerminalCommitHandoff` started in its lifespan and drained before the ledger closes, and an inline commit interrupted by teardown is re-dispatched instead of dropped. Probes re-run on the fixed tree: T1_aclose 0→1, T2_cancel 1, T3_complete 1; real-app send-failure `wal_terminal_nodes` 0→1. Eight tests in `tests/test_streaming_teardown.py`; evidence `evidence/registry/reg-d07_fixed.txt`. Residuals (in-process handoff, bounded drop, at-least-once duplicates) are `AUD-28`.
- [x] **AUD-04 [P1] — RustWal: two handles on one path silently destroy committed frames (unexercised SAFETY invariant)**
  - **Affected files:** aegis_rust_v2/src/wal.rs (SAFETY comment :149-150; WalInner :78-83; open :101-102)
  - **Root cause:** Each handle owns its own Mutex and AtomicU64 write_pos; nothing enforces single-writer exclusivity, so a second opener rescans, computes the same offsets, and overwrites flushed frames through its own MAP_SHARED mapping. Reproduced first-hand: alternating appends -> b's frames overwrote a's; a.read_all returned only b's records; both handles reported write_pos 92.
  - **Proposed solution:** Add a single-writer guard (flock or O_EXCL lock file) in RustWal::open and fail closed with a clear PyErr; document concurrent multi-handle use as unsupported (UC-051) until then; add a test that opening a second handle either fails or is safe.
  - **Estimated effort:** S-M (1-2 days + test)
  - **Closed 2026-09-21 (`REG-D08`):** `RustWal::open` takes an exclusive `File::try_lock` on the segment immediately after opening it and before any resize or mapping; the lock lives on the handle (`WalInner::_writer_lock`) and is released on drop/process exit; a losing handle fails closed with a `RuntimeError` naming the single-writer invariant, and a genuine lock error is reported as `IOError`. Before/after on real artifacts: pre-fix the second handle destroyed the first's frame (`a.read_all` lost `a1`); post-fix the open is refused and the holder's frames are intact. Cargo 9/9 wal tests, `cargo test --locked` 69 passed, clippy `-D warnings` clean; PyO3 tests 3/3 with a rebuilt extension; evidence `evidence/registry/reg-d08_fixed.txt`.
- [x] **AUD-05 [P1] — Release-profile aborts instead of exceptions for caller-controlled sizes and resource failures**
  - **Affected files:** aegis_rust_v2/src/audit.rs :44; session.rs :52; rate_limit.rs :144 and :69; forwarder.rs :55; pqc_trait.rs :252; Cargo.toml panic=abort
  - **Root cause:** Caller-supplied usize capacities reach crossbeam ArrayQueue and DashMap constructors unvalidated (capacity 0 panics; 2**40 aborts on allocation failure - reproduced first-hand), an unchecked multiply can panic on overflow, a fallible Tokio build uses .expect(), and the pure-Rust PQ backend expects the OS RNG. With panic="abort" in the release profile none of these become Python exceptions - the gateway process dies.
  - **Proposed solution:** Validate and clamp all caller-supplied sizes (reject 0 and > documented ceilings with ValueError), replace overflow-prone arithmetic with saturating ops or checked_mul+error, map runtime/RNG failures to PyErr, and add a regression suite that exercises each invalid input path.
  - **Estimated effort:** M (2-3 days + tests)
  - **Closed 2026-09-21 (`REG-D09`):** sizes validated (0 and ceiling rejections raise `ValueError`), saturating arithmetic in `rate_limit.rs`, fallible runtime init with a worker-thread pre-flight that runs before tokio's blocking pool can panic, and a fallible `keypair()`. Evidence: `evidence/registry/reg-d09_fixed.txt`. Residual published as `UC-050`: the ceilings themselves, a thread limit exhausted between the pre-flight and tokio's own spawn (panic inside tokio, unreachable from our code), and PQClean's `.expect("RNG Failed")`, which lives in the dependency.
- [x] **AUD-06 [P1] — Retracted backpressure figures (10,000 records / p99 1,189.89 ms) still presented as measured evidence in 12 documents**
  - **Affected files:** docs/PROSPECTUS.md:58; docs/PRODUCT_BRIEF_US.md:43; docs/BENCHMARKS.md:37; docs/benchmarks/BENCHMARK_RESULTS.md:15; docs/benchmarks/BENCHMARK_METHOD.md; docs/benchmarks/README.md; docs/FAQ_TECHNICAL.md:118; docs/FAQ_PROCUREMENT.md:64; docs/operations/BACKPRESSURE_RUNBOOK.md:53; docs/performance/SCALING_GUIDE.md:38; docs/ROADMAP.md:79; DEPLOYMENT_GUIDE.md:138 (plus CHANGELOG history)
  - **Root cause:** UC-018 declares the 10,000-record / p99 1,189.89 ms pair false and retracted (the committed artifact contains 2,500 records at p99 836.3514210795984 ms), but the sweep stopped at the canonical matrices; buyer-facing docs still carry the pair as the retained v3.1.0 measurement. Parent verified 13 files carry the pair (14 with CHANGELOG history); UC-017 also uses 'retained' for a different run, which is the naming mechanism that keeps the error propagating.
  - **Proposed solution:** Run a scripted sweep: replace every occurrence with the artifact-backed pair (2,500 / 836.3514210795984 ms) or an explicit retraction note, standardise the word 'retained' to name one run (the 2026-09-16 execution evidence), and add the sweep to the docs gate (a grep-based check that no md file cites the retracted pair outside the retraction rows themselves).
  - **Estimated effort:** S (1 day for the sweep; +0.5 day for a gate check)
  - **Closed 2026-09-21 (`REG-D10`):** swept to the artifact-backed figures in all fourteen sites (the twelve listed plus `docs/BENCHMARKS.md:36` and `docs/PLATFORM_OPERATOR_GUIDE.md:163`, which repeated the same claim), with an explicit retraction note where the historical framing is kept; `retained` now labels only in-tree, artifact-backed runs. The check landed as `scripts/verify_claims.py` check 9 (`retracted-figure-cited`), wired into CI's claims gate; negative control run live. Evidence: `evidence/registry/reg-d10_fixed.txt`.
- [x] **AUD-07 [P1] — BOUNDARIES.md publishes ZK cost numbers that CLM-089 forbids**
  - **Affected files:** docs/BOUNDARIES.md:30 vs docs/CLAIMS_MATRIX.md:115 (CLM-089)
  - **Root cause:** The ZK row states 'measured on one host at setup 2.5 s, prove 1.3 s, verify 0.19 s', while CLM-089 prohibits 'any setup, proving, verification or proof-size number' because the cost harness is #[ignore]d and not a reproducible artifact.
  - **Proposed solution:** Either remove the numbers from BOUNDARIES.md and restate the CLM-089 boundary, or promote the cost harness to a reproducible artifact (a committed, runnable command + output file) and update CLM-089 to name it. The two registers must not contradict.
  - **Estimated effort:** S (2-4 h either way)
  - **Closed 2026-09-21** — `8ccea5f`: the measured setup/prove/verify numbers are removed from `docs/BOUNDARIES.md:30`; the row now states the CLM-089 boundary explicitly; doc gates PASS.
- [x] **AUD-08 [P2] — Audit read endpoints iterate the live ledger deque without a lock/snapshot**
  - **Affected files:** aegis/proxy/audit_api.py :133,:148,:153,:177,:215,:230,:254,:288,:297,:324; writer aegis/proxy/app.py:1382,1845; deque aegis/core/crypto_audit.py:806
  - **Root cause:** Commits append to the deque from asyncio worker threads while handlers iterate it; a landing mutation raises RuntimeError('deque mutated during iteration') -> 500 with no data. Ledger accessors elsewhere snapshot under self._lock, so this is an inconsistency.
  - **Proposed solution:** Take a snapshot (list(ledger.chain) or a locked accessor) at every read site, matching signature_assurance/verify_integrity; add a test that commits concurrently with each endpoint.
  - **Estimated effort:** S (0.5-1 day)
- [x] **AUD-09 [P2] — Enterprise surface buffers request and response bodies without limits**
  - **Affected files:** aegis_server/main.py :894, :976 (middleware :253-262); contrast aegis/proxy/app.py:1323
  - **Root cause:** await request.body() and await resp.aread() buffer full bodies; no RequestBodyLimitMiddleware is installed on the enterprise app, so it is weaker than the gateway it fronts.
  - **Proposed solution:** Install the gateway's body-limit middleware with max_request_body_bytes and add a response-side cap/streaming path; test oversized request and oversized upstream response.
  - **Estimated effort:** S-M (1-2 days)
  - **Closed 2026-09-21 (`REG-D13`):** the gateway's body-limit middleware is installed on the enterprise app (both limits now live in `EnterpriseSettings`, so `AEGIS_MAX_REQUEST_BODY_BYTES` governs both surfaces), the proxied upstream response is streamed through `client.stream(...)` and counted rather than buffered, and the four exception-echo sites return fixed details. The middleware's chunked-body path was found broken during this work — the 413 arrived wrapped in an anyio exception group and surfaced as an unhandled server error, on both surfaces — and is fixed here. Evidence: `evidence/registry/reg-d13_fixed.txt`.
- [x] **AUD-10 [P2] — 21 CFR Part 11 signer annotation fields are not cryptographically bound**
  - **Affected files:** aegis/core/crypto_audit.py (node_hash fields :562-574; _build_signed_payload; export_part11_signatures :1520-1545)
  - **Root cause:** signer_name/signature_meaning/status are absent from node_hash, the signed payload and the MMR leaf, yet the export docstring calls node_hash a 'tamper-evident binding' for the annotation; a WAL-write attacker can rewrite signer identity and relabel rejected as committed with no verification change.
  - **Proposed solution:** Include the annotation in the hashed material (chain-versioned) or, if that is not wanted, rewrite the export to state plainly which fields are unbound; add a tamper test.
  - **Estimated effort:** M (1-2 days + migration note)
  - **Closed 2026-09-21 (`REG-D14`):** took the first branch — the annotation and the admission status are part of the signed material now, with no chain-format change and no migration: both are appended only when their value is non-default (the `waf_verdict` conditional's style), so a record written before the binding rebuilds the material it was actually signed over. Both tamper directions fail verification for records this build writes, and the fallback that keeps old chains verifiable cannot be reached by editing a fresh record. The export was also rewritten to name `signature` as the binding and `node_hash` as the chain accumulator. What remains is scoped in the narrowed `UC-055`. Evidence: `evidence/registry/reg-d14_fixed.txt`.
- [x] **AUD-11 [P2] — Transparency log: verify does not recompute entry hashes; append is not fsynced**
  - **Affected files:** aegis/core/transparency_log.py :75-79 (append), :129-140 (verify); contrast export_audit_log.py:200-204
  - **Root cause:** verify_ledger_integrity only compares prev_hash linkage against stored entry_hash, so in-place edits of binary_hash/version/timestamp verify clean; publish_binary_hash returns a success hash after a buffered write with no flush/fsync.
  - **Proposed solution:** Recompute entry_hash from fields inside verify_ledger_integrity; flush+fsync (or document the weaker durability contract) on append; test tamper detection on a non-tail entry.
  - **Estimated effort:** S (0.5 day + tests)
  - **Closed 2026-09-21 (`REG-D15`):** both halves fixed and measured against the pre-fix verifier (probe loads the previous source out of git): entry edits, a reordered ledger, a deleted line, and an edit whose author recomputed the entry hash all report `integrity=False` where the old code reported `True`; `verify_binary_presence` no longer confirms a substituted hash; one `os.fsync` runs per publish and a failed fsync propagates with no in-memory entry claimed. The unkeyed-chain limit is published as `UC-061`. Evidence: `evidence/registry/reg-d15_fixed.txt`.
- [ ] **AUD-12 [P2] — Rust forwarder buffers upstream responses with no cap**
  - **Affected files:** aegis_rust_v2/src/forwarder.rs :169-173; lib.rs:72-74
  - **Root cause:** resp.bytes().await collects the whole body, then it is copied again into a Python bytes object; a hostile or misconfigured upstream drives gateway RSS to 2x response size.
  - **Proposed solution:** Stream with a bounded reader and enforce a configurable maximum (mirroring the Python stream bound); return a PyErr on breach.
  - **Estimated effort:** S-M (1-2 days + tests)
- [ ] **AUD-13 [P2] — RustWaf documents NFKC normalisation that does not exist**
  - **Affected files:** aegis_rust_v2/src/waf.rs :19 (claim) vs :128-131 (only strip_zero_width)
  - **Root cause:** No Unicode normalisation exists in the crate (no unicode-normalization dependency); compatibility variants (fullwidth/mathematical-bold) of a critical pattern are not blocked by a direct RustWaf consumer. The Python gateway layer applies NFKC and is authoritative, so this is a library-level false negative and a false API statement, not a demonstrated gateway bypass.
  - **Proposed solution:** Implement NFKC via unicode-normalization (and non-ASCII case folding via the same path) or correct the module documentation and add the fullwidth control to the crate's tests.
  - **Estimated effort:** S-M (1-2 days)
- [ ] **AUD-14 [P2] — Inert configuration controls presented as enforceable (CAC/PIV, PHI at-rest key, LDAP family)**
  - **Affected files:** aegis/config.py :306 (cac_piv_required), :295 (phi_master_key), :191-199 (ldap_*)
  - **Root cause:** cac_piv_required and phi_master_key are read nowhere (0 references outside the declaration); no ldap_* setting is read and no LDAP authenticator is wired; each field's description promises enforcement or encryption that never happens. Operators sizing HIPAA/DoD deployments on this text are misled.
  - **Proposed solution:** Choose per control: wire it (instantiate CACPIVAuth; construct the payload encryptor; wire LDAPAuthenticator) or reword the description to say the control is not yet wired and delete the knob if it cannot ever work; add a config-surface test that fails when a settings field has no reader (a small grep-based gate).
  - **Estimated effort:** M (wire-up path is larger; reword path is S)
- [x] **AUD-15 [P2] — WAF corpus cited from a non-in-tree artifact, the practice CLM-032 retired**
  - **Affected files:** docs/compliance/COMPLIANCE_MAPPING.md:32; docs/assurance/AUDIT_EVIDENCE_INDEX.md:123
  - **Root cause:** Both still name waf_corpus_report_v1_candidate.json, which is not in the tree; CLM-032's correct in-tree evidence is evidence/execution_2026-08-20/waf_corpus_report.json.
  - **Proposed solution:** Point both rows at the in-tree artifact (or the 2026-09-16 evidence) and add a link check that artifacts named as evidence exist in-tree.
  - **Estimated effort:** S (2 h)
- **Closed 2026-09-21** — `8ccea5f`: both rows now cite `evidence/execution_2026-08-20/waf_corpus_report.json`; doc gates PASS. The 'gate that named evidence exists in-tree' half stays with `AUD-18`/`AUD-19` scope.
- [x] **AUD-16 [P2] — Two compliance technical-input docs carry boundary text that REG-023/UC-045 superseded**
  - **Affected files:** docs/compliance/EU_AI_ACT_TECHNICAL_INPUTS.md:67; docs/compliance/HIPAA_TECHNICAL_INPUTS.md:67 (also :25,:38 for the RFC 3161 depth)
  - **Root cause:** Both still say 'the record holds the scrubbed form' / 'redaction changes the evidence record only' and 'PHI reaches the provider unscrubbed' unconditionally - text corrected in docs/privacy/PII_REDACTION_BOUNDARIES.md:48 and UC-045 but not propagated.
  - **Proposed solution:** Apply the corrected wording verbatim from PII_REDACTION_BOUNDARIES.md and UC-045 to both files; align the RFC 3161 row with CLM-014's full statement.
  - **Estimated effort:** S (3-4 h)
- **Closed 2026-09-21** — `8ccea5f`: corrected wording applied at :25, :38 and :67 of both files (`UC-045`, `CLM-014`); doc gates PASS.
- [x] **AUD-17 [P2] — Capability table uses blocked wording: 'chain-of-custody' and 'trusted timestamp'**
  - **Affected files:** docs/architecture/DEEP_DIVE.md :288, :289
  - **Root cause:** The ISO 27037 row claims 'chain-of-custody' (the project's own boundary: no custody record is created - UC-024) and the RFC 3161 row says 'trusted timestamp' (blocked by CLM-014/CLM-096; the gaps - no revocation checking, no RFC 5280 name-constraint evaluation - are not named).
  - **Proposed solution:** Replace with the register's own words: evidence-package seal, offline-verifiable, and 'TSA token bound to bundle imprint - not a trusted timestamp; no revocation checking'.
  - **Estimated effort:** S (2 h)
- **Closed 2026-09-21** — `8ccea5f`: DEEP_DIVE :288/:289 rewritten; the follow-up sweep corrected the same wording class in `worm_ledger.py`, `crypto_audit.py` (2 sites) and the `app.py` OpenAPI description; doc gates PASS.
- [ ] **AUD-18 [P2] — Gate-scope drift: the Makefile formatter gate is broader than CI's and fails at HEAD**
  - **Affected files:** Makefile:34 (`ruff format --check .`) vs .github/workflows/ci.yml:144 (fixed path list); unformatted: scripts/verify_docs.py, scripts/verify_release_readback.py; newly covered: 9 markdown code fences
  - **Root cause:** Modern ruff (0.16.8) formats Python fences inside Markdown and includes .md under `.`, so `make lint` fails on 11 files while CI (narrower path list, same unpinned ruff) passes. The two Python files are outside every gate. Reproduced first-hand: exit 1, '11 files would be reformatted, 806 files already formatted'.
  - **Proposed solution:** Decide the canonical scope once: either align the Makefile with CI's path list (and add scripts/ to both), or extend CI to the whole tree and format/exclude markdown fences; then fix the two scripts and add the chosen form to CI.
  - **Estimated effort:** S (0.5-1 day incl. policy decision)
- [ ] **AUD-19 [P2] — Documentation currency & provenance sweep (stale baselines and counts)**
  - **Affected files:** llms.txt:6 (baseline 4.1.2); .aegis_ai_context/01_CANONICAL_SYMBOL_AND_TYPE_INDEX.tsv:5 (v4.1.2); docs/REPOSITORY_MAP.md:3 (Last verified 2026-08-27); docs/INDEX.md (35 of 109 docs unlinked); INTEGRITY_SEAL.md:18/:24/:26 (6920/550 files/96 claims); README.md:327,:329 (6,936 tests / mypy 206 files)
  - **Root cause:** These artifacts were written for earlier baselines and never refreshed; two in-tree counts disagree with each other and with today's measurements (ruff now scans 817 files; claims register is 102; parent's suite run at HEAD: 6,868 passed / 120 skipped).
  - **Proposed solution:** Refresh each with the current measured values (or mark historical with an explicit baseline tag); regenerate the AI-context tsv; add the 35 unlinked docs to INDEX.md (or narrow its scope statement); and add a check that llms.txt/tsv baselines match AGENTS.md's baseline line.
  - **Estimated effort:** S-M (1 day; the baseline-consistency check is the force multiplier)
- [ ] **AUD-20 [P2] — MiFID II / MAR: modules unwired, citations partly wrong, registers silent**
  - **Affected files:** aegis/core/market_abuse_detector.py :27 (mis-cites MiFID II Art. 12(1)(a)(ii); the provision is MAR Art. 12(1)(a)(ii)), :4-8 ('feeds directly into the proxy WAF verdict pipeline' - no proxy import exists); aegis/core/mifid_record_keeper.py :6-7,:21-23 ('satisfying...' / '7 years for SMCR-scope firms'); docs/CLAIMS_MATRIX.md, docs/ROADMAP.md, docs/institutional/UNSUPPORTED_CLAIMS.md (no MiFID/MAR entries)
  - **Root cause:** Two compliance modules are allowlist-classified (built, not wired) and their docstrings overclaim wiring/legal satisfaction; MiFID II has a buyer doc and a dossier section but no claims-matrix row, no UC entry and no roadmap ticket; the SMCR 7-year attribution does not match the FCA-based retention we could verify (6 years) and the MiFID 7-year figure is the competent-authority extension, not a default.
  - **Proposed solution:** Correct the citations and docstrings (MAR not MiFID for Art. 12; 'contributes technical inputs' not 'satisfying'); add CLM rows for both modules with explicit 'not wired' boundaries; add UC-056; open the roadmap items (wire or retire the modules). Counsel review for the SMCR reference.
  - **Estimated effort:** S for wording + M for wiring decision
- **Batch note 2026-09-21 (`8ccea5f`):** MAR citation and both module docstrings corrected (MiFID II five-year floor with the competent-authority extension; no 'immutable evidence' claim). Open remainder: `CLAIMS_MATRIX`/register rows for MiFID/MAR, wiring decision.
- [x] **AUD-21 [P2] — Registry rule not met for three terminal rows: boundary missing from UC/BOUNDARIES**
  - **Affected files:** docs/REGISTRY.md:122 (REG-019 compaction/cold tiering), :124 (REG-021 RFC 3161 revocation), :182 (REG-D01 dev-venv advisories); docs/institutional/UNSUPPORTED_CLAIMS.md; docs/BOUNDARIES.md
  - **Root cause:** The registry's own rule says a DOCUMENTED row's boundary must live in UNSUPPORTED_CLAIMS.md or BOUNDARIES.md; greps for 'compaction', 'cold tier', 'OCSP', 'revocation', 'setuptools', 'pip-audit' return zero hits in both registers, so three terminal rows are terminal without their boundary published where the rule says it lives. Same class: the MMR v1 residual (caller-supplied leaf bytes in verify_portable_inclusion, CLM-064) has no UC/BOUNDARIES entry.
  - **Proposed solution:** Add the three boundary entries (and the MMR v1 note) to the register that owns each class - ROADMAP-only for REG-019, BOUNDARIES for REG-021's revocation gap, UC for the dev-venv advisories and MMR v1 - or amend the rule to accept the current homes.
  - **Estimated effort:** S (3-4 h)
  - **Closed 2026-09-21** — `8ccea5f` + this commit: `REG-021` boundary row in `docs/BOUNDARIES.md:32`, `UC-059` (dev-venv advisories) and `UC-060` (MMR v1 residual) in the register, and the `REG-019` storage-growth item above; doc gates PASS.
- [ ] **AUD-22 [P2] — Compliance-wording sweep: unqualified SOC2/HIPAA/GDPR/admissibility language in sample and tooling surfaces**
  - **Affected files:** examples/README.md:35; tools/visualizer/README.md:25; Samples/README.md:26 (and :6); SECURITY_AUDIT_EXECUTION_LOG.md:130; docs/enterprise/VENDOR_SECURITY_QUESTIONNAIRE.md:148; SECURITY_AUDIT_REPORT.md:72; README.md:18
  - **Root cause:** These surfaces name SOC 2/HIPAA/GDPR/admissibility without the repository's required qualifier ('contributes technical inputs that an assessor may evaluate'; 'admissibility is a judicial determination'), while neighbouring files apply it correctly. No file asserts certification as fact, so this is drift, not fabrication.
  - **Proposed solution:** Apply the style-guide wording to each; add the deltas to the wording gate if one exists; give VENDOR_SECURITY_QUESTIONNAIRE's GDPR answer the same explicit 'No' shape as its neighbours.
  - **Estimated effort:** S (3-4 h)
- **Batch note 2026-09-21 (`8ccea5f`):** the overlapping HIPAA / EU-AI-Act / DEEP_DIVE wording is corrected; the sample and tooling surfaces listed above remain open.
- [ ] **AUD-23 [P3] — Residual robustness batch: durability, ingest validation, delimiters, bounds**
  - **Affected files:** aegis/core/wal_backup.py:85,:254-262; aegis/core/crypto_audit.py:978,:2373; aegis/core/hardware_token.py:403; aegis/proxy/app.py:1997; aegis/proxy/mtls.py:126; aegis/core/worm_ledger.py:549 (latent; module allowlisted)
  - **Root cause:** (1) restore() copies over the live WAL without temp+replace while documenting 'atomically'; (2) NaN/Infinity admitted into sealed bytes via sampling_params (non-RFC-8259 tokens; cross-language verifiers cannot parse); (3) hardware_token canonical fields are NUL-joined without validation, so a token can be re-split and (with the unkeyed hash recomputed) validate under a different subject/tenant; (4) non-streaming path buffers provider responses and re-serialises a second copy; (5) mtls 403 echoes internal exception text; (6) worm_ledger seal helpers read whole files (latent, no caller).
  - **Proposed solution:** Batch fix each with its own test: temp-file+replace+fsync restore; reject non-finite floats at ingest (or serialise them as strings); delimiter-free/length-prefixed token canonicalisation (and reject NUL in identifiers); bound the non-streaming body; fixed-string 403.
  - **Estimated effort:** M (2-3 days all-in)
- **Batch note 2026-09-21 (`8ccea5f`):** mtls 403 exception-echo fixed, plus the `export_audit_log` skip-path docstring. Open remainder: WAL-restore atomicity, NaN ingest, NUL delimiter, remaining bounds.
- [ ] **AUD-24 [P3] — Rust P3 batch: doc claims, guards, and latent edges**
  - **Affected files:** aegis_rust_v2/src/wal.rs :47,:87,:102; crdt_mmr.rs :336 (encode-side ceiling); mmr.rs :88,:213; zk_bindings.rs :144; zk_mmr.rs :663 (unbounded bincode input); pqc.rs :47,:113; rate_limit.rs :69; forwarder.rs :19,:83; audit.rs :68; hasher.rs :57; docs/benchmarks/BENCHMARK_METHOD.md:175
  - **Root cause:** Assorted: unnecessary unsafe Send/Sync impls remove compiler checking; documented capacity ceiling never enforced (1 TiB accepted); a doc comment claims all slicing goes through model-checked helpers while three sites do not; a replica can encode a clock above its own decode ceiling; two expects in non-test paths; unbounded deserialize; GIL held across ML-DSA sign/verify; unused subtle dependency; doc-comment performance numbers with no measurement record; the benchmark method doc cites a cargo bench target that does not exist; hasher doc rationale is wrong (separator suffix vs length extension).
  - **Proposed solution:** One small PR per item in the batch: add lint for unsafe_code; enforce the capacity ceiling; fix or scope the doc comments; add the encode-side ceiling check; convert expects to PyErr; cap bincode input; document the GIL behaviour; drop or use subtle; remove unmeasured numbers; correct the bench command; fix the rationale.
  - **Estimated effort:** M (2-3 days across the batch)
- **Batch note 2026-09-21 (`8ccea5f`):** `hasher.rs` separator comment corrected. Open remainder: Send/Sync claims, WAL cap, GIL, bincode bounds.
- [ ] **AUD-25 [P2] — Module inventory & ownership do not exist; navigation covers 43% of files**
  - **Affected files:** docs/REPOSITORY_MAP.md; scripts/verify_import_reachability.py:72,:74; llms.txt; .github/CODEOWNERS; docs/ROADMAP.md (19 unmapped open items)
  - **Root cause:** No artifact is a per-module inventory (purpose/status/tests/owner); the reachability gate covers only .py under three roots and its 77-entry allowlist is referenced by no navigation doc; 171 of 298 files under the six roots are named in no navigation source (68 appear nowhere at all, including all 15 Rust sources); CODEOWNERS declares a single owner for everything, so no per-module maintainer field can exist; 19 roadmap open items name no owner or unblock path.
  - **Proposed solution:** Generate a module inventory (path, purpose, status, tests, owner) from the reachability gate + allowlist + pyproject omit list, extend the gate to scripts/, tools/ and the Rust crate, reference it from the navigation docs, and name owners for the 19 unmapped roadmap items.
  - **Estimated effort:** L (3-5 days; the generator can be incremental)
- [ ] **AUD-26 [P3] — Evidence retention & claim-generating surfaces**
  - **Affected files:** PR_FINAL_ENTERPRISE_HARDENING.md:26 (producer exists, report JSON absent); benchmarks/bench_crypto_audit.py:203 ('[PROVEN]' label on a host-specific number); benchmarks/bench_forwarding.py:2 ('zero forensic latency' framing); UC-015:35, UC-016:36 (no producers)
  - **Root cause:** Harness output is labelled as absolute when host-specific; one comparison's report JSON was never committed; two UC rows have no producer at all. The docs' own rules (BENCHMARK_METHOD: 'No RPS figure is claimed for any environment') are contradicted by the harness banners.
  - **Proposed solution:** Re-label harness output as host-specific observations; commit a retained report or mark the figures historical; remove/replace '[PROVEN]' and 'zero latency' phrasings; decide the fate of UC-015/UC-016 (produce or keep retracted).
  - **Estimated effort:** S-M (1-2 days)

- [ ] **AUD-27 [P3] — Bind the declared signature scheme into the signed payload (select-then-sign)**
  - **Affected files:** aegis/core/crypto_audit.py (_build_signed_payload :629; _sign selection order; the three node-creation paths)
  - **Root cause:** `REG-D06` authenticated the scheme label by shape and dispatch, but the label is still not an input to the signed payload: the signing path learns its scheme as the *result* of `_sign` (priority order including mid-flight HSM fallback), so the payload cannot be built before the scheme is known. A well-shaped fabricated claim for a tier with no in-build verifier (`pkcs11-*`) therefore still reads `unverified` and passes the sweep (published boundary: `UC-054`).
  - **Proposed solution:** Split `_sign` into scheme selection + signing, build the payload with the selected scheme appended (same additive/conditional pattern as `waf_verdict`), gate the change on a trail-version bump so v1/v2 chains keep verifying, and add a tamper test asserting a label rewrite breaks the signature for every verifiable scheme. No `node_hash` change is required.
  - **Estimated effort:** M (2-3 days incl. migration note)

- [ ] **AUD-28 [P3] — Durable outbox for terminal evidence torn down by cancellation**
  - **Affected files:** aegis/proxy/streaming.py (`TerminalCommitHandoff`), aegis/proxy/app.py (lifespan start/drain)
  - **Root cause:** `REG-D07` lands the terminal node through an in-process handoff. A crash or SIGKILL between teardown and the drained commit loses the frozen summary, and the bounded queue (64) drops-and-counts instead of blocking, so heavy teardown bursts can still lose evidence.
  - **Proposed solution:** Spool the frozen summary (a small append-only spool file next to the WAL) before the handoff acknowledges, and commit pending spool entries on the next startup before serving traffic; keep the in-memory path as the fast case and expose spool depth as a metric.
  - **Estimated effort:** M (2-3 days incl. startup recovery test)

- [ ] **AUD-29 [P3] — Gate scripts sit outside every type-check scope; `mypy --strict` flags one at HEAD**
  - **Affected files:** scripts/verify_claims.py:176 (`buf` in `_split_row`); .github/workflows/ci.yml:167-206 (mypy runs a fixed file list plus `mypy --strict aegis`; `scripts/` and `tools/` are absent); mypy-ci.ini
  - **Root cause:** The repository's doc/claim gates are Python programs, but no type-check job covers them, so `mypy --strict scripts/verify_claims.py` fails at HEAD on an un-annotated empty list (`cells, buf, in_code = [], [], False`) and nothing in CI can notice. Found while adding the retracted-figure check (`REG-D10`); the finding is the scope gap, not the annotation — fixing the one annotation would leave the class invisible.
  - **Proposed solution:** Decide the canonical type-check scope once: add `scripts/` and `tools/` to a mypy job (start with `--strict` on the two directories that already pass, and stage the remainder), annotate `_split_row`'s locals, and add the directory list to the same gate that `AUD-18` reconciles for the formatter.
  - **Estimated effort:** S (2-3 h; the annotation is one line, the scope decision is the work)

- [ ] **AUD-30 [P3] — Doc gate false positive: a decimal's last digit reads as a `v4` token in the publication rule**
  - **Affected files:** tools/docs/verify_documentation.py:126-138 (`v4 external publication or release` rule); reproduced on docs/FAQ_TECHNICAL.md:118
  - **Root cause:** The rule's trigger is `\bv?4(?:\.0(?:\.0)?)?\b` within 100 characters of `published|released`. `\b4\b` matches the final digit of an ordinary measurement — "32.4 s", "12.4 ms" — so any sentence combining a decimal that ends in 4 with the word "published" is an ERROR in strict mode even when nothing about a release is claimed. Found while sweeping the retracted backpressure pair (`REG-D10`): the corrected row was rejected for "32.4 s, ... (as previously published)".
  - **Proposed solution:** Narrow the trigger to version-shaped tokens (`v4(?:\.[0-9]+)*`, `4\.0(?:\.0)?`, `version 4`) and keep a test for the intended catch (`tests/test_documentation_verifier.py:56` already asserts "Aegis v4.0.0 has been published and released." must fail). Do not relax the prohibition itself.
  - **Estimated effort:** S (1-2 h incl. the test)

## Related documents

- [`README.md`](../README.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
- [`docs/BENCHMARKS.md`](BENCHMARKS.md)
- [`docs/SECURITY_ASSURANCE_ROADMAP.md`](SECURITY_ASSURANCE_ROADMAP.md)
- [`docs/COMMERCIAL_STRATEGY_US.md`](COMMERCIAL_STRATEGY_US.md)
- [`DEPLOYMENT_GUIDE.md`](../DEPLOYMENT_GUIDE.md)
