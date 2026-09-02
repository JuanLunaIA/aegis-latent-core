# Security Controls

**Audience:** security reviewers, platform engineers, procurement.
**Scope:** every security control implemented in the checked-out source, with its evidence, its boundary, and who is responsible for configuring it.
**Boundary:** a control being implemented is not a control being effective in your environment. Every row marked configuration-dependent requires target acceptance. See [Boundaries](../BOUNDARIES.md) and [Claims Matrix](../CLAIMS_MATRIX.md).

**Last reviewed:** 2026-09-02

---

## How to read this

| Column | Meaning |
| --- | --- |
| **State** | `Implemented` — in source with tests. `Configuration-dependent` — behaviour depends on deployment. `Roadmap` — not built. |
| **Evidence** | Where to look. |
| **Boundary** | What the control does not do. This column is the point of the document. |
| **Owner** | Who must act for the control to be effective: the project, or you. |

A control with an empty boundary column would be a documentation defect. Every control has one.

---

## 1. Authentication and authorization

| Control | State | Evidence | Boundary | Owner |
| --- | --- | --- | --- | --- |
| API-key authentication with per-key principal mapping | Implemented | `aegis/auth/apikey.py`; `aegis/proxy/dependencies.py`; `tests/test_apikey_new.py`, `tests/test_api_key_scopes.py` | Keys are bearer credentials. Compromise of a key is compromise of its principal. The gateway does not rotate, expire, or distribute keys. | You |
| OIDC authentication with strict claim validation | Configuration-dependent | `aegis/auth/oidc.py`; `tests/auth/` | Depends entirely on your IdP's issuer, audience, key rotation and revocation policy. The gateway validates the token it is given; it does not assess your IdP. | You |
| mTLS client-certificate pinning | Configuration-dependent | `aegis/auth/mtls.py`; `MTLSVerifier` | Explicit leaf pinning plus verified transport provenance. This is not a general PKI: no chain building against a corporate CA, no CRL or OCSP revocation checking. | You |
| Immutable principal derivation | Implemented | `aegis/auth/principal.py`; `Principal` | The principal is derived from the authenticated credential, never from a client-supplied header. A caller cannot select their own tenant. | Project |
| Scope enforcement on audit endpoints (`audit:read`, `audit:export`) | Implemented | `aegis/proxy/audit_api.py`; `tests/test_audit_api_new.py` | Scopes gate the endpoint. They do not filter what a permitted principal may see beyond tenant visibility. | Project |
| Identity pseudonymisation for quotas | Implemented | `aegis/config.py` (`api_key_principal_digest`, HMAC with `auth_identity_hmac_key`) | Domain-separated keyed digest. Requires a key of at least 32 bytes in strict mode. Pseudonyms are stable, so they are linkable across records by design. | Both |

## 2. Tenant isolation

| Control | State | Evidence | Boundary | Owner |
| --- | --- | --- | --- | --- |
| Tenant binding from authenticated principal | Implemented | `aegis/proxy/app.py`; `tests/test_integration_proxy.py` asserts an attacker-supplied `x-aegis-tenant-id` is ignored | Isolation is logical, within one process and one WAL. It is not a multi-tenant security boundary equivalent to separate deployments. | Project |
| Tenant-scoped visibility on audit reads | Implemented | `aegis/proxy/audit_api.py` (`_visible`) | Filters retained nodes by tenant. It does not encrypt other tenants' records at rest, so an operator with filesystem access sees everything. | Project |
| Per-tenant rate limiting | Configuration-dependent | `aegis/proxy/rate_limiter.py` | Distributed limiting requires Redis. Without it, limits are per-process and a multi-replica deployment enforces N times the configured limit. | You |

## 3. Admission control and request bounds

| Control | State | Evidence | Boundary | Owner |
| --- | --- | --- | --- | --- |
| Maximum request body size | Implemented | `AEGIS_MAX_REQUEST_BODY_BYTES`; `aegis/config.py` | Bounds one request. It does not bound aggregate concurrent memory; that needs deployment-level concurrency limits. | Both |
| Bounded analysis queue with rejection | Implemented | `AEGIS_ANALYSIS_QUEUE_SIZE`; `aegis_analysis_queue_rejections_total` | Rejects rather than growing. Rejection means enrichment is skipped, not that the governed call failed. | Both |
| WAF pattern and heuristic detection | Implemented | `aegis/proxy/waf.py`; `tools/security/run_waf_corpus.py`; `tests/data/waf_corpus_v1.json` | Bounded heuristic detection over a pinned corpus. It does not prevent prompt injection and does not generalise to unseen attack classes. See [WAF Testing](WAF_TESTING.md). | Project |
| WAF session tracking (cumulative and crescendo) | Implemented | `aegis/core/waf_session.py`; bounded to 4,096 sessions | Bounded LRU. Under session pressure, older sessions are evicted and their accumulated signal is lost. | Project |
| Application-layer egress guard | Implemented | `aegis/proxy/egress_guard.py` | Rejects malformed or unauthorized endpoint forms. It does not replace network namespaces, firewall policy, Kubernetes NetworkPolicy, or cloud egress controls. | Both |
| Circuit breaker on upstream | Implemented | `aegis/core/circuit_breaker.py`; `aegis_circuit_breaker_state` | Protects the gateway from a failing upstream. It does not make the upstream available. | Project |

## 4. Streaming bounds

| Control | State | Evidence | Boundary | Owner |
| --- | --- | --- | --- | --- |
| Per-stream byte-accounted queue | Implemented | `aegis/proxy/streaming.py`; `specs/aegis_stream_buffer.smt2` | Bounds one stream. Aggregate retained memory scales with concurrent admitted streams, so admission control is a deployment responsibility. | Both |
| Terminal commit before terminal marker | Implemented | `tests/test_proxy_streaming.py::test_success_hashes_exact_output_and_commits_before_done` | Evidence for the stream exists only after terminal commit. A client that disconnects early leaves a `pending-terminal` state with no inclusion proof. | Project |
| Exact-byte hashing of emitted output | Implemented | `aegis/proxy/streaming.py` | SHA-256 covers the bytes the gateway emitted, not the bytes the upstream produced or the client rendered. | Project |
| Commit-failure suppresses the terminal marker | Implemented | `tests/test_proxy_streaming.py::test_commit_failure_omits_done` | The client sees an incomplete stream rather than an unevidenced completion. This is deliberate fail-closed behaviour, not a bug. | Project |

## 5. Redaction

| Control | State | Evidence | Boundary | Owner |
| --- | --- | --- | --- | --- |
| PHI de-identification | Implemented | `aegis/core/phi_deidentifier.py`; `AEGIS_PHI_DEIDENTIFY` | Deterministic pattern matching over visited fields. It does not detect free-text disclosure, paraphrase, indirect identifiers, novel formats, or non-English identifiers. | Both |
| PCI cardholder-data scrubbing | Implemented | `aegis/core/pci_detector.py`; `AEGIS_PCI_SCRUB` | Same pattern boundary. Detection of a PAN-shaped string is not a PCI scope determination. | Both |
| Scrubbing applies before evidence commit | Implemented | `aegis/proxy/app.py` payload visitor | Redaction protects the evidence record. It does **not** protect the upstream provider: the request already went to them. | Project |

Full detail and failure modes: [PII Redaction Boundaries](../privacy/PII_REDACTION_BOUNDARIES.md).

## 6. WAL integrity

| Control | State | Evidence | Boundary | Owner |
| --- | --- | --- | --- | --- |
| Hash-linked append-only chain | Implemented | `aegis/core/crypto_audit.py`; `verify_integrity()` | Detects tampering on read. It does not prevent a privileged actor from altering or deleting the file. | Project |
| Commit ordering: lock → node → sign → write → flush → `fsync` | Implemented | `aegis/core/crypto_audit.py` (`_persist_node`) | `fsync` is not power-loss durability. See [Storage Requirements](../operations/STORAGE_REQUIREMENTS.md). | Both |
| Single-writer enforcement via POSIX advisory lock | Implemented | `aegis/core/crypto_audit.py` (`_lock_wal_fd`, `WalWriterConflictError`); `tests/security/test_wal_single_writer.py` | Prevents a second writer; does not serialize two. POSIX-only; `flock` is advisory and per-inode, so it does not constrain a writer reaching the same bytes by another path or over a network filesystem. | Both |
| Corruption detection on replay | Implemented | `aegis/core/crypto_audit.py` (`_load_from_wal`); `tests/test_reliability.py::test_wal_corruption_recovery_partial_chain` | Replay stops at the first malformed line and marks `wal_corrupt`. Subsequent commits remain permitted; health reports degradation but the request path does not block on the fault state. | Project |
| Segment rotation with owner-only permissions | Implemented | `aegis/core/crypto_audit.py` (rotation, `0o600`) | Access restriction, not immutability. | Project |
| S3 Object Lock archival adapter | Configuration-dependent | `aegis/storage/s3_worm.py`; `aegis/storage/segment_manifest.py` | Uploads and verifies checksum, version, lock mode and retention. It does not configure or attest the target bucket, and does not establish a regulatory WORM status. | You |

## 7. Proof and signing

| Control | State | Evidence | Boundary | Owner |
| --- | --- | --- | --- | --- |
| Portable MMR inclusion proofs | Implemented | `aegis/core/mmr.py`; `sdk/shared/mmr-inclusion-v1.json`; `tests/test_mmr_portable.py` | Non-zero-knowledge: the proof discloses the leaf. Establishes inclusion under a root you trust independently, and nothing about confidentiality, identity, time, custody, consensus, non-membership, or external anchoring. | Project |
| HMAC-SHA256 node signing | Implemented | `aegis/core/crypto_audit.py` | Symmetric and classical. Anyone holding the key can produce a valid signature, so this is not third-party non-repudiation. | Both |
| HSM/PKCS#11 signing backend | Configuration-dependent | `aegis/core/hsm.py`; `AEGIS_PKCS11_*` | Fails closed when the library is unavailable in strict mode. The repository does not validate your HSM, its custody, or its FIPS status. | You |
| Strong-signing requirement in strict mode | Implemented | `require_strong_signing` on the ledger | Strict mode refuses the ephemeral-key fallback. In development mode the fallback is permitted and signatures are not meaningful. | Both |
| ML-DSA-65 post-quantum signing | Configuration-dependent | `aegis/core/pqc_signer.py`; Rust extension | Available only when the native extension is present. Constant-time behaviour is not established; see [PQC Constant Time](PQC_CONSTANT_TIME.md). | You |
| Versioned keyring hot reload | Implemented | `aegis_server/crypto/keyring.py`; `tests/test_keyring_rotation.py` | Reloads atomically without restart. Multi-replica propagation, secret-manager custody, and clock behaviour require deployment evidence. | Both |
| RFC 3161 timestamp anchoring | Configuration-dependent | `aegis/anchoring/rfc3161.py` | An obtained response is not a trusted timestamp. TSA selection, certificate lifecycle, and independent time trust require target acceptance. | You |

## 8. Runtime and kernel controls

| Control | State | Evidence | Boundary | Owner |
| --- | --- | --- | --- | --- |
| Seccomp filter | Configuration-dependent | `aegis/core/seccomp_guard.py`; `AEGIS_REQUIRE_SECCOMP` | Strict mode refuses to start without it. Filter effectiveness depends on the host kernel. | You |
| LSM enforcement check | Configuration-dependent | `aegis/core/lsm_guard.py`; `AEGIS_REQUIRE_LSM` | Verifies an LSM is active. It does not author or validate your policy. | You |
| Enforcement-mode posture metric | Implemented | `aegis/proxy/app.py` (`create_app`); `aegis_security_enforcement_mode`; `tests/security/test_enforcement_mode_metric.py` | Reports which mode the process loaded, not that strict invariants passed. Requires the optional `metrics` extra. | Both |

## 9. Supply chain and CI

| Control | State | Evidence | Boundary | Owner |
| --- | --- | --- | --- | --- |
| Hash-pinned Python dependencies | Implemented | `requirements.lock`; `--require-hashes` | Pins what is installed. It does not audit what those packages do. | Project |
| SHA-pinned GitHub Actions | Implemented | `.github/workflows/*.yml`; `scripts/verify_github_action_pins.py` | Prevents tag-movement attacks on actions. It does not review the action's source. | Project |
| Least-privilege `GITHUB_TOKEN` | Implemented | Workflow-level `permissions: contents: read`; `tests/security/test_workflow_permissions.py` | Bounds what a compromised job can reach. It does not prevent compromise. | Project |
| SAST, dependency audit, container and filesystem scanning | Implemented | `.github/workflows/security.yml` (CodeQL, Bandit, pip-audit, Trivy, OSV, cargo-audit) | Finds known patterns and known CVEs. Absence of findings is not absence of vulnerabilities. | Project |
| SBOM generation and build attestation | Implemented | `.github/workflows/ci.yml`, `release.yml` (`actions/attest-build-provenance`) | Attests what the build produced. It does not attest that the source is free of defects. | Project |
| Dashboard client-bundle secret check | Implemented | `dashboard/scripts/check-client-bundle-secrets.mjs` | Scans browser-served output for the server-only key. It checks the build it is given, not every possible build configuration. | Project |
| Signed, dispatch-only release tags | Implemented | `.github/workflows/create_release_tag.yml`; `scripts/verify_release_contract.py` | Binds artifacts to a signed target. GitHub's badge shows `bad_cert` for Sigstore certificates by design; see [Release Status §3](../RELEASE_STATUS.md#3-why-github-shows-the-tag-as-unverified). | Project |

## 10. Deployment controls

| Control | State | Evidence | Boundary | Owner |
| --- | --- | --- | --- | --- |
| Non-root, read-only-root container | Implemented in chart | `deploy/helm/values.yaml` (`podSecurityContext`, `containerSecurityContext`) | Defaults drop all capabilities and disallow privilege escalation. A deployment that overrides them loses the control silently. | Both |
| Per-replica WAL volumes | Implemented in chart | `deploy/helm/templates/statefulset.yaml`; `tests/test_deploy_manifests.py` | Prevents the shared-writer fork. It does not add cross-pod ordering. | Both |
| Default-deny NetworkPolicy | Implemented in chart | `deploy/helm/templates/networkpolicy.yaml` | Inert unless the cluster CNI enforces NetworkPolicy. Ingress and egress peers ship empty and must be supplied. | You |
| Single uvicorn worker pinned by schema | Implemented in chart | `deploy/helm/values.schema.json` | Rejects `workers != "1"` at install time rather than failing at runtime. | Project |

## 11. Observability

| Control | State | Evidence | Boundary | Owner |
| --- | --- | --- | --- | --- |
| Content-free Prometheus metrics | Configuration-dependent | `aegis/core/observability.py` | No payloads or identities in metric labels. Requires the `metrics` extra; without it every metric is a no-op and `/metrics` is not registered. | Both |
| Closed-schema SIEM export | Configuration-dependent | `aegis/telemetry/siem.py`, `aegis/telemetry/events.py` | Excludes content fields and raw identity values. Downstream delivery, retention, access control and response are external. | You |
| OpenTelemetry tracing | Configuration-dependent | `aegis/telemetry/otel.py` | Optional dependency. A documented, tested span model across the evidence lifecycle is [Roadmap](../../ROADMAP.md). | You |

---

## What is not controlled here

These are out of scope by design, not oversights. See [Threat Model](THREAT_MODEL.md) for the full statement.

- Physical access to the host or its storage.
- Hypervisor or host-root compromise.
- Side channels, except where a specific control names one.
- Guaranteed prevention of prompt injection.
- Network-layer denial of service as a complete guarantee.
- The security of your upstream model provider.

---

**Related:** [Threat Model](THREAT_MODEL.md) · [Security Architecture](SECURITY_ARCHITECTURE.md) · [Incident Response](INCIDENT_RESPONSE.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Boundaries](../BOUNDARIES.md) · [Control to Evidence Matrix](../assurance/CONTROL_TO_EVIDENCE_MATRIX.md)
