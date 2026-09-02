# Control to Evidence Matrix

**Audience:** auditors, security reviewers, compliance officers mapping controls to artifacts.
**Scope:** each control area, the implementing source, the verifying test, and the residual gap.
**Boundary:** this maps controls to self-produced evidence. It is not a control assessment, and a populated row is not an assessed control. The **Residual gap** column is the most useful column in the table; a row without one would be a documentation defect.

---

## Reading the table

| Column | Meaning |
| --- | --- |
| **Control** | The capability |
| **Implementation** | Source that provides it |
| **Verification** | Test or command that exercises it |
| **Owner** | Project, or you (the deploying organisation) |
| **Residual gap** | What remains uncovered after the control is in place |

---

## Access control

| Control | Implementation | Verification | Owner | Residual gap |
| --- | --- | --- | --- | --- |
| Credential authentication | `aegis/auth/apikey.py` | `tests/test_apikey_new.py` | Project | Keys are bearer credentials; the gateway does not rotate, expire or distribute them |
| Federated authentication | `aegis/auth/oidc.py` | `tests/auth/` | You | Security depends entirely on your IdP's issuer, audience, key rotation and revocation policy |
| Certificate authentication | `aegis/auth/mtls.py` | mTLS tests | You | Explicit leaf pinning only; no chain building, no CRL or OCSP |
| Authorization by scope | `aegis/proxy/audit_api.py` | `tests/test_api_key_scopes.py` | Project | Scopes gate endpoints; no role hierarchy or delegation model |
| Principal immutability | `aegis/auth/principal.py` | `tests/test_integration_proxy.py` | Project | Establishes which credential was used, not who used it |
| Tenant isolation | `aegis/proxy/audit_api.py` (`_visible`) | Audit API tests | Project | Logical within one process; filesystem access bypasses it entirely |

## Evidence integrity

| Control | Implementation | Verification | Owner | Residual gap |
| --- | --- | --- | --- | --- |
| Hash-linked chain | `aegis/core/crypto_audit.py` | `verify_integrity()`; crypto tests | Project | Detects tampering on read; does not prevent it |
| Commit before emission | `aegis/core/crypto_audit.py`, `aegis/proxy/app.py` | `tests/test_enterprise_durable_evidence.py` | Project | Depends on storage honouring `fsync` |
| Durable write ordering | `_persist_node` | Durable-evidence tests | Both | `fsync` success is not power-loss durability without protected storage |
| Single-writer enforcement | `_lock_wal_fd`, `WalWriterConflictError` | `tests/security/test_wal_single_writer.py` | Both | POSIX-only; `flock` is advisory and per-inode |
| Streaming terminal commit | `aegis/proxy/streaming.py` | `tests/test_proxy_streaming.py` | Project | A client that ignores the terminal marker accepts unevidenced streams |
| Corruption detection | `_load_from_wal` | `tests/test_reliability.py` | Project | Commits remain permitted after `wal_corrupt`; the request path does not check fault state |
| Node signing | `aegis/core/crypto_audit.py` | Crypto tests | Both | HMAC is symmetric: authenticity relative to key custody, not non-repudiation |
| Inclusion proofs | `aegis/core/mmr.py` | `tests/test_mmr_portable.py`; both SDK verifiers | Project | Requires an independently obtained root; discloses the leaf |

## Data protection

| Control | Implementation | Verification | Owner | Residual gap |
| --- | --- | --- | --- | --- |
| PHI redaction | `aegis/core/phi_deidentifier.py` | Module tests | Both | 17 pattern categories over 3 payload fields; no free-text or paraphrase detection; recall unmeasured |
| Cardholder-data scrubbing | `aegis/core/pci_detector.py` | Module tests | Both | Luhn + IIN gate favours precision over recall |
| Redaction before commit | `aegis/proxy/app.py` | Proxy tests | Project | The provider already received the unredacted request |
| Content-free telemetry | `aegis/core/observability.py`, `aegis/telemetry/` | Telemetry privacy tests | Project | Downstream retention and access are yours |
| Encryption at rest | Not implemented | — | You | The gateway does not encrypt the WAL |
| Encryption in transit | TLS/mTLS configuration | — | You | Not enabled by default |

## Admission and availability

| Control | Implementation | Verification | Owner | Residual gap |
| --- | --- | --- | --- | --- |
| Body size bound | `AEGIS_MAX_REQUEST_BODY_BYTES` | Config and proxy tests | Both | Bounds one request, not aggregate concurrency |
| Stream bounds | `aegis/proxy/streaming.py` | `tests/test_proxy_streaming.py`; `specs/aegis_stream_buffer.smt2` | Both | Aggregate memory scales with concurrent streams |
| Rate limiting | `aegis/proxy/rate_limiter.py` | Rate-limit tests | You | Distributed limiting requires Redis; without it, per-process limits multiply by replica count |
| WAF detection | `aegis/proxy/waf.py` | `tools/security/run_waf_corpus.py` | Project | Bounded heuristics over a pinned corpus; does not generalise |
| Bounded analysis queue | `aegis/proxy/app.py` | Queue tests | Both | Rejection means lost enrichment coverage |
| Circuit breaker | `aegis/core/circuit_breaker.py` | `tests/test_circuit_breaker.py` | Project | Protects the gateway, not the upstream |
| Egress guard | `aegis/proxy/egress_guard.py` | Egress tests | Both | Application layer only; does not replace network policy |

## Runtime and deployment

| Control | Implementation | Verification | Owner | Residual gap |
| --- | --- | --- | --- | --- |
| Strict-mode invariants | `aegis/config.py` (`validate_runtime_invariants`) | `tests/test_p0_release_gates.py` | Both | Verifies configuration, not the environment's actual behaviour |
| Posture observability | `aegis_security_enforcement_mode` | `tests/security/test_enforcement_mode_metric.py` | Both | Reports the mode loaded, not that invariants held |
| Seccomp | `aegis/core/seccomp_guard.py` | Guard tests | You | Effectiveness depends on the host kernel |
| LSM | `aegis/core/lsm_guard.py` | Guard tests | You | Verifies an LSM is active; does not validate your policy |
| Container hardening | `deploy/helm/values.yaml` | `tests/test_deploy_manifests.py` | Both | An override silently removes the control |
| Per-replica WAL volumes | `deploy/helm/templates/statefulset.yaml` | `tests/test_deploy_manifests.py` | Both | Removes the fork; adds no cross-pod ordering |
| Network policy | `deploy/helm/templates/networkpolicy.yaml` | `tests/test_deploy_manifests.py` | You | Inert unless your CNI enforces it; peers ship empty |

## Supply chain

| Control | Implementation | Verification | Owner | Residual gap |
| --- | --- | --- | --- | --- |
| Dependency pinning | `requirements.lock` | `--require-hashes` install | Project | Pins what installs; does not audit behaviour |
| Action pinning | Workflow SHAs | `scripts/verify_github_action_pins.py` | Project | Prevents tag movement; does not review action source |
| Least-privilege CI token | Workflow `permissions:` | `tests/security/test_workflow_permissions.py` | Project | Bounds reach; does not prevent compromise |
| SAST and CVE scanning | `.github/workflows/security.yml` | CI | Project | Known patterns and known CVEs only |
| SBOM | `ci.yml`, `release.yml` | Release assets | Project | Inventory, not assessment |
| Build attestation | `actions/attest-build-provenance` | `gh attestation verify` | Project | Attests the build, not the source's correctness |
| Release signing | `create_release_tag.yml`, `publish_oci.yml` | `gitsign verify`, `cosign verify` | Project | GitHub shows `bad_cert` for Sigstore certificates by design |
| Client-bundle secret check | `dashboard/scripts/check-client-bundle-secrets.mjs` | CI dashboard job | Project | Checks the build it is given |

## Operations

| Control | Implementation | Verification | Owner | Residual gap |
| --- | --- | --- | --- | --- |
| Health and readiness | `/health`, `/ready` | Proxy tests | Project | `wal_corrupt` in health does not stop commits |
| Metrics | `aegis/core/observability.py` | `tests/test_observability.py` | Both | Requires the optional `metrics` extra |
| Backup and restore | Documented procedure | — | You | Not validated against a production deployment |
| Key rotation | Documented procedure; `aegis_server/crypto/keyring.py` | `tests/test_keyring_rotation.py` | Both | Multi-replica propagation requires deployment evidence |
| Rollback | Documented procedure | — | You | Crossing the storage topology change is a migration |
| Incident response | Documented procedure | — | You | Evidence preservation depends on operator discipline |

## Controls not provided

Named so a mapping exercise does not leave silent gaps.

| Control | Status |
| --- | --- |
| Prevention of operator tampering | Not provided. Detection only. |
| WAL encryption at rest | Not provided. |
| Subject-level record lookup | Not provided. Records index by tenant and hash. |
| Retention enforcement | Not provided. No scheduled deletion. |
| Cross-replica ordering | Not provided. |
| Clock synchronisation or traceability | Not provided. |
| Chain of custody | Not provided. |
| Organisational controls (policy, personnel, physical) | Out of scope for a software component. |

---

**Related:** [Security Controls](../security/SECURITY_CONTROLS.md) · [Audit Evidence Index](AUDIT_EVIDENCE_INDEX.md) · [Assurance Roadmap](ASSURANCE_ROADMAP.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Threat Model](../security/THREAT_MODEL.md)
