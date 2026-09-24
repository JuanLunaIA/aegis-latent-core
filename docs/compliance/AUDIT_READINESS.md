# Audit Readiness Package

**Audience:** internal audit, external assessors (SOC 2 service auditors, ISO/IEC 27001 certification bodies, HIPAA assessors), compliance officers and procurement reviewers.
**Scope:** how to verify, on a real deployment, each technical control this gateway contributes to SOC 2, the HIPAA Security Rule, ISO/IEC 27001:2022 Annex A, the EU AI Act, and MiFID II/MiFIR record-keeping. It covers the configuration each control depends on, the evidence it produces, and the commands that reproduce that evidence.
**Boundary:** `LEGAL-REVIEW-REQUIRED`. Nothing here is a certification, attestation, compliance determination or legal opinion. Framework conclusions belong to the assessor and the deploying organisation. Claims are governed by the [Claims Matrix](../CLAIMS_MATRIX.md).

---

## 1. What "audit-ready" can and cannot mean for this product

None of these frameworks certifies a software component on its own:

| Framework | What an assessment actually covers | What this product can therefore be |
| --- | --- | --- |
| **SOC 2** | A CPA firm's attestation report on **an organisation's system** against the AICPA Trust Services Criteria, including operating effectiveness over a period for Type II | A component whose controls are described, configurable and testable inside that system |
| **ISO/IEC 27001** | Certification of **an organisation's ISMS** (scope, risk treatment, Statement of Applicability, internal audit, management review) | A supplier of technological controls the SoA can reference, with evidence |
| **HIPAA Security Rule** | No certification exists. Covered entities and business associates document a risk analysis and their safeguards | A technical safeguard provider. The organisational safeguards and the BAA remain the organisation's |
| **EU AI Act** (Regulation (EU) 2024/1689) | Obligations depend on the operator's role (provider or deployer) and the AI system's risk class | A logging component that a provider or deployer may evaluate against Articles 12, 19 and 26(6) |
| **MiFID II / MiFIR** | Obligations fall on investment firms | A technical input to Article 16(6)/(7) and MiFIR Article 25(1) record-keeping ([MiFID II inputs](MIFID_II_TECHNICAL_INPUTS.md); citation under legal review, `REG-D77`) |

So audit-ready here means the following. Each technical control is implemented and switched on by a documented setting. It refuses to start when misconfigured, where that is possible. It produces evidence an assessor can collect independently. It is covered by tests that the assessor can re-run at the released commit. The organisational controls in §6 are the deploying organisation's, and no software can supply them.

## 2. The deployment baseline an assessor should find

Set `AEGIS_SECURITY_ENFORCEMENT_MODE=strict`. Strict startup **refuses** the unsafe values of most rows below; "refuses" means the process exits before serving.

| Control | Setting | Strict startup | How the assessor checks it |
| --- | --- | --- | --- |
| Authenticated access | `AEGIS_AUTH_DISABLED=false`; keys in `AEGIS_API_KEYS` / `AEGIS_AUDIT_API_KEYS` or OIDC (`AEGIS_OIDC_*`) | Refuses auth disabled | Unauthenticated request → `401` (smoke test step 3) |
| One principal per credential | `AEGIS_AUTH_IDENTITY_HMAC_KEY` (≥ 32 bytes); `AEGIS_API_KEY_PRINCIPALS_JSON` made with `python -m aegis.auth.principal` | Refuses a key without a principal | Wrong-scope request → `403`; `tests/test_principal_mapping_generator.py` |
| Signed evidence | `AEGIS_SIGNING_KEY` (HMAC) or `AEGIS_PKCS11_*` (HSM); `AEGIS_PQC_IDENTITY_PATH` adds an ML-DSA identity, which signs in preference to HMAC | Refuses without an HMAC key or HSM | `signature_assurance` in `/v1/audit/integrity`: `SYMMETRIC_AUTHENTICATED`, `ASYMMETRIC_SOFTWARE` or `ASYMMETRIC_HARDWARE_ATTESTED` |
| Evidence before response | `AEGIS_REQUIRE_DURABLE_EVIDENCE=true` | Required | `tests/test_enterprise_durable_evidence.py`; `/v1/audit/integrity` `valid: true` |
| Kernel confinement | `AEGIS_REQUIRE_SECCOMP=true`, `AEGIS_REQUIRE_LSM=true`, the AppArmor profile `deploy/apparmor/aegis.profile` | Refuses without a loaded filter or LSM | `/proc/1/status` `Seccomp: 2`, `NoNewPrivs: 1`; capability report `seccomp_syscall_filter: REAL` |
| Distributed rate limiting | `AEGIS_RATE_LIMIT_BACKEND=redis`, `AEGIS_REDIS_URL`; `AEGIS_REQUIRE_DISTRIBUTED_LIMITER=true` outside strict | Refuses any backend but Redis | Configuration review |
| Transport security | TLS at the edge, or `AEGIS_SSL_CERTFILE`/`KEYFILE`; `AEGIS_MTLS_REQUIRED` with `AEGIS_SSL_CA_CERTS`; upstream CA in `AEGIS_SSL_CA_CERTS` | Refuses mTLS without a CA | TLS peer-certificate hash in the evidence snapshot (§3.3) |
| Network admission | `AEGIS_DMZ_ALLOWED_SOURCE_IPS`; Helm `NetworkPolicy` (default deny) | — | Configuration and cluster review |
| Posture monitoring | Shipped image (the `metrics` dependency is locked in since `REG-D86`) | — | `aegis_security_enforcement_mode 1.0` on `/metrics` |
| Retention and immutability | `AEGIS_MAX_WAL_BYTES` rotation; `AEGIS_S3_ARCHIVE_*` with object lock `COMPLIANCE` and `AEGIS_S3_ARCHIVE_RETENTION_DAYS` | — | Bucket object-lock configuration; [Data Retention](../privacy/DATA_RETENTION.md) |
| Erasure without breaking the chain | `AEGIS_ENABLE_CRYPTOGRAPHIC_SHREDDING=true` (off by default; `AD-14`) | — | `CLM-068`; shredder tests |
| Trusted time | `AEGIS_TSA_URL` (RFC 3161) | — | Timestamp tokens in `AEGIS_TSA_EVIDENCE_DIR`. **Without it, every time is the host's own clock** |
| Availability | `AEGIS_HA_MODE` (`active_passive` / `active_active`) with Redis and PostgreSQL | Refuses shapes that would fork evidence | `/health` `ha` block; `python -m aegis.core.ha verify` ([High Availability](../operations/HIGH_AVAILABILITY.md)) |

## 3. Producing the evidence

Run these at the released commit and against the deployed digest. Keep the outputs, with their hashes, as the audit record.

### 3.1 What was built, and by whom

```bash
scripts/verify_release_tag.sh vX.Y.Z <commit-sha>       # gitsign verify-tag: Sigstore-signed tag
cosign verify ghcr.io/juanlunaia/aegis-latent-core@sha256:<digest> \
  --certificate-identity https://github.com/JuanLunaIA/aegis-latent-core/.github/workflows/publish_oci.yml@refs/heads/main \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
gh attestation verify oci://ghcr.io/juanlunaia/aegis-latent-core@sha256:<digest> \
  --repo JuanLunaIA/aegis-latent-core
sha256sum -c SHA256SUMS                                # release assets
```

The image installs only the hash-pinned `requirements.lock` (`REG-D69`). The SBOM comes from `scripts/generate_sbom.sh`; the licence inventory is `LICENSE-THIRD-PARTY.md`. Publication status is whatever [Release Status](../RELEASE_STATUS.md) records from readback. For `5.0.1` (2026-09-24), the tag, both image signatures and the build-provenance attestations of both images and all 15 release files were verified against the exact workflow identities (§1.0a there, `CLM-112`). Where `gh` is unavailable, the same Sigstore bundles can be fetched from the GitHub attestations API and checked with `cosign verify-blob-attestation --new-bundle-format`; §1.0a records how. `gh attestation verify` itself has not been run for any release, and an assessor should repeat the checks for the artifact they are assessing rather than rely on that record.

### 3.2 The image in its hardened posture

```bash
python3 scripts/container_smoke_test.py --image ghcr.io/…@sha256:<digest> \
  --apparmor aegis-latent-core --ha
```

This runs the image the way the hardened deployment does: strict mode, the real seccomp filter, AppArmor, a read-only root and no capabilities. It then asserts, in order:

1. The gateway boots strict and reports healthy.
2. The serving process has `Seccomp: 2` and `NoNewPrivs: 1`.
3. Authentication and scopes are enforced; the WAF refuses a prompt injection; streamed and non-streamed completions are relayed.
4. The evidence chain is valid; the capability report runs without killing the process; the evidence collector (§3.3) reads strict mode and a valid chain.
5. Evidence survives a restart.
6. A graceful stop exits 0.
7. Active-passive failover on `SIGKILL` works.
8. Two active replicas share one global sequence.
9. `python -m aegis.core.ha verify` succeeds inside the image.

CI runs the same script before any image is published (`publish_oci.yml`, `gateway-smoke`).

### 3.3 A live deployment's own statements

```bash
export AEGIS_AUDIT_KEY=…            # an audit:read key; never on the command line
python3 scripts/collect_audit_evidence.py --url https://aegis.internal \
  --ca-file ca.pem --out evidence-$(date -u +%Y%m%dT%H%M%SZ) \
  --attach ha-verify.json           # optional: output of `python -m aegis.core.ha verify`
```

The collector writes the following, and `SHA256SUMS` covers every file:

- the verbatim response bodies of `/health`, `/ready`, `/metrics`, `/v1/audit/health`, `/v1/audit/integrity` and `/v1/attestation/capabilities`;
- a `manifest.json` recording the target, the TLS peer certificate's SHA-256, each status code and hash, and the facts read out of the responses (enforcement mode, chain validity, node count, signature assurance, per-control capability status, HA admission).

The collector sends the key only to the named target, never follows a redirect, and never writes the key out. Its clock is labelled untrusted. `tests/test_collect_audit_evidence.py` pins all of this. **These are the gateway's statements about itself at one moment.** They corroborate the configuration review; they do not replace it.

### 3.4 The evidence record itself

- **Chain validity:** `GET /v1/audit/integrity` checks the retained window. `full_history_retained: false` means older records live in archived segments, which the WAL replays at startup.
- **Portable proof for one record:** `POST /v1/audit/forensics/export` produces a bundle, which `aegis-sdk verify bundle.zip --public-key … --trusted-root …` checks offline (`CLM-107`; exit 0 only with a verified signature).
- **Part 11-style signature listing:** `GET /v1/audit/export/part11`.
- **Across replicas:** `python -m aegis.core.ha verify --sequencer … --wal …` (`CLM-108`).
- **Recovery:** `tools/wal_repair.py` and [Backup and Restore](../operations/BACKUP_RESTORE.md).

### 3.5 The software's own tests, at the released commit

```bash
python -m pip install --require-hashes -r requirements.lock && python -m pip install -e ".[dev]"   # as CI does
pytest -q                                              # full suite
AEGIS_TEST_REQUIRE_HA_BACKENDS=1 AEGIS_TEST_REDIS_URL=… AEGIS_TEST_POSTGRES_DSN=… pytest tests/ha
python scripts/verify_claims.py --root . && python tools/docs/verify_documentation.py --root . --strict
```

## 4. Control matrices

Status vocabulary follows the [Compliance Contribution Map](COMPLIANCE_MAPPING.md). "Org" marks the part of the control that the deploying organisation must supply (§6). Criterion and control identifiers are the frameworks' own. Whether a contribution satisfies a criterion is the assessor's judgement.

### 4.1 SOC 2 — Trust Services Criteria (2017, points of focus revised 2022)

| Criterion | Gateway contribution | Evidence | Org |
| --- | --- | --- | --- |
| CC6.1 logical access security | Every governed route requires a principal; scopes (`proxy:completions`, `audit:read`, `audit:export`) and roles gate each surface; tenant filtering on audit reads | §3.2 steps 3–4; `tests/security/test_tenant_isolation.py` | Access policy, key issuance |
| CC6.2 / CC6.3 provisioning and removal | Principals are a declared mapping; removing a key from `AEGIS_API_KEYS` revokes it at restart; strict mode refuses unmapped keys | `python -m aegis.auth.principal`; config review | Joiner/mover/leaver process, access reviews |
| CC6.6 boundary protection | Source-IP admission, egress allowlist, default-deny `NetworkPolicy`, WAF | `aegis/proxy/egress_guard.py`; `deploy/helm/templates/networkpolicy.yaml` | Network architecture, firewalls |
| CC6.7 transmission | TLS / mTLS listener, TLS to the upstream with a pinned CA | §3.3 peer-certificate hash | Certificate lifecycle |
| CC6.8 unauthorised software | Hash-locked dependencies, signed images with provenance, seccomp kill filter, AppArmor, read-only root, no capabilities | §3.1, §3.2 | Admission policy in the cluster |
| CC7.1 configuration monitoring | `aegis_security_enforcement_mode` gauge; capability report per control | §3.3 | Alert routing, review |
| CC7.2 anomaly monitoring | Refusals are committed as evidence nodes (`status="rejected"`); metrics for rejections, rate limits and backpressure | [Monitoring and Alerting](../operations/MONITORING_ALERTING.md) | SOC, on-call |
| CC7.3–CC7.5 incident response | Tamper-evident chain, forensic export, WAL repair with exit codes | §3.4 | Incident process, notification |
| CC8.1 change management | CI gates on every change (tests, type checks, SAST, dependency audit, container smoke, doc and claim gates); signed tags; provenance attestation | `.github/workflows/`; §3.1 | Approval workflow, segregation of duties |
| A1.2 availability | HA modes with failover; backup procedure | [High Availability](../operations/HIGH_AVAILABILITY.md); [Backup and Restore](../operations/BACKUP_RESTORE.md) | Capacity planning, DR sites |
| A1.3 recovery testing | Restore drill procedure; failover exercised in the smoke test | §3.2 step 7 | Scheduled DR tests |
| PI1.1–PI1.5 processing integrity | Evidence is durable before the response is observable; fail-closed on a broken chain (`CLM-059`) | `tests/test_app_wal_corrupt.py`; §3.4 | Input/output review of the AI use case |
| C1.1 / C1.2 confidentiality | The WAL holds digests rather than bodies; optional crypto-shredding; retention with object lock | [Data Retention](../privacy/DATA_RETENTION.md); `AD-14` | Classification, disposal policy |

### 4.2 HIPAA Security Rule — technical safeguards, 45 CFR §164.312

| Standard / implementation specification | Gateway contribution | Evidence | Org |
| --- | --- | --- | --- |
| (a)(1) access control | Scoped principals per credential; tenant-filtered audit reads | §3.2 step 3; tenant-isolation tests | Minimum-necessary policy |
| (a)(2)(i) unique user identification (R) | One principal per API key or OIDC `sub`; the principal's tenant is recorded on every evidence node, and rate limits are kept per credential | `aegis/auth/principal.py` | Identity lifecycle; one credential per person or system |
| (a)(2)(ii) emergency access procedure (R) | **Not provided**: there is no break-glass path | — | **Org**: a break-glass procedure outside the gateway |
| (a)(2)(iii) automatic logoff (A) | No sessions to log off: each request authenticates; OIDC `exp` is enforced | `aegis/auth/oidc.py` | Client-side session policy |
| (a)(2)(iv) encryption and decryption (A) | Per-subject AES-256-GCM sealing when shredding is on; digests, not bodies, in the WAL | `aegis/core/crypto_shredder.py` | Storage encryption at rest |
| (b) audit controls (R) | Hash-linked, signed record of every governed call, durable before the response | §3.4 | §164.308(a)(1)(ii)(D) activity review |
| (c)(1) integrity; (c)(2) authenticating ePHI (A) | Tamper detection on read; portable inclusion proofs; signature assurance tier reported | `/v1/audit/integrity`; `aegis-sdk verify` | — |
| (d) person or entity authentication (R) | API key digests under an HMAC identity key; OIDC with pinned algorithms; mTLS | `aegis/auth/` | Credential issuance |
| (e)(1) transmission security; (e)(2)(i) integrity; (e)(2)(ii) encryption (A) | TLS/mTLS listener; TLS upstream with a pinned CA | §3.3 | Network encryption elsewhere |
| §164.316(b)(2)(i) retain documentation six years | Retention of the WAL is configurable (rotation, object-locked archive) | §2 retention row | **Org**: retention schedule and policy documents |

PHI redaction is pattern-based and **not de-identification** ([HIPAA inputs](HIPAA_TECHNICAL_INPUTS.md)). A BAA with the model provider and with the operator of this gateway is the organisation's.

### 4.3 ISO/IEC 27001:2022 — Annex A

| Control | Gateway contribution | Evidence |
| --- | --- | --- |
| 5.15 access control; 5.18 access rights | Scopes, roles, tenant filtering; declared principal mapping | §4.1 CC6.1–6.3 |
| 5.16 identity management; 5.17 authentication information | One principal per credential; keys stored only as keyed digests | `aegis/auth/principal.py`; `AegisSettings.api_key_principal_digest` |
| 5.28 collection of evidence | Signed, hash-linked records; forensic export with offline verification | §3.4 |
| 5.33 protection of records | Append-only WAL with tamper detection; object-locked archive | §2 retention row |
| 8.2 privileged access rights | `audit:export` and administrator separated from `audit:read` | `aegis/proxy/audit_api.py` |
| 8.3 information access restriction | Tenant-filtered audit reads (whole-chain integrity totals excepted; [High Availability](../operations/HIGH_AVAILABILITY.md) §6) | tenant-isolation tests |
| 8.5 secure authentication | OIDC with explicit algorithms, `exp`/`iat`/`nbf` checks; mTLS | `aegis/auth/oidc.py`, `aegis/auth/mtls.py` |
| 8.8 technical vulnerabilities | Dependency audit, OSV, Trivy, cargo audit, Bandit and CodeQL in CI; hash-pinned lock | `.github/workflows/` |
| 8.9 configuration management | Typed settings with strict-mode invariants; Helm schema; refusal of unsafe shapes | `aegis/config.py` |
| 8.12 data leakage prevention | Streaming and non-streaming redaction; digests in evidence | [PII Redaction Boundaries](../privacy/PII_REDACTION_BOUNDARIES.md) |
| 8.13 information backup; 8.14 redundancy | Backup procedure; HA modes | [Backup and Restore](../operations/BACKUP_RESTORE.md); [High Availability](../operations/HIGH_AVAILABILITY.md) |
| 8.15 logging; 8.16 monitoring activities | The evidence chain; metrics with posture and rejection counters | §3.3, §3.4 |
| 8.17 clock synchronization | RFC 3161 timestamp tokens when `AEGIS_TSA_URL` is set. `aegis/core/clock_integrity.py` can assert NTP synchronisation but is **not wired into gateway startup**; host clock discipline is the organisation's | `aegis/core/rfc3161_timestamper.py` |
| 8.20 networks security; 8.22 segregation | Source-IP admission; `NetworkPolicy` | Helm chart |
| 8.24 use of cryptography | HMAC-SHA256, ML-DSA-65, PKCS#11 signing tiers; AES-256-GCM sealing; no hand-rolled primitives (`AD-14`) | `aegis/core/crypto_audit.py` |
| 8.25 secure development life cycle; 8.28 secure coding; 8.29 security testing | CI gates on every change: ruff, `mypy --strict`, Bandit and CodeQL, property-based (Hypothesis) and adversarial test suites, Kani and Miri on the Rust core, container smoke | `.github/workflows/ci.yml` |
| 8.32 change management | Signed tags; release contract; provenance attestation | §3.1 |

The organisational (5.x), people (6.x) and physical (7.x) themes, the SoA itself and the ISMS clauses 4–10 are the organisation's.

### 4.4 EU AI Act — Regulation (EU) 2024/1689

| Article | Gateway contribution | Boundary |
| --- | --- | --- |
| Art. 12 record-keeping (high-risk systems) | Automatic, per-call, tamper-evident records over the gateway's lifetime, committed before the response ([EU AI Act inputs](EU_AI_ACT_TECHNICAL_INPUTS.md)) | Whether the records meet the scope and granularity Article 12 requires for *your* system is the provider's assessment |
| Art. 19 provider logs; Art. 26(6) deployer logs (at least six months) | Retention is configurable: rotation plus an object-locked archive with a set retention | The retention period and its enforcement are the operator's configuration |
| Art. 15 accuracy, robustness, cybersecurity | Prompt-injection and adversarial-input defences; kernel confinement; fail-closed evidence | A contribution to the system's cybersecurity, not a robustness evaluation of the model |
| Art. 11, 14, 17 | **Not provided.** Technical documentation of the AI system, human oversight measures and the quality management system are the provider's | — |

### 4.5 MiFID II / MiFIR

See [MiFID II inputs](MIFID_II_TECHNICAL_INPUTS.md): the Article 16(6)/(7) and MiFIR Article 25(1) contribution, with `mifid_record_keeper.py` retention classes. That citation is under legal review (`REG-D77`, `CLM-104`). Recording of telephone conversations and electronic communications outside the gateway is the firm's.

## 5. Findings an assessor will reach, stated in advance

| Finding | Why it stands | Mitigation available now |
| --- | --- | --- |
| Default signing is symmetric (`SYMMETRIC_AUTHENTICATED`) | HMAC verifiers can also sign | Configure ML-DSA (`ASYMMETRIC_SOFTWARE`) or PKCS#11 (`ASYMMETRIC_HARDWARE_ATTESTED`) |
| No trusted time by default | Timestamps are the host clock | Configure RFC 3161 (`AEGIS_TSA_URL`) |
| `/v1/audit/integrity` reports whole-chain count and tail to any `audit:read` holder | The public JSON contract (`CLM-090`) | One chain per team ([High Availability](../operations/HIGH_AVAILABILITY.md) §6) |
| No emergency-access (break-glass) path | Not implemented | An organisational procedure outside the gateway |
| `/metrics` is unauthenticated | Standard for Prometheus scraping | Source-IP admission and `NetworkPolicy` |
| HA is untested on real storage classes, under partitions and with Redis/PostgreSQL failover | Only local and container-level tests exist | Target acceptance testing |
| No independent penetration test or external code audit | None has been commissioned | Commission one against the deployed configuration |
| `5.0.1` is published on every surface except PyPI `aegis-latent-core` (read back 2026-09-24); `pip install aegis-latent-core` still gets `4.1.2` | [Release Status](../RELEASE_STATUS.md) §1.0a | Take the gateway from GHCR or the Release assets; re-run §3.1 against the artifact you deploy |

## 6. What the deploying organisation supplies

- **SOC 2:** system description, risk assessment, policies, vendor management (including the model provider), HR controls, change approval, access reviews, incident response, business continuity and disaster recovery, and the observation period for Type II.
- **ISO/IEC 27001:** ISMS scope, risk treatment plan, Statement of Applicability, internal audit, management review, and all organisational, people and physical controls.
- **HIPAA:** risk analysis and risk management (§164.308(a)(1)), workforce security and training, BAAs, contingency plan, facility controls, policies retained for six years, breach determination and notification.
- **EU AI Act:** role and risk classification, technical documentation, human oversight, QMS, conformity assessment where required, and post-market monitoring.
- **MiFID II:** record-keeping policy, communications recording outside the gateway, and supervisory access procedures.

---

**Related:** [Compliance Contribution Map](COMPLIANCE_MAPPING.md) · [HIPAA inputs](HIPAA_TECHNICAL_INPUTS.md) · [EU AI Act inputs](EU_AI_ACT_TECHNICAL_INPUTS.md) · [MiFID II inputs](MIFID_II_TECHNICAL_INPUTS.md) · [High Availability](../operations/HIGH_AVAILABILITY.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Security](../../SECURITY.md)
