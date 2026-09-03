# Audit Evidence Index

**Audience:** auditors, security reviewers, procurement, anyone verifying a claim.
**Scope:** where every category of evidence lives, and how to check it.
**Boundary:** all evidence listed here is self-produced by the project. Independent assurance does not exist; see [Assurance Roadmap](ASSURANCE_ROADMAP.md). This index tells you where to look, not that what you find is sufficient for your purpose.

---

## How to use this

Do not accept a summary. Every row names something you can open, run, or verify yourself. Where a row says "verify with", run the command.

---

## 1. Claim evidence

| Evidence | Location | Verify with |
| --- | --- | --- |
| Public claims register | [`docs/CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md) | Spot-check three rows against their locators |
| Claims the project refuses to make | [`docs/institutional/UNSUPPORTED_CLAIMS.md`](../institutional/UNSUPPORTED_CLAIMS.md) | Read it |
| Consolidated boundaries | [`docs/BOUNDARIES.md`](../BOUNDARIES.md) | Read it |
| Claim-to-evidence relationships | [`docs/institutional/CLAIM_EVIDENCE_GRAPH.md`](../institutional/CLAIM_EVIDENCE_GRAPH.md) | Read it |
| Register coherence | — | `python scripts/verify_claims.py` |

**The highest-value audit action on this repository is spot-checking claims against locators.** If a locator does not support its row, that is a finding about the register as a whole.

## 2. Source evidence

| Control area | Source | Tests |
| --- | --- | --- |
| Evidence chain, WAL, single-writer | `aegis/core/crypto_audit.py` | `tests/security/test_wal_single_writer.py`, `tests/test_enterprise_durable_evidence.py`, `tests/test_reliability.py` |
| MMR and portable proofs | `aegis/core/mmr.py` | `tests/test_mmr_portable.py`, `sdk/python/tests/test_proof.py`, `sdk/typescript/tests/proof.test.ts` |
| Streaming bounds and terminal commit | `aegis/proxy/streaming.py` | `tests/test_proxy_streaming.py` |
| Authentication and principals | `aegis/auth/` | `tests/auth/`, `tests/test_apikey_new.py`, `tests/test_api_key_scopes.py` |
| Tenant binding | `aegis/proxy/app.py` | `tests/test_integration_proxy.py` |
| WAF | `aegis/proxy/waf.py` | `tests/data/waf_corpus_v1.json`, `tools/security/run_waf_corpus.py` |
| Redaction | `aegis/core/phi_deidentifier.py`, `aegis/core/pci_detector.py` | Module tests |
| Rate limiting | `aegis/proxy/rate_limiter.py` | Rate-limit tests |
| Forensic export | `aegis/core/forensic_bundle.py` | `tests/test_forensic_bundle.py` |
| Enforcement posture | `aegis/proxy/app.py`, `aegis/core/observability.py` | `tests/security/test_enforcement_mode_metric.py` |
| Deployment manifests | `deploy/helm/` | `tests/test_deploy_manifests.py` |
| Workflow token scopes | `.github/workflows/` | `tests/security/test_workflow_permissions.py` |

Run the suite yourself:

```bash
python -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps -e .
pytest -q
```

## 3. Formal verification

| Artifact | Location |
| --- | --- |
| TLA+ invariants | `specs/aegis_invariants.tla`, `.cfg` |
| Ledger immutability model | `specs/aegis_ledger_immutability.tla`, `.cfg` |
| Session manager model | `specs/aegis_session_manager.tla`, `.cfg` |
| Lean theorem | `specs/AegisVerification.lean` |
| Z3 SMT invariants | `specs/aegis_invariants.smt2` |
| Per-stream buffer arithmetic | `specs/aegis_stream_buffer.smt2` |
| CI gate | `scripts/verify_formal_artifacts.sh` |

**Read [Formal Verification Limits](../formal/FORMAL_VERIFICATION_LIMITS.md) before citing any of this.** These are bounded model checks over abstractions, not refinement proofs of the Python or Rust implementation.

## 4. Supply chain

| Evidence | Verify with |
| --- | --- |
| Hash-pinned Python dependencies | `requirements.lock`; installed with `--require-hashes` |
| SHA-pinned GitHub Actions | `python scripts/verify_github_action_pins.py` |
| Rust dependency lock | `Cargo.lock` |
| SBOM (SPDX) | Release assets |
| Build provenance | `gh attestation verify <artifact> --repo JuanLunaIA/aegis-latent-core` |
| Release artifact integrity | `sha256sum --check --strict SHA256SUMS` |
| Signed tag | `gitsign verify --certificate-identity ... v4.0.2` — `v4.0.2` is the most recent published tag; none exists for `4.1.0` |
| Signed images | `cosign verify ghcr.io/juanlunaia/aegis-latent-core:4.0.2 ...` — likewise the most recent published image tag |
| Release contract | `python scripts/verify_release_contract.py --root . --tag v4.1.0` — checks the checked-out source, so the tag argument tracks the source baseline |

Exact commands: [Release Status §2](../RELEASE_STATUS.md#2-readback-commands).

**Note:** release artifacts do not carry detached signatures. Integrity comes from `SHA256SUMS` plus sidecars, and provenance from the attestation store. `cosign verify` applies to images, not release blobs.

## 5. Security scanning

| Scanner | Workflow | Scope |
| --- | --- | --- |
| CodeQL | `security.yml` | Python static analysis |
| Bandit | `security.yml`, `forensic.yml` | Python SAST, high severity blocking |
| pip-audit | `security.yml`, `forensic.yml` | Python dependency CVEs |
| Trivy | `security.yml` | Filesystem scan |
| OSV-Scanner | `security.yml` | Lockfile vulnerabilities |
| cargo-audit | `security.yml` | Rust dependencies |

Absence of findings is not absence of vulnerabilities.

## 6. Dated evidence records

`evidence/` holds dated, frozen records. Catalog: [`evidence/INDEX.md`](../../evidence/INDEX.md).

| Record | Subject |
| --- | --- |
| `cold_start_reproduction_audit_2026-09-01.md` | Independent clean-container reproduction |
| `v4_0_0_release_candidate_gate_2026-08-24.md` | Candidate gate metrics |
| `apex_workstreams_9_11_gate_2026-08-24.md` | Workstream gate |
| `commercial_phase2_dashboard_qa.md` | Dashboard QA, bounded to its environment |
| `documentation_audit_2026-08-22/` | Corpus audit snapshot |
| `remediation_2026-08-21/` | Remediation records |
| `github_status_baseline_2026-08-20/` | GitHub security status snapshot |

**These are frozen.** They record what was observed on a date, and they are not updated to match current state. See [Evidence Governance](../institutional/EVIDENCE_GOVERNANCE.md).

## 7. Measurements

| Measurement | Value | Source | Date |
| --- | --- | --- | --- |
| Statement coverage | 93.9096% (11,765 / 12,528) | `coverage.json` | 2026-08-18 |
| Statement coverage | 89.7169% | `evidence/v4_0_0_release_candidate_gate_2026-08-24.md` | 2026-08-24 |
| Python suite | 5,707 passed, 37 skipped | Candidate gate record | 2026-08-24 |
| Python suite | 5,661 passed, 81 skipped, 0 failed | `evidence/cold_start_reproduction_audit_2026-09-01.md` | 2026-09-01 |
| Rust extension | 29 tests passed; Clippy `-D warnings`; abi3 wheel built | CI | Per run |
| WAF corpus | Zero observed bypasses, zero false positives | `waf_corpus_report_v1_candidate.json` | Per corpus |
| Backpressure | 2,500 offered, 2,500 durable, p99 commit 836.35 ms under 2 ms injected `fsync` delay | `evidence/execution_2026-08-20/backpressure_stall_report.json` | 2026-08-20 |

**Two coverage figures appear because two runs measured differently on different dates.** Both are recorded rather than one being selected. Cite the artifact and the date, never a bare percentage. Suite counts move as tests are added; the current count is whatever `pytest -q` reports on the commit you are evaluating.

## 8. Documentation gates

| Gate | Command |
| --- | --- |
| Structure, links, phrasing | `python scripts/verify_docs.py` |
| Claims coherence | `python scripts/verify_claims.py` |
| Links and anchors | `bash scripts/verify_links.sh` |
| Prose boundary language | `python tools/docs/verify_documentation.py --root . --strict` |

## 9. What no evidence here establishes

- **Independence.** All of it is self-produced.
- **Completeness.** Tests cover what they cover.
- **Production behaviour.** Nothing here was measured on an accepted deployment.
- **Organisational controls.** No evidence of policies, personnel or process maturity exists.
- **Certification.** None.

---

**Related:** [Assurance Roadmap](ASSURANCE_ROADMAP.md) · [Control to Evidence Matrix](CONTROL_TO_EVIDENCE_MATRIX.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Evidence Index](../../evidence/INDEX.md) · [Release Status](../RELEASE_STATUS.md)
