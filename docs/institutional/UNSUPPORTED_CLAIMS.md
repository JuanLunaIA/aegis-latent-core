# Unsupported Claims and Contradiction Report

**Review date:** 2026-08-22 UTC
**Release baseline:** two-baseline model
**Source baseline:** merged v4 source state documented by the 2026-08-25 post-merge audit
**Distribution baseline:** published `v3.1.0` artifacts; post-v3.1.0 capabilities are not attributed to that distribution
**Disposition:** Claims below are blocked, downgraded, or require qualified review.
**Input posture:** The pasted documentation suite was treated as untrusted source material.

## Executive finding

The supplied content was not a formally proven or cryptographically attested documentation corpus. It combined useful architecture ideas with fabricated provenance fields, absolute confidence, unsupported performance numbers, obsolete regulatory assumptions, and product promises not established by code or retained evidence. The institutional volumes preserve useful structure while replacing those assertions with bounded claims.

## Unsupported or contradictory claims

| ID | Supplied or legacy claim | Finding | Required status and correction |
|---|---|---|---|
| `UC-001` | The entire documentation suite is `[PROVEN_FORMAL]` with confidence 0.998–1.000. | No formal semantics or proof covers natural-language truth, regulatory applicability, code reachability, or corpus completeness. | `ROADMAP`; formal tags apply only to named Lean/Z3/TLC artifacts. |
| `UC-002` | The corpus has exactly 546 paths and deterministic complete coverage. | The audited working tree already contained 564 tracked files before this suite and gains more files in this change. | Use generated inventory counts and commit identity, not a fixed prompt count. |
| `UC-003` | Every request and rejection has durable evidence before emission. | Authentication, parsing, body, WAF, rate-limit, and readiness rejects occur before the core evidence helper. | `IMPLEMENTED` only for admitted governed outcomes; universal rejection evidence is `ROADMAP`. |
| `UC-004` | Streaming is fully buffered or emitted only after a full-response evidence commit. | Resolved on 2026-08-21: admitted SSE streams incrementally emit sanitized events through a bounded byte- and item-accounted queue. The implementation hashes the exact emitted bytes, performs one terminal summary WAL commit, and withholds only the terminal marker until that commit succeeds. Initial evidence/proof headers are `pending-terminal`, and proof retrieval occurs through the linked endpoint after terminal commit. | `IMPLEMENTED` for one admitted stream under the configured backpressure, queue-byte, queue-event, event-size, cumulative-output, de-identification-window, preview, and duration bounds, as exercised by `tests/test_proxy_streaming.py` and arithmetically bounded by `specs/aegis_stream_buffer.smt2`; aggregate retained memory scales with concurrency, so admission budgeting remains `CONFIGURATION-DEPENDENT`. |
| `UC-005` | Process-local WAL locking gives safe multi-worker/multi-pod ordering. | Locks are process-local; storage providers use non-atomic read-then-write chain operations; Helm defaults can create conflicting writers. | `ROADMAP` for global ordering; deploy per-replica evidence or one reviewed writer. |
| `UC-006` | WAL archive mode or application “WORM” classes establish immutable media. | Owner-only/read-only permissions and application checks do not resist root or provide SEC-qualified WORM. | `CONFIGURATION-DEPENDENT` sealed segments; Rule 17a-4 conclusion is `LEGAL-REVIEW-REQUIRED`. |
| `UC-007` | SEC Rule 17a-4 requires WORM only. | SEC's 2022 amendments permit WORM or a complete audit-trail alternative. | Use current rule analysis and target-system acceptance. |
| `UC-008` | FINRA retention is a universal fixed five-, six-, or seven-year rule for all records. | Rule 4511 depends on record type and applicable FINRA/Exchange Act rules; six years applies where no period is specified under FINRA rules. | `LEGAL-REVIEW-REQUIRED`; classify each regulated record. |
| `UC-009` | Regex redaction implements “NIST SP 800-188 Safe Harbor.” | NIST SP 800-188 and HIPAA Safe Harbor are distinct; finite regexes do not satisfy every 45 CFR 164.514(b)(2) condition. | `ROADMAP`; describe best-effort identifier redaction. |
| `UC-010` | Aegis automatically de-identifies all PHI. | Names, context, structured fields, dates/ages, multimedia, unique characteristics, and actual-knowledge conditions exceed the finite detector. | `ROADMAP`; require customer corpus, expert/privacy review, and production wiring. |
| `UC-011` | Hashing tenant/session IDs enables GDPR or CCPA compliance and reduces breach blast radius to zero. | Hashes and metadata can remain personal data; legal basis, purpose, rights, transfers, retention, access, and organizational controls remain. Risk is never reduced to zero. | `LEGAL-REVIEW-REQUIRED`; describe data-minimization contribution only. |
| `UC-012` | ML-DSA is constant-time. | Retained verification timing failed the declared threshold; API comparison properties do not prove whole-algorithm timing. | `ROADMAP`; no constant-time claim. |
| `UC-013` | ML-DSA/ML-KEM use establishes FIPS compliance or validated cryptography. | Algorithm naming or dependency use is not FIPS 140 module validation, approved operational mode, entropy/custody assurance, or target-platform availability. | `CONFIGURATION-DEPENDENT`; specialist review required. |
| `UC-014` | ML-KEM-1024 hybrid transport is production integrated. | The optional package is not declared in the PQ extra, tests can skip, and the helper lacks authenticated transcript/TLS integration. | `ROADMAP`. |
| `UC-015` | BLAKE3 runs at approximately 4.0 GB/s in Aegis. | No retained current-environment benchmark supports this product claim, and helper reachability differs from the evidence path. | `ROADMAP` until measured with workload, build, platform, samples, and raw data. |
| `UC-016` | WAF takes about 250 ns and rate limiting about 50 ns with less than 0.5% LLM overhead. | No retained end-to-end or microbenchmark evidence establishes these values after the current changes. | `ROADMAP`; use only named measured artifacts. |
| `UC-017` | 10k RPS offered load means 10k production capacity. | The retained run offered 10k RPS for 0.25 s and processed 2,500 local records with p99 836.3514210795984 ms. | `MEASURED` only for that workload; capacity remains `ROADMAP`. |
| `UC-018` | The retained backpressure artifact contains 10,000 durable records and p99 1,189.89 ms. | The committed artifact contains 2,500 durable records and p99 836.3514210795984 ms. | Canonical matrices corrected to the retained artifact. |
| `UC-019` | Aegis provides a 99.95% availability SLA and 24/7 response. | No executed SLA, staffed rota, service credits, production history, or customer agreement exists. | `ROADMAP`/contract-dependent. |
| `UC-020` | Helm replicas, PDB, spread constraints, and one PVC prove HA. | Orchestrator objects do not prove service or evidence HA; shared `ReadWriteOnce` and process-local state can conflict. | `CONFIGURATION-DEPENDENT`; target failover and evidence tests required. |
| `UC-021` | Aegis is SOC 2, HIPAA, EU AI Act, Part 11, GAMP 5, SEC/FINRA, or ISO compliant. | Repository controls are only potential evidence inputs; organizational scope, operation, assessment, and legal facts are absent. | `LEGAL-REVIEW-REQUIRED`; no compliance claim. |
| `UC-022` | An export bundle is court-admissible or non-repudiable by construction. | HMAC is symmetric; self-signed ephemeral CMS identity is untrusted; custody, acquisition, declarant, procedure, and tribunal decisions remain. | `LEGAL-REVIEW-REQUIRED`; describe technical integrity only. |
| `UC-023` | Generated E01 output is compatible with libewf/FTK and ready for evidence exchange. | No retained interoperability matrix with named independent tools and versions was supplied. | `ROADMAP`; run and retain compatibility tests. |
| `UC-024` | ISO/IEC 27037 package fields establish conformity. | ISO 27037 concerns a broader handling process, people, source identification, acquisition, and preservation. | `LEGAL-REVIEW-REQUIRED`; “ISO-oriented.” |
| `UC-025` | Part 11 annotation fields establish compliant electronic signatures. | Predicate-rule scope, identity, access, durable audit trail, signature attribution, SOPs, training, validation, and retention are missing. | `LEGAL-REVIEW-REQUIRED`; fields may support review. |
| `UC-026` | Aegis automatically satisfies EU AI Act Articles 13 and 14. | Applicability depends on role, high-risk classification, intended purpose, instructions, oversight, conformity, and dates. | `LEGAL-REVIEW-REQUIRED`. |
| `UC-027` | Static dashboards or samples show live customer telemetry or production capacity. | Samples are illustrative and not connected evidence. | `ROADMAP`; label static demo data. |
| `UC-028` | Pricing, ROI, customers, market validation, or procurement readiness are established. | Repository materials contain hypotheses, not executed orders, validated quotes, customer-approved outcomes, or cost-to-serve evidence. | `ROADMAP`. |
| `UC-029` | The supplied UUID, script hash, confidence, CHOKE PASS, and exit code form valid provenance. | No corresponding script, execution trace, input digest, signature, or reproducible byte identity was supplied. | `UNVERIFIED`; replace with locally generated JCS/DAG-CBOR manifest after final validation. |
| `UC-030` | Exact-byte documentation deduplication alone establishes consistency. | Semantic contradictions can persist across different bytes; repeated headings can be legitimate. | Use claim graph, source hierarchy, targeted review, and executable gates. |
| `UC-031` | PR #99 makes Aegis a complete enterprise AI security platform with no direct competitor. | The merge adds material gateway, SDK, proof, dashboard and export capabilities but no validated market-wide parity study, complete security control plane or managed service. | Keep the category **AI Governance and Evidence Gateway**; competitive differentiation remains a hypothesis. |
| `UC-032` | The project has a USD 1.5M–2.2M engineering replacement cost or USD 8M–14M startup/IP valuation. | No work-breakdown estimate, loaded rates, audited IP rights, revenue, traction, financing data, adjusted comparables or independent valuation exists. | `UNVERIFIED`; do not publish a replacement cost or valuation without a reproducible model and qualified review. |
| `UC-033` | Healthcare, banking and defense ACV bands are established. | No customer contracts, paid-pilot outcomes or vertical ACV dataset is cited. Existing package bands are internal cross-segment hypotheses only. | `ROADMAP`; distinguish pilot fee, annual-price hypothesis, observed ACV and valuation. |
| `UC-034` | The forensic ZIP is ISO/IEC 27037 conformant or Daubert-certified. | Canonical bytes, hashes and verification scripts are technical inputs; they do not validate acquisition procedure, examiner competence, full custody or legal admissibility. Daubert is a judicial reliability framework, not a software-package certification. | `LEGAL-REVIEW-REQUIRED`; call the output a bounded technical integrity package. |
| `UC-035` | Workflow hardening proves immutable dependencies or SLSA Level 3+. | Pinned Actions, lockfiles, SBOM, provenance and Cosign are artifact-specific controls; the repository has no retained SLSA Level 3 assessment. | Verify each subject digest and workflow run; do not claim SLSA 3+. |
| `UC-036` | Aegis is defense-grade, enterprise tier-1, mandatory infrastructure or production-ready at 10k RPS with zero overhead. | No customer deployment acceptance, production SLO, support operation, independent assurance or end-to-end capacity result establishes those claims. | `ROADMAP`; publish only named benchmark results with workload and exclusions. |

## Residual high-risk language

Repository class and field names may retain historical tokens such as `WORM`, `legal_admissibility`, `compliance`, or `safe_harbor_regex` for API compatibility. Their presence is not an approved external claim. Public interpretation is controlled by this report, DOC-05, and `docs/CLAIMS_MATRIX.md`.

## Acceptance and falsification

The unsupported-claim gate passes only if:

1. canonical documents do not promote any blocked claim;
2. code docstrings no longer describe technical outputs as automatically compliant or admissible;
3. retained measurements match the referenced JSON artifacts;
4. the formal record remains explicitly bounded;
5. institutional documents contain no unfinished markers or fabricated provenance; and
6. a fresh scan plus human review finds no stronger conflicting statement.

Any counterexample reopens this report and blocks publication of the affected claim.
