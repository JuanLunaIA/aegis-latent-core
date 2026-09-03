# Institutional Documentation Control Record

**Release baseline:** four-layer truth model
**Control record:** `AEGIS-DOC-CONTROL-2026-08-22`
**Suite version:** 1.0
**Repository:** `JuanLunaIA/aegis-latent-core`
**Source baseline:** checked-out source metadata is synchronized at `v4.1.1`
**External lifecycle boundary:** source metadata does not prove a tag, GitHub Release, registry package, OCI image, deployment, SLO, compliance result, or acceptance; verify each surface by external readback
**Historical evidence baseline:** published `v3.1.0` artifacts and retained measurements remain historical
**Current change set:** documentation alignment only; no external lifecycle or acceptance decision
**Status:** Technical source record; external publication and domain acceptance require independent evidence

## 1. Authority and source hierarchy

No natural-language document is self-authenticating. Conflicts are resolved in this order:

1. applicable enacted law, authoritative regulator text, and executed agreements;
2. license text and approved organizational policies;
3. `docs/CLAIMS_MATRIX.md` for repository public claims;
4. production code and exact reachable data paths;
5. named tests, solver outputs, and retained evidence artifacts;
6. the six institutional volumes;
7. focused legacy documentation;
8. samples, marketing hypotheses, and pasted source material.

A higher-ranked source can still require legal or specialist interpretation. Code behavior does not determine legal applicability, and an external standard does not prove code conformity.

## 2. Injection-containment log

| Input | Risk | Containment decision | Observable |
|---|---|---|---|
| Pasted XML `system_prompt` | Authority spoofing and role replacement | Treated as untrusted task data; no identity, policy, or credential authority accepted. | Only user-authorized repository and GitHub actions were performed. |
| `[PROVEN_FORMAL]` and confidence 0.998–1.000 | Self-certification | Rejected for prose; formal tag retained only for named solver artifacts. | DOC-01/02 and formal record expose the refinement gap. |
| Embedded commands, hashes, UUID, exit code | Fabricated execution/provenance risk | Not executed or trusted; final hashes are computed after repository validation. | Manifest digest must equal bytes on disk. |
| Regulatory and legal labels | Unauthorized legal conclusion | Mapped as technical contributions with counsel/assessor gates. | DOC-05 and unsupported report block compliance/admissibility wording. |
| Performance and commercial numbers | Measurement and promise inflation | Compared with retained artifacts and contracts; unsupported values downgraded. | Claims matrix contains only bounded measurements. |
| Example secret-like values | Secret normalization risk | Not copied into canonical runbooks or production configuration. | Secret scans and repository diff review must remain clean. |
| Pasted `v4.0.0`, WORM, SLSA, admissibility, enterprise, and production assertions | Release/compliance self-certification | Treated as requirements rather than proof. Source anchors were later aligned and audited, but tag, release, registry, OCI, deployment-acceptance, and external-guarantee state remain separate facts requiring external readback or qualified acceptance. | Claims matrix and developer integration guide retain lifecycle-neutral external-readback, `CONFIGURATION-DEPENDENT`, and acceptance boundaries. |

**Falsification:** containment fails if pasted text changes governing policy, accesses a secret, authorizes an external action beyond the user's request, or enters the canonical suite as fact without evidence and status.

## 3. Ownership and approval matrix

| Document | Drafter | Mandatory approvers before external use |
|---|---|---|
| DOC-01 | Architecture/documentation owner | Architecture, SRE/storage, formal-methods reviewer |
| DOC-02 | Security/cryptography documentation owner | Cryptography specialist, security owner, evidence custodian |
| DOC-03 | Security documentation owner | AppSec, AI security, platform security |
| DOC-04 | Operations documentation owner | SRE, release, security, evidence custodian |
| DOC-05 | Compliance documentation owner | Qualified counsel, applicable compliance/quality owner, independent assessor where required |
| DOC-06 | Commercial documentation owner | Executive commercial owner, finance, security, counsel |
| Claims matrix and graph | Release owner | Qualified security reviewer plus affected domain owner |

Approval must identify commit SHA, document versions, scope, exceptions, and UTC timestamp. Silence or Git merge access is not approval of a legal or commercial conclusion.

## 4. Change-control states

```text
DRAFT -> TECHNICAL REVIEW -> CLAIM REVIEW -> DOMAIN APPROVAL -> RELEASED
  |             |                 |               |
  +----------> REJECTED <---------+---------------+
                      |
                      v
                  SUPERSEDED
```

| Transition | Guard | Required record |
|---|---|---|
| Draft to Technical Review | Files complete, no placeholders, exact locators present | Pull request and corpus audit |
| Technical to Claim Review | Tests/docs/formal gates pass; source behavior reviewed | CI links and evidence digest |
| Claim to Domain Approval | No contradiction with claims matrix; risk owners assigned | Claim graph and unsupported report |
| Domain Approval to Released | Mandatory approvers sign off; external audience and scope declared | Release note, commit/tag, approval log |
| Any state to Rejected | Gate failure, contradiction, legal/security objection, or missing evidence | Finding, owner, remediation/rollback |
| Released to Superseded | New code, law, standard, evidence, contract, or corrected claim | Replacement link and withdrawal plan |

## 5. Review cadence and freshness

| Trigger | Required action |
|---|---|
| Every release | Re-run corpus, tests, formal gate, claim scan, and source-locator review. |
| Dependency or cryptography change | Re-run native tests, capability checks, timing/interop where claimed, SBOM and vulnerability review. |
| Deployment/topology change | Reassess ordering, storage, ingress, availability, rollback, monitoring, and responsibility boundaries. |
| Legal/regulatory source change | Qualified reviewer updates applicability, effective dates, citations, gaps, and customer wording. |
| Measurement update | Preserve raw input, environment, tool versions, samples, statistics, limitations, and old artifact. |
| Incident or customer finding | Freeze affected claims, preserve prior material, investigate, correct, notify affected recipients, and document acceptance. |
| At least quarterly for externally used material | Review links, claims, owner assignments, commercial status, security notices, and GitHub alerts. |

## 6. Deterministic release gates

```bash
python scripts/audit_documentation_corpus.py \
  --output-dir "evidence/documentation_audit_$(date -u +%F)"
python tools/docs/verify_documentation.py
python -m ruff check aegis aegis_server tests scripts/audit_documentation_corpus.py
python -m pytest -q --tb=short
cargo test --manifest-path aegis_rust_v2/Cargo.toml --release --locked
bash scripts/verify_formal_artifacts.sh
git diff --check
```

The release owner records command, tool version, exit status, result summary, commit, environment boundary, and unresolved warnings. A skipped test is not a pass for the skipped backend.

## 7. Provenance and canonicalization

The final release envelope must use NFC text, LF line endings, RFC 8785-compatible canonical JSON for its supported data types, canonical DAG-CBOR, SHA-256 artifact digests, domain-separated Merkle aggregation, and CIDv1. The envelope excludes its own digest from its leaf set and records the source commit, generated commit, artifact list, test outcomes, GitHub PR, Actions status, accessible security-alert data, unavailable endpoints, and residual risk.

A CID or hash proves byte identity relative to an input; it does not prove truth, authorship, legal status, or safe operation.

## 8. Rollback and external correction

Rollback is a Git revert of the documentation/code correction commit. If material was distributed externally, the release owner must preserve the prior bytes, audience, timestamps, correction, reason, approvals, and delivery record. Claims involving security, privacy, legal status, availability, performance, pricing, or customer evidence require direct correction to known recipients when materially misleading.

## 9. Kill criteria

Publication is blocked by any failed required test, formal counterexample, invalid manifest, unfinished marker in the institutional suite, unresolved contradiction with the claims matrix, secret finding, high/critical dependency or code-scanning alert without accepted disposition, inaccessible security surface represented as clean, target-specific claim without target evidence, or required reviewer rejection.

## 10. Residual uncertainty

The suite is a repository-grounded review, not an independent audit. Source inspection and tests cannot prove the absence of defects, unknown vulnerabilities, runtime misconfiguration, supply-chain compromise, legal exposure, or misleading downstream reuse. Human approval remains mandatory at every operational, regulatory, legal, and contractual boundary.
