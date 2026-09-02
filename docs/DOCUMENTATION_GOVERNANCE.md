# Documentation Governance

**Audience:** maintainers, contributors, security reviewers, release owners.
**Scope:** how documentation changes are proposed, reviewed, verified, and released in this repository.
**Boundary:** this document governs process. It does not itself make product claims. Claims live in [Claims Matrix](CLAIMS_MATRIX.md).

---

## 1. Principle

Documentation is part of the evidence surface. A public document that asserts a control the source does not implement is a defect of the same class as an unimplemented control, and is treated the same way: it blocks release until corrected.

## 2. Roles

| Role | Owns |
| --- | --- |
| Maintainer | Merge decisions; conformance to [Style Guide](STYLE_GUIDE.md). |
| Security reviewer | Any change touching `SECURITY.md`, `docs/security/**`, threat model, or a security claim. |
| Release owner | [Release Status](RELEASE_STATUS.md), [CHANGELOG](../CHANGELOG.md), and publication-state accuracy. |
| Claim owner | The named owner in each [Claims Matrix](CLAIMS_MATRIX.md) row. |

A single person may hold several roles. The obligations do not merge: a security claim still requires a security review even when the maintainer wrote it.

## 3. Change rules

These are conditions on merging, not suggestions.

1. **Every documentation change is reviewed against [Claims Matrix](CLAIMS_MATRIX.md).** If the change adds, widens, or narrows a public claim, the matrix row changes in the same pull request.
2. **Public claims carry evidence locators.** An `Implemented` or `Measured` claim without a source path, test, or artifact is not merged.
3. **Release-status changes update [Release Status](RELEASE_STATUS.md).** No other document states publication state; they link to it.
4. **Security-control changes update [Security Controls](security/SECURITY_CONTROLS.md).** A new control that appears only in prose is not documented.
5. **Compliance mappings update [Compliance Mapping](compliance/COMPLIANCE_MAPPING.md).** Framework text lives there and in the per-framework technical-input documents, nowhere else.
6. **A feature is documented before it appears in public release notes.** Release notes may not be the first description of a capability.
7. **A withdrawn or disproven claim moves to [Unsupported Claims](institutional/UNSUPPORTED_CLAIMS.md).** It is not silently deleted; the prohibition is recorded so it is not reintroduced.
8. **Documentation passes `scripts/verify_docs.py` before release.** See §5.

## 4. Evidence locators

An evidence locator is precise enough for a reviewer to reach the evidence without asking.

| Claim state | Acceptable locator |
| --- | --- |
| Implemented | Source path plus symbol, and a named test. `aegis/core/crypto_audit.py` (`_lock_wal_fd`); `tests/security/test_wal_single_writer.py`. |
| Measured | Artifact path, value, date, environment. `coverage.json`, 93.9096%, 2026-08-18. |
| Configuration-dependent | Configuration surface plus the target acceptance required. `deploy/helm/values.yaml`; storage class and CNI enforcement must be accepted on target. |
| Roadmap | None. A Roadmap row must have no locator, because there is nothing to locate. |
| Legal-review-required | The deferral itself, plus any technical input offered. |

A locator pointing at a line range in code is acceptable only in dated `evidence/` records. Prose cites files and symbols, because line numbers drift and a drifted citation reads as a false one.

## 5. Verification gates

Three checkers, with distinct jobs. They are complementary; none supersedes another.

| Gate | Checks | Command |
| --- | --- | --- |
| `scripts/verify_docs.py` | Required files exist; relative links resolve; no placeholders; no prohibited phrasing outside registered claim-control documents; one status callout in README; internal markers present; trailing newlines. | `python scripts/verify_docs.py` |
| `scripts/verify_claims.py` | Claims matrix is well-formed; every row has a valid state; `Implemented`/`Measured` rows carry locators; `Roadmap` rows carry none; documents do not assert claims absent from the matrix. | `python scripts/verify_claims.py` |
| `scripts/verify_links.sh` | Relative Markdown links and anchors across the corpus. | `bash scripts/verify_links.sh` |
| `tools/docs/verify_documentation.py` | Pre-existing prose-level boundary-language linting and required-corpus checks. Retained; not replaced. | `python tools/docs/verify_documentation.py --root . --strict` |

All four run in CI. A documentation change that fails any of them does not merge.

## 6. Review checklist

A reviewer confirms each of these before approving a documentation change:

- [ ] Every new or modified public claim has a matrix row with a state and, where required, a locator.
- [ ] No prohibited term from [Style Guide §3](STYLE_GUIDE.md#3-prohibited-language) is asserted.
- [ ] Terminology matches [Style Guide §4](STYLE_GUIDE.md#4-canonical-terminology).
- [ ] Release status appears only in [Release Status](RELEASE_STATUS.md).
- [ ] Internal documents carry the internal marker.
- [ ] Measurements carry artifact, value, date and environment.
- [ ] Unverifiable facts are marked `[UNKNOWN_MISSING_PRIMARY_SOURCE]`, not omitted or estimated.
- [ ] All four verification gates pass.

## 7. Handling disagreement about a claim

When a reviewer and an author disagree on whether evidence supports a claim, the claim is narrowed to what both accept, and the disputed portion moves to Roadmap or is marked `[UNKNOWN_MISSING_PRIMARY_SOURCE]`. Escalation to the claim owner resolves it. The default on an unresolved dispute is the narrower statement, never the broader one.

## 8. Frozen records

Files under `evidence/` are dated records of what was observed at a point in time. They are not maintained documents.

- Do not edit a dated evidence file to match current state. A record that changes is not a record.
- Correct an arithmetic or transcription error in place only when the correction is itself dated and the `.sha256` sidecar is regenerated.
- Supersede rather than rewrite: add a new dated record and link the old one.

The same applies to historical claims in maintained documents. Preserve them in their original scope and mark them superseded; do not retroactively restate what was believed at the time.

## 9. Cadence

- Claim rows are reviewed when touched, and in full before any release-candidate promotion.
- [Release Status](RELEASE_STATUS.md) is re-verified by readback before any statement that a version is published. Source metadata is never accepted as evidence of publication.
- [Unsupported Claims](institutional/UNSUPPORTED_CLAIMS.md) is append-only in practice; entries are removed only when evidence arrives that supports the claim, and the removal cites that evidence.

---

**Related:** [Style Guide](STYLE_GUIDE.md) · [Claims Matrix](CLAIMS_MATRIX.md) · [Release Status](RELEASE_STATUS.md) · [Boundaries](BOUNDARIES.md) · [Unsupported Claims](institutional/UNSUPPORTED_CLAIMS.md) · [Evidence Governance](institutional/EVIDENCE_GOVERNANCE.md)
