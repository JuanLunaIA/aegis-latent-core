# Governance

**Audience:** contributors, security reviewers, procurement, anyone assessing how decisions get made here.
**Scope:** who decides what, how changes are reviewed, and what controls apply to claims and releases.
**Boundary:** this describes the project's own process. It is not an assurance artifact, and following it does not constitute independent audit, certification, or third-party review.

---

## 1. Model

This is a single-maintainer project with a public contribution process. `@JuanLunaIA` is the maintainer and holds final decision authority on merges, releases, and public claims.

Stating that plainly matters more than presenting a larger structure. A reviewer assessing supply-chain risk should know that the bus factor is one, that there is no independent second approver on the critical path, and that the controls below are process controls rather than separation-of-duties controls. Those are real limitations and they belong in the record.

## 2. Roles and decision rights

| Role | Decides | Cannot |
| --- | --- | --- |
| Maintainer | Merges, releases, roadmap, public claims, enforcement | Bypass the release contract or claim gates without recording it |
| Contributor | What to propose, how to implement within review | Merge their own change |
| Security reviewer | Whether a security-relevant change is acceptable | Waive a claim boundary |
| Release owner | Whether a version may be tagged and published | Assert publication without readback |
| Claim owner | Whether evidence supports a public claim | Approve a claim with no locator |

Roles are functions, not necessarily separate people. Where one person holds several, the obligations still apply individually: wearing the release-owner hat does not let you skip the claim gate you own as claim owner.

## 3. Contribution review

Every change goes through a pull request. See [CONTRIBUTING.md](CONTRIBUTING.md) for mechanics.

A change merges when it:

1. Passes CI, including lint, typecheck, tests, security scanning, and the documentation gates in §6.
2. Carries tests for behaviour it adds or changes, including the failure path.
3. Preserves fail-closed behaviour and evidence ordering where it touches the evidence path.
4. Does not widen a public claim without a matching [Claims Matrix](docs/CLAIMS_MATRIX.md) row.
5. Does not suppress a check to pass.

**Changes that require security review** before merge: anything under `aegis/core/crypto_audit.py`, `aegis/core/mmr.py`, `aegis/auth/`, `aegis/proxy/waf.py`, `aegis/proxy/streaming.py`, the signing and key paths, the CI workflows' `permissions:` blocks, and the deployment manifests' security context or network policy.

## 4. Claims control

Public claims are governed, not editorial.

- Every public claim maps to a row in [Claims Matrix](docs/CLAIMS_MATRIX.md) with a state, an evidence locator, a boundary, and an owner.
- A claim that loses its evidence moves to [Unsupported Claims](docs/institutional/UNSUPPORTED_CLAIMS.md) rather than being deleted, so it is not reintroduced later by someone who does not know it was withdrawn.
- The five evidence states and their meanings are defined in [Style Guide §5](docs/STYLE_GUIDE.md#5-evidence-states) and are not extended informally.
- On an unresolved dispute about whether evidence supports a claim, the narrower statement wins. See [Documentation Governance §7](docs/DOCUMENTATION_GOVERNANCE.md#7-handling-disagreement-about-a-claim).

Prohibited assertions are listed in [Style Guide §3](docs/STYLE_GUIDE.md#3-prohibited-language). They are prohibited regardless of who is asking and regardless of commercial pressure.

## 5. Release policy

A release is a sequence of separately verifiable facts, not a single event.

1. **Version anchors** must agree across all fourteen anchor points before a tag is cut.
2. **The tag** is created by dispatch-only workflow, signed with Sigstore, and bound to its full target commit.
3. **Artifacts** are built only from the exact signed source, with attestations.
4. **Publication** to registries or a container registry is a further step, and is only true once readback confirms it.
5. **[Release Status](docs/RELEASE_STATUS.md) is updated** with the readback result, including negative results.

Source metadata never establishes publication. The release owner does not state that a version is published on the basis of a version number in a file.

**Rollback** is governed by [Rollback Runbook](docs/operations/ROLLBACK_RUNBOOK.md). A rollback that crosses a storage-topology change is a migration, not a revision step, and follows [Operations Playbook §6.4](docs/institutional/DOC-04_OPERATIONS_PLAYBOOK.md).

## 6. Documentation control

Documentation is gated in CI by four checkers with distinct jobs:

| Gate | Job |
| --- | --- |
| `scripts/verify_docs.py` | Required corpus, links, placeholders, prohibited phrasing, README shape, internal markers |
| `scripts/verify_claims.py` | Claims-register coherence and claim-reference integrity |
| `scripts/verify_links.sh` | Relative links and heading anchors |
| `tools/docs/verify_documentation.py` | Prose-level boundary-language linting |

The full process is in [Documentation Governance](docs/DOCUMENTATION_GOVERNANCE.md).

## 7. Security governance

- Vulnerabilities are reported privately and never in a public issue. See [SECURITY.md](SECURITY.md) and [Vulnerability Disclosure](docs/security/VULNERABILITY_DISCLOSURE.md).
- Remediation targets are best-effort in the open-source project. They become commitments only under an executed agreement.
- Incident handling follows [Incident Response](docs/security/INCIDENT_RESPONSE.md), which prioritises evidence preservation before remediation.
- Dependencies are pinned by hash in `requirements.lock`, and GitHub Actions are pinned by commit SHA. A change that unpins either requires explicit justification in the pull request.

## 8. Evidence governance

Records under `evidence/` are dated and frozen. They are not maintained documents and are not edited to match current state. See [Evidence Governance](docs/institutional/EVIDENCE_GOVERNANCE.md).

## 9. Changing this document

Governance changes are pull requests like any other, and take effect on merge. A change that reduces a control — removing a gate, widening who may merge, relaxing a claim rule — states in its description what risk it accepts and why.

---

**Related:** [Contributing](CONTRIBUTING.md) · [Code of Conduct](CODE_OF_CONDUCT.md) · [Security Policy](SECURITY.md) · [Documentation Governance](docs/DOCUMENTATION_GOVERNANCE.md) · [Claims Matrix](docs/CLAIMS_MATRIX.md) · [Release Status](docs/RELEASE_STATUS.md)
