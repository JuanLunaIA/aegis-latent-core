# Evidence Governance

**Audience:** maintainers, auditors, anyone producing or citing a record under `evidence/`.
**Scope:** how dated evidence records are produced, frozen, cited, and superseded.
**Boundary:** this governs the repository's own evidence records. It does not govern evidence produced by a deployment, which is the operator's; see [Incident Response](../security/INCIDENT_RESPONSE.md).

---

## 1. Principle

A record that changes is not a record.

Files under `evidence/` are dated observations. They state what was true when someone looked, under conditions they described. Editing one to match current state destroys the only property that made it worth keeping.

This is the difference between the two kinds of document in this repository:

| | Maintained documents | Evidence records |
| --- | --- | --- |
| Location | `docs/`, root | `evidence/` |
| Describe | Current state | A past observation |
| On change | Updated in place | Superseded by a new record |
| Cite | Freely | With its date |

## 2. What belongs in an evidence record

A record is produced when an observation is worth being able to point at later:

- A reproduction run in a clean environment.
- A gate result before a release decision.
- A readback of external state — registries, releases, images.
- A measurement with its environment.
- An audit or review conclusion.
- An incident timeline.

A record is **not** the place for design rationale, roadmap, or claims. Those are maintained documents.

## 3. Required content

Every record states:

| Element | Why |
| --- | --- |
| **Date, UTC** | Without it the record is unusable |
| **What was observed** | The actual finding |
| **How it was observed** | Commands, environment, versions — enough to reproduce |
| **What it does not establish** | The boundary, as with any claim |
| **Who produced it** | Attribution |

The fourth is the one most often skipped. A record saying "the suite passed" without saying "in a clean container with optional backends absent, so 81 tests skipped" invites over-reading later.

## 4. Digest sidecars

Records that support a release or audit decision carry a `.sha256` sidecar:

```bash
sha256sum evidence/<record>.md > evidence/<record>.md.sha256
```

The sidecar detects accidental modification. It does not prevent deliberate modification by anyone who can also rewrite the sidecar — the same limit that applies to the forensic bundle checker. It is a tripwire, not a control.

## 5. Correcting a record

The default is: **do not edit a dated record.**

There is one narrow exception. An arithmetic or transcription error may be corrected in place when:

1. The correction is itself dated within the record.
2. The original value is preserved alongside the corrected one.
3. The `.sha256` sidecar is regenerated.
4. The correction is described in the commit message.

**Precedent from this repository.** A record stated a collected test count of 5,741 where 5,742 tests executed; the two numbers came from `--collect-only` and from the run itself. The correction led with 5,742, footnoted 5,741 with its origin, and refreshed the sidecar. Both numbers survive, because a reader encountering either elsewhere needs to know which is which.

Anything beyond an arithmetic or transcription fix is not a correction. It is a new observation, and it gets a new record.

## 6. Superseding

To record that a past observation no longer holds:

1. Write a new dated record with the current observation.
2. Link the superseded record from it.
3. Optionally add a one-line pointer in the old record — dated, not rewriting its findings.
4. Update [`evidence/INDEX.md`](../../evidence/INDEX.md).

Never delete a superseded record. The sequence of what was believed and when is often the most useful thing the directory contains.

## 7. Citing a record

Cite with the date and, where relevant, the specific value:

> The cold-start reproduction on 2026-09-01 recorded 5,661 passed, 81 skipped, 0 failed in a clean container, with skips attributed to uninstalled optional backends.

Not:

> The suite passes with 5,661 tests.

The second is stale the moment a test is added, drops the environment that explains the skips, and presents a dated observation as a standing property.

**Where two records disagree, cite both with their dates.** Statement coverage appears as 93.9096% (`coverage.json`, 2026-08-18) and 89.7169% (candidate gate, 2026-08-24). Both are real measurements from different runs. Selecting one and presenting it as "the" coverage figure would be a misrepresentation by omission.

## 8. Records are not maintained by linters

`evidence/` is excluded from the documentation gates. That is deliberate: a linter that rewrites a frozen record to satisfy a current style rule has destroyed it.

The excluding gates: `scripts/verify_docs.py`, `scripts/verify_links.sh`, and `tools/docs/verify_documentation.py`.

A consequence to accept: evidence records may contain line-range citations, superseded terminology, and phrasing that current style would reject. That is correct. They record how things were described at the time.

## 9. What evidence records do not establish

- **Not independent.** Self-produced by the project.
- **Not complete.** They record what someone looked at.
- **Not current.** By construction.
- **Not assurance.** A dated record of a passing gate is not an audit.

---

**Related:** [Evidence Index](../../evidence/INDEX.md) · [Documentation Governance](../DOCUMENTATION_GOVERNANCE.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Audit Evidence Index](../assurance/AUDIT_EVIDENCE_INDEX.md) · [Governance](../../GOVERNANCE.md)
