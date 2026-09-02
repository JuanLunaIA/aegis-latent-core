# Documentation Style Guide

**Audience:** anyone writing or reviewing documentation in this repository.
**Scope:** every Markdown file tracked in this repository except vendored third-party content and dated files under `evidence/`, which are frozen records.
**Enforcement:** [`scripts/verify_docs.py`](../scripts/verify_docs.py) checks the mechanical rules. The judgement rules are enforced at review, under [Documentation Governance](DOCUMENTATION_GOVERNANCE.md).

---

## 1. Why this guide exists

This project's product is evidence. A document that overstates a control is not a marketing problem here; it is the same category of defect as code that claims to hold a lock it never acquired. The rules below exist to keep prose and implementation in the same state.

## 2. Voice and construction

Write in active voice. Name the actor.

| Prefer | Avoid |
| --- | --- |
| The gateway commits the node before returning the response. | The node is committed before the response is returned. |
| Set `AEGIS_SIGNING_KEY` before starting a governed deployment. | It is recommended that a signing key be configured. |
| `flock` is advisory, so it does not constrain a writer reaching the same inode by another path. | Note that certain limitations may apply in some environments. |

Additional rules:

- State a limit once, in the place a reader needs it. Do not restate the same disclaimer in every section; link to [Boundaries](BOUNDARIES.md) instead.
- Do not repeat release-status information outside [Release Status](RELEASE_STATUS.md). Other documents link to it.
- Do not hedge a fact you have verified. "The suite passes" is correct if it passes; "the suite should generally pass" is not more careful, it is less useful.
- Do not apologise for limitations. Record them.

## 3. Prohibited language

### 3.1 Marketing superlatives

Never use: `revolutionary`, `game-changing`, `best-in-class`, `unmatched`, `world-class`, `cutting-edge`, `top #1`, `market-leading`, `guaranteed`.

### 3.2 Assurance and legal terms

Never assert, in any public document:

| Prohibited assertion | Why | Say instead |
| --- | --- | --- |
| certified, SOC 2 / ISO 27001 / HIPAA / FedRAMP / PCI compliant | No independent audit exists. | "contributes technical inputs that an assessor may evaluate" |
| legally admissible | Admissibility is a judicial determination. | "technical integrity evidence; admissibility requires qualified legal review" |
| immutable | Rotation applies `0o600` and renames; a privileged actor can still alter files. | "append-only within the process; external immutability requires a storage control" |
| WORM | The repository ships an S3 Object Lock adapter, not a WORM guarantee. | "can target an S3 Object Lock bucket, subject to target-bucket configuration" |
| production-ready | No target deployment acceptance exists. | "source baseline; target acceptance required" |
| guaranteed prompt-injection prevention | Detection is heuristic. | "bounded heuristic detection over a pinned corpus" |
| removes all PII | Redaction is deterministic pattern matching. | "best-effort deterministic redaction; see [PII Redaction Boundaries](privacy/PII_REDACTION_BOUNDARIES.md)" |

These terms may appear when the sentence is explicitly denying them, quoting a prohibited claim, or defining the rule — as this table does. `scripts/verify_docs.py` allows that only in files registered as claim-control documents.

## 4. Canonical terminology

Use these exact terms. Do not introduce synonyms.

| Term | Meaning | Not |
| --- | --- | --- |
| gateway | the `aegis` proxy process | server, proxy service, engine |
| WAL | the authoritative JSONL write-ahead log | ledger file, journal, log |
| MMR inclusion proof | a proof that a disclosed leaf is in a Merkle Mountain Range under a given root | merkle proof, receipt |
| trusted root | an MMR root the verifier obtained independently of the gateway serving the proof | known root, anchor |
| evidence status | the per-response state: `durable`, `pending-terminal`, or absent | proof status |
| governed call | a request admitted by the gateway and carried through the evidence path | request, transaction |
| pending-terminal | an SSE stream whose terminal summary has not yet committed | in-flight, provisional |
| durable | committed, flushed and `fsync`-ed to the WAL | persisted, saved |
| `audit:read` | scope permitting read access to audit endpoints | read scope |
| `audit:export` | scope permitting forensic bundle export | export scope |

Write `fsync`, `flock`, and environment variable names in backticks. Write frameworks as their official names: `EU AI Act`, `HIPAA`, `MiFID II`, `ISO/IEC 27037`.

## 5. Evidence states

Every public claim carries exactly one state. Definitions are normative and shared with [Claims Matrix](CLAIMS_MATRIX.md).

| State | Means | Requires |
| --- | --- | --- |
| **Implemented** | The behaviour exists in the checked-out source. | A source path, and a test that exercises it. |
| **Measured** | A number was observed in a named environment. | The artifact holding the number, its date, and the environment. |
| **Configuration-dependent** | The behaviour depends on deployment configuration the repository does not control. | The configuration surface, plus what the target must accept. |
| **Roadmap** | Not implemented. | No evidence locator; must not appear in present tense. |
| **Legal-review-required** | The statement is a legal conclusion, not a technical one. | An explicit deferral to qualified counsel. |

`Implemented` describes source, not distribution. Source metadata never establishes that a tag, release, registry package, or image exists; that requires readback per [Release Status](RELEASE_STATUS.md).

## 6. Structure

Every document opens with:

```markdown
# Title

**Audience:** who this is for.
**Scope:** what it covers.
**Boundary:** what it does not establish.
```

Then content. Documents that discuss limits link to [Boundaries](BOUNDARIES.md) or [Claims Matrix](CLAIMS_MATRIX.md).

Use ATX headings (`##`), sentence case, and no skipped levels. Prefer tables over long bullet lists when rows share a shape. Keep code blocks runnable: a reader must be able to paste and execute without editing, or the block must say which values to replace.

## 7. Links and paths

- Use relative links from the file's own location: `[Boundaries](BOUNDARIES.md)`, `[SECURITY](../SECURITY.md)`.
- Never link to a line range in source from prose that will drift. Cite the file and the symbol: `aegis/core/crypto_audit.py` (`_lock_wal_fd`). Line ranges are acceptable only in dated evidence records, which are frozen.
- Every relative link must resolve. `scripts/verify_links.sh` fails the build otherwise.

## 8. Dates and numbers

- Dates are UTC, `YYYY-MM-DD`. No locale formats.
- Quote a measurement with its artifact and date: "93.9096% statement coverage (`coverage.json`, 2026-08-18)". A bare percentage is not a measurement.
- When two runs disagree, record both with their dates rather than picking one.

## 9. Internal documents

A document that carries commercial hypotheses, pricing models, or positioning is internal. It must begin with this exact line, before the title:

```markdown
> **INTERNAL DOCUMENT — NOT FOR EXTERNAL DISTRIBUTION**
```

`scripts/verify_docs.py` requires that marker on every file registered as internal, and forbids internal pricing ranges from appearing in `README.md`.

## 10. Unknowns

If a fact cannot be established from repository evidence or readback, write:

```
[UNKNOWN_MISSING_PRIMARY_SOURCE]
```

Do not estimate, do not infer from a related number, and do not omit the row. An explicit unknown is a usable audit finding; a plausible invention is not.

## 11. Prohibited placeholders

Final documentation contains no `TODO`, `TBD`, `FIXME`, `XXX`, `Lorem ipsum`, `Coming soon`, or empty section stubs. Either write the content, mark it `[UNKNOWN_MISSING_PRIMARY_SOURCE]`, or move the item to [Roadmap](../ROADMAP.md).

---

**Related:** [Documentation Governance](DOCUMENTATION_GOVERNANCE.md) · [Claims Matrix](CLAIMS_MATRIX.md) · [Boundaries](BOUNDARIES.md) · [Unsupported Claims](institutional/UNSUPPORTED_CLAIMS.md)
