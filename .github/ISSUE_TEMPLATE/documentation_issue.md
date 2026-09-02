---
name: Documentation issue
about: Report an error, an overclaim, or a gap in the documentation
title: ''
labels: documentation
assignees: ''
---

<!--
Do NOT use this template for a security finding. Report those privately:
https://github.com/JuanLunaIA/aegis-latent-core/security/advisories/new

Never paste a credential, customer payload, raw WAL record, or real personal
data into a public issue.
-->

## Document

Path, and section or heading. If it is a claim, include the `CLM-NNN` identifier from [docs/CLAIMS_MATRIX.md](../../docs/CLAIMS_MATRIX.md).

## What kind of problem

- [ ] **Overclaim** — the documentation asserts more than the evidence supports
- [ ] **Factual error** — a statement about the code or its behaviour is wrong
- [ ] **Stale reference** — a path, symbol, command or version no longer exists
- [ ] **Broken link or anchor**
- [ ] **Gap** — something a reader needs is missing
- [ ] **Ambiguity** — the text supports two readings, and one of them is wrong

## What it says

Quote the passage.

## What is actually true

What the code, configuration or artifact actually does. **Cite it**: a file and symbol, a test, a command with its output, or an artifact with its date.

## Why it matters

Who would be misled, and what would they do wrong? An overclaim in a security or compliance document is more serious than an awkward sentence, and saying which this is helps triage.

---

### Overclaims are treated as defects

If documentation asserts a capability, a compliance status, or an assurance property the evidence does not support, that is a defect of the same class as a broken control — not a wording preference.

Reports of overclaiming are especially welcome. The project maintains a public claims register with evidence locators specifically so that this kind of report is possible, and **spot-checking a claim against its locator is the most useful review anyone can do here.** If a locator does not support its row, say so — that is a finding about the whole register.

See [docs/STYLE_GUIDE.md §3](../../docs/STYLE_GUIDE.md#3-prohibited-language) for the prohibited-language rules, and [docs/DOCUMENTATION_GOVERNANCE.md](../../docs/DOCUMENTATION_GOVERNANCE.md) for how claims are controlled.
