<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Reference and case-study template

**Status:** template. **No customer has agreed to be a reference.** Do not
publish a case study, a logo, a quote, or a metric until the customer has signed
the release in §5.

**Audience:** founder and whoever writes the first public reference.
**Scope:** the minimum structure of a truthful case study, with the fields that
must come from the customer or from a reproducible artifact.
**Boundary:** a template. Empty fields are not permission to invent a result.

## 1. Before writing

- [ ] The customer signed a paid pilot or Order.
- [ ] The customer named a business and a technical reviewer.
- [ ] The customer agreed in writing to the facts, the quote, and the logo use.
- [ ] Every number has a source the customer can reproduce.
- [ ] The security reviewer has seen the draft.
- [ ] Counsel has reviewed any claim about compliance or audit.

If any box is empty, the case study stays internal.

## 2. Structure

### Title

`[Customer] cuts [specific evidence task] from [before] to [after] with Aegis`

Do not put "revolutionary", "best-in-class", or "military-grade" in a title.

### At a glance

| Field | Value (source) |
| --- | --- |
| Customer | `[NAME]`, or "a [industry] company" if anonymous |
| Size | `[employees / revenue / requests]` (customer-confirmed) |
| Region | `[COUNTRY]` |
| Product | Aegis Latent Core `[VERSION]`, self-hosted |
| Use case | `[one sentence]` |
| Deployment | `[cloud / on-prem / BYOC]` |
| Time to first governed request | `[measured, not estimated]` |

### The problem

What did the customer have to prove, to whom, and what happened when they could
not? Use the customer's words, not a generic "AI governance is hard".

### The constraint

What made the obvious answer fail: no vendor-hosted service, data residency,
existing gateway, latency budget, audit requirement, or a certificate they did
not have.

### What they deployed

Architecture in five sentences or fewer. State what Aegis does **not** do in
this deployment.

### What changed

| Metric | Before | After | How measured | Window |
| --- | --- | --- | --- | --- |
| evidence retrieval time | `[ ]` | `[ ]` | `[customer tool / query]` | `[dates]` |
| requests governed | `[ ]` | `[ ]` | gateway counter | `[dates]` |
| verification result | `[ ]` | `[ ]` | `aegis verify` / SDK | `[date]` |
| incidents detected | `[ ]` | `[ ]` | `[customer process]` | `[dates]` |

Do not put a percentage without the numerator and denominator. "40% faster" is
not a metric; "median retrieval 14 min -> 3 min over 120 tickets" is.

### What did not change

The honest section: certifications not obtained, availability not promised,
features not used, and work still owned by the customer. This is what makes the
rest credible.

### Customer quote

A named person, their role, and a quote they approved. No quote invented by the
vendor. If the customer will not be named, say "a [role] at a [industry]
company" and keep the quote approved.

### Call to action

A 30-day evaluation, a scoped pilot, or a technical call. No "book a demo" that
promises a SaaS the product does not have.

## 3. Claims that require extra evidence

| Claim | Extra evidence |
| --- | --- |
| "reduced audit time" | customer's audit log and the before/after sample |
| "saved $X" | finance-approved calculation, stated assumptions |
| "compliant with [framework]" | do not make it; say "contributed evidence to the customer's assessment" |
| "production at scale" | request volume, duration, and the operator's architecture; not a lab test |
| "zero downtime" | monitoring data for the window; not a memory |

## 4. Anonymous case study

Allowed if the customer requires it. Replace the name with a category and remove
any detail that re-identifies them (region + size + vendor can be enough). The
customer still approves the text.

## 5. Release authorization

```
Customer legal name: ______________________
Contact and role: _________________________
Approved text version / hash: _____________
Approved logo use: yes / no
Approved quote: yes / no
Approved metrics: yes / no
Signature: _______________________________
Date: ___________________________________
```

Keep the signed release in the data room. A verbal "sure" is not a release.

## 6. Publication checklist

- [ ] signed release on file;
- [ ] every metric has a source and a window;
- [ ] no certification implied;
- [ ] no competitor disparaged;
- [ ] no customer logo without written permission;
- [ ] link to `docs/truth/PUBLIC_SURFACE_MAP.md` row added;
- [ ] `audit-claims` passes;
- [ ] counsel review for any legal/regulatory sentence.
