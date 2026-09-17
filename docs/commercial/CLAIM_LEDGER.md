<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Sales Claim Ledger

**Audience:** the maintainer; any reviewer checking whether a buyer-facing statement is supportable.
**Scope:** every value, capability, pricing and assurance claim extracted from the revenue artifacts read line by line in this pass.
**Boundary:** a row here records a classification and the action taken. It does not itself license a claim — [Claims Matrix](../CLAIMS_MATRIX.md) does, and [Unsupported Claims](../institutional/UNSUPPORTED_CLAIMS.md) blocks what neither permits.

**Coverage, stated plainly:** twelve artifacts were read in full — `README.md`, `COMMERCIAL.md`, the three pricing sources, `SOFTWARE_ESCROW_POLICY.md`, `COMMERCIAL_READINESS.md`, `SUPPORT_MODEL.md`, `PRODUCT_ONE_PAGER.md`, `POSITIONING_AND_MESSAGING.md`, and both prospectuses. Eleven further artifacts were enumerated in [Artifact Inventory](ARTIFACT_INVENTORY.md) §2.4 but not claim-extracted. A ledger that implied full-corpus extraction would be the defect it exists to catch.

---

## 1. Buckets

| Bucket | Definition | Disposition |
|---|---|---|
| `BACKED` | In the Claims Matrix with a locator and a boundary | Keep; sharpen the wording, never the claim |
| `TRUE-BUT-UNINDEXED` | Real in the code, absent from the Matrix | Add the Matrix row **first**, then use it |
| `UNVALIDATED` | Price, SLA, certification, escrow, support capacity | Relabel with a visible status token |
| `OVERCLAIM` | Not supportable as written | Delete, or rewrite to the honest version |

An **understatement that is false** is classified `OVERCLAIM`. The bucket is about supportability, not direction: "published nowhere" when three registries carry the artifact fails a buyer's check exactly as a fabricated capability would, and for a product whose thesis is evidence integrity it fails worse.

---

## 2. The ledger

### 2.1 `OVERCLAIM` — rewritten to the honest version

Every row here is a statement a buyer could falsify in one command.

| # | Claim as written | Source | Why it fails | `CLM`/`UC` | Action |
|---|---|---|---|---|---|
| 1 | "these are **published list prices** — offers the vendor is making" | `commercial/ENTERPRISE_PRICING_GUIDE.md:10` | Asserts a live commercial offer. No pricing validation exists — no recorded buyer interview, no cost-to-serve model, no pilot | `UC-028`, `UC-033` | Relabelled `[HYPOTHESIS-UNVALIDATED]`; validation checklist added |
| 2 | "Nothing is published for the `5.0.0` source tree" | `enterprise/SUPPORT_MODEL.md:94` | False. `5.0.0` was read back on tag, GitHub Release, PyPI `aegis-latent-sdk`, npm, and both GHCR images on 2026-09-16 | `CLM-048` | Corrected to the readback, including the one real gap |
| 3 | "Source baseline is `5.0.0`, published nowhere" | `corporate/PRODUCT_ONE_PAGER.md:60` | Same falsehood, on the one-page asset most likely to be forwarded | `CLM-048` | Corrected |
| 4 | "Candidato de código/release: `4.1.2`… no se afirma publicación externa de `v4.1.2`" | `docs/PROSPECTUS_ES.md:13` | Two releases stale, and denies a publication read back on 2026-09-04 | `CLM-048` | Rewritten to parity with the English prospectus |
| 5 | "Published on PyPI at 4.1.2 → SDKs are at 4.0.0" | `corporate/POSITIONING_AND_MESSAGING.md:88` | The prohibited-claims table itself carries a stale fact. Both registries carry the SDK at `5.0.0` | `CLM-048` | Corrected |
| 6 | "a developer who installs `4.0.0` from PyPI and reads `4.1.2` documentation will hit a mismatch" | `corporate/POSITIONING_AND_MESSAGING.md:43` | The mismatch is real but the versions are wrong, which inverts the guidance | `CLM-048` | Corrected to the live mismatch |
| 7 | `p99 commit 836.35 ms` presented as the current backpressure result | `README.md:279` | Superseded. That run predates the coalesced group-commit engine; `CLM-034` already names the current artifacts | `CLM-034`, `UC-017` | Replaced with the current measurement, both runs cited |
| 8 | Suite counts at the `4.1.2` and `4.3.0` baselines, in a table headed "Verified metrics" | `README.md:271-272` | Neither is the current count | — | Current count added; historical rows kept and dated |
| 9 | "`mypy --strict` 0 errors over **186** files" | `README.md:274` | 206 source files now | — | Corrected |
| 10 | `docker pull ghcr.io/juanlunaia/aegis-latent-core:4.1.2` | `README.md:119` | GHCR carries `5.0.0`; the README's own §SDKs says so twenty lines later | `CLM-048` | Corrected |
| 11 | "the SDK is `4.1.2` on **both** PyPI and npm" | `enterprise/SUPPORT_MODEL.md:94` | `5.0.0` on both | `CLM-048` | Corrected |
| 12 | "On 2026-09-03 … **npm still carries `4.0.0`**, and no signature or attestation verification was run" | `COMMERCIAL.md:20` | Contradicts line 7 **of the same file**, which states the 2026-09-16 readback | `CLM-048` | Paragraph replaced |
| 13 | "Last verified: 2026-08-27" | `COMMERCIAL.md:5` | Predates two readbacks the same file cites | — | Corrected |
| 14 | "## v4.1.2 source forensic verification" | `docs/BUYER_GUIDE_US.md:101` | Section heading names a baseline its own body no longer describes | — | Corrected |
| 15 | "stores portable `aegis-mmr-inclusion-v1` proofs" | `docs/BUYER_GUIDE_US.md:103` | New chains default to `aegis-mmr-inclusion-v2` with RFC 6962 domain separation | `CLM-064` | Corrected, with the v1 compatibility position stated |
| 16 | "What **v4.1.2** source integration and evidence artifacts are available?" | `docs/FAQ_PROCUREMENT.md:69` | Same stale-heading defect | — | Corrected |
| 17 | "The source release target is `v5.0.0` … and is **published nowhere**" | `.aegis_ai_context/08_COMPONENT_PACKAGE_WORKFLOW_MATRIX.md:3` | False, in the pack agents read to learn the project's state — so the error propagates | `CLM-048` | Corrected |
| 18 | "`…aegis-latent-core:4.1.2` — **the most recent published tag**" | `docs/enterprise/ENTERPRISE_READINESS.md:29` | GHCR carries `5.0.0`, read back 2026-09-16 | `CLM-048` | Corrected, with the "a signature object is not verification" caveat added |
| 19 | `docker pull …aegis-latent-core:4.1.2` | `docs/USAGE_EXAMPLES.md:36` | Same stale tag as `README.md:119` | `CLM-048` | Corrected |

**Count: 19 `OVERCLAIM` rows. Eighteen are stale facts; one is a status misassignment. Zero were fabricated capabilities.**

Rows 17–19 were **missed by the first extraction pass** and found only by a verification grep after the corrections were applied. That is recorded rather than quietly folded in: an audit that reports its findings without reporting its own miss rate is asserting a completeness it did not demonstrate. The first pass read twelve artifacts and caught sixteen; a mechanical sweep for the same phrases across the whole corpus caught three more, one of them in the AI-context pack that other agents read to learn this project's state.

That distribution is the finding. This corpus was not overselling the product — it was **failing to keep up with it**, and in fifteen of nineteen cases the stale text understated what is true. The correction makes the documents both more accurate and stronger.

### 2.2 `UNVALIDATED` — relabelled, not deleted

| # | Claim | Source | Status label applied |
|---|---|---|---|
| 20 | SKU prices `$45,000 / $95,000 / $175,000 / $250,000–$500,000+` | `ENTERPRISE_PRICING_GUIDE.md` | `[HYPOTHESIS-UNVALIDATED]` |
| 21 | Engine add-ons `$35k / $30k / $25k / $50k` | `ENTERPRISE_PRICING_GUIDE.md` | `[HYPOTHESIS-UNVALIDATED]` |
| 22 | MGT volume tiers `$1,500 / $950 / $500` | `ENTERPRISE_PRICING_GUIDE.md` | `[HYPOTHESIS-UNVALIDATED]` |
| 23 | Professional services `$35k / $50k / $25k` | `ENTERPRISE_PRICING_GUIDE.md` | `[HYPOTHESIS-UNVALIDATED]` |
| 24 | Support severity response targets (1h / 4h / 1 business day) | `ENTERPRISE_PRICING_GUIDE.md` | `[FRAMEWORK-ONLY]` — was already "a template for negotiation"; token made explicit |
| 25 | Escrow deposit scope and release conditions | `SOFTWARE_ESCROW_POLICY.md` | `[FRAMEWORK-ONLY]` — the file already opens with "not an executed arrangement"; token made explicit |
| 26 | Commercial licence availability | `COMMERCIAL.md`, `ENTERPRISE_PRICING_GUIDE.md` | `[FRAMEWORK-ONLY]` — `CR-04` is `NOT STARTED`; **no signable template exists** |
| 27 | Five-package hypothesis (Community → Sovereign/OEM) | `COMMERCIAL.md:26-32` | `[HYPOTHESIS-UNVALIDATED]` |
| 28 | Certification posture | `SUPPORT_MODEL.md` §5, `README.md` | `[NOT-CERTIFIED]` — already stated as "does not exist"; token made explicit |

Row 26 is the one most likely to cost a deal quietly. `COMMERCIAL.md` says a commercial agreement "may be available"; `ENTERPRISE_PRICING_GUIDE.md` describes what a subscription grants. Neither says that **the licence text has not been drafted** — `COMMERCIAL_READINESS.md` `CR-04` records it as `NOT STARTED`. A buyer told the AGPL problem is solvable, who then asks to see the document, finds there is nothing to send. The corpus must say so before the buyer discovers it.

### 2.3 `CONTRADICTED` — resolved to one source of truth

| # | Conflict | Resolution |
|---|---|---|
| 29 | Three price books: `$95,000` vs `$100k–250k+` for "Enterprise", with opposite declared status | `ENTERPRISE_PRICING_GUIDE.md` becomes the sole source. `COMMERCIAL.md` and `COMMERCIAL_STRATEGY_US.md` drop their competing numbers and link to it |

### 2.4 `BACKED` — kept, wording sharpened

| # | Claim | `CLM` | Note |
|---|---|---|---|
| 30 | Evidence is durable before an admitted non-streaming response is observable | `CLM-043`, `CLM-003` | The wedge. Leads every asset |
| 31 | Portable MMR inclusion proofs verify without local MMR state | `CLM-005` | The second half of the wedge |
| 32 | Verification requires a root obtained independently of the gateway | `CLM-044` | Stated as prominently as the capability — it is what makes the proof mean anything |
| 33 | A stream reports `pending-terminal` until its terminal summary commits | `CLM-046` | |
| 34 | Refused requests are committed to the same signed chain | `CLM-060` | |
| 35 | Strict mode fails closed on missing auth, storage or signer | `CLM-002` | |
| 36 | The embedded engine applies the same WAF, redaction and ledger in-process | `CLM-061` | Carries its own boundary: cooperative code, not containment |
| 37 | `aegis-mmr-inclusion-v2` applies RFC 6962 domain separation | `CLM-064` | |
| 38 | No production SLO, uptime guarantee or capacity commitment | `CLM-051` | A negative claim, and a selling point to this buyer |
| 39 | The WAF is bounded detection, not an injection boundary | `UC-042` | |
| 40 | HMAC establishes authentication, not non-repudiation | `UC-041` | |
| 41 | Layer 2 scans raw **and** normalized text | `CLM-093` | Merged in #183 |
| 42 | Concurrent governed streams are capped; refusal is 429, not queueing | `CLM-094` | |
| 43 | Forensic bundle manifests carry an Ed25519 signature; the public key is not in the archive | `CLM-095` | |
| 44 | RFC 3161 tokens are verified as real CMS, with revocation explicitly unchecked | `CLM-096` | |

### 2.5 `TRUE-BUT-UNINDEXED`

**None found.** Every capability claim encountered in the twelve artifacts already carried a `CLM` row. No new Matrix row was required by this pass, so none was added — adding rows to appear thorough would corrupt the register this ledger depends on.

---

## 3. Summary

| Bucket | Count | Disposition |
|---|---|---|
| `BACKED` | 15 | Kept; wording sharpened |
| `TRUE-BUT-UNINDEXED` | 0 | — |
| `UNVALIDATED` | 9 | Relabelled with a visible status token |
| `CONTRADICTED` | 1 | Resolved to one source |
| `OVERCLAIM` | 19 | Rewritten to the honest version |

**Zero `OVERCLAIM` rows remain open.** Each of the nineteen is corrected in the same change that publishes this ledger; §2.1 names the file and line for verification. The check that proves it is mechanical rather than assertive: grep the corpus for each quoted string in §2.1 and the only remaining hits are this ledger, the inventory, and the Spanish prospectus's own retraction note — all three quoting the old text in order to document the correction.

---

## 4. The rule this ledger enforces going forward

A revenue-facing sentence that states a fact about publication, price, certification, support or capacity must be traceable to one of:

- a `CLM` row with a locator, or
- a readback recorded in [Release Status](../RELEASE_STATUS.md) with its date, or
- a visible `[HYPOTHESIS-UNVALIDATED]`, `[FRAMEWORK-ONLY]` or `[NOT-CERTIFIED]` token.

Anything else is unsupported and should be treated by the reader as such. **A stale fact is an unsupported claim** — the nineteen rows above are the evidence for why that has to be written down rather than assumed, and rows 17–19 are the evidence for why the check has to be mechanical rather than a careful read.

---

**Related:** [Artifact Inventory](ARTIFACT_INVENTORY.md) · [Positioning](POSITIONING.md) · [Enterprise Pricing Guide](ENTERPRISE_PRICING_GUIDE.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Unsupported Claims](../institutional/UNSUPPORTED_CLAIMS.md) · [Release Status](../RELEASE_STATUS.md)
