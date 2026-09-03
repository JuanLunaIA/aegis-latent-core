# PII Redaction Boundaries

**Audience:** privacy officers, security reviewers, developers, procurement.
**Scope:** exactly what the redaction controls detect, what they do not, and what that means for a privacy assessment.
**Boundary:** redaction here is deterministic pattern matching. It does not remove all personal data, does not implement any statutory de-identification method, and produces no compliance determination. Read this before making any privacy claim about a deployment.

---

## 1. The claim, stated precisely

> Deterministic pattern-based redaction removes matched PHI and cardholder-data patterns from governed payload fields before the evidence record is committed.

Everything outside that sentence is not claimed. In particular:

| Not claimed |
| --- |
| That all personal data is removed |
| That HIPAA Safe Harbor is implemented |
| That Expert Determination has been performed |
| That output is de-identified under any statute |
| That data sent to your model provider is protected |
| That any regulatory obligation is satisfied |

`aegis/core/phi_deidentifier.py` states this in its own module docstring: it targets textual forms associated with Safe Harbor identifier categories, and "does not implement or establish the complete 45 CFR 164.514(b)(2) Safe Harbor method, Expert Determination, or NIST SP 800-188 de-identification process."

## 2. What is implemented

### PHI de-identification

Enabled with `AEGIS_PHI_DEIDENTIFY=true`. Source: `aegis/core/phi_deidentifier.py`.

Seventeen pattern categories, each producing a `[REDACTED:<CATEGORY>]` token:

`ACCOUNT`, `ADDRESS`, `BIOMETRIC`, `DATE`, `DEVICE_ID`, `EMAIL`, `HEALTH_PLAN_ID`, `IP_ADDRESS`, `LICENSE`, `MRN`, `NAME`, `NPI`, `PHONE`, `SSN`, `URL`, `VIN`, `ZIP`

The scrubber is pure-Python, stateless and thread-safe, with no NLP dependency. `scrub_with_audit()` returns per-category hit counts, per-category confidence scores, and a UTC timestamp. **The audit record carries category metadata only — no PHI** — which is what makes it safe to retain alongside the evidence.

### Cardholder-data scrubbing

Enabled with `AEGIS_PCI_SCRUB=true`. Source: `aegis/core/pci_detector.py`.

A candidate is treated as a PAN only if it passes a **Luhn checksum** and matches a known issuer IIN range (Visa, Mastercard, Amex, Discover, Diners, JCB). Matches are masked.

The Luhn-plus-IIN gate is a precision choice: it keeps a random long number from being masked as a card. The cost is recall, discussed below.

### Where redaction applies

`aegis/proxy/app.py` walks the payload and scrubs string values under the keys `content`, `system`, and `text`. Redaction runs **before** the evidence record is committed, so the record holds the scrubbed form.

## 3. What redaction does not catch

This section is the reason the document exists.

### Structural limits

| Limit | Consequence |
| --- | --- |
| **Only visits `content`, `system`, `text`** | Personal data in any other field — a custom metadata key, a tool-call argument, a function result — is not visited and is not redacted. |
| **String values only** | Data embedded in a structure the walker does not treat as a scrubbing target passes through. |
| **Pattern matching, not comprehension** | The scrubber recognises forms, not meaning. |

### Detection limits

| Not detected | Example |
| --- | --- |
| Free-text disclosure | "the patient is the man who runs the hardware store on Third Street" |
| Paraphrase and description | An identity described rather than named |
| Indirect and quasi-identifiers | Combinations that re-identify: rare condition + employer + age |
| Non-English identifiers | National ID formats, name conventions, address forms outside the implemented patterns |
| Novel or malformed formats | An identifier written unconventionally, or split across tokens |
| Context-dependent identifiers | A number that is personal in one context and not in another |
| Images, audio, encoded blobs | Only text is scrubbed |
| PANs failing Luhn or IIN | A mistyped or non-standard card number is not masked |

### Streaming: the bounded holdback and its fail-closed edge

Streamed responses are scrubbed incrementally by `StreamingDeidentifier`, which retains a finite
suffix (`window_chars`, default 128) so an identifier split across provider chunks is matched
before any of its characters are released. When a candidate cannot settle inside that bounded
holdback, the stream **fails closed**: `StreamingDeidentificationError` is raised and the proxy
reports a `privacy_failure` terminal outcome rather than emitting text it could not finish
inspecting.

Because that failure is visible to the client, its trigger has to be precise. Each open-candidate
check now tests whether the buffered text is a **viable prefix of the detector that would redact
it** — `_TRACK1_OPEN_PREFIX` and `_TRACK2_OPEN_PREFIX` are derived from the track-data patterns
in `pci_detector`, and the email candidate is the trailing whitespace-free token, because the
`EMAIL` pattern admits no whitespace. Looser tests aborted ordinary text: any semicolon followed
by more than `window_chars` with no `?` was treated as open track data, and any `@` anywhere in
the holdback — a mentioned address, a Python decorator — was treated as an open email. Marker
searches are also case-insensitive now, matching the URL and track-1 detectors; previously an
unterminated `HTTPS://` or `%b` candidate passed the guard entirely, which was a fail-open on the
exact grammar the guard exists to catch.

**The `ADDRESS` over-trigger is now closed, at a stated cost.** That pattern allowed an unbounded
`[A-Za-z0-9 ]+` between the street number and the street-type suffix, which made any number-led
run of letters, digits and spaces a viable address prefix — so ordinary prose beginning with a
figure ("3 reasons the migration succeeded…", "In 2026, the company…") could not settle inside
the holdback and aborted the stream.

The run is bounded at **40 characters**, and the streaming guard mirrors the same bound. Forty is
measured headroom rather than a tuned constant: the longest street-name span in a sample of real
addresses was 18 characters (`500 South Buena Vista Street`), so the bound is 2.2× the observed
maximum. It also makes the abort structurally unreachable — a viable candidate is at most 46
characters, below the 64-character minimum `window_chars`, so an address candidate always fits
the smallest permitted holdback.

**What this costs.** A street name longer than 40 characters between the number and the street
type is no longer matched, and therefore no longer redacted, in the streaming *and* non-streaming
paths alike. That is a recall reduction at the far tail of the street-name length distribution,
accepted deliberately because aborting every stream of number-led prose was judged the worse
failure. `tests/test_phi_address_bound.py` asserts the cost directly, so it cannot be forgotten:
one test proves a long street name passes through unredacted.

**Separately, and pre-existing:** the street-type list does not include every suffix. `Plaza` and
`Pike` are absent, so `30 Rockefeller Plaza` and `8600 Rockville Pike` are not matched — before or
after the bound. That gap is recorded in the same test file.

### The re-identification limit

Removing the seventeen listed categories does not make text non-identifying. Re-identification from residual detail is well documented in the de-identification literature, and a regex scrubber does nothing about it. **Do not treat scrubbed output as de-identified data.**

## 4. The limit that surprises people

**Redaction protects the evidence record. It does not protect your model provider.**

```
caller ──► gateway ──── request sent as received ────► provider
              │
              └──► redact ──► commit evidence record
```

The request reaches the upstream provider before redaction touches anything. If a caller sends a Social Security number, the provider received that Social Security number. Redaction changes what is written to the WAL; it cannot change what has already crossed the network.

If your privacy position depends on the provider not receiving personal data, redaction is the wrong control. You need input filtering before the gateway, or a provider agreement that covers it.

## 5. Consequences for a privacy assessment

| Question | Answer |
| --- | --- |
| Does enabling redaction make us HIPAA compliant? | No. It contributes a technical control. Compliance is an organisational determination. See [HIPAA Technical Inputs](../compliance/HIPAA_TECHNICAL_INPUTS.md). |
| Is scrubbed output de-identified? | No. It is text with matched patterns removed. |
| Can we skip a DPIA because redaction is on? | No. This document makes no determination about your obligations. |
| Does redaction reduce risk? | Yes, for the categories it matches, in the fields it visits, in the evidence record. That is a real but bounded benefit. |
| Can we tell what was redacted? | Yes — category counts and confidence, without the values, via `scrub_with_audit()`. |
| What if we need a category that is not implemented? | It is not implemented. Do not assume coverage; test it. Adding a pattern class is a feature request. |

## 6. Verifying coverage for your data

Do not assume. Measure, with synthetic data only:

1. Build a representative synthetic corpus containing the identifier forms your traffic actually carries.
2. Run it through the scrubber and count what survives, per category.
3. Test the fields your payloads use, not only `content`.
4. Record the result, dated, with the corpus version.
5. Repeat when your traffic shape changes.

**Never use real personal data to test redaction coverage.** Testing a redaction control by feeding it live personal data creates the exposure the control exists to reduce.

The measured recall of this scrubber against your traffic is `[UNKNOWN_MISSING_PRIMARY_SOURCE]` — no such measurement exists in this repository, for any corpus.

## 7. Related controls

Redaction is one control among several, and the others carry their own limits:

- **Retention** — [Data Retention](DATA_RETENTION.md). Redaction reduces what is stored; retention decides how long.
- **Logging** — payloads are not logged by default and must not be enabled. See [Monitoring and Alerting](../operations/MONITORING_ALERTING.md).
- **Export** — a forensic bundle contains records as written, subject to whatever redaction was configured at write time. See [Forensic Export](../api/FORENSIC_EXPORT.md).
- **Access** — `audit:read` and `audit:export` gate who reads records. See [Audit Endpoints](../api/AUDIT_ENDPOINTS.md).

Note the interaction: **records written before redaction was enabled are unredacted, permanently.** Enabling the control does not retroactively scrub the chain, and the chain is append-only, so it cannot.

---

**Related:** [Data Retention](DATA_RETENTION.md) · [Data Processing Checklist](DATA_PROCESSING_CHECKLIST.md) · [HIPAA Technical Inputs](../compliance/HIPAA_TECHNICAL_INPUTS.md) · [Compliance Mapping](../compliance/COMPLIANCE_MAPPING.md) · [Security Controls](../security/SECURITY_CONTROLS.md) · [Boundaries](../BOUNDARIES.md)
