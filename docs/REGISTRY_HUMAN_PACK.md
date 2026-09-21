<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Registry — Human Handoff Pack

**Audience:** the founder. Nobody else can execute any item in this file.
**Scope:** the ten `REG-Hxx` items from the master registry that require a signature, a purchase order, or another person.
**Boundary:** this file records *intent, cost estimates and vendor candidates*. Nothing here has happened. Every item is `NOT STARTED` unless a linked artifact says otherwise, and naming a vendor is not a relationship with them.

> ## No code REG substitutes for any HUMAN REG
>
> This is the point of keeping them in a separate file. An agent can close a `CLM` row, wire a scanner, or fix a race. It cannot commission a penetration test, sign an escrow agreement, form a company, or hire an engineer. Conflating the two produces a roadmap that looks closeable and is not.
>
> These ten also gate more of the product's public language than all the code items combined. Until `REG-H01` completes, **no document may say "externally assessed", "pen-tested", or "independently reviewed"** — see [Unsupported Claims](institutional/UNSUPPORTED_CLAIMS.md).

---

## Two inputs this pack could not verify

`PD-R3` requires evidence or the claim does not stand. Two figures arrived with the directive that commissioned this pack and **appear nowhere in this repository**:

| Supplied | Verification status |
|---|---|
| Azure burn model: **$17.54/mo typical, $44.77/mo worst; runway 11.4 / 4.5 months** | **UNVERIFIED.** No such figure exists anywhere in the corpus — `grep` for `17.54`, `44.77`, `runway` returns nothing. Recorded as an owner-supplied planning input, not a measurement |
| `deploy/azure/phase0/phase0_guardrails.sh` on tenant `8c1e7bd7-…` | **NOT IN REPOSITORY.** `deploy/azure/` contains only `aks/`. There is no `phase0/` directory and no such script. `REG-H07` cannot be executed against this tree as written |

Both are stated rather than silently carried, because a handoff pack that passes an unverified number through to a budget decision is the failure mode the registry exists to prevent.

---

## REG-H01 — Independent penetration test

| | |
|---|---|
| **Severity** | CRITICAL |
| **Cost** | $15,000–25,000 |
| **Timeline** | 4–6 weeks |
| **Vendors** | Cure53 · NCC Group · Trail of Bits |
| **Tracked as** | `CR-01` |

**Checklist**

1. Scope it to the **evidence path**, not the WAF. A test scoped to "can you bypass the WAF" will succeed and teach you nothing — it is a finite pattern set by design (`UC-042`).
2. Name the three questions that matter: can a response be emitted without a durable commit; can a receipt be forged; can one tenant read another's records.
3. Require a published report and a remediation record per finding.

**Unblocks:** any "externally assessed" or "independently reviewed" language. It is the single most common request in a security questionnaire.

## REG-H02 — SOC 2 Type I

| | |
|---|---|
| **Severity** | CRITICAL |
| **Cost** | $20,000–80,000/yr (platform + audit) |
| **Timeline** | 3–6 months |
| **Vendors** | Vanta · Drata, plus an independent auditor |
| **Tracked as** | `CR-02` |

**Checklist**

1. Platform first; auditor second.
2. Understand what you are buying: Type I attests controls were **designed** appropriately at a point in time. Type II attests they **operated** over a period, and cannot start until Type I exists.

**Unblocks:** most enterprise procurement, which treats its absence as disqualifying rather than negotiable.

## REG-H03 — Escrow execution

| | |
|---|---|
| **Severity** | CRITICAL |
| **Cost** | $5,000–10,000 to establish |
| **Timeline** | 2–4 weeks |
| **Vendors** | NCC Group · Escrow London — **neither has been engaged** |
| **Tracked as** | `CR-03` |

**Checklist**

1. Execute a tri-party agreement — vendor, buyer, agent.
2. **Insist on a verification exercise:** the agent independently rebuilds a working artifact from the deposit. An unverified deposit is a box of files, and unverified deposits are the normal failure mode of software escrow.
3. Do **not** deposit the Ed25519 licence-signing private key. Deposit the custody procedure.

**Unblocks:** the bus-factor objection, partially. It addresses artifacts, not maintainer capacity — that is `REG-H05`.

## REG-H04 — Commercial licence counsel + open-core decision

| | |
|---|---|
| **Severity** | HIGH |
| **Cost** | $3,000–5,000 |
| **Timeline** | 2–4 weeks |
| **Vendors** | Qualified software-licensing counsel |
| **Tracked as** | `CR-04` |

**Checklist**

1. Draft the commercial licence that sits beside AGPLv3.
2. Decide the open-core boundary — currently **no feature is withheld by a runtime check**, and that is a deliberate legal position worth preserving explicitly.

**Unblocks:** every AGPL-blocked buyer. **Today there is nothing to send them** — the template does not exist, and `ENTERPRISE_PRICING_GUIDE.md` now says so beside the model that depends on it.

## REG-H05 — Second maintainer

| | |
|---|---|
| **Severity** | CRITICAL |
| **Cost** | $150,000–250,000/yr |
| **Timeline** | 2–4 months |
| **Tracked as** | `CR-06` |

**Checklist**

1. Hire a senior systems or cryptography engineer.
2. **The acceptance test is real:** they ship a security fix end to end — triage, patch, review, release, publish — **without the founder in the loop**. Anything short of that is bus factor one with extra headcount.

**Unblocks:** the `CRITICAL` finding every audit has raised, and any staffed support commitment. A response-time SLA is arithmetic a single maintainer cannot satisfy.

## REG-H06 — Three buyer interviews + one paid pilot

| | |
|---|---|
| **Severity** | CRITICAL |
| **Cost** | $0 direct; founder time |
| **Timeline** | 2–3 months to first signature |
| **Tracked as** | `CR-05` + `CR-07` |

**Checklist**

1. Identify 5–10 mid-market fintech or healthtech companies with a **statutory** evidence requirement. Qualify on the obligation and a named owner, never on interest.
2. Offer a paid pilot — [Pilot Proposal](commercial/SALES_KIT/PILOT_PROPOSAL.md). Insist on the failure tests.
3. Record what each buyer would pay and what they compared against.

**Unblocks:** everything downstream. It removes `[HYPOTHESIS-UNVALIDATED]` from every figure in the pricing guide, makes `REG-H01` and `REG-H02` rational spends rather than speculative ones, and is the only item that produces revenue.

**This is the one to do first.** The other eight are largely consequences of it.

## REG-H07 — Azure Phase-0 guardrails

| | |
|---|---|
| **Severity** | HIGH |
| **Status** | **CANNOT EXECUTE AS WRITTEN** |

`deploy/azure/phase0/phase0_guardrails.sh` **does not exist in this repository.** `deploy/azure/` contains only `aks/`, whose `bootstrap.sh` is the AKS provisioning path.

**Owner action:** supply the Phase-0 kit, or restate the item against `deploy/azure/aks/bootstrap.sh`, which does exist and carries its own cost annotations. The tenant identifier supplied with this item is recorded as given and was not resolved or verified.

**Unblocks:** Azure Phase 1, per the directive that named it.

## REG-H08 — HSM / Key Vault procurement decision

| | |
|---|---|
| **Severity** | MEDIUM |
| **Cost** | Managed HSM quoted at $2.34k/mo — **as supplied, not verified here** |
| **Tracked as** | related to `UC-041` |

**Checklist**

1. Decide between Managed HSM, standard Key Vault, and staying on the software path.
2. Understand what it buys: it is the difference between `SYMMETRIC_AUTHENTICATED` and an asymmetric tier — **the difference between authenticating a key and attributing a record to a party** (`UC-041`, `CLM-090`).

**Unblocks:** any non-repudiation position. Until then the default HMAC chain means any key holder can forge, and the documentation says so.

## REG-H09 — Corporate entity formation

| | |
|---|---|
| **Severity** | HIGH |
| **Cost** | Jurisdiction-dependent |
| **Checklist** | Form the entity; align it with `REG-H04`'s licensing work; it is the counterparty every commercial agreement needs |

**Unblocks:** signing anything at all.

---

## REG-H10 — Regulatory counsel review: MiFID II / MAR input modules and the SMCR reference

| | |
|---|---|
| **Severity** | MEDIUM |
| **Cost** | $1,500–4,000 |
| **Timeline** | 2–4 weeks |
| **Vendors** | Regulatory counsel with UK FCA / EU MiFID II experience |
| **Tracked as** | `AUD-20` (closed on the repository side) |

**Checklist**

1. Confirm the retention statement `aegis/core/mifid_record_keeper.py` and `CLM-104` now carry: MiFID II Art. 16(6)/25(1) is a **five-year** minimum, extendable to seven at a competent authority's request — not a seven-year default.
2. Decide the **UK SMCR** question the module explicitly puts outside its scope: whether an SMCR-scope firm would have a retention period this module cannot serve, and if so, whether that belongs in the module's docstring, its CLM row, or neither.
3. Confirm the market-abuse citation split in `CLM-103` (MAR Art. 12(1)(a)(ii) for spoofing; MiFID II Art. 12 is "Assessment period") and that no document may read either module as monitoring coverage.

**Unblocks:** the last unverified legal statement in the repository's MiFID II / MAR surfaces. Until it completes, `CLM-103`/`CLM-104` and `UC-056` carry the contribute-technical-inputs framing, and `docs/compliance/MIFID_II_TECHNICAL_INPUTS.md` keeps its "Not a MiFID II compliance statement" boundary.

**Note:** this is a *wording* review. The wiring-or-retire decision for the two modules is `AUD-36`, which is code work and does not wait on counsel.

---

## Ordering

```
REG-H06 (design partner + pilot)
   ├──> removes [HYPOTHESIS-UNVALIDATED] from pricing
   ├──> makes REG-H01 / REG-H02 rational spends
   └──> REG-H09 (entity) ──> REG-H04 (licence) ──> first signature
                                   └──> REG-H03 (escrow), REG-H05 (2nd maintainer)
```

`REG-H07` and `REG-H08` are independent and can run in parallel whenever infrastructure work resumes. `REG-H10` is independent too and can ride along with the next counsel engagement (`REG-H04`).

---

**Related:** [Master Registry](REGISTRY.md) · [Commercial Readiness](commercial/COMMERCIAL_READINESS.md) · [Software Escrow Policy](commercial/SOFTWARE_ESCROW_POLICY.md) · [Objection Handling](commercial/SALES_KIT/OBJECTION_HANDLING.md) · [Unsupported Claims](institutional/UNSUPPORTED_CLAIMS.md)
