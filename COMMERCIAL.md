<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core — Commercial Licensing & Enterprise Offerings

Aegis Latent Core is dual-licensed under **AGPLv3** (open-source) and a
**Commercial License** for closed-source, proprietary, and enterprise deployments. This
document covers: why the AGPL creates a hard commercial obligation, what tiers
are available, how they are priced, automated delivery mechanics, and how to procure.

---

## Part I — Intellectual Property & Ownership

**Sole copyright holder.** Aegis Latent Core is the original work of
**Juan Luna** (`juan.c.luna04@gmail.com`), who holds sole, undivided copyright in the
project. See `NOTICE` and `AUTHORS`.

**Exclusive right to commercialize.** As the sole copyright holder, Juan Luna
reserves the exclusive right to license the software under proprietary
commercial terms, to sublicense it, and to sell it as a component of
closed-source, embedded, or managed offerings. The AGPLv3 grant to the public does not
diminish this right.

**Contributions are license-aligned.** All contributions are accepted under
the DCO + CLA in `CONTRIBUTING.md`, which grants Juan Luna a perpetual,
irrevocable, worldwide, royalty-free, sublicensable license to relicense
contributed code under both the AGPLv3 and commercial terms. Contributors
retain ownership of their own contributions; the maintainer retains sole
copyright in the project as a whole.

**Trademark.** The "Aegis Latent Core" name and logo are not licensed under
the AGPLv3 and may not be used to imply endorsement without written permission.

---

## Part II — The AGPL Copyleft Obligation (Why Enterprises Must License)

The **GNU Affero General Public License v3 (AGPL-3.0-only)** contains a
network-use clause — **§13** — that the standard GPL does not:

> *"If you modify the Program, your modified version must prominently offer all
> users interacting with it remotely through a computer network … an
> opportunity to receive the Corresponding Source of your version."*

### When §13 Triggers

§13 is triggered the moment an organization:

1. **Modifies** Aegis Latent Core in any way (configuration is modification;
   so is wrapping it in a new service layer, or passing proprietary prompts), **AND**
2. **Operates it over a network** — including internal corporate networks, even
   if no external users interact with the service directly.

This is not a theoretical edge case. Every production deployment of Aegis
falls under scenario (2). Any organization that (a) modifies the source or
(b) cannot legally disclose its proprietary modifications as AGPL source must
obtain a commercial license.

### The Mathematical Forcing Function

The AGPL creates an **economically forced choice**:

```
IF  deploy_aegis AND (modify_source OR cannot_disclose_modifications_or_prompts)
THEN
    EITHER  publish all proprietary source code & prompts under AGPL-3.0
    OR      purchase a commercial license
```

There is no third option. The "we'll just use it quietly" path is a copyright
violation with the sole copyright holder as the injured party — making
enforcement unambiguous and recovery straightforward under 17 U.S.C. § 504
(actual damages + lost profits, or statutory damages up to $150,000 per
willful infringement).

### Practical Disclosure Requirement

An enterprise operating Aegis without a commercial license must, on request
from any network user, provide the complete Corresponding Source of their
version of Aegis — including:

- All proprietary prompt engineering / system prompts passed through the proxy.
- All custom WAF rule additions and threat models.
- All internal configuration files that materially alter behavior.
- Any internal tooling or orchestration frameworks that wrap or extend the proxy.

For most enterprises, this is not commercially viable. The commercial license
eliminates the obligation entirely.

---

## Part III — License Tiers & Pricing

All tiers (except Enterprise and Sovereign) feature **fully automated checkout and zero-touch license key delivery** via our Merchant of Record (LemonSqueezy/Stripe) integrated with Keygen.sh. Enterprise and Sovereign tiers are available via invoice.

---

### Tier 0 — Evaluation / Developer (Free)

**Who it's for:** Individual engineers, PoC assessments, internal non-production demos,
and sandbox testing. **Not for production** — no SLA, no compliance
artifacts.

| Feature | Included |
|---------|----------|
| Full AGPLv3 source access | Yes |
| Evaluation use (non-production) | Yes |
| Community support (GitHub Issues) | Yes |
| Email installation support | Yes — best-effort, 5 business days |
| Production deployment rights | **No** — commercial license required |
| SLA / security patch stream | No |
| Compliance export artifacts | No |

**License:** AGPLv3 only. No proprietary modifications permitted.

---

### Tier 1 — Professional (Self-Serve) — $99 / month or $948 / year

**Who it's for:** Startups, independent developers, and small software teams deploying Aegis as a closed-source component in a single product. Under 500,000 requests/month aggregate.

| Feature | Included |
|---------|----------|
| Commercial License (closed-source, single org) | Yes — AGPLv3 Exemption |
| Production deployment rights | Yes — max 1 active production instance |
| Automated License Delivery | Yes — instant key via LemonSqueezy/Stripe + Keygen.sh |
| Monthly request quota | 500,000 requests/month |
| Email / Discord support | 72-hour response target (business hours) |
| Security patch stream | 72-hour notification for critical CVEs |
| Basic WAF & Rate Limiting | Yes |
| Compliance export artifacts | No |

**Overage:** requests/month > 500,000 → Tier 2 required.

---

### Tier 2 — Business (SME / Growth) — $299 / month or $2,988 / year

**Who it's for:** Growing mid-market and small-to-medium enterprise (SME) organizations requiring basic regulatory compliance presets and cardholder-data scrubbing without dedicated contract negotiation.

| Feature | Included |
|---------|----------|
| Commercial License (closed-source, single org) | Yes — AGPLv3 Exemption |
| Production deployment rights | Yes — max 3 active production instances |
| Automated License Delivery | Yes — instant key via LemonSqueezy/Stripe + Keygen.sh |
| Monthly request quota | 2,000,000 requests/month |
| Regulatory Presets | Yes — HIPAA Safe Harbor, SEC Rule 17a-4, PCI-DSS v4.0 |
| PCI-DSS PAN/CVV Masking | Yes — `AEGIS_PCI_SCRUB=true` |
| HIPAA PHI De-identification | Yes — `AEGIS_PHI_DEIDENTIFY=true` |
| Email / Discord support | 24-hour response target (business hours) |
| Security patch stream | 48-hour critical CVE notification + patch |
| Compliance export artifacts | No |

**Overage:** requests/month > 2,000,000 → Tier 3 required.

---

### Tier 3 — Corporate Enterprise — $29,900 / year

**Who it's for:** Mid-market and enterprise organizations that need verifiable
SOC 2 / HIPAA / ISO 27001 compliance artifacts and unlimited replication capacity without committing to a dedicated, high-touch support engagement. Onboarding is self-service; there is no scheduled direct-access to the maintainer.

| Feature | Included |
|---------|----------|
| Commercial license (closed-source, unlimited nodes, single enterprise) | Yes — AGPLv3 Exemption |
| Production deployment rights | Yes — unlimited replicas within licensed entity |
| Payment terms | Invoice (net-30 or net-60 available) |
| Security patch stream | 48-hour critical CVE notification + patch |
| Monthly patch releases | Yes |
| Documentation portal access | Yes — private compliance runbooks, Helm playbooks, vertical-specific guides |
| Annual signed SBOM (CycloneDX + SPDX) | Yes |
| Reproducible build attestation (SLSA Level 2) | Yes |
| Sealed compliance bundle templates (SOC 2, HIPAA, ISO 27001) | Yes — JSON, PKCS#7, EWF/E01 formats |
| Automated compliance export scripts | Yes |
| GitHub Security Advisory notifications | Yes (private advisory channel) |
| Email support | 24-hour response target (business hours) |
| Direct-access SLA (phone / video calls) | **No** — documentation-only |
| On-site or bespoke onboarding | **No** |

**Sub-processor agreement:** A DPA (Data Processing Addendum) and standard
sub-processor addendum are available on request for GDPR Article 28 / HIPAA
BAA requirements.

---

### Tier 4 — Premium Sovereign — $150,000 / year base (Negotiated)

**Who it's for:** Defense contractors, government agencies, financial
institutions under MiFID II / SEC Rule 17a-4, healthcare systems under
HIPAA / 21 CFR Part 11, and any organization where an AI governance failure
has material legal or national-security consequences. Direct technical access
to the founder-architect is included and justified by the deployment stakes.

The base price is the floor. Multi-year, high-QPS, air-gapped, or DoD IL5/IL6
deployments are scoped separately. The base price justifies a maximum of 48
hours/year of direct founder time; additional engagement is billed at $5,000/
day or included in a scoped SOW.

| Feature | Included |
|---------|----------|
| Commercial license (closed-source, unlimited nodes, unlimited subsidiaries within licensed group) | Yes — AGPLv3 Exemption |
| Production deployment rights | Yes |
| Security patch stream | 4-hour critical CVE notification; 1 business day patch target |
| Priority patch releases | Yes — out-of-band for P0 vulnerabilities |
| Direct founder access (SLA) | **Yes** — P1 ack within 4 hours (business hours); escalation path documented |
| On-boarding sessions | Yes — up to 4 remote sessions (90 min each) in year 1 |
| Architecture review | Yes — 1 deep-dive session per year (remote or on-site within CONUS) |
| Air-gap / FIPS 140-3 deployment packaging | Yes — static binaries, offline installation bundles |
| Signed SBOM (CycloneDX + SPDX), reproducible attestation | Yes — per-release |
| Sealed compliance bundle (PKCS#7 CMS, EWF/E01, archival) | Yes — quarterly automated exports |
| Vertical-specific compliance evidence packs | Yes — SEC 17a-4 WORM, HIPAA, FedRAMP High, DoD IL5, Daubert |
| Custom Helm values / AppArmor / seccomp profiles | Yes — delivered as part of onboarding |
| Private security advisory channel (24×7 escalation) | Yes |
| BAA / DPA / sub-processor agreement | Yes — standard forms provided; custom review billable |
| Quarterly executive briefing (threat landscape, roadmap) | Yes |
| NDA, MSA, and procurement-ready SOW | Yes — standard forms; legal customization billable |

**Optional add-ons (priced per SOW):**

| Add-on | Indicative Price |
|--------|-----------------|
| On-site deployment (travel + 2 days) | $12,000 + travel |
| Custom feature development | $5,000/day, 5-day minimum |
| Private fork with enterprise backport track | From $50,000/yr |
| 24×7 on-call pager rotation (≤ 15 min MTTRS) | $75,000/yr |
| FedRAMP / DoD IL5 accreditation support (documentation, artifacts) | Scoped per engagement |
| Formal verification / FIPS 140-3 validation coordination | Scoped per engagement |

---

### Tier 5 — OEM / Embedded (Negotiated)

**Who it's for:** Technology vendors who wish to redistribute Aegis as a
component of their own product — bundled, white-labeled, or as an OEM module.

OEM licenses require a bespoke MSA covering:

- White-labeling rights (use of "Aegis" trade name: excluded unless licensed)
- Redistribution rights (sublicensing to customers)
- Extended indemnities and IP warranties
- Audit rights and source escrow
- Per-unit or per-seat royalty structure vs. flat license
- Export control compliance (EAR, ITAR where applicable)

**Contact for OEM pricing:** juan.c.luna04@gmail.com — include intended
product, target market, estimated distribution volume, and timeline.

---

## Part IV — SLA Definitions and Escalation Matrix

| Severity | Definition | Tier 1 | Tier 2 | Tier 3 | Tier 4 |
|---------|-----------|--------|--------|--------|--------|
| **P0 — System Down** | Proxy completely unavailable; audit chain not persisting | Email 72h | Email 48h | Email 24h | Pager / email 4h ack |
| **P1 — Critical Security** | Exploitable vulnerability in auth, WAF, or audit chain | Patch notification 72h | Patch notification 48h | Patch notification 48h | Notification 4h; patch target 1 BD |
| **P2 — Degraded** | Non-critical functional defect; workaround available | Next monthly release | Next monthly release | Next monthly release | Next patch release (≤ 14 days) |
| **P3 — Advisory** | Performance, documentation, configuration guidance | Community (Discord) | Email / Discord 48h | Documentation portal | Email; 24h response |

**SLA clock runs business days (Monday–Friday, 09:00–17:00 US Eastern),
excluding US federal holidays**, unless a 24×7 add-on is contracted.

---

## Part V — Engagement and Procurement Process

### For Tier 1 and Tier 2 (Self-Serve)

1. **Instant Purchase:** Navigate to our self-serve checkout page (powered by LemonSqueezy/Stripe).
2. **Automated License Generation:** Upon successful payment processing, LemonSqueezy triggers a secure webhook to our serverless handler.
3. **Key Provisioning:** A cryptographically signed license key is generated via Keygen.sh and bound to your email address and chosen policy.
4. **Immediate Delivery:** The key and private binary download instructions are sent to your inbox within seconds.
5. **Activation:** Set `AEGIS_LICENSE_KEY=<your-key>` in your environment file.

### For Tier 3 and Tier 4 (Enterprise & Sovereign)

```
1. Initial inquiry (email below) → 2. NDA (optional) → 3. Technical discovery
call (Tier 3+) → 4. Proposal & Scope of Work → 5. MSA / License Agreement
→ 6. Invoice & Payment → 7. License key delivery + private repo access
→ 8. Onboarding (Tier 4+)
```

**Standard procurement timelines:**
- Tier 3: 5–10 business days from first email to signed license
- Tier 4: 15–30 business days (MSA negotiation, DPA/BAA review)
- Government / DoD (OTA / FAR-compliant): 30–90 days depending on vehicle

**Required information for initial contact (Tier 3 & 4):**

```
Company name and primary contact (name, title, email)
Deployment model: SaaS / on-premises / hybrid / air-gapped
Estimated request volume: req/month or req/day peak
Target vertical: FinReg / Healthcare / Defense / Gov / Enterprise
Compliance frameworks in scope: SOC 2 / HIPAA / FedRAMP / PCI / other
Desired SLA tier: Tier 3 / 4 / OEM
Procurement path: direct / GSA Schedule / OTA / SEWP V / other
Timeline: evaluation deadline, deployment target date
```

**Contact:** juan.c.luna04@gmail.com

---

## Part VI — Legal Notes

This document is a summary of commercial offerings and is **not a binding
contract**. Specific terms — limitation of liability, indemnification,
governing law, export controls, and IP warranties — are governed by the
executed Master Services Agreement (MSA) and License Agreement.

**Governing law:** California, United States (default). Alternative
jurisdictions available for international enterprise and government customers.

**Export compliance:** Aegis Latent Core is subject to the U.S. Export
Administration Regulations (EAR). The software includes cryptographic
functionality. Licensees are responsible for determining applicable export
classification (ECCN 5D002) and obtaining required licenses for re-export to
controlled destinations.

**No legal advice:** This document does not constitute legal advice. Licensees
should engage qualified legal counsel to evaluate contractual terms, compliance
obligations, and any jurisdiction-specific requirements.

---

*Open-source: https://github.com/JuanLunaIA/aegis-latent-core — AGPLv3*

**Commercial licensing contact:** juan.c.luna04@gmail.com
