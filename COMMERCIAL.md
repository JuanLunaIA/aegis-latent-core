<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core — Commercial Licensing & Enterprise Offerings

Aegis Latent Core is dual-licensed under **AGPLv3** (open-source) and a
**Commercial Source License** for closed-source, proprietary, and private cloud deployments. 

Under our commercial licensing model, **100% of the complete, unredacted, production-grade source code (including Python core modules, enterprise server extensions, and Rust PyO3 acceleration sources) is delivered directly to all purchasing organizations.** We do not ship obfuscated binaries, closed DLLs, or telemetry-heavy black boxes. You own, audit, compile, and host the code entirely inside your own virtual private cloud (VPC) or local infrastructure.

Our commercial tiers are structured on **deployment scale (active container replicas), regulatory pre-built components, and direct consultative engineering support from the founder and lead systems architect (Juan Luna).**

---

## Part I — Intellectual Property & Ownership

**Sole copyright holder.** Aegis Latent Core is the original, proprietary work of
**Juan Luna** (`juan.c.luna04@gmail.com`), who holds sole, undivided copyright in the
project. See `NOTICE` and `AUTHORS`.

**Exclusive right to commercialize.** As the sole copyright holder, Juan Luna
reserves the exclusive right to license the complete source code under proprietary
commercial terms, to sublicense it, and to authorize its execution in closed-source or managed environments. The AGPLv3 grant to the public does not diminish this right.

**Contributions are license-aligned.** All contributions are accepted under
the DCO + CLA in `CONTRIBUTING.md`, which grants Juan Luna a perpetual,
irrevocable, worldwide, royalty-free, sublicensable license to relicense
contributed code under both the AGPLv3 and commercial source terms. Contributors
retain ownership of their own contributions; the maintainer retains sole
copyright in the project as a whole.

**Trademark.** The "Aegis Latent Core" name and logo are not licensed under
the AGPLv3 and may not be used to imply endorsement without written permission.

---

## Part II — The AGPL Copyleft Forcing Function (Why Enterprises Buy)

Aegis Latent Core's public repository is licensed under the **GNU Affero General Public License v3 (AGPL-3.0-only)**. This license contains a network-use copyleft clause — **§13** — that standard GPL and permissive licenses (like MIT or Apache) do not:

> *"If you modify the Program, your modified version must prominently offer all
> users interacting with it remotely through a computer network … an
> opportunity to receive the Corresponding Source of your version."*

### When §13 Triggers

§13 is triggered the moment an organization:
1. Runs Aegis Latent Core over a network (including internal corporate networks, VPCs, or behind an API gateway), **AND**
2. Has configured or modified the application (which includes passing proprietary system prompts, custom WAF patterns, internal configurations, or wrapping the proxy in a new company-specific service layer).

This means that under the AGPLv3, **you are legally obligated to publish your entire proprietary application code, custom threat rules, and highly sensitive system prompts** to anyone who interacts with your AI features over the network. 

To protect your trade secrets, business logic, and intellectual property, you must acquire a **Commercial Source License**. The commercial license exempts your organization from all AGPLv3 disclosure requirements.

---

## Part III — License Tiers, Source Code Access & Support

Every commercial tier includes immediate, unrestricted access to the **100% complete, unredacted production-grade source code repository** (via private GitHub access or secure package distribution) so your team can audit, compile, and deploy it locally.

---

### Tier 0 — Evaluation / Developer (Free)

**Who it's for:** Individual engineers, PoC assessments, internal non-production testing, and local sandboxes. **Not for production** — no SLA, no commercial rights, and bound strictly by AGPLv3.

| Feature | Included |
|---------|----------|
| **Complete Source Code Access** | Yes (via public GitHub repository) |
| Exemption from AGPLv3 | **No** — proprietary modifications or prompts must be open-sourced if deployed on a network |
| Deployment model | Local self-hosted, non-production |
| Uptime / support SLA | No — community-only (GitHub Issues) |
| Installation support | No |
| Compliance templates | No |

---

### Tier 1 — Professional (Self-Serve) — $99 / month (Billed Monthly)

**Who it's for:** Startups, independent SaaS developers, and small software teams deploying Aegis as an audited, local component. Billed and delivered automatically.

| Feature | Included |
|---------|----------|
| **Complete Source Code Access** | **Yes** — private repository access containing full Python + Rust source |
| Exemption from AGPLv3 | **Yes** — commercial waiver protecting your proprietary prompts and code |
| Deployment model | Local self-hosted |
| Production deployment rights | Yes — max 1 active production container/instance |
| Automated License Delivery | Yes — instant key via LemonSqueezy/Stripe + Keygen.sh |
| Monthly request quota | 500,000 requests/month |
| Email / Discord support | 72-hour response target (business hours) |
| Security patch stream | 72-hour notification for critical CVEs |

**Overage:** requests/month > 500,000 or replicas > 1 → Tier 2 required.

---

### Tier 2 — Business (SME / Growth) — $299 / month (Billed Monthly)

**Who it's for:** Growing mid-market and SME companies requiring pre-built regulatory components (HIPAA, SEC, PCI) and active architectural guidance from the creator.

| Feature | Included |
|---------|----------|
| **Complete Source Code Access** | **Yes** — private repository access containing full Python + Rust source |
| Exemption from AGPLv3 | **Yes** — commercial waiver protecting your proprietary prompts and code |
| Deployment model | Local self-hosted |
| Production deployment rights | Yes — max 3 active production containers/instances |
| Automated License Delivery | Yes — instant key via LemonSqueezy/Stripe + Keygen.sh |
| Monthly request quota | 2,000,000 requests/month |
| Regulatory Presets | Yes — HIPAA Safe Harbor, SEC Rule 17a-4, PCI-DSS v4.0 |
| PCI-DSS PAN/CVV Masking | Yes — `AEGIS_PCI_SCRUB=true` |
| HIPAA PHI De-identification | Yes — `AEGIS_PHI_DEIDENTIFY=true` |
| Email / Discord priority support | 24-hour response target (business hours) |
| Security patch stream | 48-hour critical CVE notification + patch |
| **Direct Founder Support** | **Yes** — up to 2 hours/year of direct architectural review and integration assistance with **Juan Luna** |

**Overage:** requests/month > 2,000,000 or replicas > 3 → Tier 3 required.

---

### Tier 3 — Corporate Enterprise — $1,499 / month (Billed Annually, $14,990 / year)

**Who it's for:** Mid-to-large enterprises requiring unlimited node deployment, high-throughput clustering, and comprehensive compliance artifacts (SOC 2, ISO 27001, FedRAMP, GxP) backed by active engineering support.

| Feature | Included |
|---------|----------|
| **Complete Source Code Access** | **Yes** — private repository access containing full Python + Rust source |
| Exemption from AGPLv3 | **Yes** — commercial waiver protecting your proprietary prompts and code |
| Deployment model | Private Cloud (VPC), Local Kubernetes (Helm), or On-Premise |
| Production deployment rights | Yes — unlimited active production containers/instances |
| Payment terms | Invoice (net-30 or net-60 available) or Credit Card |
| Security patch stream | 48-hour critical CVE notification + patch |
| Monthly patch releases | Yes |
| Documentation portal access | Yes — private compliance runbooks, Helm playbooks, vertical-specific guides |
| Annual signed SBOM (CycloneDX + SPDX) | Yes |
| Reproducible build attestation (SLSA Level 2) | Yes |
| Sealed compliance bundle templates (SOC 2, HIPAA, ISO 27001) | Yes — JSON, PKCS#7, EWF/E01 formats |
| **Direct Founder Engineering** | **Yes** — up to 12 hours/year of direct, on-demand code customization, custom WAF profile engineering, and optimization support from **Juan Luna** |
| Email / Slack support | 24-hour response target (business hours) |

---

### Tier 4 — Premium Sovereign — Negotiated

**Who it's for:** Defense contractors, government agencies, systemic financial institutions, and critical infrastructure operators requiring high-assurance isolated deployments, FIPS boundaries, and custom feature development.

| Feature | Included |
|---------|----------|
| **Complete Source Code Access** | **Yes** — private repository access containing full Python + Rust source |
| Exemption from AGPLv3 | **Yes** — commercial waiver protecting your proprietary prompts and code |
| Deployment model | Air-Gapped networks, secure military enclaves, or hardware enclaves (TEE) |
| Production deployment rights | Yes — unlimited active production containers/instances |
| Security patch stream | 4-hour critical CVE notification; 1 business day patch target |
| Priority patch releases | Yes — out-of-band for P0 vulnerabilities |
| On-boarding sessions | Yes — up to 4 remote sessions (90 min each) in year 1 |
| Architecture review | Yes — 1 deep-dive session per year (remote or on-site) |
| Air-gap / FIPS 140-3 deployment packaging | Yes — static binaries, offline installation bundles |
| Signed SBOM (CycloneDX + SPDX), reproducible attestation | Yes — per-release |
| Sealed compliance bundle (PKCS#7 CMS, EWF/E01, archival) | Yes — quarterly automated exports |
| Vertical-specific compliance evidence packs | Yes — SEC 17a-4 WORM, HIPAA, FedRAMP High, DoD IL5, Daubert |
| **Direct Founder Co-Engineering** | **Yes** — up to 48 hours/year of dedicated code customisation, on-demand security auditing, custom feature development, and active GxP/DoD IL5 accreditation support from **Juan Luna** |
| Private security advisory channel (24×7 escalation) | Yes |
| BAA / DPA / sub-processor agreement | Yes — standard forms provided; custom review billable |
| Quarterly executive briefing (threat landscape, roadmap) | Yes |

---

### Tier 5 — OEM / Embedded (Negotiated)

**Who it's for:** Technology vendors wishing to bundle or embed Aegis's complete source code as a white-labeled security component in their own commercial products.

OEM licenses require a bespoke MSA covering:
- White-labeling rights (use of "Aegis" trade name: excluded unless licensed).
- Redistribution rights (sublicensing to customers).
- Extended indemnities and IP warranties.
- Audit rights and source escrow.
- Per-unit or per-seat royalty structure vs. flat license.
- Export control compliance (EAR, ITAR where applicable).

**Contact for OEM pricing:** juan.c.luna04@gmail.com — include intended product, target market, estimated distribution volume, and timeline.

---

## Part IV — SLA Definitions and Escalation Matrix

| Severity | Definition | Tier 1 | Tier 2 | Tier 3 | Tier 4 |
|---------|-----------|--------|--------|--------|--------|
| **P0 — System Down** | Proxy completely unavailable; audit chain not persisting | Email 72h | Email 48h | Email 24h | Pager / email 4h ack |
| **P1 — Critical Security** | Exploitable vulnerability in auth, WAF, or audit chain | Patch notification 72h | Patch notification 48h | Patch notification 48h | Notification 4h; patch target 1 BD |
| **P2 — Degraded** | Non-critical functional defect; workaround available | Next monthly release | Next monthly release | Next monthly release | Next patch release (≤ 14 days) |
| **P3 — Advisory** | Performance, documentation, configuration guidance | Community (Discord) | Email / Discord 48h | Documentation portal | Email; 24h response |

**SLA clock runs business days (Monday–Friday, 09:00–17:00 US Eastern), excluding US federal holidays**, unless a 24×7 add-on is contracted.

---

## Part V — Engagement and Procurement Process

### For Tier 1 and Tier 2 (Self-Serve)

1. **Instant Purchase:** Navigate to our self-serve checkout page (powered by LemonSqueezy/Stripe).
2. **Automated License Generation:** Upon successful payment processing, LemonSqueezy triggers a secure webhook to our serverless handler.
3. **Key Provisioning:** A cryptographically signed license key is generated via Keygen.sh and bound to your email address and chosen policy.
4. **Immediate Source Delivery:** The key, private GitHub repository invitation, and download links for the complete codebase (including Python and Rust files) are sent to your inbox within seconds.
5. **Activation:** Set `AEGIS_LICENSE_KEY=<your-key>` in your environment file.

### For Tier 3 and Tier 4 (Enterprise & Sovereign)

```
1. Initial inquiry (email below) → 2. NDA (optional) → 3. Technical discovery
call (Tier 3+) → 4. Proposal & Scope of Work → 5. MSA / License Agreement
→ 6. Invoice & Payment → 7. Source code delivery + private repo access
→ 8. Onboarding (Tier 4+)
```

**Standard procurement timelines:**
- Tier 3: 5–10 business days from first email to signed license
- Tier 4: 15–30 business days (MSA negotiation, DPA/BAA review)
- Government / DoD (OTA / FAR-compliant): 30–90 days depending on vehicle

**Required information for initial contact (Tier 3 & 4):**

```
Company name and primary contact (name, title, email)
Deployment model: Private Cloud (VPC) / on-premises / hybrid / air-gapped
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
