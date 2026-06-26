<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core — Commercial License

Aegis Latent Core is distributed under a **Dual-Licensing Model**:
*   **AGPLv3 (Open-Source Core):** The complete, production-grade codebase is publicly accessible on GitHub. Free for open-source projects, academic use, and local evaluation.
*   **Commercial License:** A single, permanent legal license for closed-source, proprietary, and private cloud deployments.

Running Aegis Latent Core in a proprietary network environment without a Commercial License exposes your organization to copyleft disclosure requirements under the AGPLv3.

---

## Part I — The AGPLv3 Forcing Function (Why You Need a License)

Aegis Latent Core is licensed under the **GNU Affero General Public License v3 (AGPL-3.0-only)**. This license contains a network-use copyleft clause (§13).

If you deploy Aegis over a network (including internal VPCs) and pass proprietary system prompts, custom WAF patterns, or wrap it in your own service, **you are legally obligated to publish your entire proprietary application code and system prompts** to anyone who interacts with your AI features.

To protect your trade secrets, proprietary prompts, and business logic from open-source exposure, you must acquire a **Commercial License**. This license explicitly exempts your organization from all AGPLv3 copyleft obligations.

---

## Part II — What the Commercial License Includes

There is only one codebase. Every customer — open-source or commercial — runs the exact same software that is publicly auditable on GitHub. A Commercial License does not unlock hidden features, a private fork, or a different build. It grants you:

1.  **The AGPLv3 exemption.** A signed digital Certificate of Exemption (PDF) releasing you permanently from the §13 network-copyleft obligation.
2.  **The permanent legal right** to run the entire Aegis Latent Core v2.x suite within any proprietary, closed-source, or air-gapped environment — indefinitely, with no renewal.
3.  **100% access to every feature** in the codebase: all compliance modules (HIPAA, SOC 2, SEC 17a-4, PCI-DSS, FedRAMP, DoD IL5/IL6), post-quantum signing (ML-DSA-65), DFIR exporters, OEM integrations, and everything else that exists in the repository at the time of purchase and in future v2.x releases.
4.  **Best-effort email support** from the maintainer (me) for questions about configuration, integration, and bug reports. Response during business hours, Argentina time (UTC-3).

This is the honest scope. There are no artificial tier locks, no telemetry, and no "calling home" in the code. You are paying for a permanent legal right, not an ongoing service.

---

## Part III — The License: One Payment. Everything. Forever.

> **Aegis Latent Core Commercial License — $499 USD (One-Time Payment / Pago Único)**

**One payment. Full access. Permanent.**

| What you get | Detail |
|---|---|
| **AGPLv3 Exemption** | Permanent legal waiver covering the entire Aegis v2.x feature set |
| **Deployment scope** | Single legal entity (company, LLC, freelancer, sole proprietor) — unlimited servers, nodes, containers, environments |
| **Feature access** | 100% — every module, every compliance preset, every integration currently in the repository |
| **Future v2.x updates** | Included. You receive all updates within the v2.x release line at no additional cost |
| **Payment model** | One-time purchase. No subscriptions, no annual renewals |
| **Support** | Best-effort email access to the maintainer for configuration, integration, and bug questions |
| **Delivery** | Instant digital Certificate of AGPLv3 Exemption (PDF) + receipt via email |
| **No DRM** | No license keys, no activation servers, no telemetry. Your deployment stays 100% air-gapped |

**Purchase:** [LemonSqueezy checkout link — juan.c.luna04@gmail.com]

---

## Part IV — Buyer Registration Requirement

Upon purchase, the **buyer must provide the following information** for the license registry. This is a legal requirement of the license agreement and is used solely to maintain an auditable record of valid license holders:

*   **Legal entity name** (company, LLC, individual name if freelancer/sole proprietor)
*   **Country of incorporation / country of residence**
*   **Primary contact email** (for delivery of the Certificate of Exemption and future security notices)
*   **Intended use case** (brief description: e.g., internal SaaS audit proxy, healthcare platform, fintech backend)
*   **Approximate team size** (optional, for support prioritization)

This information is kept confidential, is never sold or shared with third parties, and is used only to:
1.  Issue your Certificate of AGPLv3 Exemption with the correct legal entity name.
2.  Send you critical security notices related to Aegis Latent Core (e.g., CVE patches).
3.  Maintain a verifiable record that your organization holds a valid license, in case of legal audit.

**Submit registration data** to: `juan.c.luna04@gmail.com` with subject line `[Aegis License Registration] — [Your Company Name]`.

---

## Part V — Anti-Resale & "Internal Use Only" Guardrail

Aegis Latent Core is sold on a **Single-Entity, Non-Transferable basis**.

If your organization is a **Software Factory, Dev Agency, or IT Consultancy** building applications for third-party clients:

*   **Each client** that will run Aegis in a proprietary environment must hold their **own independent Commercial License**.
*   You may not purchase one license and deploy it for multiple clients under a single agreement.
*   **OEM / White-Label:** If you wish to bundle Aegis inside your own commercial product and distribute it to multiple third parties, contact me for a bespoke OEM agreement (see Part VII).

---

## Part VI — Support Policy: What "Solo Maintainer" Actually Means

Aegis Latent Core is built and supported by one person. There is no support team, no rotating shifts, and no guaranteed SLA.

*   **No 24/7, no on-call.** Uptime, deployment stability, and incident response are your responsibility.
*   **Business hours, Argentina time (UTC-3), best-effort.** I do not commit to a fixed response-time guarantee I cannot consistently hold during exam seasons or major release cycles.
*   **Scope:** Configuration guidance, architectural questions, bug reports, and security patches for Aegis Latent Core itself. Not a consulting retainer for your custom application code.
*   **No maintenance contract.** If you need a formal SLA or dedicated support hours, contact me to negotiate an OEM/Partner arrangement.

---

## Part VII — Procurement & Activation

Aegis Latent Core operates entirely offline. There are no license keys to manage, no activation servers, and no trackers in your code.

### Self-Serve Purchase

1.  **Purchase:** Complete the one-time checkout via LemonSqueezy (Merchant of Record — handles global VAT/tax compliance automatically).
2.  **Register:** Email `juan.c.luna04@gmail.com` with your registration data (see Part IV). You will receive your personalized Certificate of AGPLv3 Exemption (PDF) within 1 business day.
3.  **Activate:** Set the environment variable `AEGIS_COMMERCIAL_MODE=true` in your deployment. This disables the AGPLv3 warning banners in server logs and asserts to your auditors that you hold a valid commercial license.

There are no keys to manage and no servers to ping. Your deployment remains 100% air-gapped, offline, and secure.

### Enterprise / Invoice Purchase

For custom MSAs, corporate vendor onboarding, or Net-30 invoicing:
*   **Contact:** `juan.c.luna04@gmail.com` with your company name, target vertical, and procurement requirements.
*   **Timeline:** Please allow 5–10 business days to process legal reviews and invoice generation.

---

## Part VIII — OEM / Partner License — Negotiated

**For Software Factories, IT Consultancies, and SaaS Vendors who want to bundle Aegis and distribute it to multiple third-party clients.**

OEM and Partner licenses require a bespoke Master Services Agreement (MSA) covering:
- Sublicensing and redistribution rights.
- White-labeling rights (removing the "Aegis" name and presenting it as your proprietary security module).
- Volume-based pricing or per-client royalty structures.
- Extended technical support and code escrow options.

**Contact for OEM/Partner pricing:** `juan.c.luna04@gmail.com` — include your agency's name, target market, estimated client volume, and timeline.

---

## Part IX — Legal & Copyright

**Sole copyright holder.** Aegis Latent Core is the original, proprietary work of **Juan Luna** (`juan.c.luna04@gmail.com`), who holds sole, undivided copyright in the project.

This document is a summary of commercial offerings and is not a binding contract. Specific terms are governed by the executed License Agreement provided at checkout.

*Open-source: https://github.com/JuanLunaIA/aegis-latent-core — AGPLv3*  
*Commercial licensing contact: juan.c.luna04@gmail.com*
