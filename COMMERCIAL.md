<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# Aegis Latent Core — Commercial Licensing

Aegis Latent Core is distributed under a **Dual-Licensing Model**:
*   **AGPLv3 (Open-Source):** The complete, production-grade codebase is publicly accessible on GitHub. Free for open-source projects and evaluation.
*   **Commercial License:** A legal waiver and commercial agreement for closed-source, proprietary, and private cloud deployments.

Running Aegis Latent Core in a proprietary environment without a Commercial License exposes your organization to copyleft disclosure requirements under the AGPLv3.

---

## Part I — The AGPLv3 Forcing Function (Why You Need a License)

Aegis Latent Core is licensed under the **GNU Affero General Public License v3 (AGPL-3.0-only)**. This license contains a network-use copyleft clause (§13).

If you deploy Aegis over a network (including internal VPCs) and pass proprietary system prompts, custom WAF patterns, or wrap it in your own service, **you are legally obligated to publish your entire proprietary application code and system prompts** to anyone who interacts with your AI features.

To protect your trade secrets, business logic, and intellectual property, you must acquire a **Commercial License**. This license explicitly exempts your organization from all AGPLv3 disclosure requirements.

---

## Part II — What a Commercial License Actually Includes

There is only one codebase. Every customer — open-source or commercial — runs the exact software that is publicly auditable on GitHub right now. A Commercial License does not unlock hidden features, a private fork, or a different build. It buys exactly three things:

1.  **The AGPLv3 exemption.** A signed legal waiver releasing you from the §13 network-copyleft obligation.
2.  **A signed license key**, checked by your own deployment at startup.
3.  **Direct email access to the maintainer** — me. See Part IV for what that realistically means in practice.

That is the honest scope of the product. The differences between tiers below are about support priority and invoicing terms, not about code you can't otherwise read on GitHub.

---

## Part III — Commercial Tiers & Pricing

### 1. Startup License — $399 / year
**For early-stage startups and independent developers building proprietary AI products.**

*   **AGPLv3 Exemption:** Yes.
*   **Deployment:** Self-hosted / Private Cloud.
*   **Usage:** Unlimited requests & replicas.
*   **Support:** Standard email support. Best-effort, business hours. No response-time guarantee.
*   **Delivery:** Signed license key via email. Typically same-day; allow up to 48h while the key-issuing pipeline is caught up with the latest major release (see Part V).

### 2. Business License — $1,499 / year
**For companies that need the exemption plus priority over the standard queue.**

*   **AGPLv3 Exemption:** Yes.
*   **Deployment:** Self-hosted / Private Cloud.
*   **Usage:** Unlimited requests & replicas.
*   **Support:** Priority email — answered ahead of the Startup queue, best-effort. No fixed SLA hour count: a number I can't consistently hold is worse than no number.
*   **Delivery:** Same terms as Startup tier.


### 3. Enterprise License — $4,900 / year
**For organizations that need an invoice and a license waiver — not a guaranteed sales call.**

*   **AGPLv3 Exemption:** Yes.
*   **Deployment:** Self-hosted / Private Cloud.
*   **Usage:** Unlimited requests & replicas.
*   **Support:** Priority email, same best-effort basis as the Business tier.
*   **Optional add-on:** A 60-minute architecture/onboarding call can be scheduled separately, subject to availability. Not bundled, not guaranteed within any fixed window after purchase.
*   **Payment:** Credit card, or invoice (Net-30) on request.


---

## Part IV — Support Policy: What "Solo Maintainer" Actually Means

Aegis Latent Core is built and supported by one person. There is no support team, no shift coverage, and no SLA desk behind the email address.

*   **No 24/7, no on-call.** Uptime and incident response for *your* deployment are your responsibility — I have no access to your infrastructure, logs, or data.
*   **Business hours, Argentina time (UTC-3), best-effort.** "Priority" tiers get answered first, not necessarily fast. Response times vary, especially around major releases.
*   **Scope of support:** configuration guidance, architecture questions, bug reports, and security patches for Aegis Latent Core itself. This is not a consulting retainer for your application code.

---

## Part V — Procurement & Activation

### Self-Serve (Startup & Business Tiers)
1.  **Purchase:** Checkout via LemonSqueezy.
2.  **Delivery:** License key by email — see delivery note under Part III. Automated where the pipeline supports it; manual fallback during version transitions like the current one.
3.  **Activation:** Set `AEGIS_LICENSE_KEY=<your-key>` in your environment. You are immediately legally compliant.

### Enterprise Procurement
For the Enterprise tier, or a custom Master Services Agreement (MSA):
*   **Contact:** `juan.c.luna04@gmail.com` with company name, target vertical, and procurement requirements.
*   **Timeline:** Allow 5–10 business days. This is handled by one person alongside active development, not a dedicated procurement desk.

---

## Part VI — Legal & Copyright

**Sole copyright holder.** Aegis Latent Core is the original, proprietary work of **Juan Luna** (`juan.c.luna04@gmail.com`), who holds sole, undivided copyright in the project.

This document is a summary of commercial offerings and is not a binding contract. Specific terms are governed by the executed License Agreement provided at checkout.

*Open-source: https://github.com/JuanLunaIA/aegis-latent-core — AGPLv3*
*Commercial licensing contact: juan.c.luna04@gmail.com*
