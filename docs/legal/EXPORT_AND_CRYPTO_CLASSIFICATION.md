<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
SPDX-License-Identifier: LicenseRef-Aegis-Commercial-1.0
Licensed under the Aegis Commercial License 1.0; see LICENSE and NOTICE.
-->

# Export and cryptography classification

**Audience:** owner, export counsel, and any customer whose procurement team
asks for an export classification.
**Scope:** the cryptographic functions in the source tree, the jurisdictions
involved, and the questions that must be answered before selling or shipping.
**Boundary:** an inventory and a list of open questions. **No export
classification has been obtained.** Do not state an ECCN, an EAR status, or an
"export compliant" conclusion.

> **[COUNSEL-REVIEW-REQUIRED]** Draft prepared by an AI agent. Not legal advice.
> Export control is fact-specific and jurisdiction-specific.

## 1. What is in the box

| Function | Where | Type | Notes |
| --- | --- | --- | --- |
| Ed25519 signatures | `aegis/core/crypto_audit.py`, SDK verifiers | asymmetric signature | standard library / Rust implementation |
| ML-DSA-65 (post-quantum) | `aegis/core/`, Rust extension | asymmetric signature | FIPS 204 algorithm; implementation is not FIPS validated |
| SHA-256 / SHA-512 | hashing and chain links | hash | standard |
| HMAC | keyed integrity | MAC | standard |
| AES-GCM | optional storage / transport helpers | symmetric AEAD | check actual deployment use |
| TLS | ingress / database connections | transport | operator-configured |
| RFC 3161 timestamp client | `aegis/anchoring/rfc3161.py` | timestamp request | optional, external TSA |
| MMR inclusion proofs | `aegis/core/mmr.py` | hash-based proof | no encryption |
| Zero-knowledge proof surface | `aegis/crypto/` | **stub** | capability report labels it non-real; do not describe it as production ZK |

The repository does **not** implement a general-purpose cipher suite for
customer data, a VPN, or a key escrow service. It signs and hashes evidence.

## 2. Jurisdictions and flows

| Flow | From | To | Question |
| --- | --- | --- | --- |
| Source download | GitHub / PyPI / npm / GHCR | anywhere | is a public source download a controlled export? |
| Container image | GHCR | customer registry | does the image contain controlled cryptography? |
| Hosted console | customer | AWS `us-east-1` | account metadata only; no customer prompts |
| Support access | customer environment | owner | does remote support constitute a deemed export? |
| Customer delivery | owner | customer country | sanctions screening and end-use statement |

## 3. Open questions for export counsel

1. What is the classification of the software in Argentina, the United States
   (EAR), and the EU dual-use regime? The answer may differ by destination and
   by whether the source is publicly available.
2. Does the presence of ML-DSA-65 change the classification compared with
   Ed25519-only builds?
3. Is the "publicly available" exception available for a source-available
   repository that requires a commercial licence for production use? The
   licence is not open source, so do not assume the exception applies.
4. Does providing the hosted console as a service trigger a different control
   than shipping the software?
5. What end-use / end-user statement should the Order Form require?
6. Which denied-party and sanctioned-country lists must be screened, and at
   what frequency?
7. Is a self-classification report or a commodity classification request
   appropriate before the first paid customer?

## 4. What sales may say

Allowed, if true for the delivered build:

- "The software uses Ed25519 and ML-DSA-65 signatures and SHA-256 hashes."
- "The ML-DSA implementation is not FIPS 140-3 validated."
- "Export classification is pending; we will provide the classification we
  obtain for the delivered version."

Not allowed:

- "Export compliant", "EAR99", "ECCN 5D002", "FIPS certified", or any
  classification not issued for the exact version and destination.
- "ITAR-free" or "munitions-free" without a legal review.

## 5. Gate

The export gate is **OPEN**. Before the first paid international Order:

- [ ] export counsel engaged;
- [ ] classification recorded for the delivered version;
- [ ] sanctions screening procedure written;
- [ ] Order Form end-use statement reviewed;
- [ ] customer-facing wording approved.
