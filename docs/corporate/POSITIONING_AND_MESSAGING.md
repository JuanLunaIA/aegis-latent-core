> **INTERNAL DOCUMENT — NOT FOR EXTERNAL DISTRIBUTION**

# Positioning and Messaging

**Audience:** internal — anyone writing about this project for an external audience.
**Scope:** category, audiences, core message, and the language rules that apply to all of them.
**Boundary:** this document sets internal guidance for how to describe the product. It creates no claim of its own. Where it appears to permit something [Claims Matrix](../CLAIMS_MATRIX.md) does not, the matrix governs.

---

## 1. Category

**AI Governance and Cryptographic Evidence Gateway.**

Use that phrase. It is accurate and it is the category the product actually occupies.

Do not describe it as:

| Not this | Why |
| --- | --- |
| An AI firewall | Implies prevention as the primary function. The primary function is evidence. |
| A compliance platform | Implies determinations it does not make. |
| An observability tool | Understates the evidence properties and invites comparison on the wrong axis. |
| An LLM gateway | Accurate but incomplete; loses the entire differentiator. |
| A guardrails product | Detection is bounded and best-effort. Leading with it sets up a claim we cannot defend. |

## 2. Core message

> Every governed AI call produces a signed, hash-linked evidence record committed before the response returns, with a portable proof a third party can verify without trusting the gateway.

That sentence carries the three things that matter: **ordering**, **verifiability**, and **independence from us**. Anything longer dilutes it; anything shorter loses one of the three.

## 3. Audiences

### Developers

**They care about:** getting it running, not breaking their integration, understanding the streaming semantics.

**Lead with:** OpenAI-compatible drop-in, source quickstart, one governed call showing the evidence headers.

**Do not lead with:** compliance, cryptography theory, or enterprise framing.

**Be honest early about:** `pending-terminal` semantics, one worker per WAL path, and the SDK registry lag — a developer who installs `4.0.0` from PyPI and reads `4.1.0` documentation will hit a mismatch and lose trust.

### Security reviewers

**They care about:** the threat model, what is out of scope, where the trust boundaries sit, and whether we are honest about limitations.

**Lead with:** the threat model's out-of-scope section and the operator-trust boundary. A reviewer who finds a limitation we did not disclose stops believing the ones we did.

**Be honest early about:** no independent audit, no penetration test, and detection-not-prevention on tampering.

**This audience rewards candour more than any other.** Stating the operator-trust assumption first is a stronger position than having it discovered.

### Procurement

**They care about:** licence, support, continuity, assurance artifacts, and risk.

**Lead with:** self-hosted custody, dual licensing, and the disqualifier list.

**Be honest early about:** no certification, no SLA, single maintainer.

Surfacing disqualifiers in the first conversation costs some deals and saves everyone the evaluations that were going to fail in month three.

### Executives

**They care about:** what problem it solves, what risk it carries, and whether it fits.

**Lead with:** the problem — logs are a weak answer when a decision is questioned — then the three properties.

**Be honest early about:** the risk table in [Executive Summary](EXECUTIVE_SUMMARY.md).

## 4. Prohibited claims

These are prohibited in every channel, to every audience, regardless of who is asking or what a deal depends on.

| Never say | Say instead |
| --- | --- |
| Compliant with anything | Produces technical inputs an organisation may evaluate |
| Certified, audited, assessed | No independent assurance exists |
| Legally admissible, court-ready | Technical integrity evidence; admissibility requires legal review |
| Immutable, tamper-proof, WORM | Append-only with tamper detection; external immutability requires a storage control |
| Prevents prompt injection | Bounded heuristic detection over a pinned corpus; records what occurred |
| Removes all PII | Best-effort deterministic redaction over specific fields and patterns |
| Production-ready | Source baseline; target acceptance required |
| Guaranteed, SLA, uptime | No service level exists outside an executed agreement |
| Enterprise-grade, best-in-class, unmatched | Say what it does |
| Published on PyPI at 4.1.0 | SDKs are at 4.0.0; source is at 4.1.0 |

Full list: [Style Guide §3](../STYLE_GUIDE.md#3-prohibited-language) and [Unsupported Claims](../institutional/UNSUPPORTED_CLAIMS.md).

## 5. Competitive framing

**Do not produce competitor comparison matrices.** Asserting what another product does or does not do requires evidence about their systems that we do not have, and getting it wrong is both a credibility failure and a legal exposure.

Position on what we can evidence about ourselves:

- Evidence committed before emission, not after.
- Proofs verifiable without trusting us.
- Self-hosted custody; we hold nothing.
- A public claims register with locators and boundaries.

If a prospect asks how we compare, describe our properties and let them evaluate. "I can tell you precisely what we do; you should ask them the same question" is a stronger answer than a matrix we cannot defend.

## 6. Handling pressure

When a prospect, a deal, or an internal stakeholder asks for a stronger claim than the evidence supports, the answer is no. Not "let me check" — no.

The product is evidence integrity. An organisation that overstates its own claims has demonstrated exactly the failure mode the product exists to prevent, and any sophisticated buyer will read it that way.

Practical responses:

- *"Can we say compliant?"* → No. We can say what technical inputs we contribute and to which framework.
- *"Can we say immutable?"* → No. We can say append-only with tamper detection, and name what would be needed for more.
- *"They need SOC 2."* → We do not have it and it is not in progress. Offer the source, the claims register, and support for their own review.
- *"Just for this one deck."* → No. A claim in a deck is a claim.

## 7. Proof points we can actually use

Each is verifiable by the audience, which is what makes them useful:

- Commit-before-emission, with the named test.
- Portable proofs verified by two independent SDK implementations.
- Bounded formal artifacts under `specs/`, with their limits stated.
- Hash-pinned dependencies, SHA-pinned actions, signed tags and images.
- A public claims register — and the invitation to spot-check three rows.

The last one is the strongest thing we have. Inviting verification is a claim about our confidence that no amount of adjectives can substitute for.

---

**Related:** [Style Guide](../STYLE_GUIDE.md) · [Claims Matrix](../CLAIMS_MATRIX.md) · [Unsupported Claims](../institutional/UNSUPPORTED_CLAIMS.md) · [Executive Summary](EXECUTIVE_SUMMARY.md) · [Corporate FAQ](CORPORATE_FAQ.md) · [Commercial Strategy](../COMMERCIAL_STRATEGY_US.md)
