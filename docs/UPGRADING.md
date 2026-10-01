# Upgrading to 5.0.0

**Audience:** anyone running `4.1.2` — the most recent release on PyPI, npm and GHCR — or building from a `4.x` source tree.
**Scope:** every change between `4.1.2` and the `5.0.0` source target that can break a working deployment or a working integration.
**Boundary:** this guide covers upgrade mechanics. It makes no claim that `5.0.0` is on any registry; consult [Release Status](RELEASE_STATUS.md) for what is actually published, and never infer publication from a version number appearing here.

`5.0.0` is a major version because it breaks the public JSON API. The jump from `4.3.0` skips `4.4.0` deliberately; `4.2.0` was skipped earlier for the same kind of reason. Neither number exists at any surface.

Read §1 and §2 before upgrading anything. They are the two changes most likely to break you silently rather than loudly.

## 1. `legal_admissibility` is gone, replaced by `signature_assurance` (breaking)

**What changed.** `/audit/health` and `/audit/integrity` returned a field named `legal_admissibility` carrying the string `"High"` or `"Compromised"`. That field no longer exists. It is replaced by `signature_assurance`, with a five-value vocabulary.

**Why it changed, which matters for how you read old data.** The old property was:

```python
if self._signing_key:
    return "High"
if any(n.is_fallback for n in self.chain):
    return "Compromised"
return "High"
```

It consulted the ledger's *current configuration* and returned `"High"` before ever examining chain history. A WAL written entirely under the ephemeral `ed25519-fallback` tier reported `"High"` the moment a later process reopened it with a signing key configured. **Any `"High"` you recorded from a `4.x` deployment is therefore not evidence that the chain was signed well** — it is evidence that a key was configured at read time. Re-derive that judgement from `signature_assurance` against the current chain rather than trusting a retained `"High"`.

**The new vocabulary**, weakest to strongest, reported as the weakest tier appearing anywhere in the chain:

| Value | Means |
|---|---|
| `UNSIGNED` | no signature |
| `COMPROMISED_EPHEMERAL` | signed under a discarded per-process key (`ed25519-fallback`) — attributes nothing |
| `SYMMETRIC_AUTHENTICATED` | `hmac-sha256`; authenticates the key, **not** a party, so no non-repudiation |
| `ASYMMETRIC_SOFTWARE` | software-held asymmetric key (PQC ML-DSA) |
| `ASYMMETRIC_HARDWARE_ATTESTED` | HSM / PKCS#11 |

**Migration.** Rename the field at every read site. If you branched on `== "High"`, the nearest honest equivalent is `in {"ASYMMETRIC_SOFTWARE", "ASYMMETRIC_HARDWARE_ATTESTED"}` — **not** "anything but `Compromised`", because `SYMMETRIC_AUTHENTICATED` would have reported `"High"` before and is materially weaker. There is no compatibility alias: the old name is removed outright, so a client reading it gets nothing rather than a stale value. That is deliberate — a silently-wrong assurance string is the defect being fixed.

**Not affected:** `aegis.core.iso27037_evidence.EvidencePackage.legal_admissibility` is a different field with its own `Admissible`/`Conditional`/`Compromised` vocabulary and keeps its name. `ForensicPDFReportBuilder`'s caller-supplied parameter of the same name is also unchanged.

## 2. The enterprise server no longer trusts every client's forwarded headers (breaking for proxied deployments)

**What changed.** `aegis_server`'s `main()` passed `forwarded_allow_ips="*"` to uvicorn unconditionally. It now passes `EnterpriseSettings.get_trusted_proxy_cidrs()`, which defaults to `127.0.0.1,::1`.

**Who this breaks.** Any deployment terminating TLS or load-balancing at a proxy that reaches the gateway from an address other than loopback. Before, `X-Forwarded-For` was honoured from any peer; now it is honoured only from the configured CIDRs. Symptom: client IPs collapse to your proxy's address, so IP allowlisting, rate limiting and audit attribution all see the proxy instead of the real client.

**Migration.** Set the env var to the addresses your proxy actually connects from:

```bash
AEGIS_TRUSTED_PROXY_CIDRS="10.0.0.0/8,192.168.1.5"
```

In strict enforcement mode, `validate_runtime_invariants()` **refuses to start** if `*` appears in that list. That refusal runs from the ASGI lifespan, so it covers `uvicorn aegis_server.main:app` as well as `python -m aegis_server.main`. Development mode still permits an explicit `*` for local testing.

**Note on what was never affected:** `deploy/docker/docker-compose.enterprise.yml` passes no `--forwarded-allow-ips` flag, so it already ran under uvicorn's own conservative CLI default. If that compose file is your deployment, this change is a no-op for you.

## 3. MMR v2 is the default for new chains — gateway and SDKs must move together

`AEGIS_MMR_HASH_SCHEME` defaults to `auto`: a **new** chain starts on the domain-separated v2 construction, and an **existing** chain is reopened under whatever scheme its WAL recorded. Existing chains are not migrated and cannot be — a root cannot be recomputed under a different construction without rewriting the history it commits to. v1 chains stay verifiable under v1 indefinitely.

**The wire boundary is the upgrade hazard.** A receipt issued from a v2 chain does **not** verify against an SDK build predating `4.3.0`, which includes the published `4.1.2` packages. Upgrade the gateway and both SDKs together, or verification fails on receipts that are in fact valid.

To keep new chains on v1 during a staged rollout, set `AEGIS_MMR_HASH_SCHEME=v1` explicitly.

## 4. The WAF blocks payloads it previously allowed

Layer 1 normalization gained homoglyph mapping (Cyrillic/Greek/letterlike confusables to ASCII), letter-spacing collapse, and leetspeak folding. Requests that previously slipped past the critical patterns by obfuscation — `іgnоrе` with Cyrillic letters, `i g n o r e`, `1gn0r3` — are now blocked.

This is the intended fix, but it is a behaviour change: if you have traffic that legitimately trips the patterns after normalization, you will see new blocks. The de-obfuscation is matching-only and additive — it alters no bytes on the evidence path, and the canonical form is always scanned, so it can add a detection and never mask one. Bounds are in `CLM-091`; the limits are real and stated there.

## 5. The `pqc` extra now installs a library the code actually imports

The extra previously declared `oqs-python`, which nothing in the tree imported, so installing it enabled nothing. It now declares `kyber-py`, which `aegis/core/mlkem_session.py` actually uses. If you installed `.[pqc]` expecting the hybrid KEM to be live, it was not; it is now. Re-install the extra.

## 6. Additive node fields

`AuditNode` gained `waf_verdict` (`CLM-088`) and `shredding_version` (`CLM-068`). Both are omitted from the MMR leaf when empty, so **every pre-existing leaf, signature and issued proof is byte-identical** and no SDK wire boundary is created. If you parse audit nodes with a strict schema that rejects unknown keys, relax it.

## 7. Cryptographic shredding can now be enabled on an existing chain

`AEGIS_ENABLE_CRYPTOGRAPHIC_SHREDDING` remains **off by default**. Documentation through `4.3.0` said the flag could not be turned on for a chain that already holds records; that was wrong and is corrected in `5.0.0`. Sealing is decided per commit, so enabling it seals everything committed from that point forward and leaves earlier leaves exactly as written; the mixed chain still verifies.

The asymmetry to plan around is the reverse: nothing retroactively seals records already committed as plain digests, so enabling the flag does not make existing history erasable. See `CLM-068` for the full boundary, and note that no regulatory conclusion follows from the mechanism.

## 8. `AEGIS_MAX_FORENSIC_BYTES` now takes effect — and refuses values above 65,536 (`5.0.1` target)

`.env.example` has set `AEGIS_MAX_FORENSIC_BYTES=1048576` since `3.0.1`, but no setting read it: every gateway used a 65,536-byte preview cap whatever the variable said. Since the published `5.0.1` release (2026-09-24) a setting reads it (`REG-D59`), with a range of `0`–`65,536`. **If your environment still carries `1048576` from the old example, startup now refuses with a validation error** rather than silently growing every leaf sixteen-fold. Remove the variable to keep today's behaviour, or set a value in range.

Lowering the cap shrinks request and response previews in new leaves only; existing leaves, signatures and proofs are untouched. It is the precondition for zero-knowledge inclusion proofs (`DOC-08` §6.3), and it costs the preview evidence those bytes carry.

## 9. Signature verification pins keys, and the ledger refuses commits while faulted (unreleased source)

These changes are on `main` after `5.0.1` and are not in any published release. They change what verification reports, so read this before you upgrade a verifier.

**ML-DSA keys are pinned.** Earlier builds checked a `pqc-ml-dsa` signature against the public key recorded in the node itself, so anyone able to rewrite the WAL could re-sign a rewritten chain under a new key and it verified. A verifier now pins the public half of its own ML-DSA identity (`AEGIS_PQC_IDENTITY_PATH`) plus every key listed in `AEGIS_TRUSTED_SIGNING_PUBLIC_KEYS`, a comma-separated list of hex-encoded public keys.

| Your deployment | What you see after upgrading | What to do |
|---|---|---|
| One gateway that signs under its own identity and verifies its own chain | Nothing changes; its nodes read `valid`. | Nothing. |
| An identity was rotated, so older nodes carry an earlier key | Older nodes read `invalid` and `verify_integrity()` fails at the first of them. | List each retired public key in `AEGIS_TRUSTED_SIGNING_PUBLIC_KEYS`. |
| HA replicas, each with its own identity, sharing one chain | Each replica reads the other's nodes as `invalid`. | List every replica's public key on every replica. |
| A verifier with no identity and an empty allowlist | ML-DSA nodes read `unverified` (they read `valid` before), and `signature_assurance` reports `UNSIGNED`; strict mode fails the chain. | Configure the allowlist with the keys you trust. |

**`ed25519-fallback` reads `unverified`.** A fallback signature that checks now reads `unverified` rather than `valid`, because its key was minted for that one node and proves only internal consistency. `verify_integrity()` and the `COMPROMISED_EPHEMERAL` tier are unchanged. If you counted `valid` statuses, fallback nodes no longer count.

**The ledger refuses commits while faulted.** `commit_forensic`, `commit_state`, `commit_rejection` and `commit_forensic_summary` raise `LedgerFaultedError` (a `RuntimeError`) while the fault latch is anything but `healthy`. The gateway already answered `503` for this state; code that drives `CryptographicAuditLedger` directly and kept committing after a failed write will now get the exception. Recovery is the same as before: repair with `tools/wal_repair.py` where that applies, then open a new ledger.

**HA epoch after Redis data loss.** Nothing to configure. A replica lifts the writer epoch above the highest handover its WAL records when it takes the lease, so the manual step of restoring `aegis:ha:epoch:<chain>` after a Redis restart without persistence is no longer needed.

## 10. Malformed bodies answer `400`, a strict gateway refuses `tsa_url`, and the WAF refuses less ordinary prose (unreleased source)

These changes are on `main` after `5.0.1` and are not in any published release.

**Malformed bodies answer `400`, not `500`** (`CLM-118`). The three model endpoints parse every body with one helper.

| Body | Before | After |
|---|---|---|
| Invalid UTF-8, or an integer longer than Python's digit limit | `500 Internal server error` | `400 Invalid JSON` |
| Valid JSON that is not an object (a list, a string, `null`) | `500` at `/v1/chat/completions` and `/v1/completions`; `400 Anthropic request must be an object` at `/v1/messages` | `400 Request body must be a JSON object` at all three |
| Nested 11 to 32 levels | `403` from the WAF depth guard, with a rejection node | unchanged |
| Nested 33 levels to the parser's limit | `403` with a rejection node, or `500` once `canonical_normalize` ran out of stack | `400 JSON nesting exceeds 32 levels`, with a rejection node |
| Nested past the parser's own recursion limit | `500` | `400 Invalid JSON` |

If a client or dashboard counted `403` for over-deep bodies, count `400` with an `X-Aegis-Rejection-ID` instead. A `400` without that header is a body the gateway could not use, and it is not recorded, as before.

**A strict gateway refuses `tsa_url`** (`CLM-119`). RFC 3161 verification runs the `openssl` binary, and the seccomp profile forbids starting a program. Until now, the first anchor killed the gateway with SIGSYS. With `tsa_url` set and the filter about to load, the lifespan now raises before loading it:

- Strict mode with `require_seccomp` fails startup with `Seccomp enforcement required but unavailable: tsa_url is set, ...`.
- Development mode logs the reason and runs without the filter.

To keep trusted-time anchoring alongside the filter, unset `AEGIS_TSA_URL` on the gateway and timestamp the archived segment manifests from a separate process.

**The WAF refuses less ordinary prose** (`REG-D94`). Words containing "dan" ("guidance", "accordance", "Jordan") and "disregard previous" without an instruction object ("disregard previous correspondence") are no longer refused. If you relied on those refusals as a crude filter, add the phrases to your own policy. The DAN and disregard attack forms are still refused.

**The WAF refuses more attacks** (`CLM-117`). It now refuses several spellings it used to pass:

- tag-character, invisible-character and combining-mark spellings;
- star-, slash- and pipe-separated spellings;
- phrases with their spaces removed;
- base64-wrapped phrases;
- Layer-2 phrases in any field, not only `messages`.

A tool description or metadata string that contains a Layer-2 phrase can now cause a refusal. Check your tool schemas against `/v1/chat/completions` in development mode before upgrading.

**WAL rotation, S3 archival and cryptographic shredding now run behind the filter.** Nothing to configure. They were killed with SIGSYS on first use before (`CLM-119`). The larger profile is loaded only when archival, shredding or the SQLite HA sequence store is configured.

## 11. The licence changes to Apache-2.0 (`5.0.2` published release)

**What changed.** The `5.0.2` source is licensed under the Apache License, Version 2.0. Releases up to and including `5.0.1` were published under the GNU Affero General Public License v3 or a separate commercial licence and keep those terms. The licence of a copy is the licence it was published under, and an executed agreement keeps its own terms; a repository edit amends neither. `5.0.2` is published, so no copy exists yet that carries the new terms ([Release Status](RELEASE_STATUS.md) §1.0c).

**What it means for you, stated as obligations of the licence text, not as legal advice.** Apache-2.0 asks a redistributor to give recipients a copy of the licence, to keep the `NOTICE` attribution, to mark files it changed, and to keep copyright, patent and attribution notices. It does not carry the AGPLv3 network-use clause, so running a modified copy as a service does not by itself oblige you to offer its source. It grants no right to the name or marks (Section 6) and provides the software as is (Section 7). Whether a particular use or distribution complies is a question for your counsel.

**What does not change.** The runtime, the wire formats, the configuration surface and the evidence schema are unchanged; apart from the version strings, headers and one reworded licensing-engine error message, no code path moved. A `5.0.1` gateway and a `5.0.2` gateway behave the same.

**What you may notice.**

- Package metadata reads `Apache-2.0` (PEP 639 `License-Expression`); the AGPL trove classifier is gone. Tools that classify by licence will see the change.
- The Python SDK, the TypeScript SDK and all three container images carry `LICENSE` and `NOTICE` (the images under `/licenses/`), and the OCI `licenses` label reads `Apache-2.0`.
- Each source file opens with a three-line header naming `SPDX-License-Identifier: Apache-2.0`.
- The licence-entitlement engine is unchanged: it is off by default, `AEGIS_LICENSE_ENFORCEMENT` still gates only the optional engine facades, and it is an entitlement signal, not a licence grant.
- The deployment defaults that name `ghcr.io/juanlunaia/aegis-latent-core:5.0.2` resolve to nothing until that image is published; pin `5.0.1` if you must deploy before then.

**Migration.** None is required to keep running `5.0.1`. If you consume the source or a future `5.0.2` artifact, review the licence conditions above; if you hold a commercial agreement, its terms still govern your copy. See [`legal/LICENSE_TRANSITION_5.0.2.md`](legal/LICENSE_TRANSITION_5.0.2.md).

---

## Upgrade order

1. Read §1 and §2 and change your API reads and proxy configuration **first**.
2. Upgrade both SDKs and the gateway together (§3).
3. Roll out to a non-production environment and exercise your own traffic against the stricter WAF (§4).
4. Verify `/audit/integrity` returns the `signature_assurance` tier you expect, and that it is not weaker than you assumed.
5. Before upgrading any verifier to a build that pins keys (§9), list every rotated or replica public key it must accept.

## Rollback

Rolling back to `4.1.2` is a provenance operation as well as a deployment one; the constraints in [Release Status §7](RELEASE_STATUS.md) apply. In particular: preserve every WAL before changing versions, and note that a chain started on v2 under `5.0.0` **cannot** be read by a `4.1.2` gateway, so rollback is not symmetric. Plan the v2 decision (§3) accordingly.

---

**Related:** [Release Status](RELEASE_STATUS.md) · [Claims Matrix](CLAIMS_MATRIX.md) · [CHANGELOG](../CHANGELOG.md) · [Platform Compatibility](PLATFORM_COMPATIBILITY.md)
