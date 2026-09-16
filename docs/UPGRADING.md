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

## Upgrade order

1. Read §1 and §2 and change your API reads and proxy configuration **first**.
2. Upgrade both SDKs and the gateway together (§3).
3. Roll out to a non-production environment and exercise your own traffic against the stricter WAF (§4).
4. Verify `/audit/integrity` returns the `signature_assurance` tier you expect, and that it is not weaker than you assumed.

## Rollback

Rolling back to `4.1.2` is a provenance operation as well as a deployment one; the constraints in [Release Status §7](RELEASE_STATUS.md) apply. In particular: preserve every WAL before changing versions, and note that a chain started on v2 under `5.0.0` **cannot** be read by a `4.1.2` gateway, so rollback is not symmetric. Plan the v2 decision (§3) accordingly.

---

**Related:** [Release Status](RELEASE_STATUS.md) · [Claims Matrix](CLAIMS_MATRIX.md) · [CHANGELOG](../CHANGELOG.md) · [Platform Compatibility](PLATFORM_COMPATIBILITY.md)
