# Product and Evidence Boundaries

**Last verified:** 2026-09-01 UTC
**Release baseline:** checked-out source baseline `v5.0.0` with fourteen synchronized anchors, published 2026-09-16 on every surface except PyPI `aegis-latent-core` (see `docs/RELEASE_STATUS.md` §1.0)

This document consolidates the boundary statements that apply across Aegis. It exists so that `README.md` and the developer guides can describe mechanisms plainly and link here once, instead of repeating a disclaimer beside every sentence.

Nothing here weakens a claim made elsewhere. Where this document and marketing copy disagree, this document and [`CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md) control.

## What Aegis is

An OpenAI-compatible governance and evidence gateway. It sits between an application and an upstream model provider, applies configured request policy, and commits a signed, hash-linked record of governed interactions before returning a response.

## What Aegis is not

It is not a model, a universal web application firewall, a compliance certification, a legal-admissibility determination, a service level objective, or a replacement for network, identity, privacy, retention, or incident-response controls in the deploying organization.

## Evidence boundaries

| Mechanism | What it establishes | What it leaves open |
|---|---|---|
| Durable commit before response | The evidence record was written, flushed, and synchronized through the configured path before the response returned | `fsync` returning means the process asked the kernel to flush. Survival of a power cut is a property of the device, controller, and filesystem. See [storage requirements](operations/STORAGE_REQUIREMENTS.md). |
| Hash chain and signature | Modification of a committed record is detectable without the signing key | The signer is symmetric HMAC by default. A holder of that key can rewrite history consistently. Third-party non-repudiation requires an asymmetric signer and external key custody. |
| Portable MMR inclusion proof | A disclosed leaf is included under a root the verifier already trusts | It does not establish authorship, time, custody, ordering across processes, external immutability, or that the trusted root is authentic. The root must be pinned through an independent channel. |
| Streaming terminal summary | Exactly one summary covering the exact emitted bytes was committed before the terminal marker | Initial stream headers are `pending-terminal` and carry no proof. Per-stream bounds are enforced; aggregate memory scales with concurrency and needs deployment-level admission control. |
| Formal artifacts | The stated formulas and bounded models hold under their declared assumptions | They are abstractions, not refinement proofs of the Python runtime, the Rust runtime, the FFI boundary, the filesystem, or any deployment. |
| Streaming de-identification | Supported bounded identifier grammars are settled before release, including across chunk boundaries | It is deterministic pattern matching. It does not detect every encoding, paraphrase, or semantic disclosure, and it is not the complete HIPAA Safe Harbor method or Expert Determination. |
| Non-JCS integrity seals | `aegis/core/rfc3161_timestamper.py`, `forensic_pdf_report.py`, `iso27037_evidence.py`, and `dfir_export.py` compute their SHA-256 seal over `json.dumps(obj, sort_keys=True, separators=(",", ":"))` — deterministic for the accepted Python object and serializer behavior | This is **not** RFC 8785 JSON Canonicalization Scheme: `ensure_ascii` is left at Python's default (`True`), so non-ASCII characters are `\uXXXX`-escaped rather than emitted as raw UTF-8, and float formatting follows Python's shortest-round-trip `repr`, not RFC 8785's mandated ECMAScript `Number.prototype.toString()` algorithm. A seal computed this way only agrees with an independent RFC 8785 JCS implementation for inputs where both algorithms happen to coincide (ASCII-only strings, no floats or floats both encode identically). It remains valid tamper-evidence for same-process write/verify, since both sides use the same Python serializer. The genuinely RFC 8785-conformant path is `canonical_jcs_bytes` (`aegis/core/forensic_bundle.py`), which sidesteps the float-formatter gap by rejecting floats from its canonical domain outright rather than reimplementing ECMAScript formatting. See [`institutional/DOC-02_CRYPTOGRAPHIC_FORENSIC_BLUEPRINT.md`](institutional/DOC-02_CRYPTOGRAPHIC_FORENSIC_BLUEPRINT.md) §5 and its `DOC02-SER-001` row for the per-function locators. |
| Refused commit on group-commit `fsync` failure | A caller told the commit failed (`503`, `wal_persist_failed` latched) saw a real failure — no node is returned as committed to that caller, and no later node links against an unconfirmed one | The refused record's bytes were already `write()`n and `flush()`ed under the ledger lock *before* the shared `fsync` that failed (`CLM-082`'s coalesced-commit ordering), so they are still in the WAL file. Replay on restart parses that line like any other and reads it back as committed — evidence exists for a request whose caller was told it failed. That is the safe direction of the asymmetry: `_await_durable` never lets the reverse happen (a caller told "durable" with nothing behind it). See [`architecture/FAILURE_SEMANTICS.md`](architecture/FAILURE_SEMANTICS.md) §3 and `tests/test_coalesced_commit.py`. |
| Zero-knowledge inclusion proof feasibility | Circuit cost is linear in leaf length; a leaf built with a small or zero `max_forensic_bytes` proves and verifies (`CLM-089`: no setup, proving, verification or proof-size figure is claimed) | `max_forensic_bytes` is **not configurable through the gateway** — `aegis/proxy/app.py` constructs `CryptographicAuditLedger` without it and `aegis/config.py` defines no setting or environment variable for it — so every gateway-written leaf uses the 65,536-byte default, a ~262 KB hex-encoded prefix, and on the order of 10⁸ constraints (`CLM-089`); only an in-process caller passing `max_forensic_bytes` directly to the ledger constructor can produce a provable shape. Nothing bounds a declared shape either: `zk_verifier_key(prefix_len, path_depth, peak_count)` allocates from three caller-supplied integers with no backing bytes, so a verifier deriving a key from a prover-published shape must bound it themselves first. See [`institutional/DOC-08_ZERO_KNOWLEDGE_INCLUSION.md`](institutional/DOC-08_ZERO_KNOWLEDGE_INCLUSION.md) §6.3 and §6.5. |
| Recovered terminal evidence (`REG-D32`) | A node signed `stream-terminal-evidence-recovered` is a new node committed at startup from the opt-in outbox: its digests, sizes, counts and labels match the lost live commit, its request and response previews are empty, and its timestamp is the replay time. The outbox makes teardown evidence survive process death once written and power loss once the worker has synced; it is off by default, does not cover an inline completion commit, suppresses duplicates only within the retained window, and does not replay onto a ledger whose fault state is not `healthy`. | `docs/CLAIMS_MATRIX.md` (`CLM-106`); `tests/test_terminal_outbox.py` |
| Zero-knowledge circuit build (`zk-spartan`) on x86-64 | The feature is opt-in and off by default; when enabled on x86-64 it compiles `halo2curves`' assembly field arithmetic — `spartan2` 0.9's x86-64 dependency declares `halo2curves` with `feature = "asm"`, which makes `halo2derive` emit `adcx`/`adox` limb code — and the circuit tests execute only on a CPU that implements ADX | On an x86-64 CPU without ADX (Intel pre-Broadwell, AMD pre-Excavator; this repository's own seal host is a Haswell `i5-4300U`) the prover path executes an illegal instruction and the process dies with `SIGILL` — there is no runtime feature detection in that dependency chain to refuse gracefully. Nine of the sixteen `zk_mmr` unit tests and the seven-test `zk_mmr_end_to_end` target crash on such a host; the same commands pass in CI's Rust Extension job on ADX-capable runners (`dc20a2c`, CI run #582). See [`REGISTRY.md`](REGISTRY.md) `REG-D04` and [`../evidence/registry/reg-d04_documented.txt`](../evidence/registry/reg-d04_documented.txt). |
| RFC 3161 TSA response acceptance | Tokens are persisted only after nonce/imprint checks and OpenSSL verification against an explicit trust store; no OCSP/CRL revocation checking and no RFC 5280 name-constraint/policy/EKU evaluation is performed, and an obtained response is not a trusted timestamp. | `REG-021`, `CLM-014`, `CLM-096` |

## Regulatory boundaries

Aegis can contribute technical inputs to a customer's own governance programme. It does not determine regulatory applicability, perform a conformity assessment, issue a certification, establish a lawful basis, or decide admissibility. Scope, configuration, retention, custody, operating effectiveness, and jurisdiction-specific conclusions belong to the deploying organization and its qualified reviewers.

See [`compliance/COMPLIANCE_MAPPING.md`](compliance/COMPLIANCE_MAPPING.md) for the framework-by-framework mapping and [`institutional/DOC-05_REGULATORY_DOSSIER.md`](institutional/DOC-05_REGULATORY_DOSSIER.md) for the full dossier.

## Deployment boundaries

Topology determines evidence semantics. A single process with one worker and its own write-ahead log produces one process-local ordered sequence. Multiple workers sharing one log path do not, and that configuration is unsupported for a single ordered chain. Cross-process and cross-region total ordering is not implemented.

See [`institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md`](institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md) section 8 for the topology matrix.

## Threat-model non-goals

Physical attacks, hypervisor or firmware compromise, host-root adversaries, micro-architectural side channels, guaranteed prevention of prompt injection, upstream provider trustworthiness, and network-layer denial of service are outside the model by design.

See [`institutional/DOC-03_THREAT_MODEL.md`](institutional/DOC-03_THREAT_MODEL.md) section 5.3.

## Evidence-state vocabulary

| State | Meaning |
|---|---|
| **Implemented** | Source and regression tests establish the behavior under stated conditions. |
| **Measured** | A named workload, revision, environment, date, and retained artifact establish a bounded result. |
| **Configuration-dependent** | The control requires validation in the target deployment. |
| **Roadmap** | Incomplete or unmeasured; must not be described as available. |
| **Legal-review-required** | Regulatory, certification, procurement, contractual, and admissibility conclusions sit outside repository evidence. |

## Related documents

- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md) — controlling public claims register.
- [`docs/RELEASE_STATUS.md`](RELEASE_STATUS.md) — version, publication, and provenance record.
- [`docs/institutional/UNSUPPORTED_CLAIMS.md`](institutional/UNSUPPORTED_CLAIMS.md) — claims explicitly not supported.
- [`docs/security/THREAT_MODEL.md`](security/THREAT_MODEL.md) — security threat model.
