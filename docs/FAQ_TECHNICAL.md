# Technical FAQ — Aegis Latent Core

This FAQ answers implementation and operating questions for developers and platform engineers. Each answer states the current boundary and links to the implementation or verification path. It is not a substitute for the architecture or deployment guides.

**Last verified:** 2026-08-27 UTC
**Release baseline:** `v5.0.0`, **published 2026-09-16 on every surface except PyPI `aegis-latent-core`**; `v4.1.2` remains the most recent version published on every surface. External release status always requires independent readback, recorded in `docs/RELEASE_STATUS.md` §1.0 and §1.1
**Source baseline:** `v5.0.0`; the source version does not by itself prove that the tag, packages, images, or attestations were published — each was read back separately, and PyPI `aegis-latent-core` was **not** published at `5.0.0`
**Retained evidence baseline:** `v3.1.0`; retained measurements are historical evidence for that release only
**Comparison anchor:** `fdace8844568eb788216740b2cb5daf187d99d3b` (the pre-v4.0.2 source snapshot; its active version anchors were `4.0.0`)
**Audience:** Developers, platform engineers and technical evaluators
**Root document:** [`README.md`](../README.md)

Answers about implementation behavior refer to the `v4.1.2` source unless they identify retained evidence. Publication status must be verified independently against the Git tag, GitHub Release, package registries, OCI registry, and their attestations. All retained numeric measurements in this FAQ belong to the published `v3.1.0` historical evidence baseline; they must not be promoted to v4 capacity, latency, availability, detection, security, or SLO claims without a v4 rerun and applicable target-environment acceptance evidence.

## What does Aegis do?

Aegis is an OpenAI-compatible AI Governance and Evidence Gateway. It applies configured request controls and forwards admitted traffic to an upstream provider. Non-streaming governed outcomes return after their evidence commit. Admitted SSE emits sanitized events incrementally, then emits its terminal marker only after the one terminal summary commit succeeds.

## Is Aegis an LLM?

No. Aegis does not generate model output, determine whether an upstream answer is correct, or replace provider safety, identity, network, privacy or incident-response controls.

## What does durable mean?

In the declared local implementation, durable means the evidence record was appended, flushed and synchronized through the configured WAL path before a non-streaming governed response returns or an SSE terminal marker is emitted. Initial SSE headers say `pending-terminal`, not `durable`. This does not prove power-loss durability, replicated cloud-volume semantics, immutable backup, or external retention.

## Are request and response bodies stored?

The documented WAL model stores hashes and evidence metadata rather than plaintext request and response bodies. Operators must still inspect reverse proxies, upstream providers, logs, traces, crash dumps, enrichment stores and backups. A hash or tenant identifier can remain sensitive or personal data.

## What happens when `fsync` stalls?

The authoritative path can block or reject according to configured bounds. It must not silently return a governed accepted response without its evidence record. The in-tree 2026-08-20 offered-load run preserved all 2,500 records at 10,000 RPS offered under 2 ms injected delay and recorded p99 commit latency of 836.3514210795984 ms; the current 2026-09-16 baseline records 51.87 ms (`evidence/execution_2026-08-20/`, `evidence/execution_2026-09-16/`). The previously published 10,000-record run with p99 1,189.89 ms is retracted (`UC-018`): no artifact in this tree produces it. Neither result is v4 capacity or SLO evidence. See [`docs/operations/BACKPRESSURE_RUNBOOK.md`](operations/BACKPRESSURE_RUNBOOK.md).

## What happens when Redis fails?

Strict distributed rate limiting is intended to fail closed or return the documented unavailable-backend path. The development in-memory limiter is not a production substitute. Verify Redis TLS, authentication, HA and capacity in the target environment.

## What happens when the upstream returns `503`?

The gateway records the terminal outcome through the configured durable error-evidence path when the evidence boundary is available. If the signer or storage path fails, the operation is not treated as a successful governed response.

## Are streaming responses emitted immediately?

Yes, after finite de-identification holdback and queueing: the governed path incrementally emits sanitized canonical SSE events through a bounded, byte-accounted queue. It computes SHA-256 over the exact emitted bytes and makes one terminal summary WAL commit. The terminal marker (`[DONE]` or the provider-specific equivalent) is emitted only after that commit succeeds; initial headers therefore report evidence and proof as `pending-terminal`, and the linked proof endpoint is queried after termination. Backpressure, queue-byte, queue-event, event-size, cumulative-output, de-identification-window, preview, and duration bounds apply to each admitted stream, while aggregate retained memory scales with concurrent streams. See `tests/test_proxy_streaming.py` and `specs/aegis_stream_buffer.smt2`. Provider-specific semantics still require integration testing.

## Does the local WAF cover HTTP/2 evasion?

No. The pinned application-layer corpus covers 15 malicious and 8 benign cases. It does not cover HTTP/2 frame fragmentation, pseudo-header ordering, continuation boundaries, parser differential behavior, compressed-body parsing, or ingress proxy translation. `nuclei-templates/waf-bypass` remains unexecuted in the retained evidence.

## Does the WAF guarantee zero bypasses?

No. The retained corpus observed zero bypasses and zero false positives, but the corpus is small and its confidence interval is wide. The result is a regression signal for the named corpus, not universal detection coverage.

## How are portable MMR proofs delivered?

Durable non-streaming responses expose the `aegis-mmr-inclusion-v1` format, leaf, logical index/count, base64url proof and root in `X-Aegis-MMR-*` headers. Both non-streaming and SSE responses link to authenticated `GET /v1/audit/proofs/{request_id}`. Because SSE headers cannot change after emission begins, its proof status is initially `pending-terminal`; query the linked endpoint after terminal commit. Python and TypeScript SDK verifiers consume the same portable format and do not require the gateway's in-memory MMR state. See [`docs/api/MMR_PROOF_V1.md`](api/MMR_PROOF_V1.md).

## Are the SDKs provider-native?

Yes. The Python `aegis_sdk.openai.OpenAI`/`AsyncOpenAI` and `aegis_sdk.anthropic.Anthropic`/`AsyncAnthropic` classes subclass the official clients. TypeScript exposes equivalent wrappers at `aegis-latent-sdk/openai` and `aegis-latent-sdk/anthropic`. OpenAI traffic uses `/v1/chat/completions`; native Anthropic messages use `/v1/messages` and require `AEGIS_PROVIDER=anthropic`.

## Is the native Rust WAL the replay authority?

No. The JSONL WAL remains authoritative for replay and recovery. When the native extension is available, Aegis opens `<wal_path>.stream.rwal` as an optional auxiliary `RustWal` segment and appends a CRC-framed copy after the JSONL terminal stream node commits. If that auxiliary append fails, the process increments `aegis_native_stream_wal_errors_total`, logs and disables the segment, and preserves the already-authoritative JSONL outcome and client terminal marker.

## How is the forensic dashboard authenticated and exported?

The Next.js dashboard keeps `AEGIS_DASHBOARD_API_KEY` inside `server-only` route handlers and uses `AEGIS_PRIMARY_BASE_URL` for backend requests. Do not expose the key through a browser bundle or `NEXT_PUBLIC_*`. The forensic export route returns a bounded ZIP containing integrity files, `manifest.json` and `VERIFY.sh`; it is technical integrity evidence, not a legal-admissibility decision.

## Does HMAC provide non-repudiation?

No. HMAC is symmetric. Any verifier that holds the HMAC key can create a valid HMAC. HMAC is classical and does not provide a third-party non-repudiation argument by itself.

## Is ML-DSA constant-time?

No constant-time claim is approved. The retained 1,000,000-sample experiment reported `p=0.8521504207157158` for `sign` and `p=0.0` for `verify`. The verify experiment detected a class-dependent timing difference at the measured Python-to-Rust boundary.

## Does Aegis provide global ordering across replicas?

No. Independent replicas produce independently verifiable evidence bundles unless a centralized writer or equivalent ordering service is deployed. A three-replica local key rotation result does not prove global ordering or production failover.

## There is a CRDT in the repository — doesn't that give ordering across replicas?

Not for any running system, and enabling the mesh does not change that. `CausalMmr` (`aegis_rust_v2/src/crdt_mmr.rs`) is a join-semilattice whose `join` is idempotent, commutative and associative, so replicas exchanging leaf sets converge on one root whatever order they merge in. `GossipDaemon` now supplies a real transport for it over mutual TLS, started by the gateway's own lifespan and **off by default** (`CLM-080`). What has not changed is the part that matters here: it reconciles the **CRDT accumulator, not the ledger**. Each replica's WAL remains its own single-writer chain, no receipt or root the ledger issues is affected, and there is still no membership protocol or persistence for the accumulator — so the answer above is unchanged.

Two further limits are worth stating because they do not go away once a transport exists. Convergence is not agreement about truth: `join` reconciles replicas that disagree about *ordering*, not replicas that lie, and a replica contributing fabricated leaves has them merged like any other — Byzantine resistance is a separate, unaddressed problem. And a merged root commits to a *set* of leaves; it does not re-link the per-replica `prev_hash` chains into one. No convergence-latency or throughput figure exists, and none can be measured until there is something to measure, so no comparison against a consensus protocol may be quoted. `CLM-066`; [DOC-01 §8.8](institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md).

## Can I erase a subject's data from the ledger?

Not by deletion, and not on a chain that is already running. Deleting or editing a committed node breaks chain linkage and invalidates the root for every record after it — the integrity check would then report an untampered chain as corrupt.

`aegis/core/crypto_shredder.py` resolves that structural conflict: per-subject AES-256-GCM envelope encryption, where the ledger commits the ciphertext, so destroying the key leaves the root, the peaks and every previously issued proof bit-for-bit unchanged. Since `4.3.0` the ledger can use it, behind `AEGIS_ENABLE_CRYPTOGRAPHIC_SHREDDING=true`. **It is off by default**, and a default-configured gateway commits payload digests exactly as before, so `crypto_shred()` on such a ledger refuses rather than quietly reporting success. **Turning it on for a chain that already holds records is supported**: sealing is a per-commit decision, not a per-chain one — `_seal_leaf` branches on whether the shredder is configured at the moment each leaf is built — so re-opening an existing WAL with the flag newly on seals every commit from that point forward and leaves history exactly as written. The resulting chain is genuinely mixed, and `verify_integrity()` passes on it, because neither leaf form was ever a `node_hash` input; `AuditNode.shredding_version` is what tells the two kinds apart. What has no migration path is the **reverse** — nothing seals leaves already committed as plain digests, matching the append-only design.

Where it is on, the claim is still bounded: the plaintext becomes unrecoverable *to a holder of the ciphertext*. It says nothing about key material on the physical medium, a restored backup of the key vault undoes every erasure performed through it, and the node keeps its request and response digests — keyed to the subject under the current `v2` scheme, so a guess stops being confirmable when the key is destroyed, while a legacy `v1`-sealed node keeps plain digests a guessed plaintext can still be confirmed against (`CLM-098`). Whether any of this discharges a legal obligation is a controller determination made with counsel — see [DOC-05 §5.8.1](institutional/DOC-05_REGULATORY_DOSSIER.md) and `CLM-068`. Do not describe Aegis as satisfying a right to erasure.

## How do I rotate HMAC keys without a restart?

Configure the versioned keyring path and reload interval, deliver a complete validated snapshot atomically, keep an overlap verification key during the declared window, and monitor key IDs and failures. See [`docs/operations/KEY_ROTATION_RUNBOOK.md`](operations/KEY_ROTATION_RUNBOOK.md). A local keyring is not a secret manager.

## What must I test before production?

Test the target ingress, TLS, provider, storage, backup/restore, Redis, secret manager, key rotation, kernel profiles, network egress, logging redaction, queue saturation, rollback and incident response. The repository's local gates are necessary evidence but are not a substitute for environment acceptance.

## How can I verify integrity offline?

Use the repository verifier and the retained export manifest for the applicable release. Preserve the original bytes and metadata. Offline integrity verification shows that the declared data matches the declared hash/signature chain; it does not establish the truth of the upstream content or legal admissibility.

## What performance overhead does Aegis add?

No general overhead figure is published, and none should be quoted, because overhead depends on your workload, hardware, storage device, provider latency, and configuration. The retained measurements below are each valid only inside their declared scope, and all are recorded in [`BENCHMARK_RESULTS.md`](benchmarks/BENCHMARK_RESULTS.md).

| Retained measurement | Scope | Result | What it does not establish |
|---|---|---|---|
| Bounded SSE transformation | In-process transform on a recorded sandbox host; 7 rounds × 1,000 deterministic events | First-byte p50 `2.030 ms`, p95 `2.295 ms`; `3,155.654` events/s p50; queue high-water `664` bytes / `8` items; allocation peak `141,338` bytes | Excludes network, provider, and durable-WAL latency. It opens no socket and performs no ledger commit, so it does not establish gateway capacity, end-to-end latency, or an absence of measurable cost. |
| Backpressure under injected I/O stall — **current in-tree baseline** (2026-09-16, `88e01f0`) | 2,500 offered requests over a 0.25 s window at 10,000 RPS offered, 2 ms injected `fsync` delay; 1.57 s to drain | 2,500 durable commits, 0 failures, 0 missing identifiers, 0 duplicates, valid chain; p50 `33.545 ms`, p95 `41.176 ms`, p99 `51.875 ms`, max `59.726 ms`; 200 `fsync` calls | The queue is still not low-latency under this stall. It is a bounded-behavior gate, not a service level objective, and does not model a real block device. The latency is queueing at an offered rate that is not accepted capacity, not per-request overhead. |
| Backpressure under injected I/O stall — superseded pre-group-commit baseline (2026-08-20, `20fa011`) | Identical parameters; 6.63 s to drain | 2,500 durable commits, 0 failures, 0 missing identifiers, 0 duplicates, valid chain; p50 `167.290 ms`, p95 `504.704 ms`, p99 `836.351 ms`, max `2,290.622 ms`; 2,501 `fsync` calls | Correct for the tree it measured, which fsynced once per committed node. Superseded for current-state citation by the row above — do not quote it as current. |
| Backpressure under injected I/O stall — **retracted `v3.1.0` observation** | 10,000 offered requests over 32.4 s, 2 ms injected `fsync` delay (as previously published) | **Not citable:** the 10,000-record count and the p99 `1,189.891 ms` figure are retracted (`UC-018`) because no artifact in this tree produces them. Cite the two in-tree rows above. | Same boundaries as the rows above, plus one more: the raw JSON for the retracted run was never committed, so a reader cannot re-derive it here and the pair is no longer restated as evidence. |

The first two rows are the same workload at two source commits; the third is a different workload. Cite the 2026-09-16 row for current source. Quoting one run's latency beside another's request count produces a number that was never measured. See [`BENCHMARK_METHOD.md`](benchmarks/BENCHMARK_METHOD.md).

**None of these three is the answer to "how much latency does Aegis add per request."** For that, the closest measured figure is `commit_forensic` with a real `fsync` per node at 808.565 µs/op, in [`evidence/evidence_path_measurements_2026-09-03.md`](../evidence/evidence_path_measurements_2026-09-03.md) §2 — itself an in-process microbenchmark on four shared vCPUs, not an end-to-end figure.

The structural point matters more than either number. On the non-streaming path a governed response returns only after its evidence commit, so **storage latency is request latency by design**. Choosing a slow or contended device converts directly into user-visible latency rather than into silent evidence loss. Measure on your own workload before committing to any internal target; do not promote either figure above into a capacity, availability, or service-level claim.

## Is Aegis quantum-ready?

No such claim is made. ML-DSA-65 is reachable through the native Rust dependency when that extension is present, and hybrid key-encapsulation surfaces are documented as boundaries rather than delivered guarantees. Availability of an algorithm is not a migration: key custody, protocol negotiation, interoperability with your counterparties, and provider-side support all remain external.

The repository does not claim a validated implementation, and the retained ML-DSA timing experiment returned `p = 0.0`, so no timing-resistance claim is approved. A p-value above 0.05 in any such experiment would not prove constant-time execution either; it would only mean the experiment did not detect a difference at its declared sensitivity. Treat post-quantum readiness as a programme you run, not a checkbox this gateway satisfies.

## Does Aegis have FIPS validation?

No. There is no FIPS 140-2 or 140-3 validated cryptographic module in this repository, and no validation certificate exists for any component. The cryptographic capability report deliberately labels FIPS validation as absent rather than pending, so that a reader cannot infer partial credit.

If your programme requires a validated module, that requirement is satisfied by the platform you deploy onto — a validated OpenSSL provider, an HSM with its own certificate, or an equivalent — and it must be evidenced by that vendor's certificate, not by this project. Nothing in the gateway's use of SHA-256, HMAC, or an HSM interface confers validation status.

## Related documents

- [`docs/DEVELOPER_QUICKSTART.md`](DEVELOPER_QUICKSTART.md)
- [`docs/architecture/ARCHITECTURE.md`](architecture/ARCHITECTURE.md)
- [`docs/PLATFORM_OPERATOR_GUIDE.md`](PLATFORM_OPERATOR_GUIDE.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
- [`docs/FAQ_SECURITY.md`](FAQ_SECURITY.md)
- [`docs/FAQ_PROCUREMENT.md`](FAQ_PROCUREMENT.md)
