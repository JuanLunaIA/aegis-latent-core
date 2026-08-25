# Technical FAQ — Aegis Latent Core v3.1.0

This FAQ answers implementation and operating questions for developers and platform engineers. Each answer states the current boundary and links to the implementation or verification path. It is not a substitute for the architecture or deployment guides.

**Last verified:** 2026-08-22 UTC
**Release baseline:** `v3.1.0`
**Current main verified:** `45d95188d40792639fdd654369765a7233bef09a` (post-release; not the `v3.1.0` tag)
**Audience:** Developers, platform engineers and technical evaluators
**Root document:** [`README.md`](../README.md)

## What does Aegis do?

Aegis is an OpenAI-compatible AI Governance and Evidence Gateway. It applies configured request controls and forwards admitted traffic to an upstream provider. Non-streaming governed outcomes return after their evidence commit. Admitted SSE emits sanitized events incrementally, then emits its terminal marker only after the one terminal summary commit succeeds.

## Is Aegis an LLM?

No. Aegis does not generate model output, determine whether an upstream answer is correct, or replace provider safety, identity, network, privacy or incident-response controls.

## What does durable mean?

In the declared local implementation, durable means the evidence record was appended, flushed and synchronized through the configured WAL path before a non-streaming governed response returns or an SSE terminal marker is emitted. Initial SSE headers say `pending-terminal`, not `durable`. This does not prove power-loss durability, replicated cloud-volume semantics, immutable backup, or external retention.

## Are request and response bodies stored?

The documented WAL model stores hashes and evidence metadata rather than plaintext request and response bodies. Operators must still inspect reverse proxies, upstream providers, logs, traces, crash dumps, enrichment stores and backups. A hash or tenant identifier can remain sensitive or personal data.

## What happens when `fsync` stalls?

The authoritative path can block or reject according to configured bounds. It must not silently return a governed accepted response without its evidence record. The retained 10k offered-load run preserved all 10,000 records under 2 ms injected delay but recorded p99 commit latency of 1,189.89 ms. See [`docs/operations/BACKPRESSURE_RUNBOOK.md`](operations/BACKPRESSURE_RUNBOOK.md).

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

## How do I rotate HMAC keys without a restart?

Configure the versioned keyring path and reload interval, deliver a complete validated snapshot atomically, keep an overlap verification key during the declared window, and monitor key IDs and failures. See [`docs/operations/KEY_ROTATION_RUNBOOK.md`](operations/KEY_ROTATION_RUNBOOK.md). A local keyring is not a secret manager.

## What must I test before production?

Test the target ingress, TLS, provider, storage, backup/restore, Redis, secret manager, key rotation, kernel profiles, network egress, logging redaction, queue saturation, rollback and incident response. The repository's local gates are necessary evidence but are not a substitute for environment acceptance.

## How can I verify integrity offline?

Use the repository verifier and the retained export manifest for the applicable release. Preserve the original bytes and metadata. Offline integrity verification shows that the declared data matches the declared hash/signature chain; it does not establish the truth of the upstream content or legal admissibility.

## Related documents

- [`docs/DEVELOPER_QUICKSTART.md`](DEVELOPER_QUICKSTART.md)
- [`docs/architecture/ARCHITECTURE.md`](architecture/ARCHITECTURE.md)
- [`docs/PLATFORM_OPERATOR_GUIDE.md`](PLATFORM_OPERATOR_GUIDE.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
- [`docs/FAQ_SECURITY.md`](FAQ_SECURITY.md)
- [`docs/FAQ_PROCUREMENT.md`](FAQ_PROCUREMENT.md)
