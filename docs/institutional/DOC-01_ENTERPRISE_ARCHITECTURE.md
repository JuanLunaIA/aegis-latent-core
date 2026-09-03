# DOC-01 — Enterprise Architecture and Mechanistic Lifecycle Specification

**Document ID:** DOC-01
**Title:** Enterprise Architecture and Mechanistic Lifecycle Specification
**Canonical language:** US English
**Source baseline:** checked-out source metadata is synchronized at `v4.1.0`; external tag, release, registry, OCI, deployment, and acceptance claims require independent readback
**Historical inspection scope:** findings and evidence dated 2026-08-20 UTC remain a `v3.1.0`-era review record unless a claim is explicitly revalidated against the current source
**Status:** Architecture review record with bounded claims
**Normative claim control:** [`docs/CLAIMS_MATRIX.md`](../CLAIMS_MATRIX.md)
**Primary human-review owners:** Release owner, platform/SRE owner, storage owner, qualified security reviewer, and formal-methods reviewer

## 1. Purpose and evidentiary posture

This document specifies the implemented Aegis gateway architecture, the client-visible request lifecycle, trust boundaries, deployment topology, evidence persistence mechanisms, formal abstractions, and failure semantics. It treats repository prose as a source to be audited rather than as proof. Implementation statements below are grounded in exact production paths and named tests. Statements that depend on an operating system, filesystem, external database, cloud service, ingress, signer, or deployment topology are explicitly classified as **`CONFIGURATION-DEPENDENT`**. Unimplemented or unverified properties are classified as **`ROADMAP`** rather than inferred from component names or deployment templates.

The status vocabulary is preserved from `docs/CLAIMS_MATRIX.md:16-24`:

| Status | Meaning in this document |
|---|---|
| `IMPLEMENTED` | Production source and named regression tests establish the behavior under the stated assumptions and operational boundary. |
| `MEASURED` | A reproducible repository artifact records an observed result for a named workload and environment. |
| `CONFIGURATION-DEPENDENT` | The behavior requires deployment-specific controls or semantics outside the process. |
| `ROADMAP` | The capability, proof, test, or operational guarantee is incomplete or absent. |
| `LEGAL-REVIEW-REQUIRED` | The statement could be interpreted as a legal, regulatory, certification, procurement, or contractual conclusion. |

> **Controlling interpretation:** Aegis implements an OpenAI-compatible governance and evidence gateway. It does not, by repository evidence alone, establish global ordering, power-loss durability, immutable custody, high availability, legal admissibility, regulatory conformity, or correctness of model output.

## 2. Audited corrections to prior architecture language

Several repository narratives overstate the current mechanism and must not be carried into enterprise representations.

| Supplied or existing assertion | Audited correction | Basis |
|---|---|---|
| Every request follows a durable commit-before-emission path. | The core gateway durably records admitted upstream successes, admitted upstream non-2xx responses, circuit-open responses, and caught forwarding exceptions. Authentication, malformed JSON, WAF, behavioral-WAF, rate-limit, body-limit, and readiness rejections occur before the evidence helper and are not durably recorded by this handler. | `aegis/proxy/app.py:1004-1080,1144-1206,1242-1346`; named tests `tests/test_proxy.py::TestAuthentication::test_missing_auth_returns_401`, `tests/test_proxy.py::TestChatCompletions::test_invalid_json_returns_400`, and `tests/test_app_coverage_extended.py::test_chat_generic_forward_error_is_durably_rejected`. |
| Streaming is fully buffered before evidence commit and client emission. | Corrected on 2026-08-21: admitted SSE incrementally emits sanitized canonical events through an item- and byte-bounded queue. SHA-256 covers the exact emitted bytes; one terminal summary is committed to the WAL; and only the terminal marker is withheld until that commit succeeds. Initial evidence/proof headers are `pending-terminal`, with proof retrieval from the linked endpoint after termination. The configured backpressure, byte, event, and duration bounds are per admitted stream, so aggregate retained memory scales with concurrency. | `aegis/proxy/streaming.py`; stream integration in `aegis/proxy/app.py`; `aegis/config.py`; `tests/test_proxy_streaming.py`; per-stream arithmetic contract `specs/aegis_stream_buffer.smt2`. |
| The system has a universal hot path that emits all response bytes before background audit persistence. | This conflates authoritative evidence with optional enrichment. Non-streaming admitted outcomes await authoritative evidence before return. SSE incrementally emits non-terminal sanitized events, then awaits one authoritative terminal summary commit before emitting the terminal marker. Optional enrichment may be queued separately and is not part of the durable claim. | `aegis/proxy/app.py`; `aegis/proxy/streaming.py`; `tests/test_proxy.py::TestChatCompletions::test_response_contains_aegis_headers`; `tests/test_proxy_streaming.py::test_success_hashes_exact_output_and_commits_before_done`, `test_first_event_arrives_before_upstream_second_event`, and `test_commit_failure_omits_done`; corrected `docs/architecture/DEEP_DIVE.md`. |
| WAL archive segments are immutable. | Rotation renames segments and applies owner-only mode `0o600`; this is access restriction, not filesystem or object-lock immutability. A privileged actor can still alter or delete files unless an external storage control prevents it. | `aegis/core/crypto_audit.py:641-679`; claim boundary in `docs/CLAIMS_MATRIX.md:34`. |
| Replay reconstructs the complete cryptographic accumulator. | Replay reconstructs the bounded in-memory deque of stored nodes but does not replay leaves into the in-memory `MerkleMountainRange`. After restart, subsequent MMR roots begin from a fresh accumulator. Full cross-restart MMR continuity is therefore not established by this class. | `aegis/core/crypto_audit.py:285-296,756-794`; `_load_from_wal` appends nodes but does not call `_mmr.add_leaf`. |
| A multi-worker PostgreSQL enterprise deployment has an atomic chain append. | PostgreSQL persists individual rows, but `get_latest_node()` and `write_node()` are separate operations with no advisory lock or atomic compare-and-append transaction. The source itself calls for advisory locking. DynamoDB has the same read-then-write chain race; SQLite's lock covers only `write_node`, not the preceding read. | `aegis_server/main.py:499-576`; `aegis_server/storage/postgres_provider.py:215-283`; `aegis_server/storage/dynamodb_provider.py:173-258`; `aegis_server/storage/sqlite_provider.py:216-294`. |
| The Helm defaults provide an accepted highly available evidence topology. | The chart no longer places multiple writers on one WAL path: it renders a `StatefulSet` whose `volumeClaimTemplates` give each replica a private claim, pins `workers` to `"1"`, and the ledger takes a POSIX advisory lock so a second writer on a path fails closed instead of forking the chain. That removes the fork; it does not create high availability. Each replica still produces an independent local bundle with no cross-pod order or atomicity, and storage class, scheduler, zones, ingress, and Redis still require target acceptance. | `deploy/helm/values.yaml:4,53-59,69-73,181-205`; `deploy/helm/templates/statefulset.yaml`; `aegis/core/crypto_audit.py` (`_lock_wal_fd`, `WalWriterConflictError`); `tests/security/test_wal_single_writer.py`. Superseded state: two pods × two workers over one `ReadWriteOnce` PVC, guarded only by a process-local Python lock. |
| WAL corruption is always fail-closed. | Startup replay stops at the first malformed line and marks `wal_corrupt`, but subsequent commits remain permitted. Health reports degradation; the request path does not check the fault state before committing. | `aegis/core/crypto_audit.py:756-794`; `aegis/proxy/app.py:937-985`; named test `tests/test_reliability.py::test_wal_corruption_recovery_partial_chain`. |

## 3. System context and deployment boundaries

Aegis has two distinct production application surfaces in this repository. The **core gateway** is created by `aegis/proxy/app.py::create_app` and serves `/v1/chat/completions` and `/v1/completions` using `CryptographicAuditLedger`, a process-local JSONL WAL, and optional post-commit enrichment. The **enterprise gateway** is created by `aegis_server/main.py::create_app` and serves `/v1/enterprise/proxy/chat/completions` using a `StorageProvider` backed by SQLite, PostgreSQL, or DynamoDB. These surfaces share concepts but not one transactional implementation; assurances from one must not be transferred to the other without a named test.

```text
UNTRUSTED / EXTERNAL                                                CUSTOMER-CONTROLLED

 Client
   |
   | HTTP(S), credentials, payload
   v
+------------------+     +------------------------------------------------+
| Ingress / LB     |---->| Aegis process boundary                         |
| TLS, HTTP parse  |     |                                                |
+------------------+     | auth -> bounds -> normalize -> WAF -> limiter  |
                         |                         |                      |
                         |                         v                      |
                         |                  upstream adapter -------------+----> Model provider
                         |                         |                      |       external trust
                         |             +-----------+-----------+          |
                         |             |                       |          |
                         |       non-stream bytes      sanitized SSE      |
                         |             |               bounded queue      |
                         |             v                       |          |
                         |       evidence commit        incremental emit  |
                         |             |                       |          |
                         |             v               terminal summary  |
                         |       emit response          evidence commit   |
                         |                                     |          |
                         |                              terminal marker    |
                         |                                     |          |
                         |                         optional queue          |
                         +-----------------------------|------------------+
                                                       |
                         +-----------------------------+------------------+
                         | Evidence dependency boundary                   |
                         | Core: local/shared JSONL WAL + signer           |
                         | Enterprise: SQLite/PostgreSQL/DynamoDB + signer |
                         +------------------------------------------------+
                                                       |
                                                       v
                                          backup, archive, custody, verifier
                                          separate operational boundary
```

The application boundary does not include the ingress parser, upstream provider, Redis service, host kernel, filesystem controller, external database durability configuration, KMS/HSM availability, backup system, or evidence custodian. `fsync` in the core ledger means that the process requested synchronization of a file descriptor; it is not proof of stable-media survival after power loss. An acknowledged database or cloud write similarly inherits the configured backend's transaction, replication, and consistency semantics.

## 4. Core gateway mechanistic lifecycle

### 4.1 ASCII state machine

The following state machine describes the reachable core handler behavior more precisely than a universal linear lifecycle. `PRE-ADMISSION REJECTED` is intentionally outside the durable-evidence state because the current handler does not invoke `_commit_evidence` for those failures.

```text
                                  +-------------------------+
                                  | PRE-ADMISSION REJECTED  |
                                  | no handler evidence node|
                                  +-------------------------+
                                      ^    ^    ^    ^
                                      |    |    |    |
[RECEIVED] -> [AUTHENTICATED] -> [PARSED/BOUNDED] -> [CONTROLLED]
                   |                    |                 |
                   | auth fail          | JSON/body fail  | WAF/rate/readiness fail
                   +--------------------+-----------------+
                                                           |
                                                           v
                                                    [UPSTREAM PENDING]
                                                           |
                  +----------------------------------------+------------------+
                  |                                        |                  |
                  v                                        v                  v
         [SUCCESS BYTES]                          [UPSTREAM ERROR]      [SSE SANITIZE]
                  |                               or caught fault             |
                  +------------------------+---------------+          [BOUNDED QUEUE]
                                           |                              |
                                           v                              v
                                  [EVIDENCE PENDING]              [INCREMENTAL EVENTS]
                                           |                              |
                              sign -> append -> flush -> fsync             v
                                           |                     [TERMINAL SUMMARY]
                         +-----------------+-------------------+            |
                         |                                     |            v
                         v                                     v    [EVIDENCE PENDING]
               [EVIDENCE COMMITTED]                   [COMMIT FAILURE]      |
                         |                                     |             v
                         v                                     v    [TERMINAL COMMITTED]
                 [RESPONSE EMITTED]                       [TERMINATED]       |
                         |                                               marker
                         +--------------------+-----------------------------+
                                              v
                                     [OPTIONAL ENRICHMENT]
```

### 4.2 Transition table

| From | Event or guard | To | Durable evidence at transition | Production locator | Named test |
|---|---|---|---|---|---|
| `RECEIVED` | Proxy dependency accepts credentials | `AUTHENTICATED` | No | `aegis/proxy/app.py:1004-1008,1242-1246`; `aegis/proxy/dependencies.py` | `tests/test_proxy.py::TestAuthentication::test_valid_key_passes` |
| `RECEIVED` | Missing or invalid credential | `PRE-ADMISSION REJECTED` | No handler node | Same handler dependencies | `tests/test_proxy.py::TestAuthentication::test_missing_auth_returns_401`; `test_wrong_key_returns_401` |
| `AUTHENTICATED` | Body is read, bounded, decoded, and normalized | `PARSED/BOUNDED` | No | `aegis/proxy/app.py:85-119,1010-1014` | `tests/test_p0_release_gates.py::test_request_body_limit_rejects_declared_oversize`; `tests/test_proxy.py::TestChatCompletions::test_invalid_json_returns_400` |
| `PARSED/BOUNDED` | WAF, entropy guard, session WAF, and limiter allow | `CONTROLLED` | No | `aegis/proxy/app.py:1016-1073` | `tests/test_market_hardening_gates.py::test_waf_pinned_corpus_has_no_critical_bypass_or_benign_false_positive`; `tests/test_p0_release_gates.py::test_distributed_rate_limit_never_fails_open` |
| `CONTROLLED` | Provider call starts | `UPSTREAM PENDING` | No | `aegis/proxy/app.py:1089-1106,1139-1145,1297-1300` | `tests/test_proxy.py::TestChatCompletions::test_logprobs_injected_into_upstream_call` |
| `UPSTREAM PENDING` | Non-streaming 200 bytes received | `SUCCESS BYTES` | No | `aegis/proxy/app.py:1186-1195` | `tests/test_proxy.py::TestChatCompletions::test_response_contains_aegis_headers` |
| `UPSTREAM PENDING` | Non-2xx, circuit-open, or caught forwarding exception | `UPSTREAM ERROR` | No | `aegis/proxy/app.py:1145-1184,1300-1335` | `tests/test_app_coverage_extended.py::test_chat_generic_forward_error_is_durably_rejected`; `test_chat_upstream_non_200_is_durably_forwarded` |
| `UPSTREAM PENDING` | SSE events arrive | `SSE SANITIZE` / `BOUNDED QUEUE` / `INCREMENTAL EVENTS` | Initial headers are `pending-terminal`; no terminal node yet | `aegis/proxy/app.py`; `aegis/proxy/streaming.py` | `tests/test_proxy_streaming.py::test_first_event_arrives_before_upstream_second_event`, split-redaction tests, and `test_large_logical_stream_retained_memory_is_bounded`. |
| Non-streaming terminal bytes, or an SSE terminal summary containing exact emitted-byte hash and outcome | The applicable commit helper runs in a worker thread | `EVIDENCE PENDING` | Pending | `aegis/proxy/app.py`; `aegis/proxy/streaming.py`; `aegis/core/crypto_audit.py` | `tests/test_market_hardening_gates.py::test_ledger_fsync_injection_preserves_durable_commit_and_integrity`; `tests/test_proxy_streaming.py::test_success_hashes_exact_output_and_commits_before_done`. |
| `EVIDENCE PENDING` | JSON line write, flush, and `fsync` return; node then enters deque | `EVIDENCE COMMITTED` | Process-observed commit complete | `aegis/core/crypto_audit.py:417-419,719-754` | `tests/test_forensic.py::TestCryptographicAuditLedger::test_commit_forensic_request_and_response`; fsync test above |
| `EVIDENCE PENDING` | Signer, write, flush, or `fsync` raises | `COMMIT FAILURE` | No durable claim | `aegis/proxy/app.py:851-857` | Core handler lacks a direct injected-commit-failure response test; enterprise equivalent is `tests/test_enterprise_durable_evidence.py::test_storage_failure_fails_closed_and_does_not_claim_durable`. |
| `EVIDENCE COMMITTED` | Non-streaming response is returned | `RESPONSE EMITTED` | Header states `durable` | Non-streaming branches in `aegis/proxy/app.py` | `tests/test_proxy.py::TestChatCompletions::test_response_contains_aegis_headers`; `tests/test_app_coverage_extended.py::test_chat_upstream_non_200_is_durably_forwarded`. |
| `TERMINAL SUMMARY` | One summary WAL commit succeeds | `TERMINAL COMMITTED` then terminal marker emitted | Initial stream headers remain `pending-terminal`; proof becomes retrievable from the linked endpoint | `aegis/proxy/app.py`; `aegis/proxy/streaming.py:213-220,413-428` | `tests/test_proxy_streaming.py::test_success_hashes_exact_output_and_commits_before_done`, `test_commit_failure_omits_done`, and `test_prehashed_terminal_commit_binds_outcome_and_replays`. |
| `EVIDENCE COMMITTED` | Optional queue accepts, rejects, or skips job | `OPTIONAL ENRICHMENT` or terminal | Authoritative node unchanged | `aegis/proxy/app.py:186-230,896-935` | Queue behavior is covered in app tests; no claim depends on enrichment completion. |

### 4.3 Causal commit-before-emission ordering

For the implemented core non-streaming success path, the causal program order is:

```text
await upstream bytes
    -> await _commit_evidence with the request and terminal response bytes
        -> await asyncio.to_thread calling ledger.commit_forensic
            -> acquire process-local ledger lock
            -> compute chain node and signature
            -> write JSON line
            -> flush language buffer
            -> os.fsync(file descriptor)
            -> append node to in-memory deque
        -> return from worker thread
    -> optionally enqueue enrichment
    -> construct and return HTTP response
```

The corresponding streaming path constructs a `StreamingResponse` with `pending-terminal` evidence/proof headers, incrementally sanitizes and emits canonical events through a bounded byte-accounted queue, and updates SHA-256 over the exact bytes yielded. At terminal outcome it invokes exactly one summary commit and yields the terminal marker only after that commit returns. This establishes **terminal-commit-before-terminal-marker**, not commit-before-every-SSE-event. The configured backpressure, queue-byte, queue-event, event-size, cumulative-output, de-identification-window, preview, and duration bounds apply per admitted stream; aggregate retained memory scales with concurrent admitted streams. These properties do not establish stable-media durability, client receipt, global ordering, or correctness under multiple unsynchronized processes. `tests/test_proxy_streaming.py` exercises ordering, exact-byte hashing, redaction, limit, cancellation, commit-failure, and retained-memory behavior; `specs/aegis_stream_buffer.smt2` checks only the declared per-stream retained-byte arithmetic.

If the upstream ends without its terminal marker, the stream finalizes once with `terminal_outcome="upstream_incomplete"`, does not synthesize or emit the terminal marker, and records the hash and size of bytes actually emitted. Initial headers remain `pending-terminal`; callers retrieve proof after terminal commit through the linked proof endpoint. A completed terminal summary therefore binds the observed terminal outcome and exact emitted bytes but does not imply that the upstream completed normally.

### 4.4 Per-stream retained-memory arithmetic

The streaming path is bounded rather than buffered: no code path accumulates the full upstream response in RAM. The proxy retains a rolling SHA-256 state, a bounded queue, a bounded de-identification holdback, and a fixed-size preview. The implemented accessor sums exactly three retained regions (`aegis/proxy/streaming.py:169-172`):

```text
retained_bytes = queue.retained_bytes
               + deidentifier.retained_chars * 4
               + len(preview)
```

The per-stream ceiling declared by `specs/aegis_stream_buffer.smt2` adds the single in-flight canonical event:

\[
R_{\max} = 4W + Q + E + P
\]

| Symbol | Meaning | Implemented bound | Locator |
|---|---|---|---|
| `W` | De-identification holdback window in characters | `64 <= W <= 4096`; default `128` | `aegis/core/streaming_deidentifier.py:71-73`; `aegis/proxy/streaming.py:126` |
| `4W` | Conservative UTF-8 byte cost of the retained character holdback | Four bytes per retained character | `aegis/proxy/streaming.py:171`; `specs/aegis_stream_buffer.smt2:15-16` |
| `Q` | Byte-accounted queue budget | Operator-configured `queue_max_bytes`; SMT range `1024 … 16777216` | `aegis/proxy/streaming.py:70-99`; `specs/aegis_stream_buffer.smt2:11` |
| `E` | Largest single canonical SSE event | `max_event_bytes`, constrained `256 <= E <= Q` | `aegis/proxy/streaming.py:403-405`; `specs/aegis_stream_buffer.smt2:12` |
| `P` | Response preview retained for evidence | `0 <= P <= 65536`; default `65_536` | `aegis/proxy/streaming.py:125,412-414`; `specs/aegis_stream_buffer.smt2:13` |

The holdback is additionally fail-closed: `feed` raises `StreamingDeidentificationError` when pending text exceeds `2W`, and the unbounded URL, magnetic-track, email, and address grammars are rejected rather than released (`aegis/core/streaming_deidentifier.py:100-107,120-157`). The queue refuses any single item larger than its whole byte budget (`aegis/proxy/streaming.py:82-84`).

Boundary. `R_max` is a **per-admitted-stream** ceiling under the declared configuration. It is arithmetic over declared parameters, not a measurement, not an allocator or fragmentation model, and not a process-wide bound: aggregate retained memory scales with the number of concurrently admitted streams, so total footprint remains **`CONFIGURATION-DEPENDENT`** on deployment-level admission and concurrency control. The SMT file checks only this arithmetic; it does not model the Python object graph, interpreter overhead, or TLS buffers.

### 4.5 Failure semantics under degraded infrastructure

| Failure mode | Implemented behavior | Evidence consequence | Classification | Locator |
|---|---|---|---|---|
| Slow or stalled `fsync` | The commit runs in a worker thread through `asyncio.to_thread`; the awaiting request does not return until write, flush, and `fsync` return. A stalled device therefore converts into request latency and, for streams, into queue backpressure that blocks the producer rather than growing memory. | No premature `durable` claim; the terminal marker is not emitted. | `CONFIGURATION-DEPENDENT` on filesystem and device | `aegis/core/crypto_audit.py:417-419`; `aegis/proxy/streaming.py:85-92` |
| `fsync` or signer raises | Handler transitions to `COMMIT FAILURE`; no durable claim is made and, on the streaming path, the terminal marker is withheld. | Absence of evidence is surfaced rather than masked. | `IMPLEMENTED` | `aegis/proxy/app.py:851-857`; `tests/test_proxy_streaming.py::test_commit_failure_omits_done` |
| Redis unreachable or partitioned | Strict mode converts limiter backend exceptions into `503` instead of admitting unlimited traffic. | Request is rejected pre-admission; no handler evidence node. | `CONFIGURATION-DEPENDENT` | `tests/test_p0_release_gates.py::test_distributed_rate_limit_never_fails_open` |
| Upstream provider fault or open circuit | Transition to `UPSTREAM ERROR`; the error outcome is itself durably committed before the response is returned. | Failure is evidence-bearing, not silent. | `IMPLEMENTED` | `aegis/proxy/app.py:1145-1184`; `tests/test_app_coverage_extended.py::test_chat_generic_forward_error_is_durably_rejected` |
| Upstream ends without its terminal marker | Stream finalizes once with `terminal_outcome="upstream_incomplete"`; no marker is synthesized. | Terminal summary binds only the bytes actually emitted. | `IMPLEMENTED` | `aegis/proxy/streaming.py:270-273` |
| Client disconnects mid-stream | Cancellation is owned by the proxy: the producer is cancelled and a shielded finalize records `client_disconnected`. | Partial delivery is recorded rather than lost. | `IMPLEMENTED` | `aegis/proxy/streaming.py:223-231` |
| Auxiliary native WAL append fails | The authoritative JSONL summary is committed **first**; the auxiliary append is then attempted. On any exception the counter `aegis_native_stream_wal_errors_total` increments, the event is logged, and `state.native_stream_wal` is set to `None`. | Fail-open for client completion; JSONL remains authoritative. | `IMPLEMENTED` | `aegis/proxy/app.py:701,709-719`; `aegis/core/observability.py:168-171` |

Two properties of the auxiliary-WAL path are frequently misread and are stated explicitly. First, the auxiliary segment is **not** a second authority: the JSONL terminal commit has already returned before the append is attempted, so an auxiliary failure cannot invalidate or reorder committed evidence. Second, the failure handler disables the auxiliary segment for the **remaining lifetime of that process object**, rather than skipping a single frame; a subsequent operator investigation must therefore treat a non-zero counter as "auxiliary capture stopped at first error", not as "one frame missing". Neither property establishes stable-media durability for either file.

## 5. Evidence and cryptographic data model

For a core ledger node `n_i`, the implementation computes:

```text
request_hash_i  = SHA256(raw_request_bytes)
response_hash_i = SHA256(non-streaming response bytes or exact emitted SSE bytes), or empty for request-only records
prev_hash_i     = node_hash_(i-1), or 64 zeroes for the process view's genesis
signed_payload  = prev_hash_i | merkle_root_i | request_hash_i | response_hash_i
node_hash_i     = SHA256(prev_hash_i | state_id_i | timestamp_i | entropy_i |
                         tenant_id_i | merkle_root_i | signature_i |
                         request_hash_i | response_hash_i)
```

The exact construction is in `aegis/core/crypto_audit.py:124-148,184-217,365-419`. The WAL stores hashes and metadata, not raw prompt and response bodies (`aegis/core/crypto_audit.py:79-114,719-754`). `verify_integrity()` checks the in-memory deque's creation hash, predecessor linkage, fallback prohibition when configured, and HMAC signatures when an HMAC key is present (`aegis/core/crypto_audit.py:453-507`). It does **not** verify HSM, PQC, or Ed25519 signatures in this method. It also verifies only the retained deque, whose length is bounded by `max_memory_nodes`, not necessarily all WAL records.

A further boundary follows from `deque(maxlen=max_memory_nodes)`: after the oldest in-memory node is evicted, the first retained node's `prev_hash` is not genesis, while `verify_integrity()` expects genesis at index zero. A full-window rollover can therefore make the in-memory verification algorithm report a predecessor mismatch even if the retained records have not been altered. No named regression establishes correct integrity verification after deque rollover. This is a **`ROADMAP`** repair and test requirement.

Signer selection is configuration-dependent. The core order is available HSM, Rust ML-DSA, HMAC-SHA256, then per-node ephemeral Ed25519 fallback (`aegis/core/crypto_audit.py:681-717`). Strict mode requires a configured HMAC key or PKCS#11 path at startup (`aegis/config.py:669-686`) and sets `require_strong_signing`, but runtime HSM failure may fall through to another available tier. HMAC is symmetric; any verifier holding the key can create valid MACs. These mechanisms provide tamper detection under key and implementation assumptions, not third-party non-repudiation or a legal-admissibility conclusion.

## 6. Enterprise external-storage lifecycle

The enterprise endpoint `/v1/enterprise/proxy/chat/completions` reads the complete upstream response, calls `_run_forensic_analytics` with `require_durable=True`, awaits `storage.write_node`, and returns the upstream response only when the helper returns `True` (`aegis_server/main.py:831-993`). Signing or storage failure returns `503` with `X-Aegis-Evidence-Status: unavailable`. The named tests are:

- `tests/test_enterprise_durable_evidence.py::test_success_response_is_returned_only_after_durable_evidence`
- `tests/test_enterprise_durable_evidence.py::test_upstream_non_2xx_is_durably_evidenced_before_return`
- `tests/test_enterprise_durable_evidence.py::test_upstream_network_error_uses_durable_error_evidence`
- `tests/test_enterprise_durable_evidence.py::test_storage_failure_fails_closed_and_does_not_claim_durable`

These tests use mocked storage and signer dependencies. They establish awaited call ordering and status behavior, not backend crash consistency or cross-worker chain serialization.

| Backend | Implemented acknowledgement | Ordering boundary | Durability boundary | Named tests |
|---|---|---|---|---|
| SQLite | `aiosqlite` insert followed by `db.commit()` | `_chain_lock` serializes only `write_node`; `get_latest_node` occurs before that lock and can race. Safe single-chain ordering under concurrent requests is not established. | `PRAGMA synchronous=NORMAL` with SQLite WAL; power-loss behavior remains platform/configuration-dependent. | `tests/test_sqlite_provider_new.py::test_write_node_then_get_latest`, `test_get_latest_node_returns_most_recent`, `test_check_integrity_chain_linkage_valid` |
| PostgreSQL | Awaited `conn.execute` of the provider's `INSERT` statement with `ON CONFLICT DO NOTHING` | The predecessor read and insert are separate calls with no transaction/advisory lock. Server row serialization alone does not prevent two nodes from referencing the same predecessor. | Inherits PostgreSQL commit, `synchronous_commit`, replication, storage, and failover configuration. | `tests/test_postgres_provider_new.py::test_write_node_success`, `test_get_latest_node_returns_record`, `test_check_integrity_valid_chain`; these are mocked provider tests, not a concurrent database acceptance test. |
| DynamoDB | Awaited conditional `PutItem` prevents overwrite of the same `node_id` | Conditional uniqueness does not serialize the separately queried latest predecessor. Timestamp-index reads and concurrent writers can fork the logical chain. | Inherits DynamoDB acknowledgement, region, table, retry, and disaster-recovery configuration. | `tests/test_dynamodb_provider_new.py::test_write_node_success`, `test_write_node_conditional_check_is_noop`, `test_get_latest_node_returns_item`, `test_check_integrity_valid_chain`; these do not establish concurrent chain order. |

The enterprise in-memory MMR is initialized empty on each process startup and is explicitly documented as not persisted (`aegis_server/main.py:194-201`). Each worker therefore has a separate accumulator. An external row can be durable while its `merkle_root` belongs only to that worker's local MMR history. A cross-worker or cross-restart unified MMR is **not implemented**.

## 7. Trust boundaries

| Boundary | Assets and flow | Implemented control | Assumption and operational boundary | Residual risk | Human-review owner |
|---|---|---|---|---|---|
| Client to ingress | Credentials, headers, request bytes | API-key dependency, optional TLS/mTLS launch configuration, request-smuggling middleware, body limit | TLS termination and proxy header normalization may occur outside Aegis. | HTTP translation differences, credential theft, header spoofing, and ingress bypass. | Platform security owner |
| Ingress to gateway process | Parsed HTTP semantics | Canonical JSON normalization, WAF, optional DMZ middleware | Ingress and ASGI must agree on framing and source identity. | HTTP/2 and intermediary parsing differences are not covered by the local WAF corpus. | Application security owner |
| Gateway to Redis | Distributed limiter identity and counters | Strict mode requires Redis; backend exception becomes `503` | Redis TLS, authentication, HA, time, and network partition policy are operator-controlled. | Limiter inconsistency or availability loss; session WAF remains process-local. | SRE owner |
| Gateway to upstream provider | Scrubbed or original prompt, model selection, response bytes | Provider adapters, egress guard, timeout, circuit breaker | Provider endpoint, TLS trust, data terms, and retention are external. | Provider compromise, retention, malformed streams, partial streams, and semantic errors. | AI platform owner |
| Gateway to signer | Chain linkage and content digests | HSM/PQC/HMAC/fallback selection; strict strong-signing requirement | Key provisioning, HSM policy, library behavior, and rotation are external/configured. | Shared HMAC authority, HSM fallback behavior, key compromise, and unverified non-HMAC signatures in `verify_integrity()`. | Cryptographic key custodian |
| Core process to WAL | JSONL evidence records | Process-local lock; append, flush, `fsync`; owner-only file mode | One writer process, accepted filesystem, sufficient capacity, and uncompromised host are required. | Multi-process chain forks, privileged modification, power-loss ambiguity, corruption fail-open, and replay/MMR discontinuity. | Storage and SRE owners |
| Enterprise process to external storage | Node row and predecessor reference | Awaited provider write and backend-specific commit acknowledgement | Atomic chain append is not part of the provider interface. | Concurrent chain forks, backend consistency differences, retries, and regional failure. | Database/cloud storage owner |
| Authoritative evidence to enrichment | Response bytes, logprobs, derived alerts | Bounded queue, configured workers, timeout, queue rejection | Enrichment is non-authoritative and may be absent. | Stale, dropped, or inconsistent analysis; analysis nodes add separately to the core ledger. | Detection engineering owner |
| Runtime to verifier/exporter | Stored records, integrity results, bundles | Audit APIs and export modules | Complete custody, independent key access, retention, and verifier correctness are separate controls. | Partial in-memory verification and misleading legal interpretation. | Evidence custodian and legal reviewer |

## 8. Topology semantics

### 8.1 Single process, one worker

Within one core process, `CryptographicAuditLedger._lock` serializes node creation, predecessor selection, MMR update, WAL persistence, and deque append (`aegis/core/crypto_audit.py:378-419`). This is the strongest topology directly supported by the core implementation. It yields one process-local sequence, assuming one active writer, a healthy WAL, and an accepted storage path. Concurrent threads or asyncio requests entering the same ledger instance are serialized at the ledger mutation.

The process-local sequence still does not prove stable-media survival, external immutability, full-history verification after deque rollover, or MMR continuity after restart.

### 8.2 Multiple workers in one host or pod

`aegis/proxy/app.py::main` passes `cfg.workers` to Uvicorn (`aegis/proxy/app.py:2005-2035`). Each worker creates its own application state, ledger lock, chain deque, MMR, session tracker, analyzer cache, and analysis queue. If workers used the same WAL pathname, each would load a point-in-time view and then append independently, producing divergent `prev_hash` relationships that the current loader cannot represent as one verified chain.

That topology is now refused rather than merely documented. `CryptographicAuditLedger._open_wal` takes a `flock(LOCK_EX | LOCK_NB)` advisory lock on the WAL descriptor before publishing the handle, so the second and later writers raise `WalWriterConflictError` at startup and never append a frame (`aegis/core/crypto_audit.py`; `tests/security/test_wal_single_writer.py::test_cross_process_writer_is_refused`).

Read the guard for what it is: it **prevents** a second writer, it does not **serialize** two. It selects no predecessor and coordinates no MMR state, so **multi-worker plus one shared core WAL remains unsupported for a single ordered evidence chain** — the change converts a silent fork into a fail-closed startup error. The safe operational restriction is unchanged: one worker per WAL path. Distinct worker-specific WAL paths produce independent bundles, not one global order.

Two scope limits apply. The lock is POSIX-only; on a platform without `fcntl` the ledger logs a warning and single-writer discipline is operator-enforced rather than process-enforced. And `flock` is advisory and per-inode on a local filesystem: it does not constrain a writer that reaches the same bytes through a different path or through a network filesystem whose lock semantics differ, which remains a target-acceptance concern.

### 8.3 Multiple pods

A pod is another process and storage boundary. With one worker per pod and one private volume per pod, each pod can produce an independently verifiable local bundle under the single-process assumptions. No cross-pod order or atomicity exists. Shared rate limiting can be provided through Redis, but WAF session state, analyzer state, MMR state, and core chain state remain local.

The Helm chart now expresses that topology directly. It renders a `StatefulSet` whose `volumeClaimTemplates` issue one claim per replica, so each pod mounts its own volume at its own WAL path, and `aegis.workers` is pinned to `"1"` by `values.schema.json` so an operator cannot raise it back past the single-writer limit (`deploy/helm/templates/statefulset.yaml`; `deploy/helm/values.yaml:4,53-59,69-73`; `deploy/helm/values.schema.json`; `tests/test_deploy_manifests.py::test_helm_gives_every_replica_its_own_wal_volume`). `persistence.accessMode` is constrained to `ReadWriteOnce` or `ReadWriteOncePod` for the same reason.

This removes the shared-writer fault; it does not add cross-pod ordering. Each replica remains an independent chain, and a governed multi-pod evidence topology still requires an accepted design for cross-pod order, signer propagation, and recovery. The superseded default — a `Deployment` with `replicaCount: 2` and `workers: "2"` over one named `ReadWriteOnce` PVC — must not be reintroduced.

### 8.4 External storage and centralized writer

The enterprise `StorageProvider` allows multiple application instances to persist rows in a shared backend, but shared persistence is not equivalent to shared order. The current read-latest, compute-node, write-node sequence lacks a compare-and-swap predecessor guard or centralized sequence service. PostgreSQL advisory locking, a serializable transaction with a chain-head row, DynamoDB transactional conditional update, or a dedicated writer could provide a candidate serialization mechanism; none is implemented in the audited path.

A centralized writer can be an operational design for one total order, but its capacity, availability, recovery, and signer/storage custody require a separate implementation and acceptance artifact. Cross-region consensus remains **`ROADMAP`**.

### 8.5 Deployment boundary matrix

| Topology | Evidence semantics today | Safe claim | Prohibited claim | Required acceptance owner |
|---|---|---|---|---|
| One process, one worker, local WAL | One process-local sequence with awaited write/flush/`fsync` | Commit-before-response construction under stated assumptions | Power-loss-proof, immutable, globally ordered, or highly available | Platform and storage owners |
| Multiple workers, shared WAL | Uncoordinated process-local heads writing one file | No approved single-chain claim | One ordered WAL or fork-free chain | Release owner must block deployment |
| Multiple workers, separate WALs | Independent worker-local sequences | Independently reviewed per-worker bundles | One node-wide order | Evidence custodian |
| Multiple pods, private per-pod WAL | Independent pod-local sequences | Per-replica evidence bundles | Cross-pod atomicity or total order | Kubernetes/SRE owner |
| Current Helm defaults | Two replicas and two workers targeting one RWO PVC path | Chart renders a deployment; no governed evidence assurance | Accepted HA evidence topology | Release and platform owners |
| Enterprise app with shared SQLite | Awaited row commits; chain race remains | Single request's storage call completed | Concurrent fork-free chain | Database owner |
| Enterprise app with PostgreSQL/DynamoDB | Awaited backend write; chain race remains | Backend acknowledged individual record under its configuration | Atomic global append or cross-region total order | Database/cloud owner |
| Dedicated centralized writer | Architectural option only | `ROADMAP` | Available global ordering | Architecture review board |

### 8.6 Active-passive high availability with storage synchronization

No active-passive failover controller, lease manager, or chain-head handover protocol exists in the audited source. This subsection therefore specifies the **evidence semantics an operator would inherit** if they built one on the current implementation; it is an architectural analysis and an acceptance checklist, not a description of shipped behavior.

The controlling fact is that authoritative chain state is process-local. The predecessor hash, the MMR peak set, and the retained node deque live inside one `CryptographicAuditLedger` instance and are rebuilt only from what the WAL loader can read at start (`aegis/core/crypto_audit.py:378-419`). A passive replica that has never loaded the active node's WAL holds no chain head.

| Failover concern | Consequence on the current implementation | Required operator control | Classification |
|---|---|---|---|
| Chain-head continuity | A promoted passive starts from whatever its loader reconstructs. If it cannot read the active node's committed WAL bytes, it starts a new chain rather than extending the old one. | Shared or synchronously replicated WAL storage that the promoted node reads before admitting traffic. | `ROADMAP` |
| Split-brain double-write | Two processes appending to one WAL path is already unsupported for a single ordered chain (§8.2). A failover that admits traffic on the passive while the active still writes reproduces exactly that fork. | Fencing: a lease, `RWO` volume detach, or STONITH that provably stops the old writer before the new one admits traffic. | `ROADMAP` |
| Replication lag | Asynchronous block or object replication can acknowledge a client response whose evidence bytes have not reached the replica. Committed-then-lost evidence is indistinguishable, after the fact, from never-committed evidence. | Synchronous replication, or an explicit accepted RPO with the evidence custodian. | `CONFIGURATION-DEPENDENT` |
| MMR reconstruction | Peak state is derived from loaded leaves; a truncated or partially replicated WAL yields a different root. | Verify the reconstructed root against the last root observed on the active node before admitting traffic. | `CONFIGURATION-DEPENDENT` |
| Retained-window queries | The in-memory deque is not replicated. Proof and forensic-export endpoints on a freshly promoted node serve only what it reloaded. | Treat post-failover retained-window gaps as expected, and source completeness from the WAL rather than the process. | `IMPLEMENTED` limitation |

Safe claim for this topology: *a promoted replica can continue producing verifiable evidence for traffic it admits after promotion.* Prohibited claims: uninterrupted chain continuity across failover, zero evidence loss, or automatic fork avoidance. None of these is established by the current source, and an active-passive design must be accepted by the platform, storage, and evidence-custodian owners before governed traffic is admitted.

### 8.7 Centralized ingress and TLS termination

Aegis does not implement ingress. The gateway is an ASGI application whose transport, TLS termination, HTTP framing, and client-identity headers are supplied by an external controller. The application boundary explicitly excludes the ingress parser (§3), and the client-to-ingress and ingress-to-gateway hops are enumerated as distinct trust boundaries (§7).

| Ingress responsibility | Aegis-side behavior | Residual risk retained by the operator |
|---|---|---|
| TLS termination and cipher policy | Not performed by the gateway; optional launch-configuration TLS/mTLS exists for direct exposure. | Certificate lifecycle, revocation, protocol downgrade, and cipher policy are external. |
| HTTP framing and request smuggling | Request-smuggling middleware and a body limit apply after the ingress has parsed the request. | Ingress and ASGI must agree on framing; HTTP/2 and intermediary parsing differences are not covered by the local WAF corpus. |
| Client identity propagation | Tenant principals derive from API-key mappings, strict OIDC claims, or pinned mTLS identities rather than from free-form forwarded headers. | A misconfigured ingress that forges or strips identity headers is outside the gateway's detection boundary. |
| Load distribution | Distribution across replicas interacts directly with §8.3: each replica is its own evidence boundary. | Routing does not create cross-replica order; a single logical session may produce evidence in several independent chains. |
| Termination of long-lived SSE | Ingress read and idle timeouts can close a stream before its terminal commit. | The proxy records `client_disconnected`; the operator must align ingress timeouts with `max_duration_seconds`. |

The final row is the one most often missed in deployment review: an ingress idle timeout shorter than the configured stream duration bound will systematically truncate long streams, producing a population of `client_disconnected` terminal summaries that reflect ingress policy rather than client behavior. Timeout alignment is an operator acceptance item, and the resulting outcome distribution must not be read as client-side evidence.

## 9. Formal models and their limits

The formal artifacts model narrow safety properties. They do not import or refine the Python, Rust, ASGI, operating-system, filesystem, PostgreSQL, SQLite, or DynamoDB implementation.

| Artifact | Checked property | Declared scope | Executed evidence | Excluded interpretation |
|---|---|---|---|---|
| `specs/aegis_invariants.tla` | `response_emitted` is a subset of IDs in `wal_log`; emission is enabled only from `COMMITTED`. | Three request IDs and WAL capacity three under `specs/aegis_invariants.cfg`. | `docs/formal/FORMAL_VERIFICATION.md:24-30`; `evidence/execution_2026-08-20/manifest.json` records the formal gate. | Does not model exceptions, pre-admission rejection, ASGI send, streaming memory, process crash, multiple WAL writers, or filesystem acknowledgement. |
| `specs/AegisVerification.lean` | Every state reachable through four declared constructors satisfies `responseEmitted = true -> durable = true`. | Induction over the exact `Step` relation in the file. | The named theorem `reachable_states_satisfy_invariant`; execution record in `docs/formal/FORMAL_VERIFICATION.md`. | The theorem is true partly because no alternative transition exists; it is not an implementation refinement proof. |
| `specs/aegis_ledger_immutability.tla` | Every historical sequence is a prefix of every newer sequence. | Abstract append-only list, three data values, maximum four appends. | TLC result in `docs/formal/FORMAL_VERIFICATION.md:28-30`. | Does not model file mutation, rotation failure, truncation, corruption, deque eviction, replay, signatures, or concurrent processes. |
| `specs/aegis_session_manager.tla` | Active session bindings refer to a root in an abstract ledger; `insecure_processing` remains false. | Two session IDs, two roots, maximum three commits, declared network states. | TLC result in `docs/formal/FORMAL_VERIFICATION.md:28-30`. | Does not model the production `SessionLifecycleManager`, WAF tracker, Redis, eviction, or cross-worker sessions. |
| `specs/aegis_invariants.smt2` | Negated bounded token-bucket admission arithmetic is unsatisfiable. | Quantifier-free bit-vector formula. | Z3 `unsat` in `docs/formal/FORMAL_VERIFICATION.md:24-30`. | Does not prove request lifecycle or distributed Redis behavior. |
| `aegis_rust_v2/src/wal.rs` tests | Native mmap WAL publishes complete flushed contiguous frames under tested thread concurrency and rejects overflow without advancing position. | One `RustWal` instance and local test filesystem. | Rust tests `concurrent_appends_publish_only_complete_frames` and `rejected_append_does_not_advance_write_position`; execution manifest reports 28 Rust tests passed. | The core `CryptographicAuditLedger` uses its Python JSONL `_persist_node`; native WAL results must not be attributed to that path without integration evidence. |

The execution record reports no counterexamples within the configured finite models and explicitly classifies the implementation-to-model relation as structured analysis (`docs/formal/FORMAL_VERIFICATION.md:3-10,44-46`). `evidence/execution_2026-08-20/manifest.json` likewise records the residual risk as absence of an implementation refinement proof and target-filesystem power-loss proof.

## 10. Controlled architecture claims

Every material claim below has a stable identifier, status, exact locator, assumptions, falsification criterion, operational boundary, and human-review owner. These claims do not supersede stronger restrictions in `docs/CLAIMS_MATRIX.md`.

| Claim ID | Material claim | Status | Exact repository locators and named tests | Assumptions | Falsification criterion | Operational boundary | Human-review owner |
|---|---|---|---|---|---|---|---|
| DOC01-ARCH-001 | The core application exposes `/v1/chat/completions` and `/v1/completions` and forwards admitted requests through a provider adapter. | `IMPLEMENTED` | `aegis/proxy/app.py:1004-1365`; `tests/test_proxy.py::TestAuthentication::test_valid_key_passes`; `tests/test_app_coverage_extended.py::test_completions_endpoint_success` | Supported request shapes and configured provider | Contract test fails or handler no longer forwards the expected endpoint/body | One running core application version | Application owner |
| DOC01-LIFE-001 | For a core non-streaming admitted success, the handler awaits JSONL WAL persistence before constructing the HTTP response. | `IMPLEMENTED` | `aegis/proxy/app.py:1196-1240`; `aegis/core/crypto_audit.py:378-419,719-754`; `tests/test_proxy.py::TestChatCompletions::test_response_contains_aegis_headers`; `tests/test_market_hardening_gates.py::test_ledger_fsync_injection_preserves_durable_commit_and_integrity` | One ledger instance, successful signer and storage calls | Instrumented trace shows response construction or ASGI send before `_persist_node` returns | Single handler and process-local causal order | Release owner |
| DOC01-LIFE-002 | Caught core upstream faults and non-2xx results are committed before their durable-status response is returned. | `IMPLEMENTED` | `aegis/proxy/app.py:1145-1184`; `tests/test_app_coverage_extended.py::test_chat_generic_forward_error_is_durably_rejected`; `test_chat_upstream_non_200_is_durably_forwarded`; `tests/test_proxy.py::TestChatCompletions::test_upstream_error_is_durably_evidenced` | Error occurs after admission and is handled by the named branches | A returned caught upstream error bears `durable` but no corresponding node exists | Core chat/completions admitted path only | Application owner |
| DOC01-LIFE-003 | Pre-admission rejections are universally durably evidenced. | `ROADMAP` | Current counter-locators: `aegis/proxy/app.py:1004-1080`; `tests/test_proxy.py::TestAuthentication::test_missing_auth_returns_401`; `test_invalid_json_returns_400` | A future rejection-evidence policy defines safe metadata and privacy handling | Any rejection class returns without required rejection evidence after the policy is enabled | Not implemented today | Security and privacy owners |
| DOC01-STRM-001 | Core SSE incrementally emits sanitized canonical events, hashes the exact emitted bytes, commits one terminal summary, and emits the terminal marker only after that commit succeeds. | `IMPLEMENTED` | `aegis/proxy/app.py`; `aegis/proxy/streaming.py`; `tests/test_proxy_streaming.py::test_success_hashes_exact_output_and_commits_before_done`, `test_first_event_arrives_before_upstream_second_event`, `test_split_phi_is_redacted_before_hash_and_delivery`, and `test_commit_failure_omits_done` | Admitted supported SSE protocol and successful terminal persistence for terminal-marker emission | Terminal marker precedes commit, digest differs from delivered bytes, unsanitized detected content is emitted, or more than one terminal summary is committed | One streaming handler invocation; initial evidence/proof headers are `pending-terminal` and proof retrieval is post-terminal | Application owner |
| DOC01-STRM-002 | Core SSE retained memory is bounded per admitted stream by byte- and item-accounted queueing plus finite event, de-identification-window, and preview storage; cumulative-output and duration policies also terminate a stream. | `IMPLEMENTED` | `aegis/config.py`; `aegis/proxy/streaming.py`; `tests/test_proxy_streaming.py::test_byte_limit_closes_without_done_and_commits_once`, `test_timeout_and_oversized_event_fail_without_done`, and `test_large_logical_stream_retained_memory_is_bounded`; `specs/aegis_stream_buffer.smt2` | Positive validated limits and one admitted stream | Queue items/bytes, event size, retained-byte expression, cumulative output, or duration exceeds its configured per-stream bound, or upstream is not closed on termination | Per admitted stream only; aggregate retained memory scales with concurrency and requires deployment admission budgeting | Reliability owner |
| DOC01-LEDG-001 | The core ledger serializes node creation and JSONL persistence among callers sharing one ledger instance. | `IMPLEMENTED` | `aegis/core/crypto_audit.py:285-290,378-419`; `tests/test_production_stresses.py::TestProductionStresses::test_NEW_03_Concurrent_Latency`; fsync regression above | All writers share the same Python object and lock | Same-instance concurrent calls create broken predecessor links or missing committed records | Single process and ledger instance | Python concurrency reviewer |
| DOC01-LEDG-002 | `verify_integrity()` detects in-memory node mutation, predecessor mismatch, and invalid HMAC for the retained deque. | `IMPLEMENTED` | `aegis/core/crypto_audit.py:453-507`; `tests/test_forensic.py::TestCryptographicAuditLedger::test_integrity_detects_tamper`; `tests/test_property_based.py::test_ledger_integrity_property` | HMAC key available for HMAC records; retained window has valid genesis semantics | Named tamper remains undetected inside the supported window | In-memory retained deque, not external immutable custody | Cryptography owner |
| DOC01-LEDG-003 | Core WAL `fsync` returned during a local injected seam and the record remained present and verifiable. | `MEASURED` | `tests/test_market_hardening_gates.py::test_ledger_fsync_injection_preserves_durable_commit_and_integrity`; `evidence/execution_2026-08-20/backpressure_stall_report.json` | Named local environment and injected 2 ms delay | Reproduction reports missing/duplicate records, failures, or invalid integrity | Local fault-injection result, not target storage capacity | Performance and storage owners |
| DOC01-LEDG-004 | The retained backpressure artifact offered 2,500 requests at a configured 10,000 RPS for 0.25 seconds; all 2,500 were durable in that run, with p99 commit latency 836.3514210795984 ms. | `MEASURED` | `evidence/execution_2026-08-20/backpressure_stall_report.json`; manifest reference in `evidence/execution_2026-08-20/manifest.json` | Exact recorded harness and environment | Artifact validation fails or rerun under same declared inputs violates the gate | Offered load is not accepted production capacity | Performance reviewer |
| DOC01-LEDG-005 | Core JSONL WAL survival across power loss, controller loss, or distributed-volume failover is guaranteed. | `CONFIGURATION-DEPENDENT` | Process call at `aegis/core/crypto_audit.py:719-754`; limitation in `docs/CLAIMS_MATRIX.md:34-35` | Named filesystem/device/mount/replication settings and crash tests | Recoverable committed records differ from acknowledged commits | Target deployment only | Storage owner |
| DOC01-TOPO-001 | One core worker per private WAL yields an independently reviewable per-worker sequence under single-process assumptions. | `CONFIGURATION-DEPENDENT` | `aegis/core/crypto_audit.py:378-419`; `docs/performance/SCALING_GUIDE.md:16-25` | Private accepted storage, strong signer, no second writer | Two writers access the path, chain verification fails, or storage acceptance fails | Per worker or replica only | Platform owner |
| DOC01-TOPO-002 | Multiple core workers or pods can share one WAL and preserve a single total order. | `ROADMAP` | Process-local lock at `aegis/core/crypto_audit.py:285-290`; worker launch at `aegis/proxy/app.py:1377-1398`; current chart at `deploy/helm/values.yaml:4,52` | Inter-process atomic chain-head protocol would be required | Concurrent multi-process test produces a fork, loss, parse error, or MMR divergence | Not implemented today | Architecture review board |
| DOC01-EXT-001 | The enterprise proxy awaits signer and storage provider completion before returning admitted upstream successes and handled upstream errors. | `IMPLEMENTED` | `aegis_server/main.py:886-993`; all four tests in `tests/test_enterprise_durable_evidence.py` | Provider correctly reports completion or failure | Response claims `durable` before `write_node` completion or after a failed write | Enterprise endpoint call ordering | Enterprise application owner |
| DOC01-EXT-002 | External storage produces a fork-free total chain under concurrent workers. | `ROADMAP` | Separate read/write at `aegis_server/main.py:499-576`; explicit lock gaps in `aegis_server/storage/postgres_provider.py:257-268` and `dynamodb_provider.py:227-242` | Atomic compare-and-append or centralized writer must be implemented | Two successful nodes reference the same non-genesis predecessor in a concurrency test | Not implemented today | Database architecture owner |
| DOC01-FORM-001 | The declared finite models and Lean theorem preserve their stated abstract commit-before-emission, append-prefix, and session-binding invariants. | `MEASURED` | `scripts/verify_formal_artifacts.sh`; `specs/aegis_invariants.tla`; `specs/aegis_ledger_immutability.tla`; `specs/aegis_session_manager.tla`; `specs/AegisVerification.lean`; `docs/formal/FORMAL_VERIFICATION.md` | Exact tool versions, configs, and artifact contents | Solver error, non-`unsat` Z3 result, Lean type-check failure, or TLC counterexample | Exact abstractions and finite bounds | Formal-methods reviewer |
| DOC01-FORM-002 | The Python/Rust/storage implementation is machine-checked as a refinement of the formal lifecycle. | `ROADMAP` | Gap recorded at `docs/formal/FORMAL_VERIFICATION.md:44-46` and `AEGIS_EXECUTION_REPORT_2026-08-20.md:79-89` | Trace mapping and refinement relation must be defined | Implementation trace is rejected by the formal relation or no proof exists | Not established today | Formal-methods reviewer |
| DOC01-LEGAL-001 | The evidence chain is legally admissible or satisfies a regulatory regime. | `LEGAL-REVIEW-REQUIRED` | Claim controls at `docs/CLAIMS_MATRIX.md:48,53-59`; architecture decision at `docs/architecture/ADR-001-AI-GOVERNANCE-EVIDENCE-GATEWAY.md:24-28` | Applicable law, custody, identity, retention, controls, and independent review | Qualified counsel or assessor rejects the conclusion or prerequisites are absent | Jurisdiction and customer-specific | Legal counsel and evidence custodian |

## 11. Falsification and acceptance tests

Existing tests should remain release gates. Proposed tests are classified as `ROADMAP` until implemented and executed.

| Test ID | Test vector | Expected safety result | Existing locator or required artifact | Status | Kill criterion | Owner |
|---|---|---|---|---|---|---|
| DOC01-FALS-001 | Inject a core ledger write/flush/`fsync` exception during non-streaming success, upstream non-2xx, and SSE terminal completion. | Non-streaming paths do not claim `durable`; SSE may already have emitted non-terminal events but must omit the terminal marker. | SSE unit coverage: `tests/test_proxy_streaming.py::test_commit_failure_omits_done`; direct integrated core-handler commit-failure coverage remains absent; enterprise analogue: `tests/test_enterprise_durable_evidence.py::test_storage_failure_fails_closed_and_does_not_claim_durable`. | `IMPLEMENTED` for the stream proxy unit boundary; integrated handler injection remains `ROADMAP` | A stream terminal marker escapes after failed terminal commit, or a non-streaming response claims `durable` after failed commit. | Release owner |
| DOC01-FALS-002 | Instrument ASGI `send`, `_persist_node` return, and response creation for concurrent success/error/SSE requests. | Non-streaming response send follows commit; SSE non-terminal events may precede terminal commit, but its terminal marker must follow the one matching summary commit. | Required trace-refinement harness; gap noted in `docs/formal/FORMAL_VERIFICATION.md`. | `ROADMAP` | A non-streaming response precedes commit, an SSE terminal marker precedes terminal commit, or a request receives duplicate/mismatched terminal commits. | Formal and application owners |
| DOC01-FALS-003 | Feed an SSE response beyond declared queue, event, cumulative-output, or duration limits, and exercise a large logical stream with a slow consumer. | Per-stream retained state stays within its declared accounting bounds; termination closes upstream, commits one terminal outcome, and omits the terminal marker on failure. | `tests/test_proxy_streaming.py::test_byte_limit_closes_without_done_and_commits_once`, `test_timeout_and_oversized_event_fail_without_done`, and `test_large_logical_stream_retained_memory_is_bounded`; `specs/aegis_stream_buffer.smt2`. | `IMPLEMENTED` at the stream-proxy test boundary | A per-stream bound is exceeded, upstream remains open, terminal commit count differs from one, or a failure emits the terminal marker. | Reliability owner |
| DOC01-FALS-004 | Start two Uvicorn workers against one core WAL and issue synchronized commits. | Deployment must be rejected, or every record must form one recoverable chain if an inter-process protocol is later added. | No current test. | `ROADMAP` | Forked predecessor, corrupt JSONL, missing record, duplicate ID, or MMR divergence. | Platform owner |
| DOC01-FALS-005 | Restart after multiple core commits and append one more record; independently recompute the MMR over all historical leaves. | Stored new root equals full-history root. | Current `_load_from_wal` at `aegis/core/crypto_audit.py:756-794` does not rebuild MMR. | `ROADMAP` | Post-restart root differs from full-history root. | Cryptography owner |
| DOC01-FALS-006 | Commit more than `max_memory_nodes`, then run `verify_integrity()` and separately verify the complete WAL. | Supported verifier has explicit window semantics and does not report a false genesis failure. | No current rollover regression. | `ROADMAP` | False integrity alarm or unexamined records are presented as a full-chain pass. | Evidence owner |
| DOC01-FALS-007 | Seed a malformed JSONL line, restart in strict mode, and submit a governed request. | Strict policy rejects readiness and governed traffic until repair or explicit recovery. | Current contrary behavior: `tests/test_reliability.py::test_wal_corruption_recovery_partial_chain`. | `ROADMAP` | New governed record is accepted while the ledger reports `wal_corrupt`. | Incident-response owner |
| DOC01-FALS-008 | Run concurrent enterprise requests against real SQLite, PostgreSQL, and DynamoDB test environments with synchronized predecessor reads. | Exactly one successor per chain head, or an explicit branch model with verifiable merge semantics. | Provider unit tests do not cover this race. | `ROADMAP` | Two nodes reference the same predecessor where a linear chain is claimed. | Database owner |
| DOC01-FALS-009 | Kill the core process before write, during write, after flush, during `fsync`, and immediately after `fsync`; repeat on target storage. | No response acknowledged before a recoverable record; recovery behavior matches the declared durability boundary. | Required target crash-consistency artifact. | `CONFIGURATION-DEPENDENT` | Acknowledged durable response lacks a recoverable record. | Storage/SRE owner |
| DOC01-FALS-010 | Execute formal gate with pinned tools and current artifacts. | Z3 is `unsat`, Lean type-checks, and TLC produces no counterexample or incomplete run. | `scripts/verify_formal_artifacts.sh`; recorded in `docs/formal/FORMAL_VERIFICATION.md`. | `MEASURED` | Any solver or model-check failure. | Formal-methods reviewer |

## 12. Operational invariants and run conditions

A governed core deployment must use strict mode and satisfy `AegisSettings.validate_runtime_invariants()` (`aegis/config.py:669-686`). That validator requires authentication, durable-evidence configuration, Redis limiting, an API key, and a signing key or PKCS#11 path. LSM and Seccomp enforcement are evaluated during lifespan startup (`aegis/proxy/app.py:630-744`). These checks validate configuration and observed startup behavior; they do not repair unsafe multi-worker storage topology.

The following architecture conditions are required for an approved single-process core boundary:

1. Exactly one writer process owns a WAL path.
2. The WAL path is on storage whose `fsync`, capacity, recovery, and backup behavior has been accepted in the target environment.
3. Strict mode starts successfully with an approved signer and Redis dependency.
4. The process is removed from readiness when `ledger._fault_state` is not healthy, and operational routing respects the readiness/health distinction. The current `/ready` endpoint checks only forwarder initialization (`aegis/proxy/app.py:987-1002`), so an external probe must not treat it as ledger-health acceptance without remediation.
5. Configure and validate the application-level per-stream queue-item, queue-byte, event-size, cumulative-output, de-identification-window, preview, and duration bounds; separately cap aggregate admitted-stream concurrency because total retained memory scales with concurrent streams.
6. Rotated files are treated as ordinary owner-only files unless an external immutable-storage control is configured and tested.
7. Evidence verification reports its retained-window scope and does not label `verify_integrity()` as a complete WAL verification after deque eviction.

For enterprise external storage, approval additionally requires a chain-head serialization design, real-backend concurrency tests, backend-specific durability settings, retry/idempotency analysis, and cross-restart/cross-worker MMR semantics. Without these controls, the safe statement is that the endpoint awaited an individual storage-provider write, not that it appended to one global ledger.

## 13. Residual risks

| Risk ID | Residual risk | Consequence | Current detection or mitigation | Required disposition | Owner |
|---|---|---|---|---|---|
| DOC01-RISK-001 | Core process-local locking does not coordinate multi-worker or multi-pod writers. | Forked or unparsable shared WAL; invalid global-chain claim. | Scaling guide warns of independent sequences. | Enforce one writer per WAL and correct Helm defaults, or implement inter-process serialization. | Platform owner |
| DOC01-RISK-002 | Aggregate streaming memory scales with concurrent admitted requests even though each stream has bounded retained state. | Concurrent streams near their queue/window/preview limits can create aggregate memory pressure. | Per-stream byte- and item-accounted queue, event/window/preview bounds, cumulative-output and duration policies, upstream closure, and one terminal summary commit; `tests/test_proxy_streaming.py` and `specs/aegis_stream_buffer.smt2`. | Set deployment concurrency/admission budgets and test aggregate RSS under the target topology; the arithmetic contract does not prove an aggregate concurrency bound. | Reliability owner |
| DOC01-RISK-003 | Startup WAL corruption is fail-open for subsequent commits. | New evidence can be appended after an untrusted prefix; health and traffic semantics diverge. | `/health` exposes `wal_corrupt`; named reliability test confirms continued writes. | Strict-mode quarantine and recovery workflow. | Incident-response owner |
| DOC01-RISK-004 | Core MMR state is not rebuilt during JSONL replay. | Post-restart roots do not represent the full pre-restart accumulator history. | Hash-chain predecessor remains loaded, but MMR continuity is absent. | Persist/rebuild peaks and add restart proof test. | Cryptography owner |
| DOC01-RISK-005 | Bounded deque verification can lose genesis context and covers only retained nodes. | False integrity failure after rollover or overstatement of full-history validation. | None in the named release tests. | Implement checkpoint/window-aware verification and full-WAL verifier. | Evidence owner |
| DOC01-RISK-006 | `verify_integrity()` does not validate non-HMAC signatures. | HSM/PQC/Ed25519 signature defects may not be detected by this API. | Strong signing rejects explicit fallback records only when configured. | Add scheme-specific verification with key/certificate metadata. | Cryptography owner |
| DOC01-RISK-007 | External provider chain append is read-then-write without atomic head control. | Concurrent enterprise nodes can form branches even when every row is durable. | Backend integrity sweep can detect some predecessor mismatch patterns after the fact. | Atomic compare-and-append or centralized writer. | Database architecture owner |
| DOC01-RISK-008 | Helm defaults combine replicas, multiple workers, and one RWO PVC path. | Unsafe shared writes or unschedulable cross-zone rollout. | None encoded in chart validation. | Change chart defaults and add policy/render tests. | Kubernetes owner |
| DOC01-RISK-009 | `fsync` and backend acknowledgements do not prove target stable-media or replicated durability. | A response labeled durable may not survive power, device, or region failure under some configurations. | Local injected-fsync evidence only. | Target crash, restore, and failover acceptance. | Storage owner |
| DOC01-RISK-010 | No implementation-to-formal refinement proof exists. | Formal success can coexist with an implementation transition absent from the model. | Bounded solver gate and code tests provide complementary but separate evidence. | Trace-refinement harness followed by reviewed refinement work. | Formal-methods reviewer |
| DOC01-RISK-011 | Pre-admission denials are not represented in the authoritative ledger. | Incomplete security-event chronology if operators assume all requests are recorded. | HTTP and observability logs may capture events but have different custody. | Define privacy-aware rejection evidence policy. | Security and privacy owners |
| DOC01-RISK-012 | Legal and compliance language can exceed technical evidence. | Procurement, regulatory, or evidentiary misrepresentation. | `docs/CLAIMS_MATRIX.md` and ADR-001 wording controls. | Qualified legal and independent review for each external claim. | Legal counsel and release owner |

## 14. Evidence register and review procedure

The following repository records were used as the primary audit basis:

| Evidence class | Repository records | Review use |
|---|---|---|
| Production lifecycle | `aegis/proxy/app.py`; `aegis/core/crypto_audit.py`; `aegis_server/main.py` | Handler order, response construction, WAL persistence, external storage acknowledgement |
| Configuration and deployment | `aegis/config.py`; `aegis_server/config.py`; `deploy/helm/values.yaml`; `deploy/helm/values.schema.json`; `deploy/helm/templates/statefulset.yaml`; `deploy/helm/templates/networkpolicy.yaml` | Strict-mode assumptions, workers, replicas, per-replica volumes, network reachability, operational boundaries |
| Storage implementations | `aegis_server/storage/base.py`; `sqlite_provider.py`; `postgres_provider.py`; `dynamodb_provider.py` | Transaction acknowledgement and concurrent chain-head limitations |
| Named regressions | `tests/test_proxy.py`; `tests/test_proxy_streaming.py`; `tests/test_app_coverage_extended.py`; `tests/test_enterprise_durable_evidence.py`; `tests/test_market_hardening_gates.py`; `tests/test_p0_release_gates.py`; provider storage tests | Implemented behavior and negative-path boundaries, including incremental SSE ordering, exact-byte hash, terminal commit, and per-stream bounds |
| Formal records | `specs/*`, including `specs/aegis_stream_buffer.smt2`; `scripts/verify_formal_artifacts.sh`; `docs/formal/FORMAL_VERIFICATION.md` | Abstract invariants, per-stream retained-byte arithmetic, finite bounds, and explicit refinement gap |
| Measured evidence | `evidence/execution_2026-08-20/manifest.json`; `backpressure_stall_report.json`; `AEGIS_EXECUTION_REPORT_2026-08-20.md` | Executed suite context and bounded local observations |
| Claim controls | `docs/CLAIMS_MATRIX.md`; `docs/architecture/ADR-001-AI-GOVERNANCE-EVIDENCE-GATEWAY.md` | Approved vocabulary, non-goals, legal and market boundaries |

A reviewer must block release of a material architecture claim when its locator changes without review, a named test fails, a dependency or topology assumption is absent, an evidence artifact does not match the stated workload, or customer-facing language is stronger than the status and boundary in this document or `docs/CLAIMS_MATRIX.md`. Human review remains mandatory because tests and models do not determine deployment reachability, legal meaning, storage truthfulness, or operational ownership.

## 15. Approval statement

DOC-01 approves the following narrow architecture statement:

> In a supported single-process core deployment with one writer per accepted WAL path, admitted non-streaming outcomes await authoritative evidence persistence before return. Admitted SSE incrementally emits sanitized canonical events through a bounded byte-accounted queue, hashes the exact emitted bytes, writes one terminal summary WAL record, and emits the terminal marker only after that commit succeeds. Initial SSE evidence/proof headers are `pending-terminal`, and proof is retrieved post-terminal from the linked endpoint. Stream backpressure, byte, event, and duration bounds apply per admitted stream; aggregate retained memory scales with concurrency. The Python ledger serializes callers sharing one ledger instance and calls write, flush, and `fsync` before returning a commit. Optional enrichment is non-authoritative. External durability, multi-process ordering, cross-pod ordering, aggregate admission, full-history verification, and legal conclusions require additional controls or remain roadmap work.

Any broader statement requires a matching claim row, exact locator, named test or measured artifact, operational boundary, falsification criterion, and accountable human owner.
