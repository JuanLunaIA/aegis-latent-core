# Implementation Manifest and Threat Notes — 2026-08-21

## Scope

This remediation addresses four bounded mechanisms: Python 3.11 lifespan shutdown, buffered SSE memory/duration bounds, repository-owned deprecation warnings, and mutable GitHub Action references. It does not claim production capacity, legal compliance, complete alert visibility, authenticated ML-KEM transport, or an aggregate concurrent-memory bound.

## Mechanistic changes

| Mechanism | Input → transformation → output | Failure mode addressed | Verification |
|---|---|---|---|
| Analysis worker cancellation | queued analysis → `wait_for(to_thread(...))` → post-commit enrichment | A CPython 3.11 cancellation retained across the inner wait can re-enter `queue.get()` while lifespan awaits unlimited `gather` | Synthetic consumed-cancellation regression, in-flight thread shutdown regression, 25 repeated Python 3.11 file runs, complete Python 3.11 suite |
| Lifespan shutdown | worker cancellation → bounded gather → subsystem close | Infinite TestClient/application shutdown | Configured `analysis_shutdown_timeout_seconds`, faulthandler CI diagnostics, explicit job timeout |
| Buffered SSE | upstream chunks → normalized bytearray → evidence commit → response | Unbounded per-request bytes and slow-drip lifetime | Exact-under-limit, limit-crossing, iterator-close, and total-deadline regressions |
| Deprecation handling | repository timestamps → UTC-aware timestamps | Future removal of `datetime.utcnow()` | 43 tests under `-W error::DeprecationWarning` |
| Workflow dependencies | `uses: owner/repo@ref` → immutable 40-character commit SHA | Mutable tag/branch takeover | 76/76 remote references pass `scripts/verify_github_action_pins.py` |
| Artifact pipeline | main/release source archive → SPDX JSON → GitHub OIDC attestation | Post-merge source artifact lacking a signed SBOM predicate | CI `Generate SBOM` job; GitHub attestation verification is required after merge |

## Threat notes

**SSE memory exhaustion.** One request is bounded by `max_stream_response_bytes`; N concurrent admitted streams can still consume approximately N times that cap plus Python/container overhead. Deployment admission control and memory limits remain required.

**Slow-drip upstream.** Per-read timeouts do not stop an upstream that emits periodically. `max_stream_duration_seconds` now establishes a total wall-clock deadline and the async generator is closed on both byte and duration failure.

**Cancellation and threads.** Cancelling `asyncio.to_thread` does not terminate the underlying native thread. The worker task and lifespan are bounded, but a blocking analyzer must still implement its own timeout and cooperative termination. The regression releases the test thread explicitly.

**Supply chain.** SHA pinning freezes exact Action source but does not prove that source trustworthy. Dependabot Action updates and review of release provenance remain required. Repository-level SHA enforcement and selected-action allowlisting are applied only after the pinned PR passes all workflows.

**Security alert visibility.** The current GitHub App user token lacks fine-grained read permissions for Dependabot, code-scanning, and secret-scanning alerts. HTTP 403 is not interpreted as zero alerts. This is blocked by external authorization and cannot be repaired in repository code.

## Rollback

Code rollback is a single PR revert. The pre-change branch protection, Actions policy, Dependabot state, and labels were captured under `evidence/remediation_2026-08-21/github-before/`. Repository settings are changed one control at a time; any missing required context, disallowed Action, unsigned-commit rejection, or administrative lockout triggers rollback of that control before proceeding.

## Falsification criteria

The shutdown fix is falsified by any bounded Python 3.11 repetition that times out. The SSE fix is falsified by accepting N+1 normalized bytes, exceeding the total deadline, or failing to close the upstream iterator. Pinning is falsified by any remote workflow reference whose revision is not `[0-9a-f]{40}`. SBOM closure is falsified unless the post-merge job succeeds and `gh attestation verify` validates the resulting subject and SPDX predicate.
