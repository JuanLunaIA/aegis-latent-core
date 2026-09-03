# Formal Specifications Mapping

The files under [`specs/`](../specs/) describe **selected abstractions**. The executable entry point is [`scripts/verify_formal_artifacts.sh`](../scripts/verify_formal_artifacts.sh), also referenced by [`.github/workflows/ci.yml`](../.github/workflows/ci.yml). A green result is not a refinement proof of Python/Rust code or a target platform. Release scope is separate: historical immutable source baseline **`fdace8844568eb788216740b2cb5daf187d99d3b`** has 14 `4.0.0` anchors; historical published GitHub Release **v4.0.1** is a lightweight tag targeting **`6469904380218584ae0b5221334bc9a46500f5ba`**; prior public PyPI/npm packages are independently observed at `4.0.0` without workflow-provenance attribution; and the **source release target v4.1.2** has 14 synchronized `4.1.1` anchors and was **published on 2026-09-03**: signed annotated tag at `5a137c86ecd914842493babb7e863033498f68c9`, GitHub Release with 31 assets, PyPI `aegis-latent-sdk` `4.1.1`, and GHCR gateway/dashboard images — **npm still carries `4.0.0`**. External lifecycle state must be independently read back and is never encoded by source metadata.

| Artifact | Property represented | Checker / expected result | Related runtime path | Explicit limit |
|---|---|---|---|---|
| [`specs/aegis_invariants.tla`](../specs/aegis_invariants.tla) | Commit-before-emission finite-state safety | TLC with [`specs/aegis_invariants.cfg`](../specs/aegis_invariants.cfg); no counterexample within configured bounds | [`aegis/proxy/app.py`](../aegis/proxy/app.py), [`aegis/core/crypto_audit.py`](../aegis/core/crypto_audit.py) | No filesystem, process crash, provider, or language refinement model. |
| [`specs/aegis_ledger_immutability.tla`](../specs/aegis_ledger_immutability.tla) | Modeled append-only ledger prefix | TLC with [`specs/aegis_ledger_immutability.cfg`](../specs/aegis_ledger_immutability.cfg) | [`aegis/core/crypto_audit.py`](../aegis/core/crypto_audit.py) | Does not prove WORM hardware, backup custody, permissions, or storage durability. |
| [`specs/aegis_session_manager.tla`](../specs/aegis_session_manager.tla) | Session binding to a committed root and no modeled insecure processing | TLC with [`specs/aegis_session_manager.cfg`](../specs/aegis_session_manager.cfg) | [`aegis/core/session_manager.py`](../aegis/core/session_manager.py) | Finite constants and abstract transitions; no distributed-system refinement. |
| [`specs/aegis_invariants.smt2`](../specs/aegis_invariants.smt2) | Saturated token-bucket admission cannot accept below cost | Z3; `unsat` | Rate-limit implementation mapped in [`docs/REPOSITORY_MAP.md`](../docs/REPOSITORY_MAP.md) | Arithmetic predicate only; no Redis, clock, network, or concurrency proof. |
| [`specs/aegis_stream_buffer.smt2`](../specs/aegis_stream_buffer.smt2) | Retained-byte expression cannot exceed itself under declared parameter bounds | Z3; `unsat` | [`aegis/proxy/streaming.py`](../aegis/proxy/streaming.py) | Arithmetic consistency, not a whole-process memory proof. |
| [`specs/AegisVerification.lean`](../specs/AegisVerification.lean) | Pure theorem statements encoded in the file | Lean type-check | Concepts connected to ledger and admission invariants | Type-checking the abstraction does not connect it automatically to runtime code. |

## Deterministic review procedure

1. Read each artifact's constants, bounds, initial state, transition relation, and asserted invariant.
2. Run `scripts/verify_formal_artifacts.sh` with locally installed checkers; retain tool versions and complete output.
3. Treat missing tools, skipped checks, widened bounds, or changed assumptions as review findings—not implicit passes.
4. Compare modeled transitions with authoritative implementation diffs and executable tests.
5. Record external acceptance separately for storage, clocks, identity, network, providers, secrets, orchestration, and recovery.
6. Stop if the checkout differs from the recorded source release target, the context manifest is stale, or formal results are being used to infer external lifecycle state.

The authoritative claim boundary is the formal-method row in [`docs/CLAIMS_MATRIX.md`](../docs/CLAIMS_MATRIX.md): bounded checks can falsify the declared models, but cannot establish production fitness, universal correctness, certification, or release publication. Historical source baseline, historical GitHub Release, prior registry observation, checked-out source release target, and current external lifecycle read-back must be reported separately.
