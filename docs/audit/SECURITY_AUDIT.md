# Aegis Audit-Chain Security Verification

> scope: cryptographic audit-chain claims verified against source, not docs
> ref branch: `claude/extract-decompress-project-files-22ynzl`
> method: each claim → `[PROVEN]` (code evidence) or `[GAP]` (mechanism + repro + fix)
> note: an earlier `[INFERENCE]`-only pass mis-flagged #1/#3 as gaps; this pass
> corrects that against the real `commit_forensic` critical section.

---

## Summary

| # | Claim | Verdict | Action |
|---|---|---|---|
| 1 | PREV_HASH linkage under concurrency | `[PROVEN]` OK | none (already correct) |
| 2 | Signature coverage of `prev_hash` | `[GAP]` → **FIXED** | bind `prev_hash` into signed payload + `node_hash` |
| 3 | Concurrent chain fork | `[PROVEN]` OK | none (already correct) |
| 4 | SSE streaming commit on disconnect | `[GAP]` → **FIXED** | commit in `finally`, background task |
| 5 | Rust↔Python MMR parity | `[PROVEN]` moot for ledger | parity test added (skip-aware) |
| 6 | Auth guard / debug bypass | `[PROVEN]` OK + intended-vs-implemented `[GAP]` → **FIXED** | enforce `auth_disabled`⇒`debug_mode` |
| 7 | STRIDE threat model | `[ANALYSIS]` | WAL `0o600` hardening applied |

---

## 1 & 3. PREV_HASH linkage / concurrent fork — `[PROVEN]` OK

`commit_forensic` performs the entire read-modify-write inside one critical
section (`aegis/core/crypto_audit.py`):

```python
with self._lock:                                  # threading.Lock
    prev_hash = self.chain[-1].node_hash if self.chain else "0" * 64
    timestamp = time.time()
    merkle_root = self._mmr.add_leaf(leaf)
    signature, ... = self._sign(signed_payload)
    node = AuditNode(...)
    self._persist_node(node)
    self.chain.append(node)
```

`prev_hash` is read **inside** the lock, not before it. `app.py` dispatches the
sync commit via `asyncio.to_thread`; every worker thread contends on the same
`self._lock`, so reads and appends are serialized. **X→Y because Z:** no two
threads can observe the same `prev_hash` and both append, because the read and
the `chain.append` are atomic under one lock.

Evidence it holds at scale: `tests/test_red_team.py::test_S1_Massive_Concurrency_Burst`
runs 100 threads × 50 commits and asserts `verify_integrity()` passes.

No change required.

## 2. Signature coverage of `prev_hash` — `[GAP]` → FIXED

**Mechanism (before):** the signature covered `merkle_root` alone. The MMR leaf
(`build_merkle_leaf`) includes the full `request_hash`/`response_hash`, so those
were transitively covered — but `prev_hash` was in neither the leaf, the
`node_hash`, nor the signed material. `verify_integrity` recomputes the HMAC over
the *stored* `merkle_root`, so an adversary with WAL write access could reorder
nodes and rewrite each `prev_hash` to the new predecessor's `node_hash`; the
unchanged per-node signatures still verified → tamper-evidence claim false for
reordering.

**Fix:**
- `_build_signed_payload(prev_hash, merkle_root, request_hash, response_hash)` is
  now the signed material (HMAC and verify both use it).
- `prev_hash` is the first field of `node_hash`, making `node_hash` a true chain
  accumulator (also protects the keyless/ed25519 path via the linkage check).

**Repro (now caught):** `tests/test_security_fixes.py::test_node_reorder_detected_by_signature`
forges a reordered, link-consistent chain and asserts `verify_integrity()` fails
at index 0 because the first node's signature was computed for a different
`prev_hash`.

## 4. SSE streaming commit on disconnect — `[GAP]` → FIXED

**Mechanism (before):** the commit was after the `async for` loop in
`_stream_chat`. On client disconnect asyncio raises `GeneratorExit`/
`CancelledError` at the `yield`, so the post-loop commit never ran → partially
delivered streams were absent from the audit chain.

**Fix:** the analyze+commit moved into a `finally` block, scheduled via
`_spawn_background` (a tracked task set so the commit survives cancellation of
the generator's own task and isn't GC'd). The two non-streaming `create_task`
sites now use the same tracked-task helper.

**Repro (now caught):** `tests/test_app_coverage.py::test_sse_commit_on_client_disconnect`
disconnects after the first chunk and asserts a node still lands in the ledger.

## 5. Rust↔Python MMR parity — `[PROVEN]` moot for ledger

The ledger constructs `MerkleMountainRange()` (pure Python) directly; it never
uses the Rust accumulator, so the audit chain's roots are Python-computed
regardless of `aegis_rust` availability. The advertised `RustBackedMMR` returns
the Rust root while serving proofs from a Python replica — a latent divergence
risk only on that dormant path.

**Action:** `tests/test_mmr_parity.py` asserts byte-identical roots across leaf
counts {1,2,3,4,7,8,15,16,33}. It is `importorskip`-guarded, so it is skipped
until the extension is built (`maturin develop`) and fails loudly on divergence
in CI once it is.

## 6. Auth guard / debug bypass — `[PROVEN]` OK + intended-vs-implemented `[GAP]` → FIXED

`debug_mode` does **not** disable authentication — it only toggles
`/docs`,`/redoc`,`/openapi.json`. Audit endpoints always carry
`Depends(validate_audit_auth)`; the only bypass is `auth_disabled`, gated in
`AuditKeyAuth`/`ProxyKeyAuth`.

**Gap:** the `debug_mode` docstring promised "Automatically forces
auth_disabled=False check at startup" — no such check existed. A stray
`AEGIS_AUTH_DISABLED=true` in production would silently open the proxy and audit
endpoints.

**Fix:** `AegisSettings._enforce_auth_posture` (`@model_validator(mode="after")`)
raises unless `debug_mode` is also set when `auth_disabled=True`.

**Repro (now caught):** `tests/test_security_fixes.py::test_auth_disabled_requires_debug_mode`.

## 7. STRIDE — residuals and applied hardening

| Class | Residual | Status |
|---|---|---|
| **T**ampering | WAL editable by FS-level attacker; HMAC catches it only if the key lives outside the WAL host | mitigated by #2 (reorder now caught); key-isolation is an operator control |
| **I**nfo disclosure | WAL held forensic metadata (tenant_id, model, request/response **hashes**, sampling params) at umask-default mode | **FIXED** — WAL created `0o600`, pre-existing files chmod-tightened on open (`test_wal_file_mode_is_owner_only`) |
| **E**oP | `auth_disabled` config-only bypass | **FIXED** via #6 |
| **R**epudiation | HMAC is symmetric → server-side forgery possible; `legal_admissibility="High"` only with a configured key | by design; PQC/ed25519 paths documented |
| **D**oS | rate-limiter fail-open/closed on Redis outage; unbounded concurrent SSE; WAL growth/rotation | open — operator/roadmap items, not addressed here |

The WAL stores **hashes**, not plaintext request/response bodies (those live only
in the MMR leaf, which is hashed, not persisted), so the disclosure blast radius
is metadata, not prompt content — `0o600` is hygiene-grade hardening regardless.

---

## Changed files

- `aegis/core/crypto_audit.py` — `_build_signed_payload`; sign/verify over it;
  `prev_hash` in `node_hash`; WAL `0o600` (both open paths).
- `aegis/proxy/app.py` — `_BACKGROUND_TASKS`/`_spawn_background`; SSE commit in
  `finally`; tracked tasks for non-stream commits.
- `aegis/config.py` — `_enforce_auth_posture` model validator.
- tests — `test_security_fixes.py` (+5), `test_mmr_parity.py` (new),
  `test_app_coverage.py` (SSE disconnect), and `auth_disabled` tests updated to
  pass `debug_mode=True`.

All gates: `226 passed, 7 skipped`; `ruff` clean on changed files; no net-new
`mypy` errors beyond the pre-existing baseline.
