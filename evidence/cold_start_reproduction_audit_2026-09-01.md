# Cold-Start Reproduction Audit — Aegis Latent Core v4.0.2

> **Nature of this document.** This is an evidence-bounded reproduction audit, not a
> certification. It records what was executed and observed in one ephemeral Linux
> container on 2026-09-01, using the repository's own gates and test suites. It adopts
> the four-layer truth vocabulary of [`docs/CLAIMS_MATRIX.md`](../docs/CLAIMS_MATRIX.md)
> and adds explicit **execution-status tags**. It does not assert certification, legal
> compliance, court admissibility, production readiness, or external assurance, and it
> does not convert source metadata into proof of an external release. Anything not
> executed here is marked as such; no result is inferred.

## [EPISTEMIC_HEADER]

| Field | Value |
|---|---|
| Audit type | Cold-start local reproduction of repository gates |
| Baseline audited | Working tree at commit `fb5696e988186b03a2d7ce42e178dce5f682e05d` (branch off `main`) |
| Declared release target | `4.0.2` (source metadata) |
| Auditor environment | Ephemeral container; Python 3.11.15, rustc/cargo 1.94.1, Node v22.22.2, npm 10.9.7 |
| Tooling **absent** (hard boundary) | `z3`, `lean`/`lake`, `tlc` + TLA+ tools jar, `cosign`, `gh attestation`, `gitsign`, `bandit` |
| Confidence | High for locally executed gates; **none asserted** for items marked NOT EXECUTED / NOT PERFORMED |
| Falsification | Any figure below is falsified by re-running the exact command shown and observing a different result on the same commit |

### Execution-status tags used

- **VERIFIED-LOCAL** — command run in this environment; result reproduced and shown.
- **READBACK-CONFIRMED** — confirmed by read-only external API readback (GitHub), not by local byte possession.
- **NOT-EXECUTED** — required tooling absent in this environment; claim neither confirmed nor refuted.
- **NOT-PERFORMED** — possible in principle but out of scope for this run (e.g. downloading release bytes); not attempted.
- **SOURCE-REVIEW** — conclusion from reading source/tests, not from executing the property.

## Executive decision

The **checked-out v4.0.2 source baseline is internally consistent and its local gates
reproduce cleanly**: the release-contract validator reports `READY` with 14/14 version
anchors at `4.0.2`; the full Python suite passes (5661 passed, 81 skipped, 0 failed); the
Rust engine passes clippy under `-D warnings` and all 29 tests; both SDK suites and the
dashboard test/build pass; and the strict documentation and action-pin gates pass. A
read-only GitHub readback confirms a published `v4.0.2` Release with 31 assets and an
annotated, Sigstore-signed tag pointing at the declared commit.

**What this audit does not establish (unchanged from the repository's own boundary):**
the formal-methods gate (Z3/Lean/TLC) was **not executed** because the solvers are absent;
release-asset byte checksums, `cosign`/`gh attestation` signature verification, and OCI/GHCR
image inspection were **not performed** here; and PyPI/npm remain observed at `4.0.0`. These
remain gated on independent readback and are not certified by this document.

## Complete repository audit matrix

### Phase 1 — Source contract & documentation

| Check | Command | Status | Result |
|---|---|---|---|
| Release source contract | `python scripts/verify_release_contract.py --root . --tag v4.0.2` | VERIFIED-LOCAL | `READY`; 14/14 anchors synchronized at `4.0.2` |
| AI context manifest | `python scripts/verify_ai_context_manifest.py --root .` | VERIFIED-LOCAL | 83 files verified; source anchor `fdace8844568eb788216740b2cb5daf187d99d3b` |
| Strict documentation | `python tools/docs/verify_documentation.py --root . --strict` | VERIFIED-LOCAL | `PASS`; 27 required files; 0 errors, 0 warnings |
| GitHub Action SHA pins | `python scripts/verify_github_action_pins.py` | VERIFIED-LOCAL | `PASS`; **112** remote references, all full-SHA pinned |
| Whitespace/conflict gate | `git diff --check` | VERIFIED-LOCAL | clean |

The 14 synchronized anchors reported by the validator: `core`, `core-runtime`, `python-sdk`,
`python-sdk-runtime`, `typescript-sdk`, `typescript-lock`, `dashboard`, `dashboard-lock`,
`rust-cargo`, `rust-pyproject`, `rust-lock`, `helm-chart`, `helm-app`, `helm-image` — all `4.0.2`.

### Phase 2 — Substrate code & test suites

| Tier | Command | Status | Result |
|---|---|---|---|
| Rust lint | `cargo clippy --locked --all-targets --all-features -- -D warnings` | VERIFIED-LOCAL | clean (exit 0) |
| Rust tests | `cargo test --locked` | VERIFIED-LOCAL | **29 passed, 0 failed** |
| Python suite | `pytest -q` | VERIFIED-LOCAL | **5661 passed, 81 skipped, 0 failed** (5741 collected) |
| Python SDK | `pytest sdk/python/tests` | VERIFIED-LOCAL | **16 passed** (required `openai`/`anthropic` peer packages) |
| TypeScript SDK | `npm ci && npm test` (`sdk/typescript`) | VERIFIED-LOCAL | **12 passed** (providers, proof, dropin, gateway); 0 npm vulns |
| Dashboard tests | `npm test` (`dashboard`) | VERIFIED-LOCAL | **6 passed** (contracts, no-fabrication, states) |
| Dashboard typecheck | `npm run typecheck` (`dashboard`) | VERIFIED-LOCAL | clean |
| Dashboard build | `npm run build` (`dashboard`) | VERIFIED-LOCAL | success (12 routes) **after building the SDK `dist/` first** — see Residual Risk R2 |

Python skips (81) correspond to uninstalled optional backends (PostgreSQL, DynamoDB, S3,
native PQC extension, GPU) — i.e. `CONFIGURATION-DEPENDENT` paths, not failures.

**`aegis_rust_v2/src/wal.rs` — SOURCE-REVIEW.** Frame layout `[crc32:4][len:4][payload]`
little-endian. Append reserves, copies, flushes, and publishes under a single `parking_lot::Mutex`;
`write_pos` is stored with `Ordering::Release` **only after `flush_range` returns**, so a failed
flush cannot advance the readable prefix. Bounds are checked with `u32::try_from` (payload length)
and `checked_add` (frame/offset/end), with an explicit capacity gate. A zero-length terminator is
written and flushed after each frame to prevent same-size resurrection of a recovered corrupt
suffix. `read_all`/`scan_write_pos` verify CRC32 and stop at the first mismatch or zero-length
header. File opened `truncate(false)` with `0o600`. Two `unsafe` regions (the `mmap` call and the
`Send`/`Sync` impls) each carry SAFETY comments. The four recovery/concurrency invariants have
dedicated tests among the 29. The module's own doc comment correctly hedges durability
("depends on the OS, filesystem, and device") and performance.

**`aegis_rust_v2/src/mmr.rs` — SOURCE-REVIEW + DISCREPANCY (D1).** Implements an MMR
**accumulator**: SHA-256 leaf hashing, equal-height peak bagging on insert, and root computation
by combining peaks in descending height. It has one test. It does **not** contain inclusion-proof
generation. The mission brief's Phase 2.1 wording ("O(log n) inclusion proof generation" in
`mmr.rs`) conflates two components: per `AGENTS.md` rule 4 and `CLAIMS_MATRIX.md`, the portable
O(log n) inclusion proofs live in **`aegis/core/mmr.py`** (`get_inclusion_proof`,
`get_portable_inclusion_proof`, `verify_portable_inclusion*`), exercised by `tests/test_mmr_portable.py`
and both SDK verifiers — all of which passed here. This is a documentation/brief conflation, not a
code defect.

**`aegis/core/streaming_deidentifier.py` — SOURCE-REVIEW.** Bounded incremental redactor: holdback
retained to ≈2× `window_chars` with `window_chars ∈ [64, 4096]`; exceeding the bound raises
`StreamingDeidentificationError` (fail-closed), as do overlong open URL / magnetic-track / email /
address candidates. No full-buffer path. Docstring explicitly disclaims HIPAA Safe Harbor / Expert
Determination.

**`aegis/proxy/streaming.py` — SOURCE-REVIEW.** Emitted bytes are incrementally hashed
(`hashlib.sha256().update` in `_accumulate`); a single terminal `StreamEvidenceSummary` is committed
via `_finalize` (guarded by an asyncio lock + `_finalized` flag) **before** the terminal marker
(`[DONE]` / `message_stop`) is yielded. Memory is bounded by a byte-accounted queue plus a fixed
preview; there is no full-response RAM buffer. (The auxiliary `RustWal` fail-open path and the
`aegis_native_stream_wal_errors_total` counter referenced in the brief live in the terminal-commit
callback / ledger, not in this module; not separately re-verified here.)

### Phase 3 — Formal methods & model checking — NOT-EXECUTED

`scripts/verify_formal_artifacts.sh` exits `127` ("z3 is required"). `z3`, `lean`/`lake`, and the
TLA+ tools jar are absent from this environment, so **no formal property was executed**. The spec
files were read (SOURCE-REVIEW only):

- `specs/aegis_invariants.smt2` — QF_BV token-bucket admission safety with 128-bit widening to avoid
  wraparound; encodes the negated-safety-is-`unsat` pattern and declares `:status unsat`. **Not run.**
- `specs/aegis_stream_buffer.smt2` — QF_LIA per-stream memory-bound contract; its `window_chars ∈ [64,4096]`
  bound matches the deidentifier source. **Not run.**
- `specs/AegisVerification.lean` — a 5-phase state machine (`received→controlled→upstream→committed→emitted`)
  with `DurableEmissionInvariant` and three theorems (initial/step-preservation/all-reachable). Structurally
  a bounded abstraction of durable-before-emission, consistent with `AGENTS.md` rule 5. **Not type-checked.**

`CLAIMS_MATRIX.md` records these as `MEASURED` with Z3/Lean/TLC falsification criteria; **this run
does not reproduce that status** and cannot, absent the solvers.

### Phase 4 — Supply chain & attestation

| Item | Status | Result |
|---|---|---|
| GitHub Release `v4.0.2` exists | READBACK-CONFIRMED | published `2026-08-28T01:59:28Z`; `draft:false`, `prerelease:false`, target `main` |
| Release asset inventory | READBACK-CONFIRMED | **31 assets** matching the declared matrix (see below) |
| Annotated tag target | READBACK-CONFIRMED | tag `v4.0.2` → commit `a6eb58dcc03f8b638c8f3e35f0300f5443a926ca` (matches declared target); tag object `308a5d001ab8ccd4841cc5a160158a7e8284e445` |
| Tag signature | READBACK-CONFIRMED (partial) | Sigstore/gitsign keyless signature; SAN identity `…/create_release_tag.yml@refs/heads/main`, OIDC issuer `token.actions.githubusercontent.com`, trigger `workflow_dispatch`, env `release`. GitHub **native** `verification.verified = false` / reason `bad_cert` — expected for Sigstore short-lived certs; true trust needs `gitsign`/`cosign` verification |
| Action SHA-pin lockdown | VERIFIED-LOCAL | 112/112 remote references SHA-pinned |
| `sha256sum --check --strict SHA256SUMS` | NOT-PERFORMED | release bytes not downloaded/hashed in this environment |
| `cosign verify` / `gh attestation verify` (OCI, SLSA) | NOT-EXECUTED | `cosign` and `gh` attestation tooling absent; GHCR images not inspected |

31 release assets (enumerated): `SHA256SUMS`; `release-asset-manifest.json` (+`.sha256`);
`aegis-latent-core-4.0.2.spdx.json` and `aegis-latent-core-build-sbom.spdx.json` (+`.sha256` each);
`aegis_latent_core-4.0.2` wheel + sdist (+`.sha256` each); `aegis_latent_sdk-4.0.2` wheel + sdist
(+`.sha256` each); `aegis-latent-sdk-4.0.2.tgz` (+`.sha256`); and **7 `aegis_rust-4.0.2-cp311-abi3`
platform wheels** (macOS x86_64/arm64, manylinux2014 x86_64, musllinux x86_64/aarch64/armv7l,
win_amd64) each with a `.sha256` sidecar.

### Phase 5 — Epistemic & regulatory boundary — VERIFIED (documentation review)

| Assertion under review | Finding |
|---|---|
| Product framed as an "AI Governance and Evidence Gateway" | Confirmed — `CLAIMS_MATRIX.md`: "OpenAI-compatible AI Governance and Evidence Gateway", explicitly "not an LLM, a universal WAF, a universal compliance product, a legal-admissibility decision" |
| Regulatory mappings framed as technical input, not compliance | Confirmed — compliance row is `LEGAL-REVIEW-REQUIRED`: "Not a SOC 2 opinion, HIPAA determination, FedRAMP authorization, EU AI Act conformity assessment, GDPR legal basis, or legal advice" |
| Pricing declared as unvalidated planning hypotheses | Confirmed — `COMMERCIAL.md`: Team/Pilot $10k–30k, Production $40k–100k, Enterprise $100k–250k+ held "solely as hypotheses… **not list prices, observed ACV, or a valuation**"; matrix row is `ROADMAP` |
| Registry state acknowledged at `4.0.0` | Confirmed — `README.md` badges "PyPI observed 4.0.0" / "npm observed 4.0.0"; `4.0.2` install commands gated on "successful publication and readback"; `v4.0.1` recorded as a failed lightweight tag |
| Portable MMR proof scope | Confirmed — matches `AGENTS.md` rule 4: non-ZK O(log n) inclusion proof of a disclosed leaf against a separately trusted root; no confidentiality/identity/time/ordering/external-immutability claim |

## Residual risk & maintenance backlog

- **R1 — Formal gate not reproducible here (severity: informational).** Z3/Lean/TLC absent. The
  `MEASURED` status of the formal abstractions rests on CI, not on this run. Recommendation: keep the
  pinned `verify_formal_artifacts.sh` provenance check (TLA+ jar SHA + `X-Git-Revision`) as the
  authoritative gate; this audit could not exercise it.
- **R2 — Dashboard build ordering (severity: low; not a defect).** `dashboard` depends on
  `aegis-latent-sdk` via `file:../sdk/typescript`, and `next build` resolves the `./proof` subpath
  export from the SDK's compiled `dist/`. An isolated `npm run build` fails with `Module not found:
  aegis-latent-sdk/proof` unless the SDK is built first. CI already does this (its dashboard job runs
  `npm run build` in `sdk/typescript` before the dashboard). Optional hardening: a dashboard
  `prebuild` step (or documented note) so a local build can't be run out of order.
- **R3 — Brief/documentation conflation on MMR (severity: informational).** See D1: inclusion proofs
  are in `aegis/core/mmr.py`, not `aegis_rust_v2/src/mmr.rs` (an accumulator). Repo docs are already
  correct; only the external mission brief was imprecise.
- **R4 — Signature/attestation trust unverified here (severity: informational).** The tag carries a
  Sigstore signature with a coherent workflow identity, but GitHub's native check reports
  `bad_cert`, and `cosign`/`gh attestation` were unavailable. Full keyless-signature and SLSA
  provenance verification remains a `cosign`/`gitsign` readback step outside this environment.
- **R5 — Static security scan not re-run (severity: informational).** `bandit` was not installed;
  this audit did not produce new SAST findings and does not restate historical counts. The repository
  carries its own `SECURITY_AUDIT_REPORT.md` (marked historical) and `evidence/` records.
- **R6 — Registry publication pending (severity: informational, by design).** PyPI/npm observed at
  `4.0.0`; `4.0.2` distribution requires a successful publish run plus registry readback.

## Provenance envelope

The block below is a structured summary of this audit's inputs and results. Digests marked
`sha256:` are ordinary SHA-256 content digests computed in this environment. This is **not** a
CIDv1/DAG-CBOR multihash seal — producing a canonical DAG-CBOR CID would require the repository's own
encoding tooling and is out of scope; the field name is retained for the requested structure but the
value is an honest SHA-256 digest of this report file (see the companion `.sha256` note appended at
commit time).

```json
{
  "audit": "cold-start-reproduction",
  "subject_repo": "JuanLunaIA/aegis-latent-core",
  "worktree_commit": "fb5696e988186b03a2d7ce42e178dce5f682e05d",
  "declared_release_target": "4.0.2",
  "auditor_date": "2026-09-01",
  "toolchain": {"python": "3.11.15", "rustc": "1.94.1", "node": "22.22.2", "npm": "10.9.7"},
  "tooling_absent": ["z3", "lean", "tlc", "tla2tools.jar", "cosign", "gh-attestation", "gitsign", "bandit"],
  "gates": {
    "release_contract": {"status": "READY", "anchors": 14, "execution": "VERIFIED-LOCAL"},
    "ai_context_manifest": {"files": 83, "anchor": "fdace8844568eb788216740b2cb5daf187d99d3b", "execution": "VERIFIED-LOCAL"},
    "docs_strict": {"errors": 0, "warnings": 0, "required_files": 27, "execution": "VERIFIED-LOCAL"},
    "action_sha_pins": {"remote_references": 112, "status": "PASS", "execution": "VERIFIED-LOCAL"}
  },
  "tests": {
    "python": {"passed": 5661, "skipped": 81, "failed": 0, "collected": 5741, "execution": "VERIFIED-LOCAL"},
    "rust": {"passed": 29, "failed": 0, "clippy_deny_warnings": true, "execution": "VERIFIED-LOCAL"},
    "sdk_python": {"passed": 16, "execution": "VERIFIED-LOCAL"},
    "sdk_typescript": {"passed": 12, "execution": "VERIFIED-LOCAL"},
    "dashboard_tests": {"passed": 6, "typecheck": "pass", "build": "pass-after-sdk-dist", "execution": "VERIFIED-LOCAL"}
  },
  "formal_methods": {"execution": "NOT-EXECUTED", "reason": "z3/lean/tlc absent"},
  "supply_chain": {
    "github_release_v4_0_2": {"present": true, "draft": false, "prerelease": false, "assets": 31, "execution": "READBACK-CONFIRMED"},
    "annotated_tag_target": {"tag": "v4.0.2", "commit": "a6eb58dcc03f8b638c8f3e35f0300f5443a926ca", "execution": "READBACK-CONFIRMED"},
    "tag_signature": {"type": "sigstore-gitsign", "github_native_verified": false, "reason": "bad_cert", "execution": "READBACK-CONFIRMED-PARTIAL"},
    "sha256sums_bytecheck": {"execution": "NOT-PERFORMED"},
    "cosign_slsa_attestation": {"execution": "NOT-EXECUTED"}
  },
  "epistemic_review": {"product_category": "confirmed", "regulatory_framing": "confirmed", "pricing_hypotheses": "confirmed", "registry_state_4_0_0": "confirmed", "mmr_proof_scope": "confirmed"},
  "decision": "Local gates reproduce cleanly on the v4.0.2 source baseline; external lifecycle (formal proofs, signature/attestation verification, asset byte-checks, registry publication) remains gated on tooling and readback not available in this environment. This is not a certification.",
  "discrepancies": ["D1: mission brief places MMR inclusion proofs in Rust mmr.rs; they are in aegis/core/mmr.py (accumulator-only in Rust)."]
}
```

## Related documents

- [`docs/CLAIMS_MATRIX.md`](../docs/CLAIMS_MATRIX.md) — canonical public claim control.
- [`AGENTS.md`](../AGENTS.md) — repository working rules and claim boundaries.
- [`evidence/INDEX.md`](INDEX.md) — evidence index.

**Last verified:** 2026-09-01 UTC
**Release baseline:** four-layer truth model (source baseline `4.0.2`)
