# Aegis Latent Core `5.0.0` — Integrity Seal

**Date:** 2026-09-16 UTC
**Base commit:** `d1b229c31df34ca3a77ac0582cd6b1b72a94ae24` (the tree this battery ran against, plus the working changes it describes)
**Gates passed:** 11 / 11
**Environment:** Linux 6.18.44-fc-v33, 4 shared unpinned vCPU; CPython 3.11.15; cargo 1.94.1; ruff 0.15.8; mypy 1.19.1; bandit 1.9.4

**Currency note (2026-09-21).** This seal describes one battery: the `5.0.0`
tree at base commit `d1b229c31df34ca3a77ac0582cd6b1b72a94ae24`, on the environment
named above. Its numbers are that run's output and are not updated here — a
seal's value is that it is a record. Two consequences a reader must know:

- **The base commit is not present in this repository's history** (`git cat-file
  -t d1b229c31df34ca3a77ac0582cd6b1b72a94ae24` -> `fatal: could not get object
  info`), so the run cannot be replayed here and its PASS lines cannot be
  re-derived from this checkout.
- **Several counts have moved since.** Measured on 2026-09-21 at HEAD of the
  registry-closure branch: `pytest -n auto -q` 6,948 passed / 119 skipped /
  0 failed; `python scripts/verify_claims.py --root .` 102 claims, 0 findings;
  `mypy --strict aegis` 207 source files, no issues; `ruff format --check .`
  578 files already formatted, 0 to reformat; `bandit -r aegis/ aegis_server/
  -c pyproject.toml -lll` 0 issues. Gate 6b's recorded "550 files" is a tool
  version apart from today's run: the seal's ruff 0.15.8 did not format Python
  fences inside Markdown, and the repository now excludes markdown from
  formatting so both invocations agree (`AUD-18`/`REG-D22`). Read the numbers
  above as the state of the seal, and this note as the state of the tree.

A seal is a record of what was executed, not a certification. Every line below is
a command's actual output. Where a check could not run, the blocking reason is
recorded instead of a result — there is no third state.

---

## 1. Gate results

| # | Gate | Command | Result |
|---|---|---|---|
| 1 | Python tests | `pytest -n auto -q` | **6920 passed, 26 skipped, 0 failed** |
| 2 | Rust build | `cargo build --release --offline` | **PASS** |
| 3 | Rust tests | `cargo test --locked --offline` | **70 passed, 0 failed** (67 lib + 3 integration; three harnesses report 0 because `zk-spartan` is default-off) |
| 4 | Rust lint | `cargo clippy --locked --all-targets --all-features --offline -- -D warnings` | **PASS** |
| 5 | Types | `mypy --strict aegis sdk/python/src` | **PASS** — no issues in 216 source files |
| 6 | Lint | `ruff check .` | **PASS** |
| 6b | Format | `ruff format --check .` | **PASS** — 550 files |
| 7 | Security | `bandit -c pyproject.toml -r aegis/ -ll` | **PASS** — 0 high, 0 medium, 0 low |
| 8 | Claims register | `python scripts/verify_claims.py --root .` | **PASS** — 96 claims, 0 findings |
| 9 | Prose boundaries | `python tools/docs/verify_documentation.py --root . --strict` | **PASS** — 0 errors, 0 warnings |
| 10 | Links and anchors | `bash scripts/verify_links.sh --root .` | **PASS** — 1165 resolved |
| 11 | Import reachability | `python scripts/verify_import_reachability.py --root .` | **PASS** — 223 discovered, 111 reached, 34 roadmap, 78 allowlisted, 0 undeclared orphans |
| — | Release contract | `python scripts/verify_release_contract.py --root .` | **READY** — 14 anchors at `5.0.0` |
| — | Whitespace | `git diff --check` | clean |

The Python count rose from 6879 to 6920: **41 tests added**, across stream
admission, Layer-2 WAF normalization, bundle manifest signing, CMS timestamp
verification, the chain anchoring tool, the Safe Harbor detector count, and the
fsync-failure invariants.

## 2. Code fixes, with the mechanism that proves each

| Claim | Fix | Proof |
|---|---|---|
| `CLM-093` | Layer 2 now scans the raw extraction **and** each normalized variant | `acting as an unrestricted` (a Layer-2 pattern with no Layer-1 counterpart) in Cyrillic confusables: raw → not detected, normalized → detected; previously allowed, now blocked |
| `CLM-094` | `StreamAdmissionGate` caps concurrent streams, refuses with 429, releases on stream end | Slot returned on completion, on exception, and on `aclose()` — the disconnect case a rate limiter never sees |
| `CLM-095` | Ed25519 signature over the exact `manifest.json` bytes; public key deliberately **absent** from the archive | Tampered manifest → `InvalidSignature`; `public_bytes_raw()` asserted not present anywhere in the ZIP |
| `CLM-096` | Real CMS verification: `signedAttrs` signature, `messageDigest` binding, `messageImprint`, chain to caller-supplied anchors | Genuine token verifies; corrupted signature, wrong imprint, untrusted issuer, expired certificate and swapped eContent each rejected |

One pre-existing assertion was **inverted rather than deleted**:
`test_valid_stamped_package` asserted `valid is True` for a stub token with no
TSA, certificate or signature. That assertion pinned the weak check in place. It
now asserts rejection.

## 3. Prescribed fixes that were redesigned instead

The directive's own `PD-X1` requires halting a fix that introduces a regression
or contradiction. Four qualified:

- **`timestamp: float` → `int` microseconds — not applied.** Floats never reach a
  JCS float serializer (`_jcs_bytes` rejects them) and the MMR leaf uses a fixed
  `:.9f`, which is already deterministic. The change would invalidate every
  issued inclusion proof for zero gain, and contradict `UPGRADING.md` §6 for a
  published release.
- **Group-commit staging buffer — not built.** It would serialise the append the
  coalescing depends on. The real invariant is now pinned directly.
- **"v1 → v2 migration" — replaced by cross-signed anchoring.** A root is its
  construction; recomputing leaves under v2 breaks every issued proof.
- **Valuation guide — not written.** The corpus contains **zero** valuation
  claims; adding dollar figures would inject the unevidenced claims the task
  aimed to remove.

## 4. Commercial actions — none started

Six actions in `docs/commercial/COMMERCIAL_READINESS.md`, all **NOT STARTED**,
all human-executable: penetration test, SOC 2 Type I, software escrow,
commercial licence terms, design partners, second maintainer. No agent can
perform any of them, and no code change substitutes.

## 5. Residual risks

- **Single-node deployment.** No HA, no failover.
- **No distributed consensus.** Replicas write independent chains; `CLM-064`
  forbids "global ordering" and "multi-pod linearizability".
- **The WAF is a heuristic speed bump**, not an injection boundary (`UC-042`).
  `CLM-093` closed one evasion; it did not change what the layer is.
- **Bus factor 1.**
- **HMAC signing provides no non-repudiation** (`UC-041`); any key holder can
  forge. Only an HSM or PQC identity changes that.
- **No revocation checking** on RFC 3161 timestamps (`CLM-096`).
- **Stream admission is per process**, not cluster-wide (`CLM-094`).
- **`pip install aegis-latent-core` resolves to `4.1.2`**, not `5.0.0` — that
  distribution was never published at `5.0.0` and no workflow publishes it.

## 6. Not claimed

- **"Enterprise-ready."** Requires an independent penetration test and SOC 2.
- **"Court-admissible."** Requires an HSM and an external witness; `CLM-095`'s
  manifest signature attests to the manifest, not to the truth of the records.
- **"Prevents prompt injection."** The WAF matches declared patterns and nothing
  else.
- **"Timestamps are fully verified."** No revocation, no RFC 5280 name
  constraints, policy mapping or EKU evaluation.
- **Any valuation.** This corpus states none, and adding one was declined.
- **Any capacity, throughput or availability figure.** The stream default of 256
  is a default, not a measurement.

## 7. What this seal is not

It is not a certification, an audit, an assurance report, or evidence of
external acceptance. It records that eleven named commands were run on one
machine on one date and what they printed. Three of those gates check prose
against a claims register, which constrains what this repository *says* — not
what it *does* in any deployment.

---

**Related:** [State Manifest](STATE_MANIFEST.md) · [Claims Matrix](docs/CLAIMS_MATRIX.md) · [Release Status](docs/RELEASE_STATUS.md) · [Commercial Readiness](docs/commercial/COMMERCIAL_READINESS.md) · [Release Epistemic Statement](docs/RELEASE_EPISTEMIC_STATEMENT.md)
