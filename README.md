# Aegis Latent Core

**AI Governance and Cryptographic Evidence Gateway**

**Aegis Latent Core commits signed, hash-linked evidence of every governed AI call — before the response reaches the caller — and issues a portable proof that a third party verifies without trusting the gateway, us, or you.**

[![source](https://img.shields.io/badge/source-v5.0.1-blue)](docs/RELEASE_STATUS.md)
[![CI](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/ci.yml/badge.svg)](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/ci.yml)
[![Security](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/security.yml/badge.svg)](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/security.yml)
[![coverage](https://img.shields.io/badge/coverage-91.30%25_(2026--09--24)-green)](#real-world-benchmarks)
[![License](https://img.shields.io/badge/license-AGPLv3%20or%20Commercial-blue)](LICENSE)

Every load-bearing claim in this file carries a locator and a stated boundary; the gates that enforce that discipline run in CI.

> **Current release:** `v5.0.0` — published 2026-09-16 on every surface except PyPI `aegis-latent-core`; the signed tag, the GitHub Release and its 31 assets, PyPI `aegis-latent-sdk`, npm `aegis-latent-sdk` and both GHCR images were read back ([Release Status](docs/RELEASE_STATUS.md) §1.0).
> **Current release candidate:** `v5.0.1`, fourteen synchronized anchors — **published nowhere**: read back 2026-09-21, no tag, no GitHub Release, no OCI tag and no registry version exists for it ([Release Status](docs/RELEASE_STATUS.md) §1.0a). **The gateway distribution `aegis-latent-core` was not published at `5.0.0`** — `pip install aegis-latent-core` still gets `4.1.2`. There is no `4.2.0`; the number was skipped.
>
> **Most recent published release:** `v4.1.2`, read back on 2026-09-04 — signed annotated tag, GitHub Release with 31 assets, PyPI `aegis-latent-core` `4.1.2`, PyPI `aegis-latent-sdk` `4.1.2`, npm `aegis-latent-sdk` `4.1.2`, and GHCR gateway and dashboard images. **`4.1.2` is the first version installable from PyPI as `aegis-latent-core`**; before it the gateway came from source or GHCR only. The npm version list skips `4.1.1`, whose publish step failed. A `v4.1.0` release object also exists but was created outside the pipeline and carries no assets; ignore it. The two PyPI gateway artifacts are byte-different from the release assets of the same name — same content, different build host — so `SHA256SUMS` does not cover the PyPI downloads. See [Release Status](docs/RELEASE_STATUS.md) for provenance and readback.

---

## The problem

Your AI decisions are logged to a database your administrators can edit. When someone asks what the model was told six months ago, you answer from records the interested party could have changed.

In a regulated industry that is not a paperwork problem — it is an existential one. The regulator, the court and the auditor each ask the same question, and "our logs are probably fine" is not an answer they accept:

1. **A record the interested party could have altered is not evidence** — it only reads as evidence until someone with a reason to doubt it asks one question.
2. **You already owe someone a record you can stand behind** — EU AI Act Art. 12, HIPAA audit controls, SEC 17a-4's audit-trail alternative, MiFID II. Those are your obligations; this software is an input to them, never a discharge of them.
3. **The fix has to be checkable by someone who distrusts you**, or it is the same problem wearing better clothes.

## The Aegis solution

- **Append-only, tamper-evident MMR.** Every record is a leaf in a Merkle Mountain Range. A portable inclusion proof (O(log n), no zero-knowledge claim) lets a third party verify a disclosed record against a root they obtained independently. `verify_integrity()` detects tampering on read; tampering is *detected, not prevented* — see the boundaries below.
- **Cryptographic sealing.** Each record is hashed into a chain link and signed — HMAC by default, Ed25519 (RFC 8032) or ML-DSA-65 (FIPS 204) where configured, with an HSM path in the enterprise server. Optional per-subject shredding (AES-256-GCM key destruction) erases plaintext from a ciphertext holder's view *without changing the MMR root or previously issued proofs*.
- **Zero-trust verification.** Proofs verify offline: a 313-line pure-Python verifier, a TypeScript twin with the same semantics, and zero network calls. No trust in the gateway, the vendor, or the operator who discloses the record — only in a root you obtained through a channel the discloser does not control.
- **Regulatory inputs.** MiFID II Art. 16(6)/16(7) and MiFIR Art. 25(1) record-keeping framing (durable, ordered-within-process records; no orders — RTS 24 — and no clock traceability — RTS 25); EU AI Act Art. 12 logging inputs (commit-before-response, tamper detection, verifiable inclusion); HIPAA Safe-Harbor-style pattern redaction; ISO/IEC 27037-style extracts. **These are technical inputs, not compliance.** No certification exists, none is in progress, and whether any obligation is met is a determination for you and your assessor (`CLM-039` is LEGAL-REVIEW-REQUIRED).

> **→ [Prove it yourself](docs/PROVE_IT.md)** — twelve lines of Python, no call to our servers, three cases of which two must fail.

---

## Architecture at a glance

```
 caller ──────────►  Aegis gateway  ──────────────────────────►  upstream provider
                        │  admission: auth · scope · bounds
                        │  WAF · rate limiting · session checks
                        │
                        │  (policy passed) forward
                        │  ◄─────────────── response ─────────
                        │
                        │  redact → hash → sign → WAL append + fsync → MMR leaf
                        │  (refused requests: the refusal is committed to the
                        │   same signed chain before the error returns)
                        │
 caller ◄──────────  response + X-Aegis-Evidence-Status
                        + X-Aegis-Request-ID + X-Aegis-MMR-* proof headers
```

**Non-streaming.** The evidence record is committed **before** the response is observable by the caller.

**Streaming.** Sanitized events are emitted incrementally through a bounded, byte-accounted queue while evidence status reads `pending-terminal`. One exact-byte terminal summary is committed, and only then is the terminal marker emitted. If that commit fails, the marker is withheld.

**Fail-closed.** No signer, no distributed limiter, or a ledger that fails to replay means no service — rather than quietly serving unevidenced traffic.

Details: [Architecture](docs/architecture/ARCHITECTURE.md) · [Failure Semantics](docs/architecture/FAILURE_SEMANTICS.md)

---

## Real-world benchmarks

Real measurements from the retained 2026-09-24 artifact ([`evidence/benchmarks/benchmarks_5.0.1_2026-09-24.json`](evidence/benchmarks/benchmarks_5.0.1_2026-09-24.json)), taken against real backends — a real WAL `fsync` per commit — on one shared, unpinned four-CPU `x86_64` container (Linux, CPython 3.11.15). Reproduce with `scripts/run_benchmarks_5.0.1.py --json`.

### Verified metrics

| Metric | Result (2026-09-24) | What it measures |
| --- | --- | --- |
| Commit latency (P99) | **1.22 ms** (p50 0.62 · p95 1.00 · max 4.18 ms, n = 1,000) | MMR append + HMAC sign + one real WAL `fsync`, per commit |
| Throughput | **1,727 commits/s** at 10 threads · 1,630/s at 50 · 1,482/s at 100 | One process, one WAL, one writer — does not scale with threads, by design (`AD-16`) |
| Memory | **+20.1 MB** RSS for 1,000 concurrent in-process SSE streams (20 events each) | Bounded stream ingestion, not network or durable-WAL cost |
| Backpressure (current) | p50 33.545 ms · p99 51.875 ms; 2,500 offered → 2,500 durable, zero failures | 2 ms *injected* `fsync` delay; superseded pre-group-commit run was p99 836.35 ms; the earlier 10,000-record run at p99 1,189.89 ms is retracted (`UC-018`) — no artifact in this tree produces it |
| Ed25519 sign / verify | 40.5 µs/op · 128.6 µs/op (`cryptography`, RFC 8032) | Device-order-of-magnitude timing on the recorded host |
| ML-DSA-65 sign / verify | 173.0 µs/op · 62.4 µs/op (`aegis_rust`, FIPS 204) | A latency sample only — the constant-time claim remains blocked (`REG-041`, `UC-012`) |

Measured suite (dated records; counts move as tests are added — run `pytest -q` on the commit you evaluate): 7,444 passed / 39 skipped / 0 failed (`pytest -n auto -q`) and 7,449 passed / 34 skipped / 0 failed (CI's exact serial Forensic command), both 2026-09-24 on the checked-out `5.0.1` tree. Statement coverage: **91.30%** (2026-09-24; 91.25% on a later same-day run). The floor CI enforces is **65%** (`--cov-fail-under=65`, `.github/workflows/ci.yml`); the 90% figure was a one-off mission floor, met at 90.07% on 2026-09-21 (`REG-D36`) and not enforced.

**None of this is a capacity claim.** Offered load is not accepted throughput. The absolute latencies are properties of one shared container; what transfers is the *shape* — per-commit cost stopped growing with chain length — not the numbers. Re-run the harnesses in your own environment before planning against any of them.

[Evidence Index](evidence/INDEX.md) · [Benchmark Method](docs/benchmarks/BENCHMARK_METHOD.md) · [Benchmark Record](docs/BENCHMARKS.md)

---

## Quickstart

Three steps, copy-pasteable. Honest channel note first: **`pip install aegis-latent-core` currently installs `4.1.2`** — the gateway distribution was not published at `5.0.0` (`UC-047`). For the gateway use this repository or the GHCR image `ghcr.io/juanlunaia/aegis-latent-core:5.0.0`.

**Step 1 — get the source:**

```bash
git clone https://github.com/JuanLunaIA/aegis-latent-core.git && cd aegis-latent-core
python3 -m venv .venv && . .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps -e .
```

**Step 2 — run it** (isolated local evaluation, against a mock upstream on `127.0.0.1:9999`):

```bash
export AEGIS_SECURITY_ENFORCEMENT_MODE=development
export AEGIS_DEBUG_MODE=true
export AEGIS_AUTH_DISABLED=true
export AEGIS_BACKEND_URL=http://127.0.0.1:9999
aegis
```

Development mode disables the controls that make records meaningful — it is for reading the API, not for evaluating security. For a hardened single node see [Deployment Profiles](docs/operations/DEPLOYMENT_PROFILES.md). Container alternative: `docker compose up --build` (evaluation profile, bound to `127.0.0.1`).

**Step 3 — make a governed call and read the evidence headers:**

```bash
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'x-session-id: demo-session' \
  -d '{"messages":[{"role":"user","content":"Hello, Aegis."}]}'

curl -sS -D - -o /dev/null http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'x-session-id: demo-session' \
  -d '{"messages":[{"role":"user","content":"Hello, Aegis."}]}' \
  | grep -i '^x-aegis'
```

Expect `X-Aegis-Evidence-Status`, `X-Aegis-Request-ID` and the `X-Aegis-MMR-*` proof headers; `X-Aegis-Proof-Status` is sent on streaming responses only (`pending-terminal`).

> **Known defect (`REG-D67`, open):** on a Linux host with `libseccomp` installed and outside Docker, step 2 exits with `Bad system call` about two seconds after startup — the gateway's own seccomp filter kills it when libuv calls `io_uring_enter`. Until it is fixed, `export UV_USE_IO_URING=0` before `aegis` avoids it. See [RELEASE_HALTED_CRITICAL_ERRORS.md](RELEASE_HALTED_CRITICAL_ERRORS.md).

More: [Developer Quickstart](docs/DEVELOPER_QUICKSTART.md) · [Usage Examples](docs/USAGE_EXAMPLES.md)

---

## Verification

A third party verifies a log entry **without trusting the Aegis server** — offline, from the exported bundle, against a key and root obtained out of band:

```bash
pip install "aegis-latent-sdk[verify]"
aegis-sdk verify export.zip --public-key operator-ed25519.pub.pem
```

Exit `0` only when nothing failed **and** the manifest signature verified against a key you supplied. Exit `3` (`INCOMPLETE`) means the digests are internally consistent but the signature was not checked. The same check in library form:

```python
from aegis_sdk.proof import InclusionProof, verify_inclusion_hash

proof = InclusionProof.from_mapping(record["mmr_proof"])
verify_inclusion_hash(record["mmr_leaf_hash"], proof, trusted_root)
```

Three cases, and two of them must fail:

| Case | Result |
| --- | --- |
| Genuine record against the root it belongs to | `INCLUDED` |
| **One altered byte in the record**, same proof and root | `NOT INCLUDED` |
| **Genuine record against a root you did not obtain independently** | `NOT INCLUDED` |

The third case is the one to understand first: **a root supplied by the same gateway that produced the proof establishes internal consistency and nothing more** (`CLM-044`). Getting the root by a path the discloser does not control is your design problem, and no software solves it for you. A passing verification establishes inclusion under the root you supplied — not that the response was correct, not who produced the record, and not that nothing was omitted. Full worked transcript with the failing cases: [docs/PROVE_IT.md](docs/PROVE_IT.md)

### Verify what you downloaded

Release assets carry a digest, and checking one needs no checkout and no cooperation from this project:

```
curl -fsSL -O https://github.com/juanlunaia/aegis-latent-core/releases/download/v5.0.0/SHA256SUMS
# then, for each artifact you downloaded:
curl -fsSL -O https://github.com/juanlunaia/aegis-latent-core/releases/download/v5.0.0/<artifact-name>
sha256sum -c SHA256SUMS --ignore-missing
```

Two things that snippet does not establish. It shows the bytes match the manifest; it does not show who built them — an OCI signature (`cosign verify`) and a build attestation (`gh attestation verify`) are separate checks against separate infrastructure. And it covers the **release assets only**: the PyPI wheels for `aegis-latent-core` are rebuilt from the same source on a different build host, so their bytes differ from the release assets of the same name and `SHA256SUMS` does not cover them (see [docs/RELEASE_STATUS.md](docs/RELEASE_STATUS.md)).

`python scripts/verify_release_readback.py --tag v5.0.0 --verify-assets` automates the whole readback — the GitHub Release, the `SHA256SUMS` sweep, the PyPI and npm versions, and the GHCR manifest digests — and prints `NOT_EXECUTED`, with the reason, for anything it could not check from where it ran. This block is emitted by that same tool, so the documented commands cannot drift from it.

---

## Compliance & security

- **JCS determinism.** Forensic exports are canonicalized with JSON Canonicalization Scheme (RFC 8785): a `manifest.json` over DAG-CBOR, content-addressed with CIDv1, plus a technical PDF and an embedded `VERIFY.sh`. Non-finite numbers are rejected fail-closed rather than silently normalized.
- **Domain-separated hashing.** New chains record leaves under the `aegis-mmr-inclusion-v2` scheme — RFC 6962-style domain separation, so a leaf payload cannot hash to an interior node (`CLM-064`). Existing `v1` chains keep verifying unchanged; a scheme mismatch faults instead of replaying to a different root.
- **Audit inputs.** Every claim in this repository carries an evidence locator and a stated boundary; the [Claims Matrix](docs/CLAIMS_MATRIX.md), the [Defect Registry](docs/REGISTRY.md), SBOMs, signed tags and signed images exist to serve an audit — they are inputs to audits, never a certification: **no SOC 2, no ISO 27001, no HIPAA attestation, no FedRAMP, and none in progress**.
- **Boundaries, stated once:** tampering is detected, not prevented — an operator with filesystem access can alter records. No universal PII removal; redaction protects the record, not your provider. No output validation — the gateway records what the model returned, it does not check whether it was true (`UC-068`). No cross-replica global ordering. No guaranteed prompt-injection prevention.

[SECURITY.md](SECURITY.md) · [Threat Model](docs/security/THREAT_MODEL.md) · [Compliance Mapping](docs/compliance/COMPLIANCE_MAPPING.md) · [Boundaries](docs/BOUNDARIES.md)

---

## Links

- [ROADMAP.md](docs/ROADMAP.md) — what is built, what is not, and the ticket ledger behind it.
- [REGISTRY.md](docs/REGISTRY.md) — master defect and debt registry: every finding, its state and its evidence file.
- [UNSUPPORTED_CLAIMS.md](docs/institutional/UNSUPPORTED_CLAIMS.md) — the register of what this software does **not** claim, and the phrases CI rejects.
- [RELEASE_STATUS.md](docs/RELEASE_STATUS.md) — per-surface publication state and readback commands (single source of truth).
- [CLAIMS_MATRIX.md](docs/CLAIMS_MATRIX.md) · [docs/BOUNDARIES.md](docs/BOUNDARIES.md) · [docs/INDEX.md](docs/INDEX.md)

---

<sub>Copyright © 2026 Juan Luna. Licensed under AGPLv3 or a commercial agreement. Full documentation index: <a href="docs/INDEX.md">docs/INDEX.md</a></sub>
