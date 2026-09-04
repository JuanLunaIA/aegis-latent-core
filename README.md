# Aegis Latent Core

**AI Governance and Cryptographic Evidence Gateway**

Aegis sits between your application and your model provider. For every governed call it applies policy, forwards the request, and commits a signed, hash-linked evidence record **before the response reaches your caller** — together with a portable inclusion proof a third party can verify without trusting the gateway that produced it. It is self-hosted: you hold your evidence, your keys, and your data.

[![CI](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/ci.yml/badge.svg)](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/ci.yml)
[![Security](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/security.yml/badge.svg)](https://github.com/JuanLunaIA/aegis-latent-core/actions/workflows/security.yml)
[![Formal verification](https://img.shields.io/badge/formal-Z3%20%7C%20Lean%204%20%7C%20TLA%2B%20%7C%20Kani-informational)](docs/formal/FORMAL_VERIFICATION.md)
[![Coverage](https://img.shields.io/badge/statement%20coverage-93.91%25%20(2026--08--18)-informational)](docs/benchmarks/BENCHMARK_METHOD.md)
[![License](https://img.shields.io/badge/license-AGPLv3%20or%20Commercial-blue)](LICENSE)

> **Current release:** `v4.1.2`, read back on 2026-09-04 — signed annotated tag, GitHub Release with 31 assets, PyPI `aegis-latent-core` `4.1.2`, PyPI `aegis-latent-sdk` `4.1.2`, npm `aegis-latent-sdk` `4.1.2`, and GHCR gateway and dashboard images. **`4.1.2` is the first version installable from PyPI as `aegis-latent-core`**; before it the gateway came from source or GHCR only. The npm version list skips `4.1.1`, whose publish step failed. A `v4.1.0` release object also exists but was created outside the pipeline and carries no assets; ignore it. The two PyPI gateway artifacts are byte-different from the release assets of the same name — same content, different build host — so `SHA256SUMS` does not cover the PyPI downloads. See [Release Status](docs/RELEASE_STATUS.md) for provenance and readback.

---

## Why Aegis

- **Evidence before emission.** For an admitted non-streaming call the record is durable before your caller can observe the response. A record that might not exist is not evidence.
- **Verifiable without trusting us.** Each record is a leaf in a Merkle Mountain Range. A portable inclusion proof lets a third party verify a disclosed record against a root they obtained independently.
- **You keep custody.** Self-hosted. The licensor holds no evidence, no keys, no payloads, and has no access to your deployment.
- **Provider independence.** An OpenAI-compatible surface; your upstream is a configured endpoint, not a lock-in.
- **Fail-closed by default.** No signer, no distributed limiter, no durable storage means no service — rather than quietly serving unevidenced traffic.
- **A broken chain stops traffic.** If WAL replay cannot read the ledger back, governed endpoints refuse with `503` before forwarding or committing. Appending onto a prefix you failed to replay produces records that each verify individually while the chain as a whole is unrecoverable — the failure the evidence contract exists to prevent.
- **Claims you can check.** Every public claim carries an evidence locator and a stated boundary in [Claims Matrix](docs/CLAIMS_MATRIX.md), and CI rejects unsupported assurance language.

---

## How it works

```
 client                    Aegis                         provider
   │                         │                               │
   │─ request ──────────────►│                               │
   │                    admission: auth, scope, bounds,       │
   │                    WAF, rate limit                       │
   │                         │── forward ───────────────────►│
   │                         │◄──────────────── response ────│
   │                    redact → sign → write → fsync         │
   │◄─ response ─────────────│  (only after the commit)      │
```

**Non-streaming.** The evidence record is committed before the response is observable. The response carries `X-Aegis-Evidence-Status`, `X-Aegis-Request-ID` and the MMR proof headers.

**Streaming.** Sanitized events are emitted incrementally through a bounded, byte-accounted queue while evidence status reads `pending-terminal`. One exact-byte terminal summary is committed, and only then is the terminal marker emitted. If that commit fails, the marker is withheld — a client that treats connection close as success will accept an unevidenced stream, so check for the marker.

**Refused requests are evidence too.** When the WAF blocks or a quota is exceeded, the refusal is committed to the same signed chain before the error is returned, and the response carries `X-Aegis-Rejection-ID` and `X-Aegis-Evidence-Status: durable-rejection`. The request body is hashed, never stored. A refusal is never conditional on the commit succeeding: if evidence cannot be written the request is still refused, and the header reads `rejection-uncommitted` rather than implying a durability that was not achieved.

Details: [Architecture](docs/architecture/ARCHITECTURE.md) · [Failure Semantics](docs/architecture/FAILURE_SEMANTICS.md)

---

## Two deployment shapes

The same controls — WAF, redaction, signed Merkle ledger, portable proofs — run in either of two places. Records from both verify with the same tooling.

**Gateway.** A separate process the application cannot bypass. This is the right shape when the boundary is organisational: several teams or languages, one enforcement point.

```bash
aegis     # or aegis-server
```

**Embedded.** The same controls inside a process that already holds a provider client and cannot add a network hop — a Lambda handler, a batch job:

```python
import aegis, openai

client = aegis.wrap(openai.OpenAI())          # or anthropic.Anthropic(), sync or async
reply = client.chat.completions.create(model="gpt-4o", messages=[...])
reply._aegis_evidence.node_hash               # signed, chained, proof-carrying
```

`wrap` recognises a client by shape, so neither provider SDK is a dependency of this package. Blocked prompts raise `AegisBlockedError` and are never dispatched. Streaming is redacted within a bounded holdback, and the terminal record is committed before the final chunk is yielded.

**The difference that matters for a threat model.** The gateway is a process the application cannot bypass. The embedded engine runs *inside* the application, so it constrains calls made through the client it wrapped and nothing else — code in the same process can call the provider directly, hold a second unwrapped client, or edit the WAL. It is an evidence and policy layer for cooperative code, not a containment boundary against the process it runs in. Where the application is itself the thing being constrained, use the gateway.

Details: [`aegis/embedded.py`](aegis/embedded.py)

---

## Agent-to-agent receipts

When one agent calls another's tool, a receipt lets the caller show a third party that the execution was recorded — without either side disclosing the arguments or the result, which travel only as SHA-256 digests.

```python
from aegis.core.a2a import generate_receipt, verify_receipt

receipt = generate_receipt(ledger, caller_agent_id="planner", target_agent_id="research",
                           tool_name="web.query", input_bytes=args, output_bytes=result)
verify_receipt(receipt, trusted_root)   # also in both SDKs
```

A valid receipt establishes that the execution's canonical envelope is included under the root you supplied — and nothing else. It does not establish that the tool ran, that either agent identifier is authentic, that the caller was authorised, or that the timestamp is accurate; that is the issuer's unattested clock. The root must be obtained independently of whoever handed you the receipt.

Details: [`aegis/core/a2a.py`](aegis/core/a2a.py)

---

## Quickstart

### Install

Three channels, because they install different things:

```bash
pip install aegis-latent-core     # the engine: aegis.wrap(), plus the aegis / aegis-server CLIs
pip install aegis-latent-sdk      # the verifier: check a proof you were handed
npm  install aegis-latent-sdk     # the same verifier, in TypeScript
```

`aegis-latent-core` carries both deployment shapes — importing `aegis.wrap` for
embedded use and the `aegis` / `aegis-server` console scripts for the gateway —
so the choice between them is a deployment decision, not a different package.
For the gateway as a container, see [Deployment Profiles](docs/operations/DEPLOYMENT_PROFILES.md):

```bash
docker pull ghcr.io/juanlunaia/aegis-latent-core:4.1.2
```

The published wheel is `py3-none-any`: **the complete feature set runs on pure
Python**, with no compiler and no native dependency. The `aegis_rust` extension
is an optional accelerator, is not part of this wheel, and is not on any
registry — it is built from source or taken from the platform wheels attached to
the [GitHub Release](https://github.com/JuanLunaIA/aegis-latent-core/releases).
What it buys, measured rather than estimated, is in [Verified metrics](#verified-metrics)
and [Rust build](docs/RUST_BUILD.md); evidence produced with and without it
verifies identically, because both paths agree on the MMR root.

Verify what you installed before relying on it — a version on a registry is not
provenance. [Release Status §2](docs/RELEASE_STATUS.md) has the readback
commands and the digests observed on 2026-09-04.

Worked examples for every mode, with the output they actually produce, are in
[Usage Examples](docs/USAGE_EXAMPLES.md).

### From source

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m pip install --no-deps -e .
pytest -q
```

For isolated local evaluation, against a mock upstream:

```bash
export AEGIS_SECURITY_ENFORCEMENT_MODE=development
export AEGIS_DEBUG_MODE=true
export AEGIS_AUTH_DISABLED=true
export AEGIS_BACKEND_URL=http://127.0.0.1:9999
aegis
```

Development mode disables the controls that make records meaningful. It is for reading the API, not for evaluating security. Use [single-node hardened](docs/operations/DEPLOYMENT_PROFILES.md#2-single-node-hardened) for anything you intend to conclude from.

### With Docker Compose

```bash
docker compose up --build
```

The root `docker-compose.yml` runs an evaluation profile bound to `127.0.0.1` with in-memory rate limiting. It is not a governed deployment; see [Deployment Profiles](docs/operations/DEPLOYMENT_PROFILES.md).

### A governed call

```bash
curl -sS http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'x-session-id: demo-session' \
  -d '{"messages":[{"role":"user","content":"Hello, Aegis."}]}'
```

### Inspect the evidence headers

```bash
curl -sS -D - -o /dev/null http://127.0.0.1:8080/v1/chat/completions \
  -H 'Content-Type: application/json' \
  -H 'x-session-id: demo-session' \
  -d '{"messages":[{"role":"user","content":"Hello, Aegis."}]}' \
  | grep -i '^x-aegis'
```

Expect `X-Aegis-Evidence-Status`, `X-Aegis-Request-ID`, `X-Aegis-Proof-Status`, and the `X-Aegis-MMR-*` proof headers.

More: [Developer Quickstart](docs/DEVELOPER_QUICKSTART.md)

---

## SDKs

Python and TypeScript SDKs provide gateway configuration, OpenAI and Anthropic integration, and portable-proof verification.

```bash
# Python, from the source tree
pip install -e ./sdk/python

# TypeScript, from the source tree
cd sdk/typescript && npm ci && npm run build
```

**Registry caution.** PyPI carries `aegis-latent-sdk` at `4.1.2`, matching this source tree. **npm still carries `4.0.0`** — installing the SDK from npm gets you different code from what these documents describe. Check which registry you are installing from.

**Proof verification caution.** A proof verified against a root supplied by the same gateway that produced it establishes internal consistency only. Obtain the trusted root through an independent channel, or the verification is circular.

[Integrations Guide](docs/DEVELOPER_INTEGRATIONS_GUIDE.md) · [SDK Guide](docs/DEVELOPER_SDK_GUIDE.md) · [MMR Proof v1](docs/api/MMR_PROOF_V1.md)

---

## Dashboard

A Next.js read-only forensic view over the audit API: ledger window, integrity, MMR proof verification in the browser, current metrics, and bounded evidence export. It renders explicit empty and unavailable states rather than synthesising records.

There is no hosted dashboard. You run it, and browser-facing authentication is your responsibility.

[Setup and boundaries](dashboard/README.md)

---

## Security and evidence model

- Authenticated principals derived from the credential, never from a client-supplied header; scopes gate audit reads and exports separately.
- Hash-linked, signed records with tamper detection on read; one writer per WAL path, enforced by an advisory lock.
- A ledger that failed to replay refuses governed traffic at ingress; `/health` and `/metrics` stay reachable so the fault is diagnosable rather than silent.
- Bounded requests and streams; deterministic pattern-based redaction before the record is written.
- **Tampering is detected, not prevented.** An operator with filesystem access can alter or delete records. Every integrity claim terminates at that boundary.
- **Redaction protects the record, not your provider.** The request reaches them as sent.

[SECURITY.md](SECURITY.md) · [Threat Model](docs/security/THREAT_MODEL.md) · [Security Controls](docs/security/SECURITY_CONTROLS.md) · [Storage Requirements](docs/operations/STORAGE_REQUIREMENTS.md) · [Boundaries](docs/BOUNDARIES.md)

---

## Formal verification

Bounded models under `specs/` check core invariants in CI: commit-before-emission, append-only ledger prefixes, session-to-ledger binding, and per-stream retained-byte arithmetic. The toolchain is Z3, Lean 4, and TLA+/TLC, gated by `scripts/verify_formal_artifacts.sh`.

**These are abstractions, not runtimes.** Nothing mechanically connects a model to the Python or Rust that executes, and the state spaces are bounded. The models can be correct while the implementation is wrong.

Separately, Kani 0.67.0 model-checks the native WAL's frame-bounds arithmetic over the whole `usize` domain. Those five harnesses run against the **real functions** rather than an abstraction, so the refinement gap above does not apply to them — but they cover two functions, not a system. Kani models no `mmap`, no filesystem and no concurrency, so nothing there establishes durability or crash safety.

[Formal Verification](docs/formal/FORMAL_VERIFICATION.md) · [Limits](docs/formal/FORMAL_VERIFICATION_LIMITS.md)

---

## Compliance contributions

| Framework | Technical contribution |
| --- | --- |
| EU AI Act, Article 12 | Per-call records with tamper detection and third-party-verifiable proofs, as an input to a record-keeping assessment |
| HIPAA | Deterministic pattern-based redaction targeting textual forms associated with Safe Harbor identifier categories |
| MiFID II | Durable, ordered-within-process records of governed AI interactions, as a record-keeping helper |
| ISO/IEC 27037 | Bounded, integrity-verifiable extracts a practitioner may handle as digital evidence |

**These are technical inputs, not compliance.** No certification exists, none is in progress, and whether any obligation is met is a determination for you and your assessor.

[Compliance Mapping](docs/compliance/COMPLIANCE_MAPPING.md)

---

## Verified metrics

| Measure | Value | Artifact | Date |
| --- | --- | --- | --- |
| Statement coverage | 93.9096% (11,765 / 12,528) | `coverage.json` | 2026-08-18 |
| Statement coverage | 89.7169% | Candidate gate record | 2026-08-24 |
| Python suite | 5,707 passed, 37 skipped | Candidate gate record | 2026-08-24 |
| Python suite | 5,661 passed, 81 skipped, 0 failed | Clean-container reproduction | 2026-09-01 |
| Python suite | 5,974 passed, 52 skipped, 0 failed | `4.1.2` source baseline | 2026-09-03 |
| Rust extension | 31 tests passed; Clippy `-D warnings`; abi3 wheel built | CI | Per run |
| Static analysis | `mypy --strict` 0 errors over 186 files; Bandit 0 findings at every severity | CI | Per run |
| Model checking | 5 Kani harnesses verified, 0 failures, over the whole `usize` domain | CI | Per run |
| Per-commit cost vs chain length | At 2,000 prior leaves: 30,153.9 → 361.7 µs/commit. Normalised, the prior curve rises `1.00× → 17.65×` with chain length; the current one is flat within noise | [`commit_scaling_measurement`](evidence/commit_scaling_measurement_2026-09-03.md) | 2026-09-03 |
| MMR append, Rust vs Python | At 100,000 leaves: 775.76k vs 156.90k leaves/s (4.94×) | [`evidence_path_measurements`](evidence/evidence_path_measurements_2026-09-03.md) | 2026-09-03 |
| WAF corpus | Zero observed bypasses, zero false positives over 15 malicious and 8 benign cases | Corpus report | Per corpus |
| Backpressure | 2,500 offered → 2,500 durable, zero missing or duplicate IDs, p99 commit 836.35 ms under 2 ms injected `fsync` delay | Stall report | 2026-08-20 |

Two coverage figures appear because two runs measured differently on different dates; both are recorded rather than one being selected. Suite counts move as tests are added — run `pytest -q` on the commit you are evaluating.

**None of this is a capacity claim.** Offered load is not accepted throughput. The absolute latencies above are properties of one shared, unpinned four-CPU container; what transfers is the *shape* — that per-commit cost stopped growing with chain length — not the numbers. Re-run the harnesses in your own environment before planning against any of them.

**A clean static-analysis run is not a correctness result.** `mypy --strict` and Bandit reporting zero says those two checkers found nothing on this source, which is weaker than an absence of defects or of vulnerabilities.

[Evidence Index](evidence/INDEX.md) · [Benchmark Method](docs/benchmarks/BENCHMARK_METHOD.md)

---

## Roadmap

Not built. No dates.

- Registry publication automation, so a release either publishes and confirms or fails
- Durable WAL backend options, and MMR continuity across replicas rather than only across restarts
- Wider OCI attestation coverage and a documented consumer verification path
- Framework integrations beyond the current provider surfaces
- OpenTelemetry span model across the evidence lifecycle
- Published benchmarks for a representative target deployment
- An enterprise assurance evidence pack

[ROADMAP.md](ROADMAP.md)

---

## Community and governance

| | |
| --- | --- |
| Issues and questions | [Issues](https://github.com/JuanLunaIA/aegis-latent-core/issues) · [Discussions](https://github.com/JuanLunaIA/aegis-latent-core/discussions) · [SUPPORT.md](SUPPORT.md) |
| Security reports | Privately, never in an issue — [SECURITY.md](SECURITY.md) |
| Contributing | [CONTRIBUTING.md](CONTRIBUTING.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) |
| How decisions are made | [GOVERNANCE.md](GOVERNANCE.md) |
| Licence | AGPLv3 **or** commercial — [LICENSE](LICENSE) · [COMMERCIAL.md](COMMERCIAL.md) |

Support is community best-effort with no SLA. This is a single-maintainer project; weigh that in any adoption decision. See [Support Model](docs/enterprise/SUPPORT_MODEL.md).

---

## Boundaries and limitations

- **No certification.** No SOC 2, ISO 27001, HIPAA attestation, or FedRAMP. None in progress.
- **No independent assurance.** No third-party audit or penetration test exists.
- **No compliance determination.** The system produces technical inputs; you and your assessor decide.
- **No legal admissibility.** Admissibility is a judicial determination, and no chain of custody is created.
- **Not immutable.** Tampering is detected, not prevented; an operator with root can alter records.
- **No universal PII removal.** Deterministic pattern matching over specific fields; it does not protect data already sent upstream.
- **No production SLO or capacity claim.** Benchmarks are local measurements.
- **No cross-replica global ordering.** Each replica is an independent chain.
- **No guaranteed prompt-injection prevention.** Bounded heuristic detection; the record is the product.

Full statements: [Boundaries](docs/BOUNDARIES.md) · [Claims Matrix](docs/CLAIMS_MATRIX.md) · [Unsupported Claims](docs/institutional/UNSUPPORTED_CLAIMS.md)

---

<sub>Copyright © 2026 Juan Luna. Licensed under AGPLv3 or a commercial agreement. Full documentation index: <a href="docs/INDEX.md">docs/INDEX.md</a></sub>
