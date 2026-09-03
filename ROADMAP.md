# Roadmap

**Audience:** evaluators, contributors, procurement.
**Scope:** what is not built yet, stated in future tense.
**Boundary:** every item here is `ROADMAP` in [Claims Matrix](docs/CLAIMS_MATRIX.md) terms. None of it exists today, none of it is promised on a date, and none of it should be relied on for a purchasing or deployment decision.

This is the summary. The detailed engineering register, including completed work and open acceptance items, is [docs/ROADMAP.md](docs/ROADMAP.md).

---

## How to read this

No dates. This project does not have a staffed delivery schedule, so a date would be an invention. Items are ordered by how much they would change an evaluator's assessment, not by expected completion.

An item leaves this document only when it is implemented, tested, and carries a [Claims Matrix](docs/CLAIMS_MATRIX.md) row with an evidence locator. Until then it stays here regardless of how far along the work is.

---

## Distribution and provenance

**Registry publication automation.** SDK publication to PyPI and npm currently lags the source baseline: the source is at `4.1.1`, the registries carry `4.0.0`. The publication workflows exist and are dispatch-only, but the path from a signed tag to a confirmed registry object is not automated end to end, and it is not verified by readback as part of the release. Closing this means a release either publishes and confirms, or fails.

**Consumer-side provenance verification.** Release artifacts carry attestations and `SHA256SUMS`, and OCI images carry cosign signatures. There is no single documented command that verifies an installed SDK back to a signed tag. See [Release Status](docs/RELEASE_STATUS.md) for what verification is possible today.

## Evidence and storage

**Durable WAL backend options.** The authoritative store is a single-writer JSONL WAL on local storage. Cross-replica ordering does not exist; each replica produces an independently verifiable bundle. Options under consideration are a centralized writer, a compare-and-append storage provider with a chain-head guard, or a consensus-backed log. None is implemented. The current limitation is described in [DOC-01 §8](docs/institutional/DOC-01_ENTERPRISE_ARCHITECTURE.md).

**Cross-restart MMR continuity — closed for the JSONL WAL.** This entry previously stated that replay reconstructed the stored node deque without replaying leaves into the in-memory Merkle Mountain Range, so roots restarted from a fresh accumulator. That is not what the code does: `_load_from_wal` replays every leaf hash through `add_leaf_hash`, and `tests/test_mmr_restart.py` asserts that a reopened ledger's root equals an uninterrupted ledger's root at every shape of tree, that proofs issued after a restart verify against the live root, and that repeated restarts do not drift.

What remains open is narrower than the old entry implied: continuity across *replicas* (each is an independent chain, see **Durable WAL backend options** above), and continuity of the auxiliary `RustWal` mmap segment, which is not the authoritative store.

**External anchoring.** RFC 3161 timestamping and an S3 Object Lock adapter exist as configuration-dependent paths. Neither is an external immutability guarantee, and no anchoring is enabled by default.

## Platform and operations

**OCI images and attestation coverage.** Images are published and signed. Reproducible-build verification, a documented consumer verification path, and multi-architecture coverage beyond the current set remain open.

**OpenTelemetry.** Tracing hooks exist behind an optional dependency. A documented, tested span model across the request and evidence lifecycle does not.

**Published benchmarks.** Local measurements exist for background-dispatch latency, native MMR operations, and an injected-`fsync` backpressure scenario. There is no published benchmark for a target deployment under representative load, and no capacity claim of any kind. See [Benchmark Method](docs/benchmarks/BENCHMARK_METHOD.md).

## Integrations

**Framework integrations.** The gateway is OpenAI-compatible and the SDKs cover OpenAI and Anthropic surfaces exercised by their tests. Direct integrations for orchestration frameworks are not implemented.

**Additional provider surfaces.** Provider compatibility is bounded by what the SDK tests exercise. Extending it means extending the tests first.

## Documentation and assurance

**Documentation automation.** Four gates run in CI. Automated cross-checking of prose claims against the claims register is partial: `scripts/verify_claims.py` verifies register coherence and reference integrity, not whether an arbitrary English sentence overstates its row.

**Enterprise assurance evidence pack.** No independent audit, penetration test, or certification exists. What a pack would need to contain, and in what order, is set out in [Assurance Roadmap](docs/assurance/ASSURANCE_ROADMAP.md). Publishing that document is not the same as having the evidence.

---

## What is deliberately not on this roadmap

Naming these is more useful than leaving them ambiguous:

- **Certification of any kind.** SOC 2, ISO 27001, HIPAA attestation, FedRAMP. These require an independent assessor and an operating organisation, not a code change.
- **Legal admissibility.** Not a feature. A determination made by a court applying its own rules.
- **Guaranteed prompt-injection prevention.** An open research problem. The gateway records and constrains; it does not certify a model cannot be manipulated.
- **Universal PII removal.** Redaction is deterministic pattern matching. See [PII Redaction Boundaries](docs/privacy/PII_REDACTION_BOUNDARIES.md).
- **A production SLO.** Requires a named topology, an agreed denominator, measurement, and a contract.

---

**Related:** [docs/ROADMAP.md](docs/ROADMAP.md) — detailed engineering register · [Claims Matrix](docs/CLAIMS_MATRIX.md) · [Boundaries](docs/BOUNDARIES.md) · [Unsupported Claims](docs/institutional/UNSUPPORTED_CLAIMS.md) · [Assurance Roadmap](docs/assurance/ASSURANCE_ROADMAP.md)
