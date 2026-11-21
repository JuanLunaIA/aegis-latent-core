# Documentation Index

**Last verified:** 2026-11-21 UTC — all targets re-checked against the checked-out tree
**Release baseline:** checked-out source baseline `v5.1.0` with 14 synchronized anchors — published release under Aegis Commercial License 1.0
**Most recent published release:** `v5.1.0`, published 2026-11-19 on every surface (PyPI, npm, GHCR) — read back confirmed in `docs/RELEASE_STATUS.md` §1.0f

---

## Start here

| Reader | Primary document | Purpose |
|---|---|---|
| Developer | [`DEVELOPER_QUICKSTART.md`](DEVELOPER_QUICKSTART.md) | Install from a registry or directly from the clone, run an offline first test, launch the real gateway entry point, and work on SDK or Rust sources. |
| Developer | [`USAGE_EXAMPLES.md`](USAGE_EXAMPLES.md) | Worked examples for embedded and gateway modes, streaming, blocked requests and proof verification, each with the output it actually produced. |
| Platform operator | [`PLATFORM_OPERATOR_GUIDE.md`](PLATFORM_OPERATOR_GUIDE.md) | Evaluate deployment dependencies, failure semantics, evidence preservation, and target-specific acceptance work. |
| Architecture reviewer | [`architecture/ARCHITECTURE.md`](architecture/ARCHITECTURE.md) | Review request flow, evidence boundaries, trust boundaries, and topology limits. |
| Claim reviewer | [`CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md) | Determine permitted claim status, evidence locators, and falsification boundaries. |
| Release or evidence reviewer | [`../evidence/INDEX.md`](../evidence/INDEX.md) | Distinguish historical v3.1.0 evidence from v4 source-readiness records and verify available sidecars. |

## Baseline rule

Use **source baseline** for statements about code and tests in the checked-out `v5.1.0` source baseline. Use **verified external object** only for the named signed tag, GitHub Release assets, and GHCR objects recorded in the release report. Use **historical baseline** only for statements tied to named immutable revisions or artifacts. Never transfer a historical benchmark or security result to the checked-out source baseline without a rerun, and never infer PyPI/npm publication from the GitHub Release or source metadata.

## Technical references

- [`REPOSITORY_MAP.md`](REPOSITORY_MAP.md) maps runtime, SDK, Rust, dashboard, test, and evidence paths.
- [`api/MMR_PROOF_V1.md`](api/MMR_PROOF_V1.md) defines the portable MMR inclusion-proof contract.
- [`RUST_BUILD.md`](RUST_BUILD.md) distinguishes the Rust source directory, Cargo crate, Python distribution, and Python import module.
- [`ROADMAP.md`](ROADMAP.md) distinguishes implemented source work, bounded measurements, deployment-dependent work, and open work.
- [`institutional/DOCUMENT_CONTROL.md`](institutional/DOCUMENT_CONTROL.md) defines document authority, review states, and publication blocks.

## Publication boundary

Repository documentation and evidence are review material. They do not by themselves authorize or prove an external tag, GitHub Release, PyPI/npm/OCI publication, production deployment, operational SLO, certification, conformity, legal admissibility, or customer acceptance. Publication may be claimed only after successful external readback.

## Related documents

- [`README.md`](../README.md)
- [`CHANGELOG.md`](../CHANGELOG.md)
- [`CONTRIBUTING.md`](../CONTRIBUTING.md)
- [`DEPLOYMENT_GUIDE.md`](../DEPLOYMENT_GUIDE.md)
- [`evidence/INDEX.md`](../evidence/INDEX.md)