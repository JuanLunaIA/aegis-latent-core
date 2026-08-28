# Documentation Index

**Last verified:** 2026-08-27 UTC
**Release baseline:** checked-out source baseline/release target `v4.0.2` with 14 synchronized anchors, plus historical external observations
**Source baseline:** `4.0.2` with fourteen synchronized anchors; immutable parent comparison `fdace8844568eb788216740b2cb5daf187d99d3b` has fourteen `4.0.0` anchors
**External state:** signed annotated `v4.0.2` targets `a6eb58dcc03f8b638c8f3e35f0300f5443a926ca`; GitHub Release and GHCR gateway/dashboard readbacks passed on 2026-08-28; PyPI/npm remain at observed `4.0.0` because their trusted-publishing jobs were skipped

This directory distinguishes the current **`4.0.2` source baseline** from historical external observations and the independently verified release objects. The signed tag, GitHub Release asset envelope, GHCR multi-architecture manifests, GitHub attestations, and keyless OCI signatures were read back successfully. PyPI/npm were not published by the dispatched workflows because the repository trusted-publishing enablement variable was not readable and the publish jobs were skipped; their observed public version remains `4.0.0`. A source version, successful repository checks, or a GitHub Release does not establish package-index upload, deployment acceptance, production service level, or compliance result.

## Start here

| Reader | Primary document | Purpose |
|---|---|---|
| Developer | [`DEVELOPER_QUICKSTART.md`](DEVELOPER_QUICKSTART.md) | Install directly from the clone, run an offline first test, launch the real gateway entry point, and work on SDK or Rust sources. |
| Platform operator | [`PLATFORM_OPERATOR_GUIDE.md`](PLATFORM_OPERATOR_GUIDE.md) | Evaluate deployment dependencies, failure semantics, evidence preservation, and target-specific acceptance work. |
| Architecture reviewer | [`architecture/ARCHITECTURE.md`](architecture/ARCHITECTURE.md) | Review request flow, evidence boundaries, trust boundaries, and topology limits. |
| Claim reviewer | [`CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md) | Determine permitted claim status, evidence locators, and falsification boundaries. |
| Release or evidence reviewer | [`../evidence/INDEX.md`](../evidence/INDEX.md) | Distinguish historical v3.1.0 evidence from v4 source-readiness records and verify available sidecars. |

## Baseline rule

Use **source baseline** for statements about code and tests in the checked-out `v4.0.2` source baseline. Use **verified external object** only for the named signed tag, GitHub Release assets, and GHCR objects recorded in the release report. Use **historical baseline** only for statements tied to named immutable revisions or artifacts. Never transfer a historical benchmark or security result to the checked-out source baseline without a rerun, and never infer PyPI/npm publication from the GitHub Release or source metadata.

## Technical references

- [`REPOSITORY_MAP.md`](REPOSITORY_MAP.md) maps runtime, SDK, Rust, dashboard, test, and evidence paths.
- [`api/MMR_PROOF_V1.md`](api/MMR_PROOF_V1.md) defines the portable MMR inclusion-proof contract.
- [`RUST_BUILD.md`](RUST_BUILD.md) distinguishes the Rust source directory, Cargo crate, Python distribution, and Python import module.
- [`ROADMAP.md`](ROADMAP.md) distinguishes implemented source work, bounded measurements, deployment-dependent work, and open work.
- [`institutional/DOCUMENT_CONTROL.md`](institutional/DOCUMENT_CONTROL.md) defines document authority, review states, and publication blocks.

## Publication boundary

Repository documentation and evidence are review material. They do not by themselves authorize or prove an external `v4.0.2` tag, GitHub Release, PyPI/npm/OCI publication, production deployment, operational SLO, certification, conformity, legal admissibility, or customer acceptance. Publication may be claimed only after successful external readback.

## Related documents

- [`README.md`](../README.md)
- [`CHANGELOG.md`](../CHANGELOG.md)
- [`CONTRIBUTING.md`](../CONTRIBUTING.md)
- [`DEPLOYMENT_GUIDE.md`](../DEPLOYMENT_GUIDE.md)
- [`evidence/INDEX.md`](../evidence/INDEX.md)
