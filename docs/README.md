# Documentation Index

**Last verified:** 2026-08-25 UTC
**Release baseline:** two-baseline model
**Source baseline:** merged v4 source state verified by [`evidence/v4_0_0_post_merge_release_readiness_2026-08-25.md`](../evidence/v4_0_0_post_merge_release_readiness_2026-08-25.md)
**Distribution baseline:** previously published `v3.1.0` artifacts; no distribution is asserted for the source baseline

This directory documents two distinct baselines. The **source baseline** is the merged v4 tree whose version anchors and repository gates were checked in the named post-merge audit. The **distribution baseline** remains the previously published `v3.1.0` artifact set. A source version and successful repository checks do not establish a tag, release, package-index upload, container publication, deployment acceptance, production service level, or compliance result.

## Start here

| Reader | Primary document | Purpose |
|---|---|---|
| Developer | [`DEVELOPER_QUICKSTART.md`](DEVELOPER_QUICKSTART.md) | Install directly from the clone, run an offline first test, launch the real gateway entry point, and work on SDK or Rust sources. |
| Platform operator | [`PLATFORM_OPERATOR_GUIDE.md`](PLATFORM_OPERATOR_GUIDE.md) | Evaluate deployment dependencies, failure semantics, evidence preservation, and target-specific acceptance work. |
| Architecture reviewer | [`architecture/ARCHITECTURE.md`](architecture/ARCHITECTURE.md) | Review request flow, evidence boundaries, trust boundaries, and topology limits. |
| Claim reviewer | [`CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md) | Determine permitted claim status, evidence locators, and falsification boundaries. |
| Release or evidence reviewer | [`../evidence/INDEX.md`](../evidence/INDEX.md) | Distinguish historical v3.1.0 evidence from v4 source-readiness records and verify available sidecars. |

## Baseline rule

Use **source baseline** for statements about code and tests present in the merged v4 tree. Use **distribution baseline** only for statements tied to the immutable `v3.1.0` artifacts and their historical evidence. Never transfer a v3.1.0 benchmark or security result to v4 without a rerun, and never infer publication from source metadata set to `4.0.0`.

## Technical references

- [`REPOSITORY_MAP.md`](REPOSITORY_MAP.md) maps runtime, SDK, Rust, dashboard, test, and evidence paths.
- [`api/MMR_PROOF_V1.md`](api/MMR_PROOF_V1.md) defines the portable MMR inclusion-proof contract.
- [`RUST_BUILD.md`](RUST_BUILD.md) distinguishes the Rust source directory, Cargo crate, Python distribution, and Python import module.
- [`ROADMAP.md`](ROADMAP.md) distinguishes implemented source work, bounded measurements, deployment-dependent work, and open work.
- [`institutional/DOCUMENT_CONTROL.md`](institutional/DOCUMENT_CONTROL.md) defines document authority, review states, and publication blocks.

## Publication boundary

Repository documentation and evidence are review material. They do not by themselves authorize or prove a v4 tag, GitHub Release, PyPI/npm/OCI publication, production deployment, operational SLO, certification, conformity, legal admissibility, or customer acceptance. The post-merge audit records a source verification decision and an explicit publication no-go.

## Related documents

- [`README.md`](../README.md)
- [`CHANGELOG.md`](../CHANGELOG.md)
- [`CONTRIBUTING.md`](../CONTRIBUTING.md)
- [`DEPLOYMENT_GUIDE.md`](../DEPLOYMENT_GUIDE.md)
- [`evidence/INDEX.md`](../evidence/INDEX.md)
