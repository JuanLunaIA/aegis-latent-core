# Documentation Index

**Last verified:** 2026-08-27 UTC
**Release baseline:** checked-out source baseline/release target `v4.1.2` with 14 synchronized anchors, plus historical external observations
**Source baseline:** `4.1.2` with fourteen synchronized anchors; immutable parent comparison `fdace8844568eb788216740b2cb5daf187d99d3b` has fourteen `4.0.0` anchors
**External state:** `4.1.2` is published, read back 2026-09-04 — signed annotated tag at `860f14177d94c194e5ae7156017d6fa74264e429`, GitHub Release with 31 assets, PyPI `aegis-latent-core` `4.1.2`, PyPI `aegis-latent-sdk` `4.1.2`, npm `aegis-latent-sdk` `4.1.2`, GHCR gateway and dashboard images. The previous published release is signed annotated `v4.0.2` at `a6eb58dcc03f8b638c8f3e35f0300f5443a926ca`, whose GitHub Release and GHCR readbacks passed on 2026-08-28 and whose SDK publish jobs were skipped

This directory distinguishes the **`4.1.2` source baseline** from historical external observations and the independently verified release objects. `4.1.2` was published on 2026-09-03 and read back on 2026-09-04: the signed annotated tag, the GitHub Release and its 31 assets, both PyPI projects, the npm package, and both GHCR images. It is the first version at which the gateway itself is on PyPI. The npm version list skips `4.1.1`, whose publish step failed on a defect in the publish command that the `4.1.2` dispatch shows fixed. For the preceding `4.0.2` release, the signed tag, GitHub Release asset envelope, GHCR multi-architecture manifests, GitHub attestations, and keyless OCI signatures were read back successfully, while both SDK publish jobs were skipped because the trusted-publishing enablement variable was not readable. A source version, successful repository checks, or a GitHub Release does not establish package-index upload, deployment acceptance, production service level, or compliance result.

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

Use **source baseline** for statements about code and tests in the checked-out `v4.1.2` source baseline. Use **verified external object** only for the named signed tag, GitHub Release assets, and GHCR objects recorded in the release report. Use **historical baseline** only for statements tied to named immutable revisions or artifacts. Never transfer a historical benchmark or security result to the checked-out source baseline without a rerun, and never infer PyPI/npm publication from the GitHub Release or source metadata.

## Technical references

- [`REPOSITORY_MAP.md`](REPOSITORY_MAP.md) maps runtime, SDK, Rust, dashboard, test, and evidence paths.
- [`api/MMR_PROOF_V1.md`](api/MMR_PROOF_V1.md) defines the portable MMR inclusion-proof contract.
- [`RUST_BUILD.md`](RUST_BUILD.md) distinguishes the Rust source directory, Cargo crate, Python distribution, and Python import module.
- [`ROADMAP.md`](ROADMAP.md) distinguishes implemented source work, bounded measurements, deployment-dependent work, and open work.
- [`institutional/DOCUMENT_CONTROL.md`](institutional/DOCUMENT_CONTROL.md) defines document authority, review states, and publication blocks.

## Publication boundary

Repository documentation and evidence are review material. They do not by themselves authorize or prove an external `v4.1.1` tag, GitHub Release, PyPI/npm/OCI publication, production deployment, operational SLO, certification, conformity, legal admissibility, or customer acceptance. Publication may be claimed only after successful external readback.

## Related documents

- [`README.md`](../README.md)
- [`CHANGELOG.md`](../CHANGELOG.md)
- [`CONTRIBUTING.md`](../CONTRIBUTING.md)
- [`DEPLOYMENT_GUIDE.md`](../DEPLOYMENT_GUIDE.md)
- [`evidence/INDEX.md`](../evidence/INDEX.md)
