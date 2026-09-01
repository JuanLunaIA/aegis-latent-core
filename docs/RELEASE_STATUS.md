# Release Status and Provenance

**Last verified:** 2026-09-01 UTC
**Release baseline:** checked-out source baseline/release target `4.0.2` with fourteen synchronized anchors

This document holds the complete version, publication, and provenance record so that `README.md` can state the current status once and link here. It is the authoritative place for release-lifecycle detail; the README is not.

## Current status at a glance

| Surface | Observed state | How to confirm it yourself |
|---|---|---|
| Source baseline | `4.0.2`, fourteen synchronized anchors | `python scripts/verify_release_contract.py --root . --tag v4.0.2` |
| Git tag | `v4.0.2`, annotated and Sigstore-signed, resolving to commit `a6eb58dcc03f8b638c8f3e35f0300f5443a926ca` | `git show v4.0.2` after fetching tags |
| GitHub Release | Present, non-draft, non-prerelease, 31 assets | [Release page](https://github.com/JuanLunaIA/aegis-latent-core/releases/tag/v4.0.2) |
| PyPI (`aegis-latent-sdk`) | Observed at `4.0.0` | [PyPI project page](https://pypi.org/project/aegis-latent-sdk/) |
| npm (`aegis-latent-sdk`) | Observed at `4.0.0` | [npm package page](https://www.npmjs.com/package/aegis-latent-sdk) |

The gateway itself is not distributed on PyPI or npm. Those registries carry the SDKs only, so a source checkout is the supported way to run the gateway regardless of registry state.

## Version anchors

The release contract requires fourteen version anchors to agree before a tag is cut. At `4.0.2` they are: `core`, `core-runtime`, `python-sdk`, `python-sdk-runtime`, `typescript-sdk`, `typescript-lock`, `dashboard`, `dashboard-lock`, `rust-cargo`, `rust-pyproject`, `rust-lock`, `helm-chart`, `helm-app`, and `helm-image`.

The immutable parent comparison commit `fdace8844568eb788216740b2cb5daf187d99d3b` retains fourteen synchronized `4.0.0` anchors and is the reference point for diffing source metadata between the two baselines.

## Release envelope readback, 2026-09-01

A read-only GitHub API readback recorded the following. It confirms that a release envelope exists with the expected shape; it is not a byte-level integrity check and not a registry publication.

**Assets (31).** `SHA256SUMS`; `release-asset-manifest.json`; two SPDX SBOMs (`aegis-latent-core-4.0.2.spdx.json`, `aegis-latent-core-build-sbom.spdx.json`); the Python core wheel and sdist; the Python SDK wheel and sdist; the TypeScript tarball `aegis-latent-sdk-4.0.2.tgz`; and seven `aegis_rust-4.0.2-cp311-abi3` platform wheels covering macOS x86-64 and arm64, manylinux2014 x86-64, musllinux x86-64, aarch64 and armv7l, and Windows amd64. Every artifact ships a matching `.sha256` sidecar.

**Tag signature.** The annotated tag carries a Sigstore keyless signature. The certificate's subject alternative name is the repository's own `create_release_tag.yml@refs/heads/main` workflow, the OIDC issuer is `token.actions.githubusercontent.com`, the trigger was `workflow_dispatch`, and the build environment was `release`.

## Why GitHub shows the tag as unverified

GitHub's native signature badge reports `v4.0.2` as unverified with reason `bad_cert`. **This is expected and is not a defect.**

Sigstore issues short-lived certificates — valid for roughly ten minutes — and records the signing event in a public transparency log. GitHub's native verifier expects a long-lived GPG or S/MIME key it can resolve to a registered account, so a Fulcio certificate that has already expired by design reads as a bad certificate. The signature is validated against the transparency log rather than against certificate lifetime.

To verify the tag properly, use a Sigstore-aware verifier and check the workflow identity rather than the GitHub badge:

```bash
# Verify the signed tag against the Sigstore transparency log.
gitsign verify \
  --certificate-identity 'https://github.com/JuanLunaIA/aegis-latent-core/.github/workflows/create_release_tag.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  v4.0.2
```

A verification that succeeds establishes that the signing workflow in this repository produced the tag. It does not establish that the artifacts attached to the release were built from that tag; that is a separate attestation check.

## Verifying release artifacts

Download the assets and check them against the published digest list:

```bash
gh release download v4.0.2 --repo JuanLunaIA/aegis-latent-core --dir ./v4.0.2
cd v4.0.2
sha256sum --check --strict SHA256SUMS
```

For build provenance on the container images:

```bash
gh attestation verify oci://ghcr.io/juanlunaia/aegis-latent-core:4.0.2 \
  --repo JuanLunaIA/aegis-latent-core
```

## Historical baseline

The previous public label `v4.0.1` is a **lightweight** tag targeting `6469904380218584ae0b5221334bc9a46500f5ba`. Its tag-triggered workflows failed, so no artifact published under that label carries attributed provenance from those runs. The `4.0.0` objects observed on PyPI and npm predate and are unrelated to those failed runs.

Two subsequent fixes addressed the tag-workflow failure: `a6eb58d` provisioned Python for the signed tag workflow, and `ed47d9c` bound publication dispatch to the signed target. The `v4.0.2` tag was cut after both landed.

## What a version number does and does not tell you

Source metadata is a statement about the working tree, not about the world. A synchronized anchor set means the repository agrees with itself; it does not mean a tag exists, a release was published, a registry accepted an upload, an image was pushed, a signature validates, or any deployment accepted the result. Each of those is a separate observable, and the commands in this document are how you check them.

## Related documents

- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md) — controlling public claims register.
- [`docs/BOUNDARIES.md`](BOUNDARIES.md) — consolidated product and evidence boundaries.
- [`evidence/INDEX.md`](../evidence/INDEX.md) — dated evidence catalog.
- [`SECURITY.md`](../SECURITY.md) — vulnerability reporting.
