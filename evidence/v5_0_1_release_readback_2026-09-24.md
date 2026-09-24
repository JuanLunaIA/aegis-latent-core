# `v5.0.1` release readback — 2026-09-24

**Scope:** the external surfaces of the `v5.0.1` release, read back after the release workflows finished. This covers what was published and who built and signed it. It says nothing about artifact correctness, deployment configuration or external acceptance.
**Source:** `main` at `46db6c0c65582bbb46137fd14182a976274b34e8`. Runs: tag `36016211316`, Release `36016251878`, OCI `36016262373`, PyPI `36016254775`, npm `36016258024`.
**Host:** Linux x86_64 container. `cosign` v2.6.5 and `gitsign` v0.17.1 were built with `go install` through the Go module proxy, which checks every module against the Go checksum database; the release binaries could not be downloaded from this host. `gh` was not available.
**Summary:** [Release Status](../docs/RELEASE_STATUS.md) §1.0a; claim `CLM-112`.

Method notes:

- The repository readback tool's own `cosign` row accepts any identity. The signature and attestation checks below were therefore run separately, with the exact certificate identity and OIDC issuer.
- Image attestations come from the GitHub attestations API. They are checked against the raw OCI index manifest fetched from GHCR, whose SHA-256 is the image digest.
- Every release file also carries GitHub's own immutable-release attestation, signed by GitHub's internal CA (`dotcom.releases.github.com`). That attestation was not verified. Only the `release.yml` SLSA provenance attestation, which uses the public-good Sigstore infrastructure, was verified.

Transcript (commands and their output, unedited apart from dropping the tool's local download path):

```text
$ date -u
2026-09-24T15:21:40Z

$ cosign version | grep GitVersion ; gitsign version | head -1
GitVersion:    v2.6.5
gitsign version v0.17.1

## 1. Tag
$ git cat-file -t refs/tags/v5.0.1 ; git rev-parse refs/tags/v5.0.1 ; git rev-list -n 1 refs/tags/v5.0.1
tag
b590a7f40df939b9efa361f3960bfa8b532296c9
46db6c0c65582bbb46137fd14182a976274b34e8
$ gitsign verify-tag --certificate-identity https://github.com/JuanLunaIA/aegis-latent-core/.github/workflows/create_release_tag.yml@refs/heads/main --certificate-oidc-issuer https://token.actions.githubusercontent.com v5.0.1
tlog index: 2940160795
gitsign: Signature made using certificate ID 0x808ee947bf42c666bdfd65e972aad4b94bee6956 | CN=sigstore-intermediate,O=sigstore.dev
gitsign: Good signature from [https://github.com/JuanLunaIA/aegis-latent-core/.github/workflows/create_release_tag.yml@refs/heads/main](https://token.actions.githubusercontent.com)
Validated Git signature: true
Validated Rekor entry: true
Validated Certificate claims: true
exit=0
$ git merge-base --is-ancestor 46db6c0c65582bbb46137fd14182a976274b34e8 origin/main
exit=0

## 2. Release, SHA256SUMS sweep, registries, digests (repository readback tool)
$ python scripts/verify_release_readback.py --tag v5.0.1 --verify-assets
release readback for v5.0.1 (repository juanlunaia/aegis-latent-core)
----------------------------------------------------------------------------------------------------
GitHub Release v5.0.1               CHECKED       published, 31 assets uploaded
asset SHA256SUMS                    CHECKED       present
asset release-asset-manifest.json   CHECKED       present
SHA256SUMS contents                 CHECKED       15 digests listed
SHA256SUMS sweep                    CHECKED       15 verified, 0 mismatched, 0 listed-but-absent of 15
PyPI aegis-latent-sdk               CHECKED       latest 5.0.1 == 5.0.1; releases: ['4.0.0', '4.1.1', '4.1.2', '5.0.0', '5.0.1']
PyPI aegis-latent-core              CHECKED       latest 4.1.2 != tag version 5.0.1; releases: ['4.1.2']
npm aegis-latent-sdk                CHECKED       latest 5.0.1 == 5.0.1
GHCR gateway 5.0.1                  CHECKED       manifest digest sha256:2d22023ef7f70cc3272950eb98684deb55dd07c2dfcaca9c77ac7e83dd090f3e
GHCR dashboard 5.0.1                CHECKED       manifest digest sha256:a05b41c5df4604556a7b148d211a6efd3a5f870ffe31681d7dde2daa2b3722a3
cosign verify gateway               NOT_EXECUTED  cosign is not installed on this host (no `cosign` on PATH)
cosign verify dashboard             NOT_EXECUTED  cosign is not installed on this host (no `cosign` on PATH)
gh attestation verify               NOT_EXECUTED  gh CLI is not installed on this host (no `gh` on PATH)
----------------------------------------------------------------------------------------------------
10 checked, 0 mismatched, 3 not executed
NOT EXECUTED is not a pass: these observables are unverified from this host.

## 3. Image signatures (exact identity, by digest)
$ cosign verify --certificate-identity https://github.com/JuanLunaIA/aegis-latent-core/.github/workflows/publish_oci.yml@refs/heads/main --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/juanlunaia/aegis-latent-core@sha256:2d22023ef7f70cc3272950eb98684deb55dd07c2dfcaca9c77ac7e83dd090f3e >/dev/null

Verification for ghcr.io/juanlunaia/aegis-latent-core@sha256:2d22023ef7f70cc3272950eb98684deb55dd07c2dfcaca9c77ac7e83dd090f3e --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The code-signing certificate was verified using trusted certificate authority certificates
exit=0
$ cosign verify --certificate-identity https://github.com/JuanLunaIA/aegis-latent-core/.github/workflows/publish_oci.yml@refs/heads/main --certificate-oidc-issuer https://token.actions.githubusercontent.com ghcr.io/juanlunaia/aegis-latent-core-dashboard@sha256:a05b41c5df4604556a7b148d211a6efd3a5f870ffe31681d7dde2daa2b3722a3 >/dev/null

Verification for ghcr.io/juanlunaia/aegis-latent-core-dashboard@sha256:a05b41c5df4604556a7b148d211a6efd3a5f870ffe31681d7dde2daa2b3722a3 --
The following checks were performed on each of these signatures:
  - The cosign claims were validated
  - Existence of the claims in the transparency log was verified offline
  - The code-signing certificate was verified using trusted certificate authority certificates
exit=0
gateway signing certificate (openssl x509 -text, selected Fulcio extensions):
1.3.6.1.4.1.57264.1.3: 
46db6c0c65582bbb46137fd14182a976274b34e8
1.3.6.1.4.1.57264.1.21: 
.Shttps://github.com/JuanLunaIA/aegis-latent-core/actions/runs/36016262373/attempts/1

## 4. Image build-provenance attestations (GitHub attestations API bundle, verified against the raw index manifest)
$ sha256sum manifest_aegis-latent-core.json
2d22023ef7f70cc3272950eb98684deb55dd07c2dfcaca9c77ac7e83dd090f3e  manifest_aegis-latent-core.json
$ cosign verify-blob-attestation --new-bundle-format --bundle bundle_aegis-latent-core.json --type https://slsa.dev/provenance/v1 --certificate-identity https://github.com/JuanLunaIA/aegis-latent-core/.github/workflows/publish_oci.yml@refs/heads/main --certificate-oidc-issuer https://token.actions.githubusercontent.com manifest_aegis-latent-core.json
Verified OK
exit=0
$ sha256sum manifest_aegis-latent-core-dashboard.json
a05b41c5df4604556a7b148d211a6efd3a5f870ffe31681d7dde2daa2b3722a3  manifest_aegis-latent-core-dashboard.json
$ cosign verify-blob-attestation --new-bundle-format --bundle bundle_aegis-latent-core-dashboard.json --type https://slsa.dev/provenance/v1 --certificate-identity https://github.com/JuanLunaIA/aegis-latent-core/.github/workflows/publish_oci.yml@refs/heads/main --certificate-oidc-issuer https://token.actions.githubusercontent.com manifest_aegis-latent-core-dashboard.json
Verified OK
exit=0

## 5. Release-asset build-provenance attestations (identity: release.yml@refs/heads/main)
Verified OK  e79d44f56f58c6d6…  aegis-latent-core-5.0.1.spdx.json
Verified OK  e79d44f56f58c6d6…  aegis-latent-core-build-sbom.spdx.json
Verified OK  ec9fb3c4a86cedd4…  aegis-latent-sdk-5.0.1.tgz
Verified OK  c5e3ec3528143fd2…  aegis_latent_core-5.0.1-py3-none-any.whl
Verified OK  cf431cf94bdc0ec6…  aegis_latent_core-5.0.1.tar.gz
Verified OK  7d5b0c9036f6c444…  aegis_latent_sdk-5.0.1-py3-none-any.whl
Verified OK  9cae15cbb9a0d345…  aegis_latent_sdk-5.0.1.tar.gz
Verified OK  4663672b6b29b7c9…  aegis_rust-5.0.1-cp311-abi3-macosx_10_12_x86_64.whl
Verified OK  ea02525ecd7e3ebf…  aegis_rust-5.0.1-cp311-abi3-macosx_11_0_arm64.whl
Verified OK  7fcc1344eccfed6b…  aegis_rust-5.0.1-cp311-abi3-manylinux_2_17_x86_64.manylinux2014_x86_64.whl
Verified OK  96ddd6fca312cd73…  aegis_rust-5.0.1-cp311-abi3-musllinux_1_2_aarch64.whl
Verified OK  4ae90607df78a2e8…  aegis_rust-5.0.1-cp311-abi3-musllinux_1_2_armv7l.whl
Verified OK  61d4e5cb1046c9ca…  aegis_rust-5.0.1-cp311-abi3-musllinux_1_2_x86_64.whl
Verified OK  be73c75bb34587e7…  aegis_rust-5.0.1-cp311-abi3-win_amd64.whl
Verified OK  b7cf20f4d7bcb0df…  release-asset-manifest.json

## 6. Registry artifacts compared with the release assets
PyPI aegis_latent_sdk-5.0.1-py3-none-any.whl sha256 7d5b0c9036f6c4443eacf09ec41f7095692201987ecaad8f46807c508fa291d5 uploaded 2026-09-24T14:56:29.400766Z | equals release asset: True
PyPI aegis_latent_sdk-5.0.1.tar.gz sha256 9cae15cbb9a0d3453d454a704f6c077f0bbb598d1feeff1d279c1f0ca6929b20 uploaded 2026-09-24T14:56:30.664010Z | equals release asset: True
npm aegis-latent-sdk 5.0.1 integrity sha512-94X5kw5PEHLsWjThDE8Oc42St0YfK9Y0M+mAGF991UgVXw+xO7L8PRTUOcyxvQezPUTRXQ+HgHFGaawlVvcHMg== | equals release asset: True | provenance predicate: https://slsa.dev/provenance/v1
```
