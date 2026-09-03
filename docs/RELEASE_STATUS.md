# Release Status and Provenance

**Audience:** release owners, security reviewers, platform engineers, procurement.
**Scope:** the version, publication, and provenance record for this repository.
**Boundary:** this is the only document that states publication state. Every other document links here. Source metadata never establishes publication; readback does.

**Last verified:** 2026-09-03 UTC (source baseline); 2026-09-02 UTC (external surfaces)
**Source baseline:** `4.1.1`, fourteen synchronized anchors
**Publication state of `4.1.1`:** **nothing is published.** No tag, release, registry package, image, signature or attestation exists for this version. For the superseded `4.1.0`, a lightweight tag and an empty immutable release exist — see §1.2.

---

## 1. Publication state

**Read this section as three separate things.** The source baseline moved to `4.1.1` on 2026-09-03. Nothing has been published for it. A `v4.1.0` tag and GitHub Release do exist, but neither came from the release pipeline and the release carries no assets. The `4.0.2` rows were last read back on 2026-09-02 and **describe `4.0.2` only**.

Nothing in this table may be restated with the version number changed. A `4.0.2` digest is not a `4.1.1` digest, and a `4.0.2` signature attests to `4.0.2` bytes.

### 1.1 The current source baseline

| Surface | State | Observed value | Readback |
| --- | --- | --- | --- |
| Source baseline | Confirmed | `4.1.1`, fourteen synchronized anchors, contract `READY` | §2.1 |
| GitHub tag `v4.1.1` | **Not created** | No tag exists | — |
| GitHub Release `v4.1.1` | **Not published** | No release exists | — |
| PyPI / npm at `4.1.1` | **Not published** | No package exists | — |
| OCI image at `4.1.1` | **Not published** | No image exists | — |
| Signatures / attestations for `4.1.1` | **Do not exist** | Nothing has been signed or attested | — |

### 1.2 `4.1.0` — tagged and released outside the pipeline, observed 2026-09-03

`4.1.0` is not a usable release and is superseded by `4.1.1`. It is recorded here because the objects exist publicly and a consumer may encounter them.

| Surface | State | Observed value |
| --- | --- | --- |
| GitHub tag `v4.1.0` | **Exists, but lightweight** | `git cat-file -t v4.1.0` → `commit`, not `tag`; targets `3c2b7e694e5bd5aa3e7211bbb9862e4f27a1017d` |
| Tag signature | **Absent** | Created by hand, so it carries no Sigstore certificate from the `create_release_tag.yml` OIDC identity and fails `scripts/verify_release_tag.sh` |
| GitHub Release `v4.1.0` | **Published, empty** | Release id `381803292`, published 2026-09-03T06:59:57Z, `assets: []` |
| Release immutability | Confirmed | `immutable: true` — the asset set is frozen at publication, so this release cannot be populated afterwards |
| PyPI / npm / OCI at `4.1.0` | **Not published** | No package or image exists |
| Build attestations for `4.1.0` | **Do not exist** | `release.yml` never ran for this tag |

**Why it is empty.** No workflow in this repository is triggered by a pushed tag. `release.yml` — which builds the wheels, SDK packages, SBOMs, `release-asset-manifest.json` and `SHA256SUMS`, and creates the release with them attached — is `workflow_dispatch` only, and was not dispatched. The absent Deployments have the same cause: they come from the `environment: release` blocks in `create_release_tag.yml` and `release.yml`.

**Do not treat `v4.1.0` as a release.** It has no verifiable artifacts, no signature and no provenance. Use `4.0.2` for a published artifact, or build `4.1.1` from source.

### 1.3 Historical readback — `4.0.2`, observed 2026-09-02

Retained as the record of what that version's surfaces actually carried, and still the most recent release produced by the pipeline. These rows are historical and are not claims about `4.1.1`.

| Surface | State | Observed value | Readback |
| --- | --- | --- | --- |
| Source baseline at that date | Confirmed | `4.0.2`, fourteen synchronized anchors | §2.1 |
| GitHub tag | Confirmed | `v4.0.2` → `a6eb58dcc03f8b638c8f3e35f0300f5443a926ca` | §2.2 |
| GitHub Release | Confirmed | Published 2026-08-28, non-draft, non-prerelease, 31 assets | §2.3 |
| PyPI (`aegis-latent-sdk`) | **Not published at 4.0.2** | Latest `4.0.0`; only release is `4.0.0` | §2.4 |
| npm (`aegis-latent-sdk`) | **Not published at 4.0.2** | `dist-tags.latest = 4.0.0`; only version is `4.0.0` | §2.5 |
| PyPI / npm (gateway) | Not applicable | The gateway is not distributed on either registry | §2.4, §2.5 |
| OCI image (gateway) | Confirmed | `ghcr.io/juanlunaia/aegis-latent-core:4.0.2` → `sha256:5b59352f17d3f602d045af8ba9cd54a18b808acd2e66b2c256af4519f106302a` | §2.6 |
| OCI image (dashboard) | Confirmed | `ghcr.io/juanlunaia/aegis-latent-core-dashboard:4.0.2` present | §2.6 |
| SBOMs | Confirmed as release assets | Two SPDX JSON documents, each with a `.sha256` sidecar | §2.3 |
| Image signatures | Confirmed present | A cosign signature object exists for the gateway `4.0.2` digest | §2.7 |
| Release-asset signatures | **Absent by design** | The release carries `.sha256` sidecars and `SHA256SUMS`, not detached signatures | §2.8 |
| Build attestations | Confirmed in workflow; verify per artifact | `actions/attest-build-provenance` covers wheels, sdists, tgz, SBOMs, manifest and `SHA256SUMS` | §2.8 |
| Tag signature | Confirmed, shows `bad_cert` on GitHub | Sigstore keyless; see §3 | §2.9 |

**The two rows that matter most for a consumer:** the SDKs on PyPI and npm are at `4.0.0` — not `4.0.2`, and certainly not `4.1.1`. Do not describe either version as released to those registries. The gateway ships from source; the registries carry SDKs only.

**The registry gap is now three versions wide.** `4.0.2` was never published to PyPI or npm, `4.1.0` produced only an empty release object, and `4.1.1` is not published anywhere at all. A consumer installing from a registry receives `4.0.0`, which is three releases behind this source tree.

## 2. Readback commands

Run these yourself. Do not accept this document's table as evidence of the current state — it records what was observed on the date above.

### 2.1 Source baseline

```bash
python scripts/verify_release_contract.py --root . --tag v4.0.2
```

### 2.2 GitHub tag

```bash
git fetch --tags origin
git rev-list -n 1 v4.0.2      # expect a6eb58dcc03f8b638c8f3e35f0300f5443a926ca
git cat-file -t v4.0.2        # expect "tag" (annotated), not "commit" (lightweight)
```

### 2.3 GitHub Release

```bash
gh release view v4.0.2 --repo JuanLunaIA/aegis-latent-core
gh release view v4.0.2 --repo JuanLunaIA/aegis-latent-core --json assets \
  --jq '.assets | length'     # expect 31
```

### 2.4 PyPI

```bash
curl -sS https://pypi.org/pypi/aegis-latent-sdk/json \
  | python3 -c 'import sys,json; d=json.load(sys.stdin); print("latest:", d["info"]["version"]); print("releases:", sorted(d["releases"]))'
```

Observed 2026-09-02: `latest: 4.0.0`, `releases: ['4.0.0']`.

### 2.5 npm

```bash
npm view aegis-latent-sdk version
npm view aegis-latent-sdk versions --json
```

Observed 2026-09-02: `4.0.0`, and `4.0.0` as the only version.

### 2.6 OCI images

```bash
crane ls ghcr.io/juanlunaia/aegis-latent-core
crane digest ghcr.io/juanlunaia/aegis-latent-core:4.0.2
```

Without `crane`, the registry API works anonymously for a public package:

```bash
TOKEN=$(curl -sS "https://ghcr.io/token?scope=repository:juanlunaia/aegis-latent-core:pull&service=ghcr.io" \
  | python3 -c 'import sys,json; print(json.load(sys.stdin)["token"])')
curl -sSI -H "Authorization: Bearer $TOKEN" \
  -H "Accept: application/vnd.oci.image.index.v1+json" \
  https://ghcr.io/v2/juanlunaia/aegis-latent-core/manifests/4.0.2 \
  | grep -i docker-content-digest
```

Observed 2026-09-02: `sha256:5b59352f17d3f602d045af8ba9cd54a18b808acd2e66b2c256af4519f106302a`.

### 2.7 Image signature

```bash
cosign verify ghcr.io/juanlunaia/aegis-latent-core:4.0.2 \
  --certificate-identity-regexp 'https://github\.com/JuanLunaIA/aegis-latent-core/\.github/workflows/.+' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```

A cosign signature object for the `4.0.2` digest was observed present on 2026-09-02. Presence of the object is not the same as a successful verification: run the command above and read its output.

### 2.8 Release artifacts

Artifact integrity is checked against the published digest list, and provenance against GitHub's attestation store:

```bash
gh release download v4.0.2 --repo JuanLunaIA/aegis-latent-core --dir ./v4.0.2
cd v4.0.2
sha256sum --check --strict SHA256SUMS

gh attestation verify aegis_latent_core-4.0.2-py3-none-any.whl \
  --repo JuanLunaIA/aegis-latent-core
```

The release does **not** carry detached `.sig`, `.pem`, or `.sigstore` assets, so there is no `cosign verify-blob` step for release files. Integrity comes from `SHA256SUMS` plus the sidecars, and provenance from the attestation store. `cosign verify` applies to the OCI images (§2.7), not to release blobs.

### 2.9 Tag signature

```bash
gitsign verify \
  --certificate-identity 'https://github.com/JuanLunaIA/aegis-latent-core/.github/workflows/create_release_tag.yml@refs/heads/main' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
  v4.0.2
```

## 3. Why GitHub shows the tag as unverified

GitHub's native signature badge reports `v4.0.2` as unverified with reason `bad_cert`. **This is expected and is not by itself an indication of compromise.**

Sigstore issues short-lived certificates — valid for roughly ten minutes — and records the signing event in a public transparency log. GitHub's native verifier expects a long-lived GPG or S/MIME key it can resolve to a registered account, so a Fulcio certificate that has already expired by design reads as a bad certificate. Trust comes from the transparency-log entry, not from certificate lifetime, so use the §2.9 command rather than the badge.

A successful `gitsign verify` establishes that the signing workflow in this repository produced the tag. It does not establish that the artifacts attached to the release were built from that tag; that is the separate attestation check in §2.8.

## 4. Version anchors

The release contract requires fourteen version anchors to agree before a tag is cut. At `4.0.2` they are: `core`, `core-runtime`, `python-sdk`, `python-sdk-runtime`, `typescript-sdk`, `typescript-lock`, `dashboard`, `dashboard-lock`, `rust-cargo`, `rust-pyproject`, `rust-lock`, `helm-chart`, `helm-app`, and `helm-image`.

The immutable parent comparison commit `fdace8844568eb788216740b2cb5daf187d99d3b` retains fourteen synchronized `4.0.0` anchors and is the reference point for diffing source metadata between the two baselines.

## 5. Release envelope detail

**Assets (31), observed 2026-09-02.** `SHA256SUMS`; `release-asset-manifest.json`; two SPDX SBOMs (`aegis-latent-core-4.0.2.spdx.json`, `aegis-latent-core-build-sbom.spdx.json`); the Python core wheel and sdist; the Python SDK wheel and sdist; the TypeScript tarball `aegis-latent-sdk-4.0.2.tgz`; and seven `aegis_rust-4.0.2-cp311-abi3` platform wheels covering macOS x86-64 and arm64, manylinux2014 x86-64, musllinux x86-64, aarch64 and armv7l, and Windows amd64. Every artifact ships a matching `.sha256` sidecar.

**Tag signature.** The annotated tag carries a Sigstore keyless signature. The certificate's subject alternative name is the repository's own `create_release_tag.yml@refs/heads/main` workflow, the OIDC issuer is `token.actions.githubusercontent.com`, the trigger was `workflow_dispatch`, and the build environment was `release`.

**Tag target versus branch head.** `v4.0.2` resolves to `a6eb58d`. The default branch has advanced past that commit. A reader evaluating the tagged release must check out the tag, not the branch head, or they are evaluating different source.

## 6. Historical baseline

The previous public label `v4.0.1` is a **lightweight** tag targeting `6469904380218584ae0b5221334bc9a46500f5ba`. Its tag-triggered workflows failed, so no artifact published under that label carries attributed provenance from those runs. The `4.0.0` objects observed on PyPI and npm predate and are unrelated to those failed runs.

Two subsequent fixes addressed the tag-workflow failure: `a6eb58d` provisioned Python for the signed tag workflow, and `ed47d9c` bound publication dispatch to the signed target. The `v4.0.2` tag was cut after both landed.

An OCI tag `4.0.1` exists in the registry. It predates the fixes above and does not inherit provenance from the failed tag workflows; treat it as unattributed and prefer `4.0.2`.

## 7. Rollback

Rolling back a release is a provenance operation, not only a deployment one.

**Selecting a target.** Roll back only to a version whose tag, release, and image digest you have re-verified with §2. A version number in a manifest is not a rollback target; a digest is. Pin by digest:

```bash
ghcr.io/juanlunaia/aegis-latent-core@sha256:<digest-from-§2.6>
```

**Constraints that apply to every rollback:**

- Preserve every WAL before changing versions. A rollback that discards evidence cannot be undone.
- Confirm WAL and export schema compatibility between the running version and the target before switching. An older gateway reading a newer WAL is not a supported path.
- Never roll back across the Helm topology change without following the migration procedure in [Operations Playbook §6.4](institutional/DOC-04_OPERATIONS_PLAYBOOK.md). The workload kind and the claim names both change; a naive rollback strands per-replica volumes.
- A rollback does not retract a published artifact. Registry and release objects are additive; yanking or deprecating a published version is a separate, deliberate act.

**Procedure and verification** are in [Rollback Runbook](operations/ROLLBACK_RUNBOOK.md).

## 8. What a version number does and does not tell you

Source metadata is a statement about the working tree, not about the world. A synchronized anchor set means the repository agrees with itself; it does not mean a tag exists, a release was published, a registry accepted an upload, an image was pushed, a signature validates, or any deployment accepted the result. Each of those is a separate observable, and §2 is how you check them.

---

**Related:** [Claims Matrix](CLAIMS_MATRIX.md) · [Boundaries](BOUNDARIES.md) · [Evidence Index](../evidence/INDEX.md) · [Rollback Runbook](operations/ROLLBACK_RUNBOOK.md) · [SECURITY](../SECURITY.md)
