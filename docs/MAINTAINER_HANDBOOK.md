# Maintainer Handbook

**Audience:** a successor maintainer, a second maintainer, an escrow agent or verifier, and a customer assessing continuity risk.
**Scope:** what someone other than the current maintainer needs to build, verify, release and support this project from the repository alone: the access to transfer, the procedures and the order they run in.
**Boundary:** [GOVERNANCE](../GOVERNANCE.md) records that the bus factor is one. This handbook reduces the knowledge part of that risk; it does not change the access part until the access in §2 is actually shared.

---

## 1. Orientation in one hour

| Question | Start at |
| --- | --- |
| What is where? | [`.aegis_ai_context/README.md`](../.aegis_ai_context/README.md), [docs/INDEX.md](INDEX.md), [Module Inventory](MODULE_INVENTORY.md) (per file: live or not, tests, owner) |
| What may be claimed publicly? | [Claims Matrix](CLAIMS_MATRIX.md) (machine-checked by `scripts/verify_claims.py`) and [Unsupported Claims](institutional/UNSUPPORTED_CLAIMS.md) |
| What is broken or open? | [Registry](REGISTRY.md): every defect has a `REG-` id, a state and an evidence file under `evidence/registry/` |
| Why is it built this way? | [Architecture Decisions](architecture/DECISIONS.md) (each entry records its cost) |
| What is published where? | [Release Status](RELEASE_STATUS.md), from readback only; source version metadata never establishes publication |
| Rules for agents and contributors | [AGENTS.md](../AGENTS.md), [CONTRIBUTING](../CONTRIBUTING.md) |

## 2. Access a successor needs

The repository holds **no long-lived publishing secret.** Workflows reference only `GITHUB_TOKEN`. The following are therefore account permissions, and each must be granted to a second person to lift the bus factor:

| Surface | Access | Used by |
| --- | --- | --- |
| GitHub repository `JuanLunaIA/aegis-latent-core` | Admin, including branch protection on `main` | Merges, settings |
| GitHub environment `release` | Required reviewer | `create_release_tag.yml`, `release.yml`, `publish_oci.yml`, `publish_pypi.yml`, `publish_npm.yml` |
| PyPI project `aegis-latent-sdk` | Owner; trusted publisher bound to this repository and `publish_pypi.yml` | SDK publication (OIDC) |
| PyPI project `aegis-latent-core` | Owner. **No workflow publishes it** (the gateway distribution was last uploaded at `4.1.2`; see AGENTS.md) | Gateway wheel, manual |
| npm package `aegis-latent-sdk` | Owner; trusted publishing from `publish_npm.yml` | TypeScript SDK (OIDC provenance) |
| GHCR `aegis-latent-core`, `aegis-latent-core-dashboard` | Package admin | `publish_oci.yml` (keyless cosign, build provenance) |
| Security reporting channel in [SECURITY](../SECURITY.md) | Recipient | Vulnerability intake |
| Commercial licensing keys (`scripts/generate_license_key.py`) | Custody of the Ed25519 private key, **outside the repository** | Commercial tier only |

Tags are Sigstore-signed by `create_release_tag.yml`, not with a personal key. Images are signed keylessly. A successor therefore inherits signing capability through the `release` environment, not through key material.

## 3. Build from a clean machine

```bash
git clone https://github.com/JuanLunaIA/aegis-latent-core && cd aegis-latent-core
python3 -m venv .venv && . .venv/bin/activate                      # Python 3.11+
python -m pip install --require-hashes -r requirements.lock        # runtime, hash-pinned
python -m pip install -e ".[dev]"                                  # test tooling, as CI does
pytest -q                                                          # full suite
docker build -f deploy/docker/Dockerfile -t aegis-latent-core:local .
python3 scripts/container_smoke_test.py --image aegis-latent-core:local --ha   # needs Docker
```

- **Rust extension:** [Rust Build](RUST_BUILD.md). The gateway runs without it, and the JSONL WAL stays authoritative.
- **Air-gapped build:** `scripts/vendor_wheels.sh` and `deploy/docker/Dockerfile.airgap`.
- **Dashboard and SDKs:** `dashboard/`, `sdk/python`, `sdk/typescript`, each with its own README and CI job.

## 4. The gates, and what each protects

Run locally before any push; CI runs them on every change (`.github/workflows/ci.yml`).

| Gate | Command | Protects |
| --- | --- | --- |
| Lint and format | `ruff check . && ruff format --check .` | Style drift |
| Types | `mypy --strict aegis && mypy --strict aegis_server` | Contract drift |
| Tests | `pytest -q` | Behaviour |
| HA against real backends | `AEGIS_TEST_REQUIRE_HA_BACKENDS=1 … pytest tests/ha` | Lease, sequence and fencing (`CLM-108`) |
| Container posture | `scripts/container_smoke_test.py --ha` | The shipped image under its own seccomp filter and AppArmor profile |
| Lock integrity | CI regenerates `requirements.lock` with pip 25.2 / pip-tools 7.5.2, seeded from the reviewed lock, and diffs it | Hash pinning |
| Claims and docs | `scripts/verify_docs.py`, `scripts/verify_claims.py`, `scripts/verify_links.sh`, `tools/docs/verify_documentation.py --strict` | Public statements |
| Generated files | `scripts/generate_ai_context_manifest.py --check`, `scripts/generate_module_inventory.py --check`, `scripts/verify_import_reachability.py` | Navigation that matches the tree |
| Release contract | `scripts/verify_release_contract.py --root . --tag vX.Y.Z` | The fourteen version anchors |

A red gate is fixed, not skipped: no test is disabled, quarantined or skipped to get green ([AGENTS.md](../AGENTS.md) working rules).

## 5. Releasing

Order matters, and each step verifies the previous one:

1. Merge to `main` with every gate green, and the version anchors synchronized (`verify_release_contract.py`).
2. Run **Create signed release tag** (`create_release_tag.yml`) from `main`. It checks that `main` is clean and exact, then signs the tag.
3. Run **Release** (`release.yml`) with `release_tag` and `expected_target` (the full commit SHA). It builds, attests and uploads the GitHub Release assets and `SHA256SUMS`.
4. Run **Publish multi-architecture OCI images** (`publish_oci.yml`) with the same inputs. Its `gateway-smoke` job runs the container smoke test on the signed commit before anything is pushed.
5. Run **Publish Python SDK to PyPI** and **Publish TypeScript SDK to npm** with the same inputs.
6. **Read back every surface** — the tag, the Release and its assets, PyPI, npm, the GHCR digests, `cosign verify`, `gh attestation verify` and `sha256sum -c` — with `scripts/verify_release_readback.py` and the commands in [Audit Readiness](compliance/AUDIT_READINESS.md) §3.1. Only then update [Release Status](RELEASE_STATUS.md).

Never state that something is published because a workflow succeeded; the readback is the record.

## 6. Keeping it running

| Event | Runbook |
| --- | --- |
| Vulnerability report | [SECURITY](../SECURITY.md) |
| Dependency advisory | `pip-audit -r requirements.lock`; `cargo audit`; `npm audit`. Regenerate the lock as §4 describes |
| Evidence chain fault (`wal_corrupt`) | `tools/wal_repair.py`; [Backup and Restore](operations/BACKUP_RESTORE.md) |
| Signing key rotation | [Key Rotation Runbook](operations/KEY_ROTATION_RUNBOOK.md) |
| Replica failover or divergence | [High Availability](operations/HIGH_AVAILABILITY.md) |
| Bad release | [Rollback Runbook](operations/ROLLBACK_RUNBOOK.md) |
| A new defect | Open a `REG-` row in [Registry](REGISTRY.md) with before/after evidence under `evidence/registry/`, fix it with a regression test, and add a CHANGELOG entry |

## 7. Escrow deposit

A deposit that a third party can rebuild and verify without the maintainer contains:

1. The repository at the signed release tag (`git bundle create aegis-vX.Y.Z.bundle vX.Y.Z`), which includes this handbook, the locks (`requirements.lock`, `Cargo.lock`, the npm lockfiles) and the workflows.
2. Vendored Python wheels for the lock (`scripts/vendor_wheels.sh`), so the build does not depend on PyPI remaining available.
3. The base image digests pinned in `deploy/docker/Dockerfile`, exported with `docker save`.
4. The release's `SHA256SUMS`, SBOM and GHCR digests as read back.
5. The access list of §2 and the custody arrangements for the commercial licence key.

**Verifying the deposit:**

1. Restore the bundle. Confirm the tag with `scripts/verify_release_tag.sh vX.Y.Z <sha>`, which runs `gitsign verify-tag` against this repository's workflow identity.
2. Install from the vendored wheels with `--no-index --require-hashes`.
3. Run §3 and §4. Every gate should pass.
4. Build the image and run the smoke test.

**Byte-identical rebuilds are not established:** the PyPI gateway artifacts already differ from the release assets of the same name (AGENTS.md). Verification is behavioural (gates and smoke test), plus hash identity of the inputs.

---

**Related:** [GOVERNANCE](../GOVERNANCE.md) · [CONTRIBUTING](../CONTRIBUTING.md) · [Release Status](RELEASE_STATUS.md) · [Audit Readiness](compliance/AUDIT_READINESS.md) · [Registry](REGISTRY.md)
