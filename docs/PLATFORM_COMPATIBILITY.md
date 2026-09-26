# Platform Compatibility Matrix

**Review date:** 2026-09-15 UTC
**Source baseline:** checked-out source metadata is synchronized at `v5.0.1` — **published 2026-09-24 on every surface except PyPI `aegis-latent-core`**, read back the same day (`docs/RELEASE_STATUS.md` §1.0a). The previous release is `v5.0.0`, published 2026-09-16 on every surface except PyPI `aegis-latent-core` (see `docs/RELEASE_STATUS.md` §1.0); `v4.1.2` remains the most recent version published on every surface
**Scope:** what this repository's own CI, tests, and shipped build artifacts actually exercise, as read back from `.github/workflows/*.yml`, `pyproject.toml`, `deploy/docker/Dockerfile`, and the relevant test modules on 2026-09-15. Nothing here is inferred from a platform's general POSIX/OCI compatibility.

Every cell below is one of:

- **SUPPORTED** — exercised on every push by a named CI job.
- **PARTIAL** — exercised, but narrower than the label suggests (a subset of the suite, a build without an execution test, a lint without a live deploy). The gap is stated.
- **UNTESTED** — no CI job, test, or build target touches this axis at all. Not a claim that it fails; a claim that nothing here says it works.
- **UNSUPPORTED** — this repository's own code documents the limit (a finding, not an omission).

## Operating system

| OS | Status | Evidence |
|---|---|---|
| Linux, glibc (Ubuntu 22.04) | **SUPPORTED** | Every functional CI job — `test`, `market-hardening`, `rust`, `forensic`, the Python-3.11/3.12/3.13 matrix — runs on `ubuntu-22.04` (`.github/workflows/ci.yml`). The shipped container base is `python:3.12-slim` (Debian, glibc) (`deploy/docker/Dockerfile:28`). |
| Windows | **PARTIAL** | One job, `WAL Single-Writer (Windows)`, runs on `windows-2022` (`.github/workflows/ci.yml:360`) and exercises exactly the native single-writer WAL lock path. No other job — the FastAPI proxy, the WAF, the Rust extension, the full `pytest` suite — runs on Windows in CI. |
| macOS | **UNTESTED** | No workflow in `.github/workflows/` names a macOS runner. |
| Linux, musl (e.g. Alpine) | **UNTESTED** | No musl target appears in any workflow, and the shipped image is glibc-based. A musl build has not been attempted; `cryptography`, `numpy`, and the Rust extension's wheel toolchain are all glibc-oriented dependencies that would need their own verification on musl before any claim could be made. |

## CPU architecture

| Arch | Status | Evidence |
|---|---|---|
| x86_64 | **SUPPORTED** | Every GitHub-hosted CI runner in this repository is x86_64. |
| arm64 | **PARTIAL** | `.github/workflows/publish_oci.yml:107` builds the container for `linux/amd64,linux/arm64` via Buildx/QEMU cross-compilation, so an arm64 image is produced. Nothing in CI *runs* that image, or any test, on real arm64 hardware or an arm64 emulator with execution. A built-but-unexecuted image is not the same claim as a tested one. |

## Python version

| Version | Status | Evidence |
|---|---|---|
| 3.11, 3.12, 3.13 | **SUPPORTED** | `.github/workflows/ci.yml:304` matrixes `["3.11", "3.12", "3.13"]` for the `test` job; `pyproject.toml`'s classifiers list the same three. |
| < 3.11 or > 3.13 | **UNTESTED** | `requires-python = ">=3.11"` sets a floor, not a ceiling beyond 3.13; nothing runs against 3.14 or later. |

## Cloud / hosting

| Target | Status | Evidence |
|---|---|---|
| Self-hosted / bare-metal, single node | **SUPPORTED** | This is what every CI job above actually is: a plain Linux process with local disk. No cloud SDK or credential is required for the base gateway to start, commit evidence, or serve requests. |
| Azure VM with a Managed Disk (`deploy/azure/vm`, Azure Kit Creator) | **DEPLOYED AND MEASURED ONCE** | One manual deployment on 2026-09-26 (`Standard_B2als_v2`, Chile Central, Premium SSD, Ubuntu 24.04): strict mode started, `verify.sh` passed, one signed record reached the WAL, and disk and harness numbers are retained in [Azure Benchmarks](benchmarks/AZURE_BENCHMARKS.md). No CI workflow deploys to Azure, so this is not a regression gate. |
| Azure AKS (`deploy/azure/aks`) | **OPERATOR-RUN, NOT VERIFIED HERE** | Authored and run by the owner against their subscription; not deployed or measured in this record. |
| Azure Container Apps | **UNSUPPORTED** | Persistent volumes are Azure Files, which breaks the single-writer lock; see [Azure Install Options](operations/AZURE_INSTALL_OPTIONS.md#d-azure-container-apps). Not tested against a live environment. |
| AWS, GCP (as a managed compute target) | **UNTESTED** | No workflow authenticates to, deploys to, or runs against a live AWS or GCP account. Claims about behavior on managed compute (e.g. instance metadata services, managed disk semantics) are not established here. |

## Storage backend

| Backend | Status | Evidence |
|---|---|---|
| Local disk (JSONL WAL, the gateway's default) | **SUPPORTED** | This is the path every CI test exercises; it is the only backend with no optional dependency. |
| SQLite (`storage-sqlite` extra) | **SUPPORTED**, locally | `CLM-081` in `docs/CLAIMS_MATRIX.md`: the concurrent-append-fork fix was reproduced and verified against SQLite in this environment. |
| PostgreSQL (`storage-postgres` extra, `aegis_server/storage/postgres_provider.py`) | **UNTESTED here** | `CLM-081`: written against `asyncpg`'s documented `FOR UPDATE` + unique partial index, but `asyncpg` and a live PostgreSQL server are both absent from this environment, so the provider has not been executed. |
| DynamoDB (`storage-dynamodb` extra, `aegis_server/storage/dynamodb_provider.py`) | **UNTESTED here** | Same finding as PostgreSQL: tests reference `moto` for a mocked endpoint, but `moto` is not installed in this environment (`python -c "import moto"` fails), so those tests skip rather than run. |
| S3 with Object Lock (`aegis/storage/s3_worm.py`) | **PARTIAL** | Wired into the real gateway path — `aegis/proxy/app.py` imports it, `tests/storage/test_s3_worm.py` and `tests/storage/test_segment_manifest.py` exercise it — but, like DynamoDB above, its `moto`-mocked tests do not execute in an environment without `moto` installed. This audit did not install `moto` to confirm a passing run; treat the S3 path as implemented and locally testable, not as measured in this pass. |
| S3 as a generic chain-storage backend via the `storage-s3` extra | **NOT IMPLEMENTED** | `pyproject.toml` declares a `storage-s3 = ["boto3>=1.35.0"]` extra, but no `s3_provider.py` (or equivalent) exists under `aegis_server/storage/` alongside the SQLite/PostgreSQL/DynamoDB providers. The extra installs a dependency with no corresponding chain-storage backend consuming it as one of the four `aegis_server/storage/*` providers; do not read the extra's existence as a working backend. |
| Archival modules not on any tested path | **WRITTEN, UNWIRED** | `aegis/core/archival_bundle.py` and `aegis/core/wal_backup.py` exist in the tree but are not reachable from any of this repository's real entrypoints, per `scripts/verify_import_reachability.py` (see `scripts/import_reachability_allowlist.txt`). Their presence is not evidence of a working archival path independent of `s3_worm.py` above. |

## Deployment mode

| Mode | Status | Evidence |
|---|---|---|
| Embedded (`from aegis import wrap`, in-process) | **SUPPORTED** | Exercised directly by `pytest` importing `aegis.embedded` on every CI run; no separate deploy step is needed for this mode by construction. |
| Gateway, single node (`aegis`/`aegis-server` console script, Docker Compose) | **SUPPORTED** | The `test`, `market-hardening`, and `forensic` CI jobs all run the real FastAPI app in-process against this path. |
| Gateway, Helm/Kubernetes | **PARTIAL** | The `Helm Lint` CI job (`helm lint` against `deploy/helm/`) runs on every push, so the chart is syntax- and schema-valid. No CI job installs the chart into a live cluster (kind/k3d or otherwise) and sends it a request; lint-clean is not deploy-tested. |
| Multi-pod / multi-replica gateway | **UNSUPPORTED for a shared, globally-ordered ledger** | This is a documented limit of the design, not a gap in test coverage: `UC-005` in `docs/institutional/UNSUPPORTED_CLAIMS.md` states plainly that the WAL's single-writer lock is process-local, storage providers use non-atomic read-then-write chain operations, and "ordering across replicas is still not established." `deploy/helm/values.yaml` gives each replica its own PVC claim (no shared-PVC default), so replicas run independent chains rather than silently corrupting a shared one — but that is *isolation*, not *consensus*. `aegis.consensus.gossip`'s `GossipDaemon` (wired into the proxy lifespan, `aegis/proxy/app.py:1012`) reconciles a separate CRDT accumulator for auxiliary metadata; it does not make the per-replica ledgers into one ordered ledger. Read "multi-pod" as "N independent single-writer ledgers," never as "one ledger with N writers." |

## What this document does not cover

Filesystem/backup durability semantics, kernel-level scheduling and cgroup behavior, TLS/ingress termination in front of the gateway, secret-manager integration, and HSM/enclave hardware availability are all target-environment properties `AGENTS.md` already places outside this repository's own proof obligations (see `AGENTS.md` §"Working rules", item 5). This matrix covers what runs *this repository's own code*, not what the surrounding infrastructure guarantees.
