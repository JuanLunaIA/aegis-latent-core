# Aegis Latent Core `v5.0.1` — Release Readiness After Remediation

**Verdict: source ready for professional review and for the owner's release steps; not released.** Every defect that halted `v5.0.1` is fixed in source. Every row in the [Defect Registry](docs/REGISTRY.md) is terminal (`SEED` = 0). The checks in §3 pass locally. PR #205's CI on the final commit, the owner's dismissal of one verified CodeQL false positive, and the publication steps in §6 remain.
**Date:** 2026-09-24 UTC
**Branch:** `claude/aegis-v4-comprehensive-audit-m2qyka` (PR #205), on top of `origin/main` at `1bda9f9`.
**Supersedes:** [RELEASE_HALTED_CRITICAL_ERRORS.md](RELEASE_HALTED_CRITICAL_ERRORS.md), which is kept unchanged below its banner as the record of the halt.

This report records what was run, on one machine, on one date. It is not a certification, an audit opinion, a compliance determination or evidence of external acceptance ([Claims Matrix](docs/CLAIMS_MATRIX.md), [Unsupported Claims](docs/institutional/UNSUPPORTED_CLAIMS.md)).

---

## 1. The four blockers

| # | Registry | Was | Now | Commit |
|---|---|---|---|---|
| H-1 | `REG-D67` (P0) | The gateway killed itself with `SIGSYS` on `io_uring_enter` on a bare Linux host | The entry point disables libuv's io_uring before the loop exists; lockdown over a live ring is refused; later `io_uring_setup` gets `EPERM` | `249a435` |
| H-2 | `REG-D68` (P0) | The filter was skipped inside Docker, so strict mode refused to start | `/.dockerenv` is no longer a sandbox marker; the shipped image serves with `Seccomp: 2` | `249a435` |
| H-3 | `REG-D69` (P1) | The image did not install the hash-pinned lock | The images install `--require-hashes -r requirements.lock`, then `--no-deps`, then `pip check` | `6c34191` |
| H-4 | `REG-D70` (P1) | The lock omitted `cachetools` | Locked, with `aiosqlite`; later `prometheus-client` (`REG-D86`) | `6c34191` |

## 2. What the fixes found

Running the shipped image as deployed, which nothing had done before, found nine more defects. Each is fixed with before/after evidence in `evidence/registry/reg-d67_d86_closure.txt`:

| Registry | Sev | Defect |
|---|---|---|
| `REG-D78` | P0 | Killed on the first request to any named host: the resolver's `uname`/`sendmmsg` were not allowlisted |
| `REG-D83` | P0 | `find_library` ran `ldconfig`: AppArmor denied it at startup, and an authenticated capability probe killed the gateway |
| `REG-D79` | P1 | A `…/v1` backend URL, as documented, produced `/v1/v1/…` |
| `REG-D80` | P1 | The AppArmor profile blocked the WAL volume and the interpreter |
| `REG-D81` | P1 | The hardened compose could not start in strict mode, and no tool produced the principal mapping |
| `REG-D82` | P1 | The filter did not cover threads started before lockdown |
| `REG-D84` | P1 | Every graceful stop ended in `SIGSYS` |
| `REG-D86` | P1 | The image served no `/metrics`, so the posture alert could never fire |
| `REG-D85` | P2 | Two test modules left the test process on real-time scheduling pinned to one CPU, livelocking the run as root |

The lower-severity findings of the halt are also fixed: `REG-D73`, `REG-D74`, `REG-D75`, `REG-D77` (legal confirmation still recommended), `REG-D60`, `REG-026` and `REG-D03`.

**Beyond single-user operation**, the owner chose active-passive, active-active, multi-team use and bus-factor work. Built:

- Replicas under a Redis writer lease with epoch fencing.
- A hash-linked global sequence in PostgreSQL across replicas, with an auditor's `verify` command. Governed by `AD-17` and `CLM-108`; operated per [High Availability](docs/operations/HIGH_AVAILABILITY.md).
- An assessor's package ([Audit Readiness](docs/compliance/AUDIT_READINESS.md)) with an evidence collector (`CLM-110`).
- A [Maintainer Handbook](docs/MAINTAINER_HANDBOOK.md).

## 3. Verification on this branch

| Check | Result |
|---|---|
| Full test suite (`pytest -q -n auto`) on the final tree | **[PASS]** 7,548 passed, 41 skipped, 0 failed (7,536 at `5f54f35`, plus the collector's 12) |
| HA suite against real Redis 7.4 and PostgreSQL 16 | **[PASS]** 43 passed, plus 4 helm-rendering tests passed with helm |
| Evidence-collector tests | **[PASS]** 12 passed |
| Container smoke test, shipped image, kill-mode filter, `--ha` | **[PASS]** every step in `CLM-109`, including SIGKILL failover (4.2–5.2 s with a 5 s lease) and `verify` inside the image |
| Seccomp LOG-mode discovery over the whole smoke flow (scratch overlay) | **[PASS]** 0 syscalls outside the allowlist, with the positive control logged in the same boot |
| AppArmor leg of the smoke test | **[NOT EXECUTED locally]** No AppArmor on this host. It runs in CI's `container-smoke` job and before publish |
| `ruff check`, `ruff format --check` | **[PASS]** |
| `mypy --strict` on `aegis`, `aegis_server`, `scripts`/`tools` | **[PASS]** 210, 14 and 45 files |
| `pip-audit --require-hashes -r requirements.lock` | **[PASS]** no known vulnerabilities in 37 packages |
| Lock regenerated with CI's toolchain | **[PASS]** the only change is `prometheus-client==0.26.0` |
| `verify_docs`, `verify_claims` (111), `verify_links`, `verify_documentation --strict`, `git diff --check` | **[PASS]** |
| Import reachability, AI-context manifest, module inventory | **[PASS]** |
| PR #205 CI on the final commit | **[PENDING]** Watched until green |
| CodeQL | **[OWNER ACTION]** One high alert (`py/clear-text-logging-sensitive-data`, the principal tool's printed HMAC digests) is a verified false positive, explained on PR #205. Only the owner can dismiss it |

## 4. Not established

- **No certification of any kind**, and none can come from source. SOC 2, ISO/IEC 27001, HIPAA, EU AI Act and MiFID II outcomes belong to the deploying organisation and its assessors. [Audit Readiness](docs/compliance/AUDIT_READINESS.md) §1 and §6 say exactly what the organisation must supply.
- **No publication.** Nothing is released for `5.0.1`; [Release Status](docs/RELEASE_STATUS.md) is unchanged. `cosign verify` and `gh attestation verify` have never been run for any release.
- **No independent assurance.** No penetration test or external code audit has been done (`CLM-041`).
- **HA scope.** HA has not been tested on real `ReadWriteMany` storage classes, under network partitions, through Redis or PostgreSQL failover, under sustained load or across zones (`CLM-108`).
- **Platform scope.** Kubernetes runtimes and arm64 were not executed.
- **Legal review.** The MiFID citation (`REG-D77`) was checked against the adopted texts; counsel's confirmation is recommended.

## 5. One decision for the owner: the version number

The fourteen anchors say `5.0.1`. This branch adds backwards-compatible functionality (HA modes, new tools, the metrics dependency in the image) as well as fixes. Semantic Versioning would call that `5.1.0`. Releasing it as `5.0.1` is allowed, but it labels new capability as a patch.

Recommendation: move the anchors to `5.1.0` before tagging. The procedure is `scripts/verify_release_contract.py` and the version-anchor steps in the [Maintainer Handbook](docs/MAINTAINER_HANDBOOK.md) §5. This report does not change them.

## 6. Owner's release steps

Run these after PR #205 merges with CI green. Each step checks the one before, and nothing is claimed as published until §6.4's readback.

```bash
# 1. Signed tag from the exact tip of main (the version is read from pyproject.toml)
gh workflow run create_release_tag.yml --ref main
TAG=v5.0.1                                   # or v5.1.0 per §5
SHA=$(git rev-parse origin/main)

# 2. GitHub Release, assets, SHA256SUMS and attestations
gh workflow run release.yml     -f release_tag=$TAG -f expected_target=$SHA

# 3. Images (runs the container smoke test on the signed commit before pushing)
gh workflow run publish_oci.yml -f release_tag=$TAG -f expected_target=$SHA

# 4. SDKs
gh workflow run publish_pypi.yml -f release_tag=$TAG -f expected_target=$SHA
gh workflow run publish_npm.yml  -f release_tag=$TAG -f expected_target=$SHA
```

Then read back every surface — tag, Release assets and `SHA256SUMS`, PyPI, npm, GHCR digests, `cosign verify`, `gh attestation verify` — with `scripts/verify_release_readback.py` and [Audit Readiness](docs/compliance/AUDIT_READINESS.md) §3.1, and only then update [Release Status](docs/RELEASE_STATUS.md). The gateway distribution `aegis-latent-core` is published to PyPI by no workflow (latest there: `4.1.2`). Uploading it is a separate, manual owner decision.

---

**Related:** [Defect Registry](docs/REGISTRY.md) · [CHANGELOG](CHANGELOG.md) · [Audit Readiness](docs/compliance/AUDIT_READINESS.md) · [High Availability](docs/operations/HIGH_AVAILABILITY.md) · [Maintainer Handbook](docs/MAINTAINER_HANDBOOK.md) · [Release Status](docs/RELEASE_STATUS.md)
