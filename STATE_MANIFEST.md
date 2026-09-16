# State Manifest

**Measured:** 2026-09-16 UTC
**Baseline commit:** `46654e9b6794d83fe7f420f483f31250b58205a5` (`origin/main`, PR #179 merged)
**Source baseline:** `5.0.0`, fourteen synchronized anchors, **published 2026-09-16 on every surface except PyPI `aegis-latent-core`** (see `docs/RELEASE_STATUS.md` §1.0). This manifest predates that publication and records source-state gates only.

Every value below was produced by running the command shown, in this
environment, on the commit above. Nothing here is carried forward from an
earlier session's numbers. Where a command could not run, the blocking reason
is recorded instead of a result — there is no third state.

## 1. Repository state

| Item | Value |
|---|---|
| `git status --short` | clean (no modified or untracked files at measurement time) |
| `HEAD` | `46654e9b6794d83fe7f420f483f31250b58205a5` |
| `origin/main` | `46654e9b6794d83fe7f420f483f31250b58205a5` — identical; no unmerged local commits |
| Open pull requests | **none** (`list_pull_requests state=open` → `[]`); nothing blocks `main` |
| Merged this line | #164, #165, #176, #177, #178, #179 |

## 2. Version anchors

`python scripts/verify_release_contract.py --root .` → `release source contract: READY`

All fourteen contract anchors read `5.0.0`: `core`, `core-runtime`, `python-sdk`,
`python-sdk-runtime`, `typescript-sdk`, `typescript-lock`, `dashboard`,
`dashboard-lock`, `rust-cargo`, `rust-pyproject`, `rust-lock`, `helm-chart`,
`helm-app`, `helm-image`. **Zero drift.**

Residual `4.4.0` / `6.0.0` matches in the tree are **not** drift and were each
checked: the `6.0.0` hits are third-party dependency versions (`r-efi`, `saxes`,
`tr46`) in `docs/security/DEPENDENCY_TRIAGE.md` and `LICENSE-THIRD-PARTY.md`;
the `4.4.0` hits are in `PR_FINAL_ENTERPRISE_HARDENING.md`, a self-described
non-durable artifact of an already-merged PR.

## 3. Test suites

| Suite | Command | Result |
|---|---|---|
| Python | `python -m pytest -n auto -q` | **6879 passed, 26 skipped, 0 failed** (6877 at the time of the §1 baseline commit; the two additions are `tests/test_safe_harbor_detector_count.py`) |
| Rust | `cargo test --locked --offline` | **70 passed, 0 failed** (67 lib + 3 integration; three harnesses report 0 tests because `zk-spartan` is default-off) |

The Python count includes the nine tests added in this pass (three for the
symmetric-signing warning, six for the WAF de-obfuscation variants); the
pre-change count on this commit was 6868.

## 4. Verifiers

| Gate | Command | Result |
|---|---|---|
| Claims register | `python scripts/verify_claims.py --root .` | **PASS** — 92 claims, 0 findings |
| Prose boundaries | `python tools/docs/verify_documentation.py --root . --strict` | **PASS** — 0 errors, 0 warnings |
| Corpus structure | `python scripts/verify_docs.py --root .` | **PASS** — 0 findings |
| Links and anchors | `bash scripts/verify_links.sh --root .` | **PASS** — 1141 resolved |
| Import reachability | `python scripts/verify_import_reachability.py --root .` | **PASS** — 222 modules discovered, 110 reached, 34 declared roadmap, 78 allowlisted, 0 undeclared orphans |
| Release contract | `python scripts/verify_release_contract.py --root . --tag v5.0.0` | **READY** (a source-consistency check; it does **not** assert the tag exists. At the time of this run no `v5.0.0` tag existed; one was created later the same day — see `docs/RELEASE_STATUS.md` §1.0) |

**One benchmark was re-executed rather than carried forward.** The backpressure
harness (`tools/benchmarks/run_backpressure_stall.py`) was run three times at
`88e01f0` with the parameters the retained 2026-08-20 report used. p99 commit latency
came back at 52.317 / 51.875 / 47.531 ms across 198–207 `fsync` calls per 2,500
records, against 836.351 ms and 2,501 `fsync` calls in the retained report. The
retained report is at `20fa011`, which predates the group-commit engine (`CLM-082`,
in tree from 2026-09-10), so it measured a ledger that fsynced once per node. Full
record, including why the millisecond delta is not a controlled speedup measurement
and why this latency is queueing rather than per-request overhead, in
[`evidence/backpressure_group_commit_remeasurement_2026-09-16.md`](evidence/backpressure_group_commit_remeasurement_2026-09-16.md).

## 5. Static analysis

| Gate | Command | Result |
|---|---|---|
| Lint | `ruff check .` | **PASS** — all checks passed |
| Format | `ruff format --check .` | **PASS** — 542 files already formatted |
| Types (mission-order scope) | `mypy --strict aegis sdk/python/src` | **PASS** — no issues in 215 source files |
| Types (repository CI scope) | `mypy aegis aegis_server sdk/python/src` | **25 errors in 4 files**, all pre-existing and all under `aegis_server/` (`dynamodb_provider.py`, `sqlite_provider.py`, `vault_signer.py`, `main.py`); unchanged by this pass |
| Security | `bandit -c pyproject.toml -r aegis/ -ll` | **PASS** — 0 high, 0 medium |
| Security (bare invocation) | `bandit -r aegis/ -ll` | 0 high, **8 medium** — every one is `B104` (bind-all-interfaces, ×7) or `B108` (hardcoded tmp dir, ×1), the exact IDs `pyproject.toml` `[tool.bandit] skips` already governs. The bare form bypasses that config because bandit reads `pyproject.toml` only when passed `-c`. |
| Rust build | `cargo build --release --offline` | **PASS** |
| Rust lint | `cargo clippy --locked --all-targets --all-features --offline -- -D warnings` | **PASS** — clean, including the `zk-spartan` feature graph |

## 6. Supply chain

| Check | Result |
|---|---|
| `pip-audit` (2.10.1) | Findings in `pip` 24.0 and `setuptools` 79.0.1 only. Neither appears in `requirements.lock`: they are this virtualenv's own build tooling, not shipped dependencies. **No finding against any Aegis runtime dependency.** |
| `npm audit --omit=dev` (npm 10.9.7), `sdk/typescript` | **0 vulnerabilities** |
| `npm audit --omit=dev`, `dashboard` | **0 vulnerabilities** |
| `cargo audit` (0.22.2, installed during this pass) | **EXECUTED, 0 vulnerabilities**, 2 allowed warnings (`bincode` 1.3.3 unmaintained `RUSTSEC-2025-0141`; `chacha20` 0.10.1 yanked) — run with CI's exact `--ignore` set, exit code 0. Previously exit 1 with "1 vulnerability found!". The advisory was `RUSTSEC-2026-0285` — "TLS 1.3 handshake messages incorrectly accepted across encryption level boundaries", severity 5.3 (medium), disclosed 2026-09-14, against rustls 0.23.41, with `Solution: Upgrade to >=0.23.45`. That text came from the failing CI job's own output (run `35039478528`, job `104615912714`), which is the authoritative source; `cargo update -p rustls --precise 0.23.45` moved the transitive pin to 0.23.45 (and `rustls-webpki` 0.103.13 → 0.103.15), an 8-line lockfile diff. rustls is transitive here, reached through `hyper-rustls` 0.27.9 and `tokio-rustls` 0.26.4. |
| Sonatype lookup for `pkg:cargo/rustls@0.23.41` | `NO_DATA_FOR_VERSION`, zero recommended upgrade targets, no vulnerability recorded in that dataset (Developer Trust Score 99, security sub-score 100). **Recorded because it was wrong in a useful way**: the advisory is real and was disclosed 2026-09-14, so this dataset was simply behind. A single supply-chain source returning "no data" is not evidence of no vulnerability, and was not treated as such. |
| `syft`, `cosign`, `slsa-verifier`, `helm`, `gh`, `trivy`, `grype` | **NOT_EXECUTED** — none is installed in this environment (`command -v` returns nothing for each). |

## 7. Environment

| Component | Version |
|---|---|
| Python | 3.11.15 |
| cargo | 1.94.1 (29ea6fb6a 2026-03-24) |
| node | v22.22.2 / npm 10.9.7 |
| pytest / ruff / mypy / bandit / pip-audit | 9.1.1 / 0.15.8 / 1.19.1 / 1.9.4 / 2.10.1 |

**One environment artifact worth recording:** `pip-audit` reports the editable
installs as `aegis-latent-core 4.0.2` and `aegis-latent-sdk 4.0.2` while
`aegis-rust` reports `5.0.0`. The two Python distributions carry stale
`.dist-info` metadata from an install performed when the tree was at `4.0.2`;
the Rust extension was rebuilt at `5.0.0` during the version convergence. This
is a property of this virtualenv, not of the tree — every version anchor in
source reads `5.0.0` (§2), and nothing in the test suite reads installed
distribution metadata for its version assertions.

---

**Related:** [Release Status](docs/RELEASE_STATUS.md) · [Release Epistemic Statement](docs/RELEASE_EPISTEMIC_STATEMENT.md) · [Platform Compatibility](docs/PLATFORM_COMPATIBILITY.md) · [Claims Matrix](docs/CLAIMS_MATRIX.md)
