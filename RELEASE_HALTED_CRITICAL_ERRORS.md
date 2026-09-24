# Aegis Latent Core `v5.0.1` — Release Halted: Critical Errors

> **Superseded 2026-09-24 — kept as the record of the halt.** All four blockers (H-1 to H-4: `REG-D67`–`REG-D70`) and the remaining open findings (`REG-D60`, `REG-D73`–`REG-D75`, `REG-D77`) are fixed on PR #205. The same work found and fixed `REG-D78`–`REG-D86`. The current state is [RELEASE_READINESS_v5.0.1.md](RELEASE_READINESS_v5.0.1.md); the per-item evidence is `evidence/registry/reg-d67_d86_closure.txt`. **Correction:** §2's Kubernetes line says H-1's exposure applied under containerd. It did not for the shipped image, which already set `UV_USE_IO_URING=0` (`deploy/docker/Dockerfile`), and the Helm chart runs that image.

**Verdict: HALTED.** `v5.0.1` must not be tagged, released or published from this tree.
**Date:** 2026-09-24 UTC
**Tree verified:** `origin/main` at `1bda9f9b250ba570155eed33c1cd1a7d176d53e2` (PR #202), plus this branch's changes, which touch documentation, evidence and one test-fixture script only — no runtime code.
**Environment:** Linux 6.18.44-fc-v37 x86_64, 4 shared vCPU; CPython 3.11.15; pytest 9.1.1; coverage 7.16.0; cargo 1.94.1; clippy 0.1.94; cargo-audit 0.22.2; ruff 0.16.8; mypy 1.19.1; bandit 1.9.4; pip-audit 2.10.1; detect-secrets 1.5.0; node v22.22.2; npm 10.9.7.
**Registry rows:** `REG-D65`–`REG-D77` ([Defect Registry](docs/REGISTRY.md)); evidence under `evidence/registry/reg-d6*_*.txt` and `reg-d7*_*.txt`.

The mission order asked for `FINAL_RELEASE_ATTESTATION_v5.0.1.md` and, if **any** check failed, for this report instead. Checks failed, so no attestation was written. This report nevertheless carries every section the attestation would have had, each check marked **[PASS]**, **[FAIL]** or **[NOT EXECUTED]** (with the reason). There is no fourth state.

A report like this records what was run, on one machine, on one date. It is not a certification, an audit opinion, a legal seal or evidence of external acceptance — the claims register forbids presenting it as one (`docs/CLAIMS_MATRIX.md`, `docs/institutional/UNSUPPORTED_CLAIMS.md`).

---

## 1. Executive summary

**The release is blocked by four defects.** Two of them are P0 availability defects in the gateway's in-process seccomp control, and both are **invisible to CI by construction**. The other two are P1 supply-chain consistency defects.

| # | Registry | Sev | Blocker, in one line | State |
|---|---|---|---|---|
| H-1 | `REG-D67` | P0 | On a Linux host with `libseccomp`, outside Docker, the gateway kills itself with `SIGSYS` about two seconds after startup — the README quickstart cannot serve a single request. | **Reproduced**, 2/2 runs; flagged, not fixed |
| H-2 | `REG-D68` | P0 | Inside Docker the same control is silently skipped, and the image's baked-in strict mode then refuses to start. | **Code path demonstrated**; not run on a Docker engine; flagged, not fixed |
| H-3 | `REG-D69` | P1 | The released gateway image is not built from the hash-pinned `requirements.lock`; two security documents said it was. | Docs corrected; build defect flagged, not fixed |
| H-4 | `REG-D70` | P1 | `requirements.txt`, and therefore the lock and the SBOM, omit `cachetools`, a core dependency. | Flagged, not fixed |

**Everything else that could be run passed.** 7,450 tests passed with 0 failures, both parallel and in CI's exact serial command. Coverage is 91.25% against CI's 65% floor. `cargo test` passed 93, clippy `-D warnings` is clean, and `mypy --strict` is clean on the gateway, scripts, tools and SDK. No known vulnerability was found in the Python lock, either Rust lockfile or either npm tree. No credential was found in the working tree or in 421 commits of history.

**Fixed on this branch** (none of these changes runtime behaviour):

- `REG-D66`: `main`'s Documentation Gates job was red.
- `REG-D65`: CodeQL alert 736.
- `REG-D71`: six PRs had no changelog entry.
- `REG-D72`: two false README sentences.
- The two false sentences behind `REG-D69`.

**Not done on purpose:**

- The four blockers are not fixed. The mission order said to flag critical architectural flaws rather than auto-fix them.
- The requested `git tag -s … && git push origin main --tags` was not run, and §9 explains why it should not be run as written.

## 2. Release-blocking errors

### H-1 — `REG-D67` (P0): the in-process seccomp filter kills the gateway on `io_uring_enter`

- **Files:** `aegis/core/seccomp_guard.py:198-213` builds the filter with `default_action=SCMP_ACT_KILL_PROCESS`, and `aegis/core/sandbox_l1.py` holds the 78-syscall allowlist. `aegis/proxy/app.py:1313-1337` applies it last in startup, in **every** enforcement mode.
- **Nature:**
  - `uvicorn[standard]`, which `requirements.lock` pins, brings in `uvloop`. On this kernel, `uvloop`'s libuv uses `io_uring`.
  - `io_uring_enter` (x86_64 syscall 426) is not on the allowlist, and a syscall outside the list kills the whole process.
  - The kill happens about two seconds after `Application startup complete`, before any request. Every later connection is refused.
- **Reproduction (executed):** the README quickstart, verbatim, against a mock upstream. Log: `seccomp-BPF filter loaded. 78 syscalls allowed …; any other syscall: kill the process.` → `Application startup complete.` → `Bad system call`. Kernel audit: `comm="aegis" … sig=31 arch=c000003e syscall=426 … code=0x80000000`, identical in both killed runs.
- **Control (executed):** the same run with `UV_USE_IO_URING=0` serves normally. Step 3 returns 200 with `x-aegis-evidence-status: durable`, `x-aegis-mmr-format: aegis-mmr-inclusion-v2` and the proof headers, and the process stays alive.
- **Why CI is green anyway:**
  - `SeccompGuard._detect_sandbox()` disables the filter when `pytest` is imported, when `HERMES_SANDBOX=true` (CI sets it at `.github/workflows/ci.yml:23` and `forensic.yml:24`), or when `/.dockerenv` exists.
  - The one test that loads the real filter, `tests/test_seccomp_enforced_serving.py`, serves a stub ASGI app, not the gateway.
  - The allowlist was recorded with `strace` on AKS nodes (PR #182), so any syscall that host never issued is fatal elsewhere.
- **Fix direction (owner decision):**
  - Allow `io_uring_*`, or answer them with `SCMP_ACT_ERRNO(EPERM)` so libuv falls back. `deploy/seccomp/aegis.json` already does this, with `defaultAction: SCMP_ACT_ERRNO` and no `io_uring` entry.
  - Reconsider `KILL_PROCESS` as the default for unknown syscalls.
  - Run the real gateway behind the real filter in CI.
- **Workaround until fixed:** `export UV_USE_IO_URING=0`, now disclosed in the README quickstart.
- **Evidence:** `evidence/registry/reg-d67_d68_seccomp_open.txt`.

### H-2 — `REG-D68` (P0): the filter is skipped in Docker, and strict mode then refuses to start

- **Files:**
  - `aegis/core/seccomp_guard.py:155-172` has `_detect_sandbox()` return `True` when `/.dockerenv` exists.
  - `deploy/docker/Dockerfile:79-83` bakes `AEGIS_SECURITY_ENFORCEMENT_MODE=strict` and `AEGIS_REQUIRE_SECCOMP=true`, as do `deploy/docker/docker-compose.yml:29-33` and `.env.example:5-8`.
  - `aegis/proxy/app.py:1328-1336` then raises.
- **Nature:** a container marker file is treated as proof that the control is unnecessary. In strict mode the gateway then fails closed on the control it just skipped.
- **Reproduction:**
  - **Executed:** the identical branch, forced with `HERMES_SANDBOX=true`, with every other strict prerequisite satisfied (a local Redis on :56379, a mapped API-key principal, 36-byte keys, and `AEGIS_REQUIRE_LSM=false` to isolate the check). Result: `RuntimeError: Seccomp enforcement required but unavailable: strict runtime requires an active seccomp filter`.
  - **Not executed:** no Docker engine exists in this environment. That Docker Engine creates `/.dockerenv` is stated from knowledge of the engine, not observed here.
- **Why CI is green anyway:** no workflow runs the built image. `publish_oci.yml` builds and pushes it; `ci.yml` has no container smoke test.
- **Kubernetes:** there is no `/.dockerenv` under containerd, so the filter is applied and H-1's exposure applies instead. Whether that bites depends on the runtime's `RuntimeDefault` profile. **[NOT EXECUTED]**.
- **Fix direction (owner decision):** container detection must not disable the control it gates. Either apply the in-process filter in containers too (filters layer, and the most restrictive action wins), or accept an outer filter only after verifying it via `/proc/self/status` `Seccomp:`.

### H-3 — `REG-D69` (P1): the released image does not install the lock

- **Files:**
  - `deploy/docker/Dockerfile:46` runs `pip install --no-cache-dir ".[storage-sqlite]"`. This is the file `publish_oci.yml:72` builds for GHCR.
  - `deploy/docker/Dockerfile.airgap:57-61` installs from wheels that `scripts/vendor_wheels.sh:40-56` downloads the same way, with `2>/dev/null || true`.
- **Nature:** the image's Python set is whatever the index serves for the `pyproject.toml` ranges on build day. There is no `--require-hashes`, and the lock is not used.
- **False documentation:** `docs/security/BUILD_SCRIPT_ATTESTATION.md` ("describes what a released image installs") and `docs/security/DEPENDENCY_RISK_REGISTER.md` ("the hash-pinned set installed into a released image") said otherwise. **Both are corrected on this branch**, and the boundary is `UC-069`.
- **Fix direction:** build from the lock (`pip install --require-hashes -r requirements.lock`, locked extras, then `pip install --no-deps .`), and vendor air-gap wheels from the lock with `--require-hashes` and no swallowed errors.

### H-4 — `REG-D70` (P1): the lock omits a core dependency

- **Files:** `pyproject.toml:50` declares `cachetools>=5.3.0` as a core dependency, and the built wheel's `METADATA` confirms it. `requirements.txt` and `requirements.lock` do not contain it.
- **Nature:**
  - The documented lock-based install (README step 1 and `AGENTS.md`) lacks `cachetools`.
  - `aegis/core/ratelimiter.py:65-79` then falls back to a plain dict that "will grow unbounded under high client-ID cardinality".
  - The SBOM built from the lock omits a package the image installs.
- **Fix direction:** add it to `requirements.txt` and regenerate the lock through CI's reviewed toolchain (Python 3.12, pip 25.2, pip-tools 7.5.2). That is a release act, not an edit.

## 3. Findings that do not block on their own

| Registry | Sev | Finding | State |
|---|---|---|---|
| `REG-D66` | P2 | `main`'s CI "Documentation Gates" red since #202 (run `35971846398`): `docs/RUST_BUILD.md:35` → removed `README.md#verified-metrics` | **FIXED** (also fixed on `main` by #203; both links resolve) |
| `REG-D65` | P3 | CodeQL alert 736, `scripts/generate_sdk_bundle_fixture.py:73`: ledger closed in `finally` instead of `with` | **FIXED** |
| `REG-D71` | P2 | `CHANGELOG.md` `[5.0.1]` lacked #182, #184, #185, #186, #187, #202; `[5.0.0]` still "unreleased" | **FIXED** |
| `REG-D72` | P2 | README "floor 90% enforced" (CI enforces 65%); `X-Aegis-Proof-Status` promised on a non-streaming call | **FIXED** |
| `REG-D77` | P2 | "MiFID II Art. 25(1)" cited 13× as record-keeping; in Directive 2014/65/EU Art. 25(1) is staff competence — the order/transaction record duty reads as MiFIR (Reg. 600/2014) Art. 25(1) | **Open — legal review** (`CLM-039`) |
| `REG-D73` | P3 | Unhandled exceptions → `text/plain` 500 from both apps; no traceback or exception text leaks | Open — owner decision |
| `REG-D74` | P3 | `[all]` extra pulls the dev toolchain (pytest, ruff, mypy, bandit, pip-audit, hypothesis) | Open |
| `REG-D75` | P3 | `host` defaults to `0.0.0.0` even with `auth_disabled=True` | Open |
| `REG-D76` | P3 | `cargo audit` now runs (0 vulnerabilities); two allowlist entries (`RUSTSEC-2026-0118`/`-0119`) are stale | **DOCUMENTED** (`UC-049`) |
| `REG-026` | P2 | `mypy --strict aegis_server`: 25 errors in 4 files (pre-existing, tracked) | Open (pre-existing) |
| `REG-D60` | P3 | Five example deployment variables read by nothing (pre-existing) | Open (pre-existing) |

## 4. Verification checklist — every check performed

**Phase 1 — dependency and supply chain**

| # | Check | Command / method | Result |
|---|---|---|---|
| 1.1 | Parse Python manifests | `tomllib` over `pyproject.toml`, `sdk/python/pyproject.toml` | **[PASS]** 16 core deps, 20 extras; SDK has 0 core deps, 5 extras |
| 1.2 | Parse Rust manifests | `tomllib` over `aegis_rust_v2/Cargo.toml`, `connectors/envoy-wasm/Cargo.toml` | **[PASS]** 27 + 2 deps |
| 1.3 | Parse npm manifests | `json` over `dashboard/package.json`, `sdk/typescript/package.json` | **[PASS]** |
| 1.4 | Python CVEs — lock | `pip-audit -r requirements.lock --require-hashes --disable-pip` | **[PASS]** No known vulnerabilities found |
| 1.5 | Python CVEs — requirements | `pip-audit -r requirements.txt` | **[PASS]** No known vulnerabilities found |
| 1.6 | Python CVEs — dev venv | `pip-audit` (environment) | **[FAIL — accepted]** 14 advisories, all `pip` 25.2 / `setuptools` 79.0.1 — bootstrap tooling, not in the lock or the wheel (`REG-D01`, `UC-059`) |
| 1.7 | Python CVEs — SDK extras | `pip-audit -r` (openai, anthropic, verify extras) | **[PASS]** No known vulnerabilities found |
| 1.8 | Rust CVEs | `cargo audit --json` (both lockfiles) | **[PASS]** 0 vulnerabilities (327 + 7 deps); warnings: `bincode` 1.3.3 unmaintained, `chacha20` 0.10.1 yanked (`REG-D02`, `REG-D03`) |
| 1.9 | Rust allowlist validity | each `.cargo/audit.toml` ignore vs advisory DB and `Cargo.lock` | **[FAIL — P3]** 2 of 6 stale (`REG-D76`); 4 still apply (unmaintained, no fix) |
| 1.10 | npm CVEs | `npm audit --package-lock-only` (dashboard, TS SDK) | **[PASS]** 0 at every severity (243 + 80 packages) |
| 1.11 | Deprecated / unmaintained | cargo-audit warnings; advisory DB | **[FAIL — accepted]** `bincode` (optional `zk-spartan` only), `paste`, `pqcrypto-*` unmaintained; `chacha20` yanked — all registered (`UC-049`) |
| 1.12 | Licences — Python lock | installed metadata for all 34 locked packages | **[PASS]** all permissive or MPL-2.0; none unknown |
| 1.13 | Licences — Rust | `cargo metadata --locked --offline` | **[PASS]** 250 + 7 packages, all permissive except the project's own AGPL crates |
| 1.14 | Licences — npm | `package-lock.json` licence fields | **[PASS]** LGPL `sharp-libvips` (optional platform binaries) and MPL entries attributed in `LICENSE-THIRD-PARTY.md` |
| 1.15 | Exact pins — Python manifests | specifier scan | **[FAIL — by design]** ranges (`>=`) in `pyproject.toml`; exact pins live in `requirements.lock` (34/34 `==` with hashes). A library that published exact pins would break every installer — ranges plus a lock is the correct form |
| 1.16 | Exact pins — Rust manifests | specifier scan | **[FAIL — by design]** caret ranges in `Cargo.toml`; `Cargo.lock` pins, and CI builds with `--locked` |
| 1.17 | Exact pins — npm | specifier scan | **[PASS]** dashboard deps exact (except the local `file:` SDK); TS SDK peer ranges are for consumers; both lockfiles present, CI uses `npm ci` |
| 1.18 | Released image installs the pinned set | read `deploy/docker/Dockerfile*`, `vendor_wheels.sh`, `publish_oci.yml` | **[FAIL — P1]** H-3 (`REG-D69`) |
| 1.19 | Lock matches declared core deps | diff `pyproject.toml` core deps vs `requirements.txt`/lock | **[FAIL — P1]** H-4 (`REG-D70`) |
| 1.20 | No dev tools in the built wheel | `pip wheel . --no-deps`; list members, read `METADATA` | **[PASS]** only `aegis/`, `aegis_server/`, `integrations/`, dist-info; 16 core `Requires-Dist`, no dev tool |
| 1.21 | No dev tools in the image | read Dockerfiles | **[PASS]** installs `.[storage-sqlite]` only; `.dockerignore` excludes `tests/`, `tools/`, `docs/` |
| 1.22 | No dev tools via extras | wheel `METADATA` | **[FAIL — P3]** `[all]` includes `dev` (`REG-D74`) |
| 1.23 | GitHub Actions SHA-pinned | `python scripts/verify_github_action_pins.py` | **[PASS]** `github_action_sha_pins=PASS remote_references=123` |
| 1.24 | Licence headers | `python scripts/apply_license_headers.py` (CI's check: no diff after) | **[PASS]** Updated 0 files |

**Phase 2 — static and dynamic analysis**

| # | Check | Command / method | Result |
|---|---|---|---|
| 2.1 | Types — gateway | `mypy --strict aegis` | **[PASS]** no issues in 208 source files |
| 2.2 | Types — scripts and tools | `mypy --strict --explicit-package-bases --follow-imports=silent scripts tools` | **[PASS]** 43 files |
| 2.3 | Types — Python SDK | `mypy --strict src` and `mypy --config-file pyproject.toml` (in `sdk/python`) | **[PASS]** 14 files, both |
| 2.4 | Types — enterprise server | `mypy --strict aegis_server` | **[FAIL — pre-existing]** 25 errors in 4 files (`REG-026`); CI's profile ignores this package, so CI stays green |
| 2.5 | Lint | `ruff check .`; `ruff check src tests` (SDK) | **[PASS]** All checks passed |
| 2.6 | Format | `ruff format --check .` | **[PASS]** 611 files already formatted |
| 2.7 | SAST — CI gate | `bandit -r aegis/ aegis_server/ -c pyproject.toml -lll` | **[PASS]** exit 0 |
| 2.8 | SAST — all severities, wider scope | `bandit -r aegis aegis_server sdk/python/src integrations scripts tools -c pyproject.toml` | **[PASS]** HIGH 0 · MEDIUM 2 · LOW 41 over 68,434 LOC; both mediums are `B310` in the dev-only `scripts/triage/dependency_triage.py` on fixed `https` OSV URLs |
| 2.9 | Suppressions justified | every `# nosec` in shipped code | **[PASS]** 75, each with an inline reason; SQL (`B608`), pickle (`B403`) and bidi (`B613`) sites read and correctly reasoned |
| 2.10 | Rust lint | `cargo clippy --locked --all-targets --all-features --offline -- -D warnings` | **[PASS]** exit 0 (`aegis_rust_v2`); `connectors/envoy-wasm` exit 0 |
| 2.11 | Rust tests | `cargo test --release --locked --offline` | **[PASS]** 93 passed, 0 failed |
| 2.12 | `unsafe` has a `// SAFETY:` comment | grep every `.rs` outside tests | **[PASS]** one site, `aegis_rust_v2/src/wal.rs:230` (`MmapMut::map_mut`), with `SAFETY:` and a local `#[allow(unsafe_code)]` under crate-level `unsafe_code = "deny"` |
| 2.13 | Rust panic surface | `unwrap`/`expect`/`panic!` outside `#[cfg(test)]` | **[PASS]** two invariant `expect`s in `mmr.rs` (documented, tested, `REG-D28`); release profile `panic = "abort"` |
| 2.14 | Python tests — parallel | `python -X faulthandler -m pytest tests/ -n auto -q` | **[PASS]** 7,450 passed, 34 skipped, 0 failed (139.8 s; re-run on the final tree: same counts); Python SDK `pytest -q`: 101 passed |
| 2.15 | Python tests — CI serial | `python -X faulthandler -m pytest -q --tb=short -rs -o faulthandler_timeout=60` | **[PASS]** 7,450 passed, 34 skipped, 0 failed (295.8 s); every skip environmental (no Postgres/DynamoDB Local, no `zk-spartan` build, no ARM MTE, no release binary) |
| 2.16 | Coverage | CI's command, `--cov=aegis --cov-fail-under=65` | **[PASS]** 91.25% (20,843 statements, 1,823 missed) |
| 2.17 | Secrets — working tree | `detect-secrets 1.5.0 scan` (tracked files) | **[PASS]** 3,104 raw hits triaged: 2,953 hex digests; every private-key, AWS-key and basic-auth hit is a WAF test payload, AWS's published example key or a `user:pass` placeholder; 28 non-test keyword hits are placeholders, env-var names or Kubernetes secret references |
| 2.18 | Secrets — full history | full clone (`git fetch --unshallow`), every added line in 421 commits scanned for AWS, GitHub, OpenAI, Anthropic, Slack, Google, Stripe, npm and PyPI token shapes and private-key bodies | **[PASS]** no private key with a body; one `sk-proj-…realKeyHere000…` string is a synthetic WAF block-test payload; files ever added with key-like names are `.env.example` and seven `config/presets/*.env` (placeholders only). gitleaks and trufflehog were not available, so coverage is those patterns |
| 2.19 | No stack trace to clients | raising route mounted on each real app, strict-shaped config | **[PASS]** both return `Internal Server Error`; traceback absent; exception text absent |
| 2.20 | Errors are structured JSON | same probe; 404; 403; audit endpoints | **[FAIL — P3]** 500 body is `text/plain` (`REG-D73`); 404/403/422 are JSON |
| 2.21 | Auth fail-closed | `AEGIS_AUTH_DISABLED=true` without debug; unmapped key in strict | **[PASS]** refuses to start; strict refuses an unmapped API key; a key with no scope gets 403 |
| 2.22 | Gateway serves on a stock Linux host | README quickstart, verbatim, mock upstream | **[FAIL — P0]** H-1 (`REG-D67`) |
| 2.23 | Gateway serves in the container | strict + seccomp path | **[FAIL — P0]** H-2 (`REG-D68`) — code path; **[NOT EXECUTED]** on a Docker engine |
| 2.24 | Kubernetes serving | — | **[NOT EXECUTED]** no cluster; runtime-profile dependent |
| 2.25 | Miri / Kani / TLA+ / Lean | — | **[NOT EXECUTED]** here (Lean and TLC absent; not re-run); all green on `main`'s CI run `35971846398` (Miri, Kani, Formal Verification jobs) |
| 2.26 | Open CodeQL alert | alert 736 | **[PASS after fix]** `REG-D65` |

**Phase 3 — documentation and claims**

| # | Check | Command / method | Result |
|---|---|---|---|
| 3.1 | Documentation corpus | `python scripts/verify_docs.py --root .` | **[PASS]** 0 findings |
| 3.2 | Claims register | `python scripts/verify_claims.py --root .` | **[PASS]** 107 claims, 0 findings |
| 3.3 | Prose boundaries | `python tools/docs/verify_documentation.py --root . --strict` | **[PASS]** 0 errors, 0 warnings |
| 3.4 | Links and anchors | `bash scripts/verify_links.sh --root .` | **[FAIL → PASS]** 1 of 1,387 broken on `main` (`REG-D66`); final tree: PASS, 1,397 resolved |
| 3.5 | Corpus audit | `python scripts/audit_documentation_corpus.py --output-dir …` | **[PASS]** status=PASS |
| 3.6 | Import reachability | `python scripts/verify_import_reachability.py --root .` | **[PASS]** no undeclared orphans |
| 3.7 | Module inventory current | `python scripts/generate_module_inventory.py --check` | **[PASS]** |
| 3.8 | AI context manifest | `python scripts/verify_ai_context_manifest.py` | **[PASS]** 83 files |
| 3.9 | Release contract | `python scripts/verify_release_contract.py --root .` | **[PASS]** 14 anchors synchronized at `5.0.1` |
| 3.10 | README: MMR, O(log n) proofs, tamper detection | code + tests | **[PASS]** `aegis/core/mmr.py`; `tests/test_crypto_audit_branch.py::test_verify_integrity_detects_in_memory_tamper`, `…prev_hash_mismatch`, `…hmac_mismatch`; `tests/redteam/test_mmr_proof_forgery.py` |
| 3.11 | README: HMAC / Ed25519 / ML-DSA-65 signing, HSM path | code + tests | **[PASS]** `tests/test_signature_scheme_binding.py`, `tests/test_pqc_signer.py`; ML-DSA timing is not a constant-time claim (`UC-012`) |
| 3.12 | README: shredding does not move the root | code + test | **[PASS]** `tests/test_crypto_shredder.py::test_the_mmr_root_does_not_move_when_a_key_is_destroyed` |
| 3.13 | README: 313-line pure-Python verifier, TS twin | `wc -l` | **[PASS]** `sdk/python/src/aegis_sdk/proof.py` 313 lines; `sdk/typescript/src/proof.ts` present |
| 3.14 | README: commit before response (non-streaming) | tests + live run | **[PASS]** `tests/test_enterprise_durable_evidence.py::test_success_response_is_returned_only_after_durable_evidence`; live: `x-aegis-evidence-status: durable` |
| 3.15 | README: streaming terminal commit, marker withheld on failure | tests | **[PASS]** `tests/test_embedded_mode.py::test_the_terminal_node_is_committed_before_the_last_chunk`, `tests/test_proxy_streaming.py::test_prehashed_terminal_commit_binds_outcome_and_replays` |
| 3.16 | README: refusals committed to the signed chain | tests | **[PASS]** `tests/test_pre_admission_rejection.py::test_rejection_is_signed_chained_and_anchored`, `tests/test_rag_injection_admission.py::test_the_refusal_is_committed_as_evidence` |
| 3.17 | README: evidence headers | live run (with the H-1 workaround) | **[FAIL → PASS]** `X-Aegis-Proof-Status` is streaming-only, README corrected (`REG-D72`); the other listed headers observed |
| 3.18 | README: quickstart runs | executed verbatim | **[FAIL — P0]** H-1 |
| 3.19 | README: coverage figure and floor | CI's command | **[FAIL → PASS]** "floor 90% enforced" false, corrected (`REG-D72`) |
| 3.20 | JCS (RFC 8785) determinism | read `aegis/core/forensic_bundle.py:34-72`; tests | **[PASS]** within its declared restricted domain: ASCII keys only (so code-point order equals RFC 8785's UTF-16 order), I-JSON-safe integers, floats and lone surrogates refused, `allow_nan=False`; `tests/test_forensic_bundle.py::test_restricted_jcs_rejects_non_ascii_keys_unsafe_integers_and_surrogates` |
| 3.21 | MMR v2 domain prefixes | read `aegis/core/mmr.py:101-106`; tests | **[PASS]** `_DOMAIN_LEAF = b"\x00"`, `_DOMAIN_NODE = b"\x01"`, `aegis-mmr-inclusion-v2`; `tests/test_mmr_domain_separation.py::test_v2_leaf_cannot_impersonate_an_interior_node` and `::test_no_cross_domain_preimage_coincidence`; v1's weakness pinned by `::test_v1_leaf_can_impersonate_an_interior_node`; new chains start on v2 (live run header) |
| 3.22 | "Immutable" | corpus | **[PASS]** the corpus claims *append-only, tamper-evident* and says tampering is detected, not prevented; no immutability claim for records |
| 3.23 | Regulatory claims (EU AI Act, MiFID II) | §6 table | **[PASS with one FAIL]** evidence-in-service-of framing holds everywhere checked; `REG-D77` citation needs legal review |
| 3.24 | CHANGELOG exhaustive since `v5.0.0` | `git log b2e4335..origin/main` vs `CHANGELOG.md` | **[FAIL → PASS]** 6 of 14 PRs missing; recorded (`REG-D71`). The file is `CHANGELOG.md` at the root — there is no `docs/CHANGELOG.md` |
| 3.25 | Supply-chain statements in docs | read vs build files | **[FAIL → corrected]** two false sentences (`REG-D69`, `UC-069`) |
| 3.26 | Whitespace | `git diff --check` | **[PASS]** |

## 5. Security posture — what was and was not established

- **Known vulnerabilities:** none **found**, on 2026-09-24, by `pip-audit` (Python lock and requirements), `cargo audit` (both Rust lockfiles, with the allowlist in §4 1.9) and `npm audit` (both trees). That is a scan result on one date, not a statement that none exist. The dev virtualenv's `pip`/`setuptools` advisories are outside the shipped set.
- **Pinning:** exact and hash-pinned for the 34-package Python lock, `Cargo.lock`-pinned for Rust (CI builds `--locked`), `package-lock.json`-pinned for npm (CI uses `npm ci`). **Not** pinned where it matters most: the released gateway image resolves ranges at build time (H-3), and the lock is missing a core dependency (H-4).
- **Error handling:** no traceback or exception text reaches a client from either app. The unhandled-exception body is plain text, not JSON (`REG-D73`).
- **Runtime hardening:** the in-process seccomp control is **not in a releasable state** (H-1, H-2).
- **Secrets:** none found in the tree or history within the stated tool coverage.

## 6. Performance baseline

From the retained artifact [`evidence/benchmarks/benchmarks_5.0.1_2026-09-24.json`](evidence/benchmarks/benchmarks_5.0.1_2026-09-24.json). It was produced by `scripts/run_benchmarks_5.0.1.py` at `ce58c58` on 2026-09-24T06:45:35Z: one shared, unpinned 4-vCPU x86_64 VM, CPython 3.11.15. **None of these is a capacity claim**, and the artifact says so itself.

| Metric | Value |
|---|---|
| `commit_forensic` latency (MMR append + HMAC sign + WAL `fsync`), n = 1,000 | p50 0.617 ms · p95 0.997 ms · **p99 1.216 ms** · max 4.175 ms |
| Commit throughput, one process, one WAL, one writer (`AD-16`) | 1,727 commits/s at 10 threads · 1,630/s at 50 · 1,482/s at 100 |
| Streaming ingestion memory, 1,000 concurrent in-process streams × 20 events | +20.1 MB RSS (52,648 → 73,256 KB) |
| Ed25519 (`cryptography`, RFC 8032) | sign 40.5 µs/op · verify 128.6 µs/op |
| ML-DSA-65 (`aegis_rust`, FIPS 204) | sign 173.0 µs/op · verify 62.4 µs/op — a latency sample, not a constant-time claim (`REG-041`, `UC-012`) |

## 7. Compliance mapping — code and tests in service of named obligations

**Framing (user-approved, `CLM-039` LEGAL-REVIEW-REQUIRED):** these are technical inputs. No row says an obligation is met — that is a determination for the operator and their assessor. No certification exists or is in progress.

| Instrument | What the provision is about | What the code contributes | Module | Test(s) | What it does **not** do |
|---|---|---|---|---|---|
| EU AI Act (Reg. 2024/1689) Art. 12(1) | Automatic recording of events ("logs") over a high-risk system's lifetime | Every governed call and every refusal is committed to a signed, hash-linked, `fsync`-durable ledger before the response is observable | `aegis/core/crypto_audit.py` (`commit_forensic`, rejection commits); `aegis/proxy/app.py` | `tests/test_enterprise_durable_evidence.py::test_success_response_is_returned_only_after_durable_evidence`; `tests/test_pre_admission_rejection.py::test_rejection_is_signed_chained_and_anchored` | Decide what a deployer must log; cover systems outside the gateway; retain for any mandated period (retention is operator storage) |
| EU AI Act Art. 12(2) | Logs that enable identifying risk situations and post-market monitoring | Tamper detection on read; portable O(log n) inclusion proofs verifiable offline | `aegis/core/mmr.py`; `sdk/python/src/aegis_sdk/proof.py`, `bundle.py` | `tests/test_crypto_audit_branch.py::test_verify_integrity_detects_*`; `tests/test_mmr_domain_separation.py`; `tests/test_sdk_bundle_contract.py` | Prevent tampering by a filesystem-level operator (detected, not prevented); prove completeness (no non-membership proofs) |
| EU AI Act Art. 17 | Quality management system of the **provider** | Inputs only: a claims register, a defect registry with terminal states and evidence files, CI gates, SBOMs | `docs/CLAIMS_MATRIX.md`, `docs/REGISTRY.md`, `.github/workflows/` | the gate battery in §4 | Constitute a QMS — Art. 17 is an organisational obligation; this corpus does not cite it as met |
| MiFID II (Dir. 2014/65/EU) Art. 16(6) | Records of services, activities and transactions sufficient for supervision | Durable, ordered-within-process records **of the AI interaction** | `aegis/core/crypto_audit.py`; `aegis/core/mifid_record_keeper.py` (**wired to no request path**, `CLM-104`, `UC-056`) | `tests/test_mifid_record_keeper.py` (library only) | Record orders or transactions (RTS 24, Del. Reg. 2017/580); provide clock traceability (RTS 25, Del. Reg. 2017/574); global ordering across replicas |
| MiFID II Art. 16(7) | Recording of communications relating to client orders | Hash-and-metadata communication records, library only | `aegis/core/mifid_record_keeper.py` | `tests/test_mifid_record_keeper.py` | Wired recording of any communication on the request path |
| "MiFID II Art. 25(1)" as cited in the corpus | **Disputed citation — `REG-D77`** | — | — | — | Resolve by legal review before any external use |
| RFC 8785 (JCS), RFC 6962-style domain separation | Deterministic, collision-separated evidence encoding | Restricted-domain JCS; `0x00` leaf / `0x01` node prefixes | `aegis/core/forensic_bundle.py`; `aegis/core/mmr.py` | `tests/test_forensic_bundle.py`; `tests/test_mmr_domain_separation.py` | Canonicalize floats or non-ASCII keys (refused, fail-closed) |

## 8. Known limitations — verbatim from `docs/institutional/UNSUPPORTED_CLAIMS.md`

These rows are copied from the register as it stands on this branch. The register governs, and this copy does not.

| ID | Supplied or legacy claim | Finding | Required status and correction |
|---|---|---|---|
| `UC-012` | ML-DSA is constant-time. | Retained verification timing failed the declared threshold; API comparison properties do not prove whole-algorithm timing. | `ROADMAP`; no constant-time claim. |
| `UC-041` | HMAC-signed evidence establishes who produced a record, or is non-repudiable. | `hmac-sha256` is a symmetric construction: the verifier holds the same secret the signer does, so any key holder can produce any signature, and a valid signature distinguishes "someone with the key" from nobody else. That is authentication of the key, not attribution to a party. `signature_assurance` reports such a chain as `SYMMETRIC_AUTHENTICATED`, two tiers below hardware-attested, and the ledger now warns at construction when it is configured this way. | `IMPLEMENTED` as authentication only (`CLM-090`). Non-repudiation requires an asymmetric tier with custody the signer alone holds — the HSM or PQC paths — and even then remains a legal conclusion this repository does not make. Blocked wording: "non-repudiable", "proves who", "legally binding signature", "attributable to the operator" for any HMAC-signed chain. |
| `UC-042` | The WAF is an injection boundary, blocks prompt injection, or makes the gateway safe against adversarial input. | Layer 1 is a finite set of regular expressions over a normalized copy of the text, hardened in `5.0.0` against homoglyph, letter-spacing and leetspeak obfuscation (`CLM-091`). Every one of those is a countermeasure against a known *encoding*, not against the space of semantically equivalent phrasings, which is unbounded and not expressible as a pattern set. Normalization additions raise the cost of a literal bypass and can each be defeated by an attacker who reads the table: the confusable map and the leet table are finite, and the spacing collapse fires only on a consistent separator at a four-character floor. | `IMPLEMENTED` as detection that reduces exposure to known patterns; a boundary is `ROADMAP` and is not achievable by this mechanism. Blocked wording: "prevents prompt injection", "injection-proof", "blocks adversarial input", "sanitises untrusted prompts", or any claim that passing the WAF establishes a payload is safe. **This row now covers two layers, not one.** `CLM-097` added retrieved-content scanning at admission (`RAGInjectionScanner` over `tool`/`function` messages and declared RAG context blocks), which closes a surface the WAF structurally could not reach — in an indirect injection the user turn is clean. It is the same kind of mechanism against a different input, so it inherits the same ceiling exactly: a finite pattern set, defeated by an attacker who reads it, establishing nothing about content that passes. Additionally blocked: "blocks indirect prompt injection", "RAG is protected", "tool output is sanitised", and "scans everything the model reads" — it does not read system prompts, model output, or anything the application never placed in `messages`. |
| `UC-047` | Installing the gateway from PyPI installs the same release as this source baseline, or `pip install aegis-latent-core` gives you the current product. | At `5.0.0` the gateway distribution has **no published version at all**: PyPI serves `4.1.2` (read back 2026-09-21 — `info.version` `4.1.2`, `releases: ['4.1.2']`) while every other surface is at `5.0.0`. `pip install aegis-latent-core` therefore installs a version earlier than this baseline and earlier than the `4.3.0`→`5.0.0` public-API change (`CLM-090`), so a `pip` install and a source checkout do not expose the same API. `publish_pypi.yml` builds `sdk/python` only, and the absence is a recorded position as of 2026-09-21 rather than a pending upload. | Blocked wording: "install with pip" as an unqualified instruction for the gateway, or any version statement that treats PyPI as carrying `5.0.0`. Source and GHCR are the channels that carry it (`docs/RELEASE_STATUS.md` §1.0). |
| `UC-049` | The Rust dependency advisories are cleared, or a green build means the advisory database was consulted. | Neither is established from this host. **`cargo audit` is not installed here** (`cargo audit --version` → `error: no such command: 'audit'`), so the allowlist in `aegis_rust_v2/.cargo/audit.toml` was not re-validated and no advisory claim may cite one. What the tree does record: `bincode` 1.3.3 (`RUSTSEC-2025-0141`, unmaintained) is declared **only** as an optional dependency of the `zk-spartan` feature (`aegis_rust_v2/Cargo.toml:54`, `:157`), and `zk-spartan` is **not** in the default feature set (`default = ["pqclean-pqc"]`), so an ordinary `cargo build` does not compile it; `chacha20` 0.10.1 is pinned in `aegis_rust_v2/Cargo.lock:255` and is yanked upstream, arriving transitively (referenced from rand's dependency list at `:1869`) rather than by declaration; and `.cargo/audit.toml` carries **no `[yanked]` section**, so that class of alert is neither suppressed nor cleared by configuration. The lock is one of the release's synchronized anchors, so replacing a pinned version is a release act with its own readback, and authoring a `[yanked]` section requires confirming its schema against `cargo audit` — which is absent here. | Blocked wording: "no known vulnerabilities", "the dependency tree is audited", "RUSTSEC-2025-0141 does not affect us", or any claim that a warning was reviewed and suppressed. `REG-D02` and `REG-D03` record the accepted state; the missing tool is part of the `REG-031`/`REG-034` BLOCKED cluster. **Currency note, 2026-09-24 (`REG-D76`):** `cargo-audit` is now installed on the recording host and was run against both lockfiles: `aegis_rust_v2/Cargo.lock` (327 dependencies) → 0 vulnerabilities with the allowlist applied, the same two allowed warnings (`bincode` 1.3.3 unmaintained, `chacha20` 0.10.1 yanked); `connectors/envoy-wasm/Cargo.lock` → 0. Two allowlist entries are stale — `RUSTSEC-2026-0118` and `-0119` do not match the locked `hickory-proto` 0.26.1 (unaffected by the first, patched for the second) — so they suppress nothing today. This updates the observation only; the blocked wording above still stands, because a scan run on one date by one tool is not "the dependency tree is audited". |
| `UC-056` | Aegis provides MiFID II / EU market-abuse (MAR) compliance capability. | `aegis/core/mifid_record_keeper.py` and `aegis/core/market_abuse_detector.py` are built but wired to no request path (both are reachability-allowlist entries, self-described as 'a worklist, not a verdict'); neither establishes any legal obligation, and the record keeper's 'satisfying…' docstring overclaims. The detector's spoofing citation must read **MAR Art. 12(1)(a)(ii)** (Reg. (EU) No 596/2014), not 'MiFID II Art. 12' — MiFID II Art. 12 is 'Assessment period'. | `ROADMAP` `AUD-20`; contribute-technology-inputs framing only, per `docs/compliance/MIFID_II_TECHNICAL_INPUTS.md`. |
| `UC-068` | Aegis validates, fact-checks, or otherwise establishes that a model's response is correct — including that it prevents or detects hallucination. | No code path on the governed request path checks response content against any ground truth, and none is claimed to. The evidence gateway's job is recording what the provider returned and signing that it was returned, not judging whether it was true. Two narrow exceptions exist and neither closes this gap: `aegis/core/dosage_hallucination.py` flags drug-dosage figures outside a reference range for a fixed set of substances (`tests/test_dosage_hallucination.py`), and `aegis/core/clinical_claim_detector.py` pattern-matches a fixed set of clinical-claim phrasings (`tests/test_clinical_claim_detector.py`) — both are implemented and tested, and **both are reachability-allowlist entries**: no production path constructs either, so as shipped they detect nothing in a live request. Even wired, a reference-range or pattern check is not general factual verification: it catches one narrow category of numeric or phrasal anomaly, not an ungrounded claim that falls inside the range or outside the pattern set. | `ROADMAP` for any hallucination-detection or correctness claim of any scope; the two narrow detectors are `IMPLEMENTED` and `LOCALLY TESTED` but **not wired** — the same undecided state `UC-064`–`UC-066` document for other allowlisted modules, and neither carries a `CLAIMS_MATRIX.md` row of its own yet. Blocked wording: "Aegis prevents hallucination", "detects hallucinated content", "validates the response", "fact-checks the model", or any phrasing implying the gateway judges correctness rather than records occurrence. |
| `UC-069` | The released gateway image installs exactly the hash-pinned `requirements.lock` set, or the Python SBOM built from that lock describes what the image contains. | It does not. `deploy/docker/Dockerfile:46` (the file `publish_oci.yml` builds for GHCR) runs `pip install --no-cache-dir ".[storage-sqlite]"`, which resolves the `pyproject.toml` version ranges against the package index at build time — no `--require-hashes`, no lock. `deploy/docker/Dockerfile.airgap` installs from wheels that `scripts/vendor_wheels.sh` downloads the same way, with download errors swallowed by `|| true`. The lock also omits two packages the image does install: `cachetools` (a core dependency in `pyproject.toml`, absent from `requirements.txt` — `REG-D70`) and `aiosqlite` (the `storage-sqlite` extra). What does hold: the lock is hash-pinned and exact for the 34 packages it lists; `pip-audit -r requirements.lock --require-hashes` found no known vulnerabilities on 2026-09-24; and the image's resolution, while not pinned, uses the same lower bounds. | `OPEN` (`REG-D69`) — building the image from the lock is a packaging change with its own readback, not a documentation fix. Blocked wording: "the image is built from the lockfile", "the SBOM describes the released image", "every image dependency is hash-pinned", "reproducible image". |
| `UC-070` | The gateway runs under its in-process seccomp-BPF filter on the documented install paths — the README quickstart on a Linux host, the Docker image, and Kubernetes. | Not on any of them as a verified fact, and demonstrably not on two. **Bare Linux host (executed 2026-09-24):** `aegis` from the README quickstart installs the filter (default action `SCMP_ACT_KILL_PROCESS`, 78 allowed syscalls) and the process is killed with `SIGSYS` about two seconds after `Application startup complete`, before any request — the kernel audit record names `syscall=426` (`io_uring_enter`, x86_64), which libuv (via `uvloop`, pulled in by `uvicorn[standard]`) issues; the same run with `UV_USE_IO_URING=0` serves durable evidence normally (`REG-D67`). **Docker (code path demonstrated, not executed against a Docker engine):** `SeccompGuard._detect_sandbox()` treats `/.dockerenv` as a sandbox marker and skips the filter, and the image bakes `AEGIS_SECURITY_ENFORCEMENT_MODE=strict` and `AEGIS_REQUIRE_SECCOMP=true`, so startup raises `strict runtime requires an active seccomp filter`; reproduced through the equivalent `HERMES_SANDBOX=true` branch with every other strict prerequisite satisfied (`REG-D68`). **Kubernetes:** configuration-dependent and not executed — no `/.dockerenv` under containerd, so the filter is applied, and whether libuv reaches `io_uring_enter` depends on the runtime's `RuntimeDefault` profile. Tests cannot see any of this: the guard disables itself when `pytest` is imported and CI sets `HERMES_SANDBOX=true`; `tests/test_seccomp_enforced_serving.py` loads the real filter but serves a trivial ASGI app, not the gateway. | `OPEN` (`REG-D67`, `REG-D68`) — the fix (an allowlist or an `ERRNO` action for `io_uring_*`, and a container detection that does not disable the control it gates) is an architectural change flagged by the 2026-09-24 gatekeeper pass, not made in it. Blocked wording: "kernel-enforced syscall allowlist in production", "seccomp-hardened container", "strict mode runs in Docker", or any claim that the quickstart runs on a stock Linux host without `UV_USE_IO_URING=0`. |

## 9. Release checklist, and the git commands

| Step | State |
|---|---|
| [x] Dependency and supply-chain audit | Done — 2 P1 failures (H-3, H-4) |
| [x] Static analysis (types, lint, format, SAST, clippy, `unsafe`) | Done — clean except the pre-existing `REG-026` |
| [x] Dynamic analysis (full suites, coverage, error-path probes, quickstart run) | Done — 2 P0 failures (H-1, H-2) |
| [x] Secrets (tree + 421-commit history) | Done — none found |
| [x] Documentation and claims gates | Done — `main`'s red links gate fixed |
| [x] README features traced to code and tests | Done — two false sentences fixed |
| [x] Regulatory mechanisms traced to code and tests | Done — one citation sent to legal review |
| [x] CHANGELOG exhaustiveness | Done — six PRs recorded |
| [ ] H-1 `REG-D67` fixed and re-verified on a stock Linux host | **Open — blocks release** |
| [ ] H-2 `REG-D68` fixed and the image started once under strict mode | **Open — blocks release** |
| [ ] H-3 `REG-D69` image built from the lock | **Open — blocks release** |
| [ ] H-4 `REG-D70` lock regenerated with `cachetools` | **Open — blocks release** |
| [ ] Container smoke test in CI (`docker run` + `/health`) | Recommended before the next release |
| [ ] `cosign verify`, `gh attestation verify`, `SHA256SUMS` sweep | Not run for any release (`AGENTS.md`); run at readback |

**The requested commands, and why they are not given as written.**

```
git add -A
git commit -S -m "chore: final preparations for v5.0.1 release"
git tag -s -a v5.0.1 -m "Aegis Latent Core v5.0.1: Production Ready, Enterprise Grade, Fully Audited"
git push origin main --tags
```

1. **The release is halted.** Tagging now would publish H-1 through H-4.
2. **A hand-made tag is not this repository's release path.**
   - Tags are created by the `create_release_tag.yml` workflow and carry a Sigstore certificate from its OIDC identity, which `scripts/verify_release_tag.sh` checks.
   - No workflow is triggered by a pushed tag.
   - `v4.1.0` was made this way, and `docs/RELEASE_STATUS.md` §1.3 records the result: no signature, and an immutable GitHub Release with **zero assets**.
3. **The tag message makes claims the register blocks.** It asserts production readiness, enterprise grade and a full audit, and none of the three is supported (`docs/CLAIMS_MATRIX.md`; `INTEGRITY_SEAL.md` §6).
4. **`git push origin main` bypasses review, and `git add -A` stages everything in the working tree**, including untracked local files that `AGENTS.md` rule 6 says must never be committed.

**The commands to use once H-1 to H-4 are closed and merged** (maintainer, from a clean `main`):

```bash
git switch main && git pull --ff-only origin main
python scripts/verify_release_contract.py --root . --tag v5.0.1   # expect READY
gh workflow run create_release_tag.yml --ref main                  # Sigstore-signed tag from CI's identity
git fetch --tags origin && TARGET=$(git rev-list -n1 v5.0.1)
bash scripts/verify_release_tag.sh v5.0.1 "$TARGET"
gh workflow run release.yml     --ref main -f release_tag=v5.0.1 -f expected_target="$TARGET"
gh workflow run publish_pypi.yml --ref main -f release_tag=v5.0.1 -f expected_target="$TARGET"
gh workflow run publish_npm.yml  --ref main -f release_tag=v5.0.1 -f expected_target="$TARGET"
gh workflow run publish_oci.yml  --ref main -f release_tag=v5.0.1 -f expected_target="$TARGET"
python scripts/verify_release_readback.py --tag v5.0.1 --verify-assets
```

A tag message, if one is ever written by hand, should state only what is true: `Aegis Latent Core v5.0.1`. Publication is established by the readback in the last command, never by the tag, and each surface is recorded in `docs/RELEASE_STATUS.md` before it is claimed. The gateway distribution `aegis-latent-core` still has no PyPI publishing workflow (`UC-047`), so `publish_pypi.yml` will publish the SDK only.

---

**Related:** [Defect Registry](docs/REGISTRY.md) · [Unsupported Claims](docs/institutional/UNSUPPORTED_CLAIMS.md) · [Claims Matrix](docs/CLAIMS_MATRIX.md) · [Release Status](docs/RELEASE_STATUS.md) · [Integrity Seal (5.0.0)](INTEGRITY_SEAL.md) · [Changelog](CHANGELOG.md)
