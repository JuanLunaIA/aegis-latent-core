# Implementation Log — 5.0.1

**Prepared:** 2026-09-21
**Source target:** `5.0.1` — **fourteen synchronized anchors, `READY`; published nowhere**
**Branch:** `registry-closure-2026-09-21`
**Base:** `cd8ec4f` (REG-D27 closure); `origin/main` at `dc20a2c`

> **Publication state.** `5.0.1` exists as source metadata only. Read back on 2026-09-21 with
> `python scripts/verify_release_readback.py --tag v5.0.1`: GitHub Release → HTTP 404, both GHCR
> manifest tags → HTTP 404, PyPI `aegis-latent-sdk` → `5.0.0`, PyPI `aegis-latent-core` → `4.1.2`,
> npm `aegis-latent-sdk` → `5.0.0`. The `cosign` and `gh attestation verify` rows report
> `NOT_EXECUTED` on this host, which is not a pass. Nothing in this log asserts a release date,
> a tag, or a published artifact. `docs/RELEASE_STATUS.md` §1.0a is the record.

---

## 1. Phase 1 — global version bump to `5.0.1`

The repository already contains the mechanism for this: `scripts/verify_release_contract.py`
(`_load_versions`) enumerates the anchors and binds the active deployment literals to them, so a
bump cannot pass by updating some files. It reported `READY` with all fourteen anchors at `5.0.1`
after the change below, and it is the evidence that nothing was missed.

### 1.1 The fourteen synchronized anchors (all `5.0.0` → `5.0.1`)

| Anchor | File | Field |
| --- | --- | --- |
| `core` | `pyproject.toml` | `project.version` |
| `core-runtime` | `aegis/__init__.py` | `__version__` |
| `python-sdk` | `sdk/python/pyproject.toml` | `project.version` |
| `python-sdk-runtime` | `sdk/python/src/aegis_sdk/__init__.py` | `__version__` |
| `typescript-sdk` | `sdk/typescript/package.json` | `version` |
| `typescript-lock` | `sdk/typescript/package-lock.json` | `packages[""].version` (+ root `version`) |
| `dashboard` | `dashboard/package.json` | `version` |
| `dashboard-lock` | `dashboard/package-lock.json` | `packages[""].version` (+ root `version`) |
| `rust-cargo` | `aegis_rust_v2/Cargo.toml` | `package.version` |
| `rust-pyproject` | `aegis_rust_v2/pyproject.toml` | `project.version` |
| `rust-lock` | `aegis_rust_v2/Cargo.lock` | the `aegis_rust` package entry only |
| `helm-chart` | `deploy/helm/Chart.yaml` | `version` |
| `helm-app` | `deploy/helm/Chart.yaml` | `appVersion` |
| `helm-image` | `deploy/helm/values.yaml` | `image.tag` |

### 1.2 Deployment and installer literals the contract binds to the core version

`deploy/docker/Dockerfile`, `deploy/docker/Dockerfile.airgap` (label + air-gap image tag),
`deploy/docker/docker-compose.yml`, `deploy/docker/docker-compose.enterprise.yml` (**both**
services: proxy and enterprise server, plus the `com.aegis.version` label),
`deploy/k8s/aegis-operator/operator.py` (`DEFAULT_AEGIS_IMAGE`),
`deploy/k8s/aegis-operator/crd.yaml` (default image + description), `scripts/vendor_wheels.sh`
(the wheel pin and both air-gap references), `scripts/install_aegis.sh` (`AEGIS_VERSION`).

### 1.3 Other versioned artifacts

- `connectors/envoy-wasm/Cargo.toml` and its `Cargo.lock` — a sibling crate versioned with the
  release. **Not** covered by the release contract; bumped deliberately so it cannot drift
  silently, and recorded here because the gate would not have caught it.
- `scripts/generate_ai_context_manifest.py` — `SOURCE_RELEASE_TARGET_VERSION` (`5.0.0` → `5.0.1`).
  `SOURCE_BASELINE_VERSION` stays `4.0.0`: it identifies the immutable historical baseline commit
  `fdace884…`, not the checked-out target.

### 1.4 Deliberately **not** changed

- Dependency pins that merely contain the string: `protobuf>=5.0.0`, `redis>=5.0.0`
  (`pyproject.toml:43-44`), `"sugarss": "^5.0.0"` (`sdk/typescript/package-lock.json:1198`).
  These are third-party version constraints; changing them would be a real defect.
- Every published-readback fact for `5.0.0` and `4.1.2`: tag object, target commit, the 31 GitHub
  Release assets, PyPI and npm versions, GHCR digests. A bump does not rewrite history, and
  `docs/RELEASE_STATUS.md` keeps each row under the version in its own heading.
- `scripts/verify_release_readback.py`'s usage examples still read `--tag v5.0.0`: the tag is a
  parameter and `v5.0.0` is a tag that exists.

### 1.5 Statements the bump would have made false — restructured, not renumbered

Thirteen artifacts paired two facts in one sentence: *"the source release target is `v5.0.0`"*
**and** *"it was published 2026-09-16"*. Swapping the number alone would have asserted that
`5.0.1` is published, which the readback contradicts. Each was split:

- `.aegis_ai_context/` corpus: `00_CORE_ONTOLOGY_AND_BOUNDARIES.xml`,
  `01_CANONICAL_SYMBOL_AND_TYPE_INDEX.tsv` (five rows), `02_OPERATIONAL_INVARIANTS_MATRIX.md`,
  `03_STATE_MACHINES_AND_DAGS.mermaid`, `04_FORMAL_SPECIFICATIONS_MAPPING.md`,
  `05_DETERMINISTIC_RECIPES_PLAYBOOK.md`, `06_SECURITY_AND_SUPPLY_CHAIN_MANIFEST.xml` (two sites),
  `07_SYSTEM_COMPACT_KERNEL.xml`, `08_COMPONENT_PACKAGE_WORKFLOW_MATRIX.md` (three sites),
  `09_COMMAND_AND_CI_MATRIX.md`, and the corpus `README.md`.
- Navigation: `AGENTS.md`, `llms.txt`, `docs/REPOSITORY_MAP.md`, `docs/CLAIMS_MATRIX.md`.
- `CHANGELOG.md` (target line), `docs/RELEASE_STATUS.md` (header block + a new §1.0a readback
  table for `5.0.1`), `README.md` (release banner).
- `sdk/python/README.md` and `sdk/typescript/README.md`: both said the registry's
  `aegis-latent-sdk` `5.0.0` *"matches this source tree's SDK"*. After the bump it does not, and
  the sentence now says so.
- `AUD-35` references in `deploy/docker/docker-compose.enterprise.yml` and
  `deploy/helm/templates/statefulset.yaml` no longer pin an **open** finding to a version number.

---

## 2. Phase 2 — code remediation status

Each item was checked against the code rather than assumed. Three of the four were already
implemented on this branch; the fourth had a real gap in *pinning*, not in behaviour.

### 2.1 Concurrency and memory — `DONE` (verified, no change needed)

- **Rust WAL `mmap` durability before acknowledgment:** `aegis_rust_v2/src/wal.rs:224-266` writes
  the frame, writes a zero-length sentinel, calls `flush_range(...)`, and **only then** publishes
  `write_pos.store(end, Ordering::Release)`. A flush failure returns `PyErr` and leaves `write_pos`
  unchanged, so no non-durable frame is ever visible to a reader. The ordering rationale is in the
  comment at `:222-223`. This is the requirement, already met.
- **Python request bodies have a hard, unbypassable limit:** `RequestBodyLimitMiddleware`
  (`aegis/proxy/body_limits.py:57-120`) is ASGI middleware installed at
  `aegis/proxy/app.py:1303`, so no route can bypass it. It enforces the cap twice — on the declared
  `Content-Length` (`413`) and on the bytes actually received via a wrapped `receive` (including
  Starlette's anyio `BaseExceptionGroup` wrapping). Pinned by
  `tests/test_enterprise_body_limits.py`. The three `await request.body()` call sites
  (`app.py:1715`, `:2051`, `:2310`) sit behind it.
- **Response-side bound:** `aegis/proxy/forwarder.py:290-330` streams the upstream response and
  refuses past `max_stream_response_bytes`, declared or counted (REG-D27). The Rust relay keeps the
  same contract (`aegis_rust_v2/src/forwarder.rs:155`, `read_body_bounded`).

### 2.2 JCS sanitisation — `DONE, with a deliberate divergence`

The order asked for non-finite floats to be "converted to `null` or string representations before
hashing". This repository does something stricter, and it should keep doing it:

- **Rejected, never sanitised.** `aegis/core/crypto_audit.py` refuses non-finite or
  non-serialisable `sampling_params` at ingest, before the lock, and writes with
  `allow_nan=False` as a backstop (REG-D27). `ForensicBundleError` → HTTP 422 for the JCS
  projection (`aegis/core/forensic_bundle.py`, REG-D05).
- **Why not sanitise:** in an evidence system, silently rewriting a client's payload to `null`
  produces a sealed record that does not match what was submitted, and the hash changes without
  the caller knowing. Rejection prevents the non-deterministic hash break *and* preserves the
  correspondence between input and sealed record. Cross-language check recorded by the recon:
  `serde_json` 1.0.150, Go `encoding/json` and `JSON.parse` all reject the non-finite token, so
  rejection is also the interoperable behaviour.

### 2.3 Input validation and stack traces — `DONE` (new gate added)

- The three handled `500` paths use fixed details and log the exception separately:
  `aegis_server/main.py:745-746` (`"compliance export failed"`), `:855-856`
  (`"audit node lookup failed"`), `:881-882` (`"audit integrity check failed"`), each with
  `logger.error("… : %s", exc)`.
- The one `detail=str(exc)` in a response (`aegis/proxy/audit_api.py:361`) is a
  **422 from `ForensicBundleError`** — a typed, client-actionable validation message, not an
  internal error. Left as the contract.
- **What was missing:** nothing pinned the *body*. Existing tests asserted
  `status_code == 500` only, so a future handler echoing `str(exc)` would have stayed green.
  New `tests/test_error_response_hygiene.py` (3 tests) drives the real app, asserts the fixed
  details, asserts an unexpected `ValueError` yields the generic `Internal Server Error` body with
  no exception class, message, `Traceback` or `File "` in it, and includes a negative control that
  proves the leak detector fires.
- Typed payloads on the audited endpoints: `aegis/proxy/audit_api.py` uses Pydantic models
  (`ForensicExportRequest`, `:321`). The `/v1` relay accepts opaque provider JSON **by design** —
  that is what a proxy is — constrained by the body limit above.

---

## 3. Phase 3 — roadmap items tagged `[FEASIBLE_FOR_5.0.1]`

**There are none, and that is a measurement rather than a judgement:**
`git grep -c '\[FEASIBLE_FOR_5.0.1\]' -- .` → zero occurrences anywhere in the tree, as does
`[IMPLEMENTED_IN_5.0.1]`. Nothing was skipped by tag. The actionable backlog in this repository is
`docs/ROADMAP.md`'s `AUD-*` tickets and `docs/REGISTRY.md`'s rows, which are processed in wave
order under the standing directive — `REG-D28` … `REG-D36` remain open, each with a ticket and an
owner-or-blocker.

---

## 4. Phase 4 — test suite expansion and verification

### 4.1 New tests added in this work

| File | Tests | What it pins |
| --- | --- | --- |
| `tests/test_error_response_hygiene.py` | 3 | fixed `500` details; generic body for unexpected exceptions; leak-detector control |
| `tests/test_no_defect_markers_in_shipped_code.py` | 3 | no `TODO`/`FIXME`/`HACK` in shipped code; non-empty walk; detector control |

### 4.2 The order's coverage command — **NOT MET, registered**

```
$ pytest -n auto -q --cov=aegis --cov-fail-under=90
TOTAL                                            20300   2300    89%
FAIL Required test coverage of 90% not reached. Total coverage: 88.67%
```

- **Measured: 88.67%** (20,300 statements, 2,300 missed) — 1.33 points below the mission floor.
- **The repository's own floor is 65%** (`Makefile:46`, `.github/workflows/ci.yml:306-309`), and
  the measured value is 23.67 points above it. The 90% figure appears nowhere in this repository
  before this log; it is the order's requirement, stricter than the project's own standard.
- The floor was **not** raised in this commit: raising it to a value the suite does not meet would
  break CI, and reaching 90% means writing tests for modules this release did not touch
  (`aegis/storage/s3_worm.py` 80%, `aegis/storage/segment_manifest.py` 76%,
  `aegis/proxy/forwarder.py` 76%, `aegis/proxy/egress_guard.py` 75%).
- Registered as **`AUD-38`** (roadmap) and **`REG-D36`** (registry, **OPEN**) with the measured
  number, the module list and an effort estimate.
- **Two tests failed intermittently under CPU contention on this host** —
  `test_audit_read_snapshot.py::test_read_endpoints_survive_concurrent_commits` and
  `test_proxy_streaming.py::test_large_logical_stream_retained_memory_is_bounded`. Both assert
  tight in-loop invariants: the first asserts `proxy.retained_bytes <= 5632` on every iteration of
  a 100,000-event loop, the second runs a writer thread committing in a tight loop while seven
  endpoints are served. They failed in the `--cov` run and in a second plain `-n auto` run that
  competed with a `cargo` build; they passed in isolation (`2 passed in 24.37s`, and `33 passed in
  22.65s` for the pair with their siblings) and in the first quiet `-n auto` run. Recorded as
  **intermittent under load**, not dismissed as false positives and not hidden.

### 4.3 Rust

| Command | Result |
| --- | --- |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | **exit 0** (compiled `aegis_rust v5.0.1`) |
| `cargo test --all-features` | **not runnable by construction** — see below |
| `cargo test --release --locked` (the repository's own CI invocation) | see §4.3.1 |

`cargo test --all-features` cannot link on Linux in this repository, and the reason is documented
in the repository itself: `Cargo.toml:12-20` explains that `extension-module` must not be a
default feature because it "would also apply to `cargo test`, which then omits the libpython link
and fails with undefined `Py*` symbols", and `full = ["extension-module"]` makes `--all-features`
enable exactly that. The failure reproduced here is that documented one
(`rust-lld: error: undefined symbol: PyExc_TypeError`, …), not a code defect. CI runs
`cargo test --release` (`.github/workflows/ci.yml:429`) plus the two `zk-spartan` steps
(`:445-446`); `zk-spartan` is excluded from the default build and needs ADX, which is REG-D04's
documented Haswell limitation.

#### 4.3.1 Running the repository's own invocation on this host

`cargo test --release --locked` builds and runs here, but a test that initialises an embedded
interpreter needs the interpreter's real prefix: this host's Python is uv-managed, whose build-time
prefix is the placeholder `/install`, so the embedded runtime reports `sys.prefix = '/install'` and
dies with `ModuleNotFoundError: No module named 'encodings'`. Three environments were tried and
recorded in `evidence/registry/version-bump-5.0.1.txt` — the failure text of the first two is kept
rather than smoothed over. The third, which passes:

```
LD_LIBRARY_PATH=<uv base>/lib PYTHONHOME=<uv base> PYO3_PYTHON=<repo>/.venv/bin/python \
  cargo test --release --locked
  running 83 tests   test result: ok. 83 passed; 0 failed
  running 3 tests    test result: ok. 3 passed; 0 failed
  EXIT: 0
```

Note the contrast with §4.3: `--all-features` cannot link (documented `extension-module`
constraint); the default-plus-`zk-spartan` invocations CI uses are the runnable surface.

---

## 5. Phase 5 — commit and tag preparation

Files changed by this work: **48 modified, 3 added** (see `git diff --stat HEAD`). The commands
below are prepared, **not executed**: tagging and pushing are release acts, and the standing
directive holds the PR until every registry row is terminal. Push credentials are absent on this
host (`git push --dry-run` → "could not read Username"), so the last two commands cannot succeed
from here today regardless of intent.

```bash
# 1. stage and inspect
git add -A
git status --short
git diff --cached --stat

# 2. commit
git commit -F - <<'COMMIT'
release(5.0.1): global version bump, error-hygiene and marker gates, register corrected

Source target 5.0.1 across the fourteen synchronized anchors and every deployment
literal the release contract binds; contract READY at 14/14. Published nowhere —
read back 2026-09-21 (GitHub Release 404, both GHCR tags 404, registries unchanged);
see docs/RELEASE_STATUS.md §1.0a. Publication statements that coupled "target is
v5.0.0" with "published 2026-09-16" were restructured rather than renumbered.

Code: no fix was needed for the order's Phase-2 items — the Rust WAL already flushes
before publishing write_pos, the ASGI body limit is unbypassable by construction, and
non-finite floats are rejected before hashing rather than sanitised (documented
divergence, with the cross-language check). What was missing was pinning, so:
tests/test_error_response_hygiene.py (3) and
tests/test_no_defect_markers_in_shipped_code.py (3), the latter after measuring that
SECURITY_AUDIT_REPORT.md's "many FIXME/TODO markers" claim and its TODO_ISSUES.md
referent were both false.

Registry: burn-down wave table recomputed from the rows (it read 94 rows / 27 FIXED /
19 open while the rows said 96 / 41 / 7 — parser validated against four known rows);
REG-D34's row returned to §4.6; "Human class (9)" → (10); REG-D35 added (FIXED);
REG-D36 added (OPEN — mission coverage floor 90% not met, measured 88.67% against the
repository's own 65%, AUD-38).

Battery: see the log's §4. Clippy --all-targets --all-features -D warnings exit 0.
COMMIT

# 3. tag — ONLY after the registry is 100% terminal and the full battery is green
git tag -s v5.0.1 -m "Aegis Latent Core v5.0.1"
git verify-tag v5.0.1

# 4. push — blocked on this host: no credentials
git push origin HEAD:registry-closure-2026-09-21
git push origin v5.0.1
```

---

## 6. What this log does not claim

- That `5.0.1` is released, tagged, or published anywhere. It is not.
- That the mission's 90% coverage floor is met. It is not (88.67%), and the row is open.
- That `cargo test --all-features` was run successfully. It cannot link in this repository by
  design, and the documented one-feature cause is reproduced in §4.3.
- That `cosign verify` or `gh attestation verify` ran. Neither tool is installed on this host.
- That the two coverage-only test failures are defects. They pass in isolation; they are recorded
  as harness sensitivity.
