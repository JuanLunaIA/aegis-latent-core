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
order under the standing directive — the `[AUDIT]` block stands at 27 terminal of 30 after the
second closure batch (see §7), the three open rows being `REG-D32`, `REG-D33` and `REG-D34`, each
with a ticket and a blocker recorded in its own row.

---

## 4. Phase 4 — test suite expansion and verification

### 4.1 New tests added in this work

| File | Tests | What it pins |
| --- | --- | --- |
| `tests/test_error_response_hygiene.py` | 3 | fixed `500` details; generic body for unexpected exceptions; leak-detector control |
| `tests/test_no_defect_markers_in_shipped_code.py` | 3 | no `TODO`/`FIXME`/`HACK` in shipped code; non-empty walk; detector control |
| `tests/test_safe_serialization_failclosed.py` | 13 | key/signature/failure branches of the guarded-pickle path — **and the nested-allow-list class that found `REG-D37`** |
| `tests/test_forwarder_sse_framing.py` | 26 | every bound in `_iter_bounded_lines`; CRLF split across transport reads; event boundaries; `_native_sse_event`; the native Anthropic relay's provider/egress/circuit-breaker paths; the whole-event cap a per-line cap cannot see |
| `tests/test_rate_limiter_reservation.py` | 35 | distributed-backend refusals (empty URL, whitespace namespace, duplicate bucket, unreachable backend, malformed reply, negative retry as infinite) and the reservation arithmetic (overage charged once, refused charge leaves the total alone, single settlement, refund/finalize below observed usage refused) |
| `tests/test_dependencies_identity_helpers.py` | 25 | role→scope mapping; Bearer extraction; the tenant comparison that must be total over Unicode; identity-object validation; domain-separated opaque credential ids |
| `tests/test_config_validation_branches.py` | 40 | every startup refusal in `aegis/config.py`, with the all-green strict configuration as the positive control |
| `tests/test_gossip_runtime_lifecycle.py` | 16 | TLS-material checks by setting name; the absent native accumulator; listener readiness; shutdown ordering; the cancel path |
| `tests/test_optional_backend_declarations.py` | +4 (23→27) | `REG-D38`: the `dev`-extra rule, the operator hint, and a tree-wide sweep over every `pytest.importorskip` |

169 tests in the eight new files, plus 4 in the existing declarations file. Every one of them
asserts the module's contract — this batch deliberately did not chase lines.

### 4.2 The order's coverage command — **met at 90.05%, exit 0**

```
before:  pytest -n auto -q --cov=aegis --cov-fail-under=90
         TOTAL   20300   2300    89%
         FAIL Required test coverage of 90% not reached. Total coverage: 88.67%

final:   pytest -n auto -q --cov=aegis --cov-precision=2 --cov-fail-under=90
         TOTAL   20298   2018  90.06%
         Required test coverage of 90% reached. Total coverage: 90.06%
         7201 passed, 115 skipped in 224.06s (0:03:44)
         EXIT: 0
```

`--cov-precision=2` is part of the final invocation because the gate's verdict is decided with
that precision and coverage.py's default of **0** rounds the total up before comparing: a run at
89.87% against a 90 floor prints `FAIL Required test coverage of 90% not reached` and still
exits **0**, because `should_fail_under(89.87, 90, 0)` is `False` while `(89.4, 90, 0)` is `True`.
That is `REG-D41`, it affects this repository's own `--cov-fail-under=65` in `Makefile:46` and
`.github/workflows/ci.yml:306-309`, and it is closed by `precision = 2` under
`[tool.coverage.report]` so every invocation inherits it.

- **284 statements newly covered** (2,300 missed → 2,019). The statement total moved by two because
  `aegis/core/safe_serialization.py` gained a docstring and no executable statements left.
- The floor was **not** raised, and this is deliberate: the repository enforces 65%
  (`Makefile:46`, `.github/workflows/ci.yml:306-309`) and a floor belongs in a release act with its
  own CI observation. CI cannot be executed on this host (`gh` absent). The 90% figure is the
  order's requirement, met on this host; the repo's floor remains the repo's.
- **Working the gap found four defects that reading had missed** — which is the argument for
  registering a measured gap rather than a conclusion:
  - **`REG-D37`** — the guarded-pickle allow-list was **inert for containers**: `_validate_allowed`
    tested `isinstance(obj, allowed)` before its recursion, and `dict`/`list` are themselves in
    `DEFAULT_ALLOWED`, so the recursion branches were unreachable and `{"k": <anything>}` passed.
    `set` payloads reach the post-load check with no `GLOBAL` opcode (`EMPTY_SET`/`ADDITEMS`), so
    that check was the only guard and it was not firing. Fixed by reordering; 7 tests fail with the
    old order restored.
  - **`REG-D38`** — the Parquet exporter's twelve tests **never ran anywhere**: nothing installs the
    `lakehouse` extra (no CI job, not in `dev`, not in `all`), so the module sat at 0% and
    `CLM-071`'s "locally tested" rested on a suite that module-level-skipped. Fixed the way the
    repository's own `pqc` precedent does it — `pyarrow` into `dev`, plus a guard that fails on any
    future silent skip.
  - **`REG-D40`** — the `metrics` extra was installed by **no** job, so seven `/metrics` tests
    skipped in every environment, including the end-to-end registry test `CLM-102` cites as its
    `LOCALLY TESTED` proof. The skip sits *inside* those tests, which is why `REG-D38`'s
    module-level sweep could not see it — it was found by checking the fix against the
    authoritative skip taxonomy (`pytest -rs`, 118 skips) rather than against the source. Fixed
    by the same rule (`prometheus-client` into `dev`); measured 44 passed / 7 skipped → 48 passed /
    3 skipped. Installing it also exposed a pre-existing order coupling in
    `tests/test_observability_new.py` (two reload tests were passing on stale globals from a
    neighbour, and would have corrupted the shared registry), fixed there with the mechanism in
    the skip reason and `raising=False` on the attributes that only exist in one branch.
  - **`REG-D41`** — the coverage gate itself: printed verdict and exit status disagreed inside a
    half-point band below the floor, for this mission's command and for the repository's own.
- **What is still uncovered, with the reason**: `aegis/proxy/app.py` (265 missed) and
  `aegis/core/crypto_audit.py` (124) need route-level and ledger-level fixtures — a project, not a
  batch; `aegis/consensus/gossip.py` (111) and `rust_integration.py` (92) are gated on the native
  extension and multi-replica transport. `AUD-38` is closed for the floor and open-ended as
  ordinary coverage debt.

### 4.3 The two tests that reded every full-suite run — diagnosed and fixed (`REG-D39`)

Both reproduced **only** under full-suite contention on this 4-core host and passed together in
33.86 s on a quiet machine. Neither was a product defect; both were assertions that depended on how
fast the machine is:

- `test_proxy_streaming.py::test_large_logical_stream_retained_memory_is_bounded` failed at
  `assert observed > 5_000_000` (`assert 2511420 > 5000000`) while its in-loop memory bound
  **passed on every iteration**. The proxy's own `max_duration_seconds=30` cap fired under load, the
  stream ended with `outcome="timeout"`, and the test could not distinguish a truncated stream from a
  completed one. Fixed by raising the cap (it is not what the test measures) and asserting the
  terminal summary — `assert outcomes == ["complete"], outcomes`; control with the cap forced to
  0.05 s makes the **new** assertion the one that fails.
- `test_audit_read_snapshot.py::test_read_endpoints_survive_concurrent_commits` failed the export
  assertion with `{"detail":"a forensic bundle is limited to 1000 nodes"}` — correct product
  behaviour, wrong workload: an unbounded writer thread ran past the documented limit while 48 reads
  and six exports executed. Fixed by bounding the writer to `number < 900` while still committing
  throughout the loop.

No bound was relaxed: `retained_bytes <= 1024+4096+512`, `peak_queue_items <= 4`,
`peak_queue_bytes <= 4096`, `calls == 1`, every `status_code == 200` and the export check all stand.

### 4.4 Rust

| Command | Result |
| --- | --- |
| `cargo clippy --all-targets --all-features --locked -- -D warnings` | **exit 0** (compiled `aegis_rust v5.0.1`) |
| `cargo test --all-features` | **not runnable by construction** — see below |
| `cargo test --release --locked` (the repository's own CI invocation) | see §4.4.1 |

`cargo test --all-features` cannot link on Linux in this repository, and the reason is documented
in the repository itself: `Cargo.toml:12-20` explains that `extension-module` must not be a
default feature because it "would also apply to `cargo test`, which then omits the libpython link
and fails with undefined `Py*` symbols", and `full = ["extension-module"]` makes `--all-features`
enable exactly that. The failure reproduced here is that documented one
(`rust-lld: error: undefined symbol: PyExc_TypeError`, …), not a code defect. CI runs
`cargo test --release` (`.github/workflows/ci.yml:429`) plus the two `zk-spartan` steps
(`:445-446`); `zk-spartan` is excluded from the default build and needs ADX, which is REG-D04's
documented Haswell limitation.

#### 4.4.1 Running the repository's own invocation on this host

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

Note the contrast with §4.4: `--all-features` cannot link (documented `extension-module`
constraint); the default-plus-`zk-spartan` invocations CI uses are the runnable surface. The
native-extension-covered portions of `rust_integration.py` are counted in §4.2's uncovered list for
the same reason.

### 4.5 Battery on the changed tree (all re-run after the last edit)

| Gate | Result |
| --- | --- |
| `pytest -n auto -q --cov=aegis --cov-precision=2 --cov-fail-under=90` | **7,201 passed / 115 skipped / 0 failed, EXIT 0**, coverage 90.06% |
| `ruff check .` | 0 findings (593 files) |
| `ruff format --check .` | 593 files already formatted |
| `mypy --strict aegis` | Success, 207 source files |
| `bandit -r aegis/ aegis_server/ -lll` | 0 findings (Low 0 / Medium 0 / High 0) |
| `verify_docs.py` | PASS, 0 findings |
| `verify_claims.py` | PASS, 105 claims, 0 findings |
| `verify_documentation.py --strict` | 0 errors, 0 warnings |
| `verify_links.sh` | PASS, 1,404 relative links and anchors resolved |
| `verify_import_reachability.py` | PASS (224 discovered / 113 reached / 34 roadmap / 77 allowlisted) |
| `verify_release_contract.py` | **READY, 14/14 anchors at 5.0.1** |
| `git diff --check` | clean |
| Rust clippy / `cargo test --release --locked` | exit 0 / 83 + 3 passed |

---

## 5. Phase 5 — commit and tag preparation

Two commits carry this work: `9dd4ab9` (the bump, the Phase-2 pinning, `REG-D35`/`REG-D36`) and the
follow-up below (the coverage closure, `REG-D37`/`REG-D38`/`REG-D39`, the register and roadmap
corrections). Tagging and pushing are **not** executed: they are release acts, the standing
directive holds the PR until every registry row is terminal, and push credentials are absent on this
host (`git push --dry-run` → "could not read Username").

```bash
# 1. stage and inspect
git add -A
git status --short
git diff --cached --stat

# 2. commit (the first commit, 9dd4ab9, is already made)
git commit -F - <<'COMMIT'
test(5.0.1): close the mission coverage floor at 90.05%, and fix what working it found

Coverage: pytest -n auto -q --cov=aegis --cov-fail-under=90 -> "Required test
coverage of 90% reached. Total coverage: 90.05%", 7189 passed / 118 skipped /
0 failed, exit 0. Was 88.67%. 284 statements newly covered by eight test files
(169 tests) written against each module's contract — the SSE framer's bounds,
the rate-limiter's refusals and reservation arithmetic, the identity helpers, the
startup-validation refusals, the gossip runtime lifecycle, the guarded-pickle
failure branches, and the extra that makes the Parquet exporter's own tests run.

The repository floor stays at 65%: raising it is a release act with its own CI
observation and gh is absent here.

Two defects found by working the gap, not by reading it:
- REG-D37: the guarded-pickle allow-list was inert for containers. _validate_allowed
  tested isinstance(obj, allowed) before its recursion, and dict/list are in
  DEFAULT_ALLOWED, so the recursion branches were unreachable and {"k": <anything>}
  passed. set payloads carry no GLOBAL opcode (EMPTY_SET/ADDITEMS), so the
  post-load check was the only guard and it never fired. Reordered; control: with
  the old order restored, 7 tests fail.
- REG-D38: the Parquet exporter's 12 tests ran nowhere — no job installs the
  lakehouse extra, so the module sat at 0% while CLM-071 rested on a suite that
  module-level-skipped. pyarrow into the dev extra (the repo's own pqc precedent),
  plus a sweep that fails on any future silent skip.

REG-D39: the two tests that reded every full-suite run here were assertions that
depended on machine speed, not defects. The streaming test truncated silently when
its own 30s duration cap fired under load (its in-loop memory bound held every
iteration); the export test's unbounded writer crossed the endpoint's documented
1000-node limit, which is correct product behaviour. Both fixed by removing the
wall-clock dependency, with one added assertion that makes truncation loud. No
bound relaxed.

Registry: 101 rows, zero open [DISC], 7 open [AUDIT] (AUD-24..AUD-30). ROADMAP
AUD-38 closed; the AUD-37 ticket's title, split by an earlier insertion, restored.
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

- That `5.0.1` is released, tagged, or published anywhere. It is not, and the tag is still owed.
- That CI runs at 90%. CI's floor is 65% and stays there; 90.06% is measured on this host, from
  this checkout, with the coverage command the order specified (`--cov-precision=2`).
- That `cargo test --all-features` was run successfully. It cannot link in this repository by
  design, and the documented one-feature cause is reproduced in §4.4.
- That `cosign verify` or `gh attestation verify` ran. Neither tool is installed on this host.
- That `REG-D37`'s allow-list is a gateway-reachable control. `aegis.core.safe_serialization` is
  allowlisted in the import-reachability gate — no production module imports it — so the exposure
  was to library callers of `safe_pickle_load`/`safe_pickle_dump`, not to the request path.
- That the three `[AUDIT]` rows still open are unimplemented features. They are `OPEN` with their
  own scope recorded; a terminal state for each is the standing directive's business, not this
  release's. (This bullet said "seven" until the second closure batch; the count is re-derived
  from `docs/REGISTRY.md` §5 — see §7.)

---

## 7. Closure progress since this log's Phase-5 record

Recorded because §3's and §6's open-set counts, and §4's suite numbers, are the state at the
Phase-5 commit — not the state of the branch. Each row below was closed after that record, one
commit per row, each with an executed evidence file under `evidence/registry/`. Nothing here
changes what §6 refuses to claim: `5.0.1` is still untagged and unpublished.

| Row | Ticket | What closed | Evidence |
| --- | --- | --- | --- |
| `REG-D28` | `AUD-24` | Rust P3 batch: two hand-written `unsafe impl Send/Sync` deleted (the compiler derives them), a 2 GiB segment ceiling checked before the file exists, the frame-arithmetic doc claim made true, `encode_state` → `Result`, size ceilings on both `zk_mmr` decoders before parsing, ring-buffer "oldest evicted" contract fixed, the unused `subtle` dependency removed, unmeasured speedup numbers removed. `cargo test --release --locked`: 90 passed / 0 failed, exit 0 (was 83). | `reg-d28_fixed.txt` |
| `REG-D29` | `AUD-25` | Module inventory: `scripts/generate_module_inventory.py` + generated `docs/MODULE_INVENTORY.md` (300 rows, kind/purpose/status/tests/owner) + `tests/test_module_inventory_current.py` (5 tests: currency, coverage, vocabulary, self-counts, roadmap agreement). Deviates from the ticket's 19-orphan count — the inventory re-derives it as 9 open tickets from the roadmap it reads. | `reg-d29_fixed.txt` |
| `REG-D30` | `AUD-26` | Claim-generating surfaces: harness labels no longer assert host-specific numbers, one shared provenance banner, three retained benchmark reports with explicit limits, and a gate (`tests/test_benchmark_claim_labels.py`) with both controls fired. | `reg-d30_fixed.txt` |
| `REG-D31` | `AUD-27` | The declared signature scheme is bound into the signed payload: `_sign_bound` selects the tier, rebuilds the payload per attempt with that tier's label appended; `HSMSigningBackend.scheme_label()` resolves the label from the key type before a signature exists; additive candidate order, so pre-binding chains still verify. 15 new tests + 5 in `test_hsm.py`. | `reg-d31_fixed.txt` |

**Suite at `REG-D31`'s commit (re-measured, not carried):** `7,233 passed, 116 skipped, 0 failed`,
coverage `90.11%` at precision 2, `EXIT: 0` — the Phase-5 section's `7,201 / 90.06%` is the
earlier commit's state and stays as history. `verify_claims` 105 · `verify_links` 1,407 ·
`verify_documentation --strict` 0 · reachability PASS · release contract READY (14/14 at `5.0.1`).

**Still owed and unchanged:** the signed tag `v5.0.1` (the register is not yet at zero open rows,
and this host has no GPG secret key), and the single PR (no push credentials on this host).

## 7. Post-merge addendum — 2026-09-24 (second re-verification pass)

The mission order behind this log was re-issued and executed a second time at
`9df5fd3`; every phase was re-verified in place, and one genuine gap was found
and closed — the baseline-currency class had recurred at this bump (`REG-D56`).

§1.5's restructure covered the thirteen artifacts whose sentences fused the
target and the publication; it did not reach the wider corpus, where 53 files
still named `5.0.0` as their checked-out source baseline. The repository-wide
currency gate could not see them: its superseded-token was pinned to `4.1.2`
(its own comment still said "because that is `5.0.0`"). This pass:

- restructured 116 sentences into the established two-fact form (target
  `5.0.1` — published nowhere, §1.0a; `v5.0.0` — most recent published
  release, §1.0), with every publication fact, readback date and review stamp
  preserved and line counts unchanged;
- extended `tests/test_documentation_currency.py` to both superseded tokens,
  framed `registr(?:y|ies)`, exempted the three dated records it would
  otherwise misread, added the `_STALE_WIRING` rule for "not wired in
  <version>" warnings, and stated the "extend at each bump" rule in the module;
- corrected the warning-string family — the 15 `**[Not wired in 5.0.0 …]**`
  config warnings, 4 preset comments, `docs/operations/DEPLOYMENT_PROFILES.md`
  and one test docstring — pinned by the new
  `test_inert_warnings_name_the_checked_out_release`;
- corrected the one lockfile copy (`dashboard/package-lock.json` line 36) and
  the two agent-facing files (`.github/copilot-instructions.md`,
  `.claude/agents/release-truth-auditor.md`);
- regenerated the AI-context manifest (83 files, anchor `fdace884…`);
- left content reviews and review stamps to `AUD-37` (dated note added there).

Re-verification results at the working tree: coverage floor reached
(`--cov=aegis --cov-fail-under=90`, **7,425 passed, 32 skipped, 0 failed,
TOTAL 91.30%, exit 0**); `cargo test --all-features` exits 101 by the
documented `extension-module` link design (CI runs the per-feature
configuration); `cargo clippy --all-targets --all-features -- -D warnings`
exit 0; zero `TODO`/`FIXME`/`HACK` markers in first-party roots (`REG-D35`
stands). Full record: `evidence/registry/baseline-currency_2026-09-24.txt`.

Release commands (the first two commits are §5; do not run the tag or push
until release is authorized — nothing is published for `5.0.1`, and `v5.0.0`
remains the most recent published release):

    git add -A
    git commit -m "docs: close the baseline-currency recurrence (REG-D56); extend the currency gate"
    git tag -a v5.0.1 -m "aegis-latent-core 5.0.1"    # release act — only on authorization
    git push origin main --follow-tags                 # publication — only on authorization


---

## 8. PR record — 2026-09-24

The commit prepared in §7's closing block above was executed after this log was
written, and the shape changed from "commit on `main`" to a reviewable branch:

- branch `fix/reg-d56-baseline-currency`; commit
  `f7dd42f58b0a11aba6e985d2a3c3e76769d85ab3` (70 files changed, +671/−164), the
  message carrying the full change inventory;
- pushed to `origin`; the remote head was read back equal to the local commit;
- opened as **PR #199** — `https://github.com/JuanLunaIA/aegis-latent-core/pull/199`,
  base `main`, not a draft — with the verification table (full suite
  7,425/32/0 at 91.30%, gates green, contract READY 14/14) and the
  nothing-published boundary in the body; CI checks were pending at open time.

This subsumes the earlier credential statements in this log (§5: "push
credentials are absent on this host"; §7: "the single PR (no push credentials on
this host)"): both were true when written and are not true now — GitHub
credentials are configured on this host and the push was verified by readback.

The tag and every release act remain **unexecuted and unauthorized**: `5.0.1` is
still unpublished, and `v5.0.0` remains the most recent published release. The
commands actually used (superseding §7's first two lines; the tag/merge lines
wait for release authorization):

    git switch -c fix/reg-d56-baseline-currency
    git add -A
    git commit -F <message-file>
    git push -u origin fix/reg-d56-baseline-currency
    # merge PR #199; then, only on release authorization: git tag -a v5.0.1
