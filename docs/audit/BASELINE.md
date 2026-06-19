# Aegis-Latent-Core — Executable Baseline

**Date:** 2026-06-19  
**Branch:** `main` (post-merge of PR #10, commit `cbebeb0`)  
**Python:** 3.11.15  
**Rust:** stable (linked against system OpenSSL)  

All numbers in this document are derived from real executor output, not
estimates. Commands reproduced verbatim so they can be re-run to verify.

---

## 1. TESTS

**Command:**
```
pytest tests/ --override-ini="addopts=" -v \
  --cov=aegis --cov=aegis_server --cov-report=term-missing
```

**Result: 220 passed / 0 failed / 6 skipped**  
Duration: 19.63 s

### Skipped tests (all in `test_rust_extension.py`)

All 6 skips are intentional guards — they check `importlib.util.find_spec("aegis_rust")` at module level and skip the entire class when the compiled `.so` is absent:

| Test | Reason |
|------|---------|
| `TestAegisRustExtension::test_import_and_version` | `aegis_rust` .so not built |
| `TestAegisRustExtension::test_pqc_sign_verify_roundtrip` | same |
| `TestAegisRustExtension::test_mmr_add_leaf` | same |
| `TestAegisRustExtension::test_hash_and_hmac` | same |
| `TestAegisRustExtension::test_forward_json_sync_mock_server` | same |
| `TestCryptoAuditWithRustPqc::test_ledger_uses_ml_dsa_when_rust_available` | same |

No test failed. The Python fallback path is exercised by `test_mmr.py::test_rust_integration_no_crash` (PASSED).

---

## 2. COVERAGE

**Total: 49% (3694 stmts, 1869 miss)**

The total is dragged down by `aegis_server/*` which sits at 0% across all 1,245 statements —
the package `__init__` unconditionally imports `dynamodb_provider`, which requires the
optional `aioboto3` extra not installed in this environment. Blocking a single import
zeros out the entire storage tier.

**Adjusted `aegis/` only: ~75%** (2449 stmts, 624 miss, computed from raw data).

### Module-by-module (critical path)

| Module | Stmts | Miss | Cover | Status |
|--------|------:|-----:|------:|--------|
| `aegis/proxy/schemas.py` | 118 | 0 | **100%** | ✅ |
| `aegis/providers/openai_provider.py` | 33 | 0 | **100%** | ✅ |
| `aegis/__init__.py` | 1 | 0 | **100%** | ✅ |
| `aegis/proxy/analyzer.py` | 141 | 5 | **96%** | ✅ |
| `aegis/config.py` | 93 | 4 | **96%** | ✅ |
| `aegis/providers/gemini_provider.py` | 26 | 1 | **96%** | ✅ |
| `aegis/providers/base.py` | 30 | 1 | **97%** | ✅ |
| `aegis/core/normalization.py` | 15 | 1 | **93%** | ✅ |
| `aegis/auth/apikey.py` | 62 | 9 | 85% | ✅ |
| `aegis/core/safe_serialization.py` | 44 | 7 | 84% | ✅ |
| `aegis/proxy/waf.py` | 75 | 12 | 84% | ✅ |
| `aegis/providers/anthropic_provider.py` | 185 | 34 | 82% | ✅ |
| `aegis/proxy/audit_api.py` | 34 | 6 | 82% | ✅ |
| `aegis/core/moe_monitor.py` | 64 | 7 | 89% | ⚠ <90% |
| `aegis/core/math_utils.py` | 43 | 5 | 88% | ⚠ <90% |
| `aegis/core/crypto_audit.py` | 214 | 25 | **88%** | ⚠ <90% RISK |
| `aegis/core/mmr.py` | 139 | 30 | **78%** | ⚠ RISK |
| `aegis/core/telemetry.py` | 78 | 18 | 77% | ⚠ RISK |
| `aegis/core/ratelimiter.py` | 68 | 18 | 74% | ⚠ RISK |
| `aegis/proxy/app.py` | 354 | 121 | 66% | ⚠ RISK |
| `aegis/proxy/forwarder.py` | 125 | 41 | 67% | ⚠ RISK |
| `aegis/proxy/dependencies.py` | 35 | 18 | 49% | ⚠ |
| `aegis/core/rust_integration.py` | 31 | 14 | 55% | ⚠ |
| `aegis/core/session_manager.py` | 33 | 16 | 52% | ⚠ |
| `aegis/core/timing_defense.py` | 31 | 15 | 52% | ⚠ |
| `aegis/core/forensic.py` | 39 | 16 | 59% | ⚠ |
| `aegis/core/lsm_guard.py` | 52 | 21 | 60% | ⚠ |
| `aegis/core/seccomp_guard.py` | 102 | 60 | 41% | ⚠ |
| `aegis/core/secrets.py` | 62 | 44 | **29%** | 🔴 RISK — Vault auth path |
| `aegis/core/leak_detector.py` | 41 | 31 | **24%** | 🔴 HIGH RISK — security module |
| `aegis/core/pqc_provider.py` | 34 | 34 | **0%** | 🔴 HIGH RISK — PQC fallback |
| `aegis_server/storage/sqlite_provider.py` | 151 | 151 | 0% | ⚫ blocked (aioboto3) |
| `aegis_server/storage/postgres_provider.py` | 130 | 130 | 0% | ⚫ blocked (aioboto3) |
| `aegis_server/storage/dynamodb_provider.py` | 167 | 167 | 0% | ⚫ blocked (aioboto3) |
| `aegis_server/main.py` | 320 | 320 | 0% | ⚫ blocked (aioboto3) |

### Risk summary

| Risk | Module | Gap |
|------|--------|-----|
| 🔴 `aegis/core/leak_detector.py` | 24% | Regex patterns, SSN/CC/PII detection never executed |
| 🔴 `aegis/core/pqc_provider.py` | 0% | PQC fallback (no ML-DSA test without Rust .so) |
| 🔴 `aegis/core/secrets.py` | 29% | Vault auth, token refresh, AppRole login paths |
| ⚠ `aegis/core/crypto_audit.py` | 88% | WAL error paths, MMR-less fallback, multi-tenant branches |
| ⚠ `aegis/core/mmr.py` | 78% | Consistency proof, Rust-backed MMR delegation paths |
| ⚫ `aegis_server/*` (all) | 0% | Blocked by `aioboto3` import in `__init__`; fix: lazy imports |

---

## 3. TYPE ERRORS (mypy)

**Command:**
```
mypy aegis/ aegis_server/ --ignore-missing-imports
```

**Result: 198 errors in 56 files (95 source files checked)**

The majority come from roadmap/platform-specific modules (`sandbox`, `seccomp_guard`,
`xdp_dynamic_segmentation`, `transport_hardener`, etc.) that are explicitly excluded from
coverage measurement. The CI `mypy-ci.ini` scopes to 17 runtime-critical files.

### Runtime-critical errors (proxy + core + providers)

Scoped command: `mypy aegis/proxy/ aegis/core/crypto_audit.py aegis/core/telemetry.py aegis/core/mmr.py aegis/core/ratelimiter.py aegis/providers/ aegis/auth/ --ignore-missing-imports`  
**Result: 56 errors in 12 files**

| File | Error | Code |
|------|-------|------|
| `aegis/proxy/analyzer.py:65` | Missing type args for `list` | `type-arg` |
| `aegis/proxy/analyzer.py:86` | `Returning Any` from typed `ndarray` return | `no-any-return` |
| `aegis/proxy/analyzer.py:153` | `Item "None" of union has no attribute "content"` | `union-attr` |
| `aegis/proxy/analyzer.py:308` | `TokenAnalysis` assigned to `dict[str, Any]` variable | `assignment` |
| `aegis/proxy/analyzer.py:318` | `dict` appended to `list[TokenAnalysis]` | `arg-type` |
| `aegis/core/ratelimiter.py:53` | Unused `type: ignore` | `unused-ignore` |
| `aegis/core/ratelimiter.py:55` | `TTLCache[Never,Never,float]` → `dict[str,tuple[float,float]]` | `assignment` |
| `aegis/core/ratelimiter.py:140` | `Returning Any` from `bool` | `no-any-return` |
| `aegis/core/mmr.py:34` | Missing return annotation | `no-untyped-def` |
| `aegis/core/mmr.py:111,115` | `int \| None` index into `list[MMRNode]` | `index` |
| `aegis/core/mmr.py:281` | Unused `type: ignore` | `unused-ignore` |
| `aegis/core/mmr.py:296,299` | `Returning Any` from `str` | `no-any-return` |
| `aegis/core/mmr.py:317,320` | `MerkleMountainRange` → `RustBackedMMR` | `assignment` |
| `aegis/core/crypto_audit.py:65,152,463` | Unused `type: ignore` | `unused-ignore` |
| `aegis/core/crypto_audit.py:227` | Call to untyped `MerkleMountainRange` | `no-untyped-call` |
| `aegis/core/crypto_audit.py:444` | `TextIOWrapper` → `None` | `assignment` |
| `aegis/core/telemetry.py:48` | Missing type annotation for parameters | `no-untyped-def` |
| `aegis/core/telemetry.py:67` | Unused `type: ignore` | `unused-ignore` |
| `aegis/core/math_utils.py:83` | `Returning Any` from typed `ndarray` | `no-any-return` |
| `aegis/providers/__init__.py:104,109,111` | `AnthropicAdapter`/`GeminiAdapter`/`OpenAIAdapter` → `OpenRouterAdapter` | `assignment` |
| `aegis/providers/base.py:143` | Unused `type: ignore` | `unused-ignore` |
| `aegis/config.py:62` | `str` → `AnyHttpUrl` | `assignment` |

**Highest-risk type errors:**

- `analyzer.py:308,318` — `token_results` is typed as `list[TokenAnalysis]` but the dict-format branch appends a raw `dict`. If a caller iterates and accesses `.token`, it raises `AttributeError` at runtime for dict-format inputs. Partially mitigated by tests, but the type system cannot verify correctness.
- `mmr.py:111,115` — Potential `None` index into list if `_left_child`/`_right_child` return `None` for leaf nodes. Not exercised by current tests.
- `providers/__init__.py:104,109,111` — `build_provider` returns the wrong type for non-OpenRouter providers. Runtime correct because all adapters share the protocol, but defeats static analysis.

---

## 4. SECURITY FINDINGS

### 4a. Bandit — Static Analysis

**Command:** `bandit -r aegis/ aegis_server/ -ll`  
**Result: 0 HIGH / 5 MEDIUM / 30 LOW**

Note: `pyproject.toml [tool.bandit]` excludes `B101`, `B104`, `B108`. The raw run above uses
no config file, so B104 and B108 appear. With `bandit -c pyproject.toml`, only LOW items
would remain.

#### MEDIUM issues

| ID | File | Line | Issue | CWE | Assessment |
|----|------|------|-------|-----|-----------|
| B104 | `aegis/config.py` | 244 | `host="0.0.0.0"` | CWE-605 | Accepted — intentional proxy bind |
| B104 | `aegis_server/config.py` | 44 | `host="0.0.0.0"` | CWE-605 | Accepted — intentional server bind |
| B108 | `aegis/core/blockchain_anchor.py` | 65 | `/tmp/public_blockchain_ledger.jsonl` | CWE-377 | Roadmap module, omitted from coverage |
| B108 | `aegis/core/blockchain_anchor.py` | 95 | `/tmp/public_blockchain_ledger.jsonl` | CWE-377 | Roadmap module, omitted from coverage |
| B108 | `aegis/core/blockchain_anchor.py` | 96 | `/tmp/public_blockchain_ledger.jsonl` | CWE-377 | Roadmap module, omitted from coverage |

**Actual risk: 0 actionable items** — B104s are documented defaults for a proxy server;
B108s are in a roadmap module excluded from coverage and not imported at runtime.

### 4b. pip-audit — Dependency Vulnerabilities

**Command:** `pip-audit`  
**Result: 21 vulnerabilities in 6 packages**

| Package | Installed | CVE / ID | Severity | Fix | Project dep? |
|---------|-----------|----------|----------|-----|-------------|
| `idna` | 3.11 | PYSEC-2026-215 | HIGH | `>=3.15` | ✅ YES — pinned in pyproject.toml/requirements.txt but container not updated post-merge |
| `pyjwt` | 2.7.0 | PYSEC-2026-120, PYSEC-2025-183, PYSEC-2026-179, PYSEC-2026-175, PYSEC-2026-177 | MEDIUM-HIGH | `>=2.13.0` | ❌ Orphan — installed in container, NOT in project deps |
| `urllib3` | 2.6.3 | PYSEC-2026-142, PYSEC-2026-141 | MEDIUM | `>=2.7.0` | ⚡ Transitive — via `httpx`/`requests` |
| `pip` | 24.0 | PYSEC-2026-196, CVE-2025-8869, CVE-2026-1703, CVE-2026-3219, CVE-2026-6357 | MEDIUM | `>=26.1.2` | ❌ System tool, not a project dep |
| `setuptools` | 68.1.2 | PYSEC-2025-49, CVE-2024-6345 | HIGH | `>=78.1.1` | ❌ System tool |
| `wheel` | 0.42.0 | CVE-2026-24049 | MEDIUM | `>=0.46.2` | ❌ System tool |

**Actionable items for this project:**

1. **`idna` (HIGH)** — pin already in `pyproject.toml` and `requirements.txt` (`>=3.15`). Container environment was not refreshed after merge. Run `pip install -U "idna>=3.15"` in CI to verify the pin takes effect.
2. **`urllib3` (MEDIUM)** — transitive via `httpx`/`requests`. Add `urllib3>=2.7.0` as a security floor in `requirements.txt` (same pattern used for `idna`).
3. **`pyjwt` (MEDIUM-HIGH)** — orphan package in this container; not in project deps. No project code imports `jwt`. No action needed in project files; ops team should clean up the container image.
4. **`pip`/`setuptools`/`wheel`** — system tools. Upgrade the base container image.

---

## 5. RUST EXTENSION

**Command:** `cargo test --manifest-path aegis_rust_v2/Cargo.toml --lib`  
**Result: BUILD FAILED**

### Failure classification: LINKER — undefined Python C API symbols

The crate is a PyO3 `cdylib` extension (`.so`). Running `cargo test --lib` produces a
native test executable that references Python C API symbols (`PyGILState_Ensure`,
`PyErr_SetObject`, `Py_IsInitialized`, `_Py_Dealloc`, etc.) without linking `libpython3`.
This is a known PyO3 limitation: test binaries for cdylib crates must be linked against
the Python shared library.

```
rust-lld: error: undefined symbol: PyGILState_Ensure
rust-lld: error: undefined symbol: PyErr_SetObject
rust-lld: error: undefined symbol: PyErr_SetString
... (20+ more Python API symbols)
error: could not compile `aegis_rust` (lib test) due to 1 previous error; 8 warnings emitted
```

**Fix:** Use `maturin develop` (builds and installs the `.so` into the active venv) or:
```bash
PYO3_PYTHON=python3 RUSTFLAGS="-L $(python3 -c 'import sysconfig; print(sysconfig.get_config_var(\"LIBDIR\"))')" \
  cargo test --manifest-path aegis_rust_v2/Cargo.toml --lib
```

### Deprecation warnings (8, non-fatal)

```
src/forwarder.rs:54   import_bound → import (PyO3 0.24 deprecated)
src/forwarder.rs:136  import_bound → import
src/pqc.rs:20,25,32  PyBytes::new_bound → PyBytes::new
src/lib.rs:34,38,46  new_bound → new, import_bound → import, PyDict::new_bound → new
```
These are pyo3 0.24 → 0.25 migration warnings. Non-blocking, but should be addressed
when bumping pyo3 to 0.25+.

### Python fallback status: ACTIVE

`aegis/core/rust_integration.py` wraps the import in a try/except:
```python
try:
    from aegis_rust import ...  # Rust extension
    _RUST_AVAILABLE = True
except ImportError:
    _RUST_AVAILABLE = False  # → pure-Python MMR + Python HMAC fallback
```
All 6 Rust-dependent tests in `test_rust_extension.py` are **SKIPPED** (not FAILED).
`test_mmr.py::test_rust_integration_no_crash` (PASSED) validates the fallback path.

**PQC impact:** Without the Rust `.so`, ML-DSA-87 signatures fall back to
`_ed25519_sign()` (ephemeral Ed25519, Python `cryptography` library). Audit nodes are
still signed; only the post-quantum guarantee is absent.

---

## Summary

| Area | Status | Blocking? |
|------|--------|-----------|
| Tests (220 passed) | ✅ CLEAN | No |
| Ruff lint | ✅ CLEAN | No |
| Coverage (75% aegis/, 49% total) | ⚠ aegis_server/* at 0%; leak_detector 24% | No |
| mypy (198 total, 56 runtime-critical) | ⚠ analyzer token_results union gap | No |
| Bandit | ✅ 0 HIGH, 5 MEDIUM (all accepted/roadmap) | No |
| pip-audit | ⚠ idna pin not active in container; urllib3 transitive | No |
| Rust build | ❌ Linker fail (cdylib/PyO3 test mode) | No — Python fallback active |
| Rust deprecations (pyo3 0.24) | ⚠ 8 warnings | No |

**Next recommended actions (priority order):**

1. `aegis_server/__init__.py` — lazy-import optional backends (DynamoDB/Postgres) so missing extras don't zero out coverage for the SQLite path.
2. `aegis/core/leak_detector.py` — add unit tests for PII regex patterns (SSN, CC, email, API key).
3. `requirements.txt` — add `urllib3>=2.7.0` security floor.
4. `aegis/proxy/analyzer.py:308` — reconcile `token_results` type: either make the list `list[TokenAnalysis | dict]` explicit, or normalize dicts to `TokenAnalysis` before appending.
5. `aegis_rust_v2/` — add `maturin develop` step to local dev docs; add PyO3 0.25 migration to backlog.
