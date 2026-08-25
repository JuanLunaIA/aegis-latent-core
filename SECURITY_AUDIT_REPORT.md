Security Audit Report — Aegis Latent Core
=========================================

> **Historical archive.** This automated report is retained for the historical
> run it describes. Its findings and remediation notes are not a statement of
> current v4 status and are superseded for current navigation by the
> [v4 evidence index](artifacts/v4-enterprise-maturation-2026-08-23/EVIDENCE.md),
> which records newer gates, bounded evidence, and unresolved external blockers.

Summary (automated findings)
-----------------------------

- Repository scanned for common sensitive patterns (API keys, secrets): none found.
- Many `FIXME` and `TODO` markers present across the codebase — technical debt hotspots.
- Dangerous patterns found in multiple files: `exec(`, `eval(`, `pickle.load` — these require manual review when handling untrusted inputs.
- Rust extension build failed in CI environment: linker errors referencing Python C API symbols (PyObject_Str, _Py_IncRef, PyErr_Print, etc.). Likely root causes:
  - Missing libpython development headers / shared library (install `libpythonX.Y-dev` / `pythonX.Y-dev`), or
  - PyO3 version mismatch with the local Python runtime (Python 3.14 vs PyO3 max supported 3.13), or
  - Building with `cargo test` attempts a different linking mode than `maturin develop`.
- Local developer environment lacked static tools (ruff, mypy, bandit, pip-audit, pytest) — CI should run these in a controlled matrix.
- GPG signing of commits failed in the runner due to pinentry timeout. Local key agents must be configured for non-interactive signing in CI, or disable commit signing in automation.

Immediate remediation (practical)
---------------------------------

1. Rust build errors
   - Install Python development headers for the Python ABI you plan to use (e.g. `sudo apt install python3.11-dev` or the equivalent for your distro).
   - Prefer building the PyO3 extension with maturin in a matching virtualenv, or run the CI workflow which uses setup-python + maturin.
   - Short-term workaround: set `PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1` before building (documented in docs/RUST_BUILD.md). This allows building against ABI3 and mitigates PyO3 version checks when appropriate.

2. Unsafe serialisation / dynamic execution
   - Audit all occurrences of `pickle.load`, `exec`, `eval` and `os.system` for usage with untrusted data.
   - Replace `pickle` with `json` or `msgpack` for on-disk interchange when possible.
   - If `pickle` is required, restrict inputs to signed, authenticated artifact bundles and validate integrity prior to un-pickling.

3. Developer tooling and CI
   - Add a GitHub Actions workflow `forensic.yml` to run `ruff`, `mypy`, `bandit`, `pip-audit`, `pytest` (matrix across Python 3.11–3.13) and a Rust build step using `maturin`.
   - Ensure the workflow sets `PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1` or uses a supported Python version.

4. Secrets and signing
   - Do not store signing keys or private keys in the repo. Ensure `AEGIS_SIGNING_KEY` is injected in production environment variables or a secrets manager.
   - For non-interactive commits in automation, either configure git to not GPG-sign commits, or provide a signing agent with unlocked keys accessible to the runner.

Files added by this run
-----------------------

- tools/visualizer/* — a lightweight dashboard that summarises Python/Rust symbols and shows a flowchart of the main components.
- tools/forensic/forensic_checks.py — automated forensic checks capturing pattern hits, syntax errors, and a Rust-build attempt (report written to tools/forensic/report.json).
- aegis/core/rust_integration.py — runtime helper wrappers to safely attempt use of aegis_rust where available (non-fatal if missing).

How to reproduce locally (developer)
------------------------------------

# 1. Run the forensic checks
python tools/forensic/forensic_checks.py
# Review tools/forensic/report.json

# 2. Try building the Rust extension (recommended inside a matching venv)
export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1
cd aegis_rust_v2
maturin develop --release

# 3. Run quick visualizer
pip install -r tools/visualizer/requirements.txt
uvicorn tools.visualizer.app:app --reload --port 8081
Open http://localhost:8081/

Notes for sensitive audiences
-----------------------------

- For governments / military / medical deployments, consider an HSM or KMS for `AEGIS_SIGNING_KEY` and strictly controlled key rotation and auditing.
- For forensic and legal admissibility, record full chain of custody (timestamps, hashes, signer identity) and store signed SBOMs with release artifacts.

Actions taken in this run
-------------------------

- Added tools/forensic/triage_unsafe.py to enumerate risky API usage and generate remediation guidance (tools/forensic/unsafe_remediation.md when run).
- Added aegis/core/safe_serialization.py offering safe JSON helpers and a guarded pickle loader that enforces allowed primitive types.
- Added scripts/build_rust.sh to streamline maturin-based builds in an isolated venv and fail early when compilers/toolchain are missing.
- Enhanced tools/visualizer with documentation and snapshots (tools/visualizer/test_results.json, tools/visualizer/summary.json) to make the dashboard ready-to-run.
- Implemented lazy-loading for aegis.core to allow lightweight tooling and unit tests to run without heavy optional dependencies.

Recommended immediate next steps:
- Run the CI workflow (.github/workflows/forensic.yml) on GitHub to collect full build artifacts and address any remaining Rust linking errors.
- Create targeted PRs for critical TODO/FIXME markers (security, chain-of-custody blockers) listed in TODO_ISSUES.md.
- Consider pinning or upgrading PyO3 only after CI confirms the target Python matrix and toolchain availability.

