Rust extension build notes (aegis_rust_v2)
=========================================

This document explains common issues encountered when building the PyO3 Rust
extension (`aegis_rust_v2`) and practical steps to build it in developer
and CI environments.

Common failure: undefined references to Python C API symbols (PyObject_Str, _Py_IncRef, PyErr_Print, etc.)
-----------------------------------------------------------------------------------------------------

Symptoms:
- Linker errors from `cc` when running `cargo test` or `maturin develop`.
- The cargo build output shows undefined reference to PyObject_* functions.

Likely causes and fixes:

1) Missing Python development headers / shared library
   - Install the Python dev package for your target interpreter, e.g. on Debian/Ubuntu:
     sudo apt-get install python3.11-dev
   - Ensure the python executable and headers match (python3.11 vs python3.14).

2) PyO3 / Python version mismatch
   - PyO3 has a maximum supported Python version for the built release. If
     building with newer Python (e.g., 3.14) and pyo3 version doesn't support
     it, either set `PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1` or upgrade PyO3.
   - Example (temporary):
     export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1
     maturin develop --release

3) Prefer maturin over raw cargo for extension builds
   - `maturin develop` handles Python interpreter discovery and linking more
     robustly and is the recommended method to build and install the extension.

4) Use a matching virtualenv for the target Python
   - Create a virtualenv with the Python version you intend to support and
     activate it before running maturin. This ensures headers and the
     interpreter match during the build.

Example developer steps (recommended):

python -m venv .venv
source .venv/bin/activate
python -m pip install -U pip maturin
export PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1  # optional workaround
cd aegis_rust_v2
maturin develop --release

CI recommendations
------------------
- Use GitHub Actions with a matrix for Python 3.11–3.13 and a single, stable
  Rust toolchain (e.g. stable). Prefer to run maturin in each job.
- Set environment variable PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1 only if you
  intentionally target ABI3 forward compatibility. Otherwise pin PyO3 to a
  version that supports the chosen Python versions.

Advanced: upgrading PyO3
------------------------
- Upgrading pyo3 in Cargo.toml may be required to support newer Python
  interpreter versions. This change can have implications: test the compiled
  extension thoroughly and run Rust unit tests.

