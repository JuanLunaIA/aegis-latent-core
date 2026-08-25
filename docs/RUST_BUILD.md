# Rust Extension Build Guide

**Last verified:** 2026-08-25 UTC
**Release baseline:** two-baseline model
**Source baseline:** merged v4 source state verified by [`evidence/v4_0_0_post_merge_release_readiness_2026-08-25.md`](../evidence/v4_0_0_post_merge_release_readiness_2026-08-25.md)
**Distribution baseline:** previously published `v3.1.0` artifacts; no distribution is asserted for the source baseline

The Rust component has four different names. Keeping them distinct prevents broken imports and incorrect distribution claims.

| Concept | Name | Source of truth |
|---|---|---|
| Source directory | `aegis_rust_v2/` | Repository layout; the suffix is historical and is not an import name. |
| Cargo package and library | `aegis_rust` | `aegis_rust_v2/Cargo.toml` `[package]` and `[lib]` |
| Python wheel distribution metadata | `aegis-rust` | `aegis_rust_v2/pyproject.toml` `[project].name` |
| Python import module | `aegis_rust` | maturin `module-name` and PyO3 module declaration |

No crates.io, PyPI, or other registry availability is asserted for this v4 source baseline. Build from the checked-out source.

## Prerequisites

Use Python 3.11 or newer, a Rust toolchain with Cargo, a C compiler/linker, and maturin 1.x. On Debian or Ubuntu, a matching Python development package may be needed when the interpreter does not provide usable headers and link metadata.

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install 'maturin>=1.5,<2'
rustc --version
cargo --version
maturin --version
```

The maturin install above downloads a build tool; record the resolved version for reproducibility. It is not an installation of an Aegis registry package.

## Run Rust tests

Run Cargo from the repository root so the source-directory name is explicit:

```bash
cargo fmt --manifest-path aegis_rust_v2/Cargo.toml -- --check
cargo clippy --manifest-path aegis_rust_v2/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path aegis_rust_v2/Cargo.toml --release --locked
```

`cargo test` uses the library configuration without making PyO3's `extension-module` feature the default, allowing the test binary to link correctly.

## Build and install the Python extension locally

```bash
maturin develop --manifest-path aegis_rust_v2/Cargo.toml --release --features extension-module
python -c 'import aegis_rust; print(aegis_rust.__version__)'
```

The import is `aegis_rust`, never `aegis_rust_v2` and never `aegis-rust`. The hyphenated spelling is only the Python distribution metadata name.

To produce a local wheel without publishing it:

```bash
maturin build --manifest-path aegis_rust_v2/Cargo.toml --release --features extension-module
```

The wheel is written under `aegis_rust_v2/target/wheels/`. A successful local build is not registry publication, platform-wide compatibility, constant-time evidence, FIPS validation, or target-runtime acceptance.

## Python and PyO3 compatibility failures

Undefined references to Python C API symbols usually mean the interpreter, headers, and link metadata do not match, or that `extension-module` was applied to a Cargo test binary. Prefer `maturin develop` for the extension and plain `cargo test --release --locked` for Rust tests. Activate the intended virtual environment before building.

`PYO3_USE_ABI3_FORWARD_COMPATIBILITY=1` is an explicit compatibility override, not a default recommendation. Use it only when intentionally testing a newer interpreter against the configured `abi3-py311` boundary, then run the Rust and Python integration tests and record that environment.

## Related documents

- [`docs/DEVELOPER_QUICKSTART.md`](DEVELOPER_QUICKSTART.md)
- [`docs/REPOSITORY_MAP.md`](REPOSITORY_MAP.md)
- [`evidence/INDEX.md`](../evidence/INDEX.md)
- [`aegis_rust_v2/Cargo.toml`](../aegis_rust_v2/Cargo.toml)
- [`aegis_rust_v2/pyproject.toml`](../aegis_rust_v2/pyproject.toml)
