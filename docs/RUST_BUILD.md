# Rust Extension Build Guide

**Last verified:** 2026-08-27 UTC
**Release baseline:** four-layer truth model
**Source baseline:** checked-out Rust and Python package metadata is synchronized at `v4.1.2`
**Immutable comparison source:** `fdace8844568eb788216740b2cb5daf187d99d3b` retains the historical `4.0.0` comparison anchors documented by [`evidence/v4_0_0_post_merge_release_readiness_2026-08-25.md`](../evidence/v4_0_0_post_merge_release_readiness_2026-08-25.md)
**External lifecycle boundary:** source metadata and a successful local build do not prove a tag, GitHub Release, registry package, OCI image, deployment, or acceptance; verify each surface by external readback
**Historical evidence baseline:** previously published `v3.1.0` artifacts remain historical

The Rust component has four different names. Keeping them distinct prevents broken imports and incorrect distribution claims.

| Concept | Name | Source of truth |
|---|---|---|
| Source directory | `aegis_rust_v2/` | Repository layout; the suffix is historical and is not an import name. |
| Cargo package and library | `aegis_rust` | `aegis_rust_v2/Cargo.toml` `[package]` and `[lib]` |
| Python wheel distribution metadata | `aegis-rust` | `aegis_rust_v2/pyproject.toml` `[project].name` |
| Python import module | `aegis_rust` | maturin `module-name` and PyO3 module declaration |

No crates.io availability is inferred from source metadata. The compiled `aegis_rust` extension is published only as the seven platform wheels attached to the GitHub Release; it is not a separate registry package. `aegis-latent-core` on PyPI is the pure-Python distribution and does not carry the compiled extension. Build from the checked-out source unless external registry readback establishes an artifact and its provenance.

## What is pure Python and what the extension changes

The published `aegis-latent-core` wheel is `py3-none-any`. **The complete
feature set runs on pure Python** — WAF, redaction, the signed ledger, the MMR,
portable proofs, embedded mode and the gateway entry points all work with no
compiler, no toolchain and no native dependency. Nothing in this document is
required to run Aegis.

`aegis_rust` is an optional accelerator. It is not published to crates.io, PyPI
or any other registry, and it is not inside the PyPI wheel: it is built from
this source tree, or taken from the seven platform wheels attached to the
GitHub Release. Building it is a deliberate act, not a missing step.

What it changes, measured rather than estimated, is throughput on the hashing
and matching hot paths — see [Verified metrics](../README.md#verified-metrics)
for the figures and the harness that produced them, each attributed to a dated
run rather than quoted as a headline. What it does **not** change is any
evidence value: the Python and Rust MMR implementations agree on the root, a
property pinned by a cross-implementation test rather than assumed, so a proof
issued by one verifies under the other and a ledger is portable between them.

Post-quantum ML-DSA-65 signing is reached through the extension. Its verify
path has not been established as constant-time; see
[PQC constant-time analysis](security/PQC_CONSTANT_TIME.md) for the bounded
statement and what remains open.

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
