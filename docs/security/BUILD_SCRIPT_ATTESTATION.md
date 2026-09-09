# Build-script and native-code attestation

Every crate in this repository's Rust trees that runs a `build.rs` at compile
time, links a native library, or compiles bundled C, with a statement of what
it is for and why it is not removable.

A build script runs with the privileges of the person or runner building the
software. That makes the set of crates holding one a real part of the attack
surface — and it also makes it a set that must not be pruned on suspicion,
because most of these are load-bearing and removing one breaks the build in a
way that invites a worse workaround.

## How this list was derived

Not from a scanner and not from crate names. Each locked crate's source was
read from `CARGO_HOME/registry/src` and included here if any of the following
held:

- its `Cargo.toml` declares a `build` key, or a `build.rs` sits at its root;
- its `Cargo.toml` declares a `links` key, meaning it claims a native library;
- it ships `.c`, `.cc`, `.cpp`, `.S` or `.asm` sources.

That yielded **52 crates** across `aegis_rust_v2/Cargo.lock` and
`connectors/envoy-wasm/Cargo.lock`. `scripts/triage/dependency_triage.py`
classifies the same set as `BUCKET-4` and will surface a new one on the next
run.

## Boundary

**This is an inventory with rationale, not an attestation in the cryptographic
sense.** Nothing here is signed, and nothing here verifies that the source in
`CARGO_HOME` matches what upstream published beyond the SHA-256 checksum Cargo
already records in `Cargo.lock` and enforces on fetch. The phrase "known-good
upstream" below means "the well-known crate of that name, at a version pinned
by checksum in our lock file" — it does not mean the build script's behaviour
was audited line by line. Where that distinction matters to a reader, it is the
weaker reading that is correct.

## Cryptography and randomness

| crate | version | mechanism | purpose | why it stays |
| --- | --- | --- | --- | --- |
| `blake3` | 1.8.5 | build.rs + C/assembly | BLAKE3 content hashing for request/response binding | the SIMD assembly is the reason it is used at all; the portable fallback would remove the performance argument |
| `ring` | 0.17.14 | build.rs, `links=ring_core_0_17_14_` | constant-time primitives under `rustls` | transitive under the TLS stack; not directly selected |
| `openssl-sys` | 0.9.117 | build.rs, `links=openssl` | locates or builds libssl/libcrypto | required by `native-tls` on Linux |
| `openssl` | 0.10.81 | build.rs | safe bindings over the above | as above |
| `openssl-src` | 300.6.1+3.6.3 | bundled C | builds OpenSSL from source | this is what `native-tls-vendored` uses to statically link OpenSSL, which is what makes the released wheels self-contained and cross-compilable; removing it reintroduces a host-libssl dependency |
| `getrandom` | 0.3.4, 0.4.3 | build.rs | OS entropy source selection per platform | the build script picks the syscall interface; there is no pure-Rust substitute for OS entropy |
| `rustls` | 0.23.41 | build.rs | TLS implementation | transitive under `reqwest` |
| `pqcrypto-mldsa` | 0.1.2 | build.rs + bundled C | ML-DSA-65 (FIPS 204) signing, from PQClean | the post-quantum signing path; see the migration note below |
| `pqcrypto-internals` | 0.2.11 | build.rs, `links=pqcrypto_internals` | shared PQClean FFI support | required by the above |

**Migration note.** `pqcrypto-mldsa`, `pqcrypto-internals` and `pqcrypto-traits`
carry RUSTSEC unmaintained notices (`RUSTSEC-2026-0166`, `-0163`, `-0162`)
because upstream PQClean is being archived. They are attested here as present
and required today; `docs/security/DEPENDENCY_RISK_REGISTER.md` records the
residual risk and the migration this implies.

## Python and WASM bindings

| crate | version | mechanism | purpose | why it stays |
| --- | --- | --- | --- | --- |
| `pyo3` | 0.29.0 | build.rs, `links=pyo3-python` | Python extension bindings | the build script probes the interpreter ABI; this crate *is* the Python boundary |
| `pyo3-ffi` | 0.29.0 | build.rs, `links=python` | raw CPython ABI | as above |
| `target-lexicon` | 0.13.5 | build.rs | target-triple parsing for the above | pulled by `pyo3-build-config` |
| `proxy-wasm` | 0.2.5 | build.rs | Envoy proxy-wasm ABI | the Envoy connector's entire reason to exist |
| `wasm-bindgen` | 0.2.126 | build.rs | JS/WASM glue | transitive in the WASM tree |
| `wasm-bindgen-shared` | 0.2.126 | build.rs, `links=wasm_bindgen` | schema version pinning across the wasm-bindgen crates | the `links` key is how it enforces that two mismatched versions cannot both link |
| `wit-bindgen` | 0.57.1 | build.rs + native | WASI component bindings | transitive in the WASM tree |
| `jni`, `jni-macros` | 0.22.4 | build.rs | JVM bindings | transitive; not reachable from any Aegis code path |

## Platform, runtime and codegen

| crate | version | mechanism | purpose |
| --- | --- | --- | --- |
| `libc` | 0.2.186 | build.rs | libc constant and ABI detection |
| `rustix` | 1.1.4 | build.rs | raw syscall interface selection |
| `cc` | 1.2.65 | native sources | the C compiler driver every bundled-C crate above uses |
| `crc32fast` | 1.5.0 | build.rs | SIMD CRC32 for WAL frame integrity |
| `crossbeam-utils`, `crossbeam-epoch` | 0.8.21, 0.9.20 | build.rs | atomics feature detection |
| `parking_lot_core` | 0.9.12 | build.rs | platform parking primitives for the WAL mutex |
| `portable-atomic` | 1.13.1 | build.rs | atomic width detection |
| `httparse` | 1.10.1 | build.rs | SIMD feature detection |
| `ipconfig`, `system-configuration-sys` | 0.3.4, 0.6.0 | build.rs | Windows/macOS network configuration; inert on Linux |
| `walkdir` | 2.5.0 | native sources | directory traversal |
| `windows_*` (8 crates) | 0.52.6 | build.rs | Windows import libraries, one per target triple; inert on non-Windows |

## Macro and serialization infrastructure

| crate | version | mechanism | purpose |
| --- | --- | --- | --- |
| `serde`, `serde_core` | 1.0.228 | build.rs | compiler feature detection for derive |
| `serde_json` | 1.0.150 | build.rs | as above |
| `proc-macro2` | 1.0.106 | build.rs | proc-macro API detection |
| `quote` | 1.0.46 | build.rs | as above |
| `thiserror` | 2.0.18 | build.rs | error-derive feature detection |
| `rustversion` | 1.0.22 | build.rs | compiler version detection |
| `num-traits` | 0.2.19 | build.rs | numeric feature detection |
| `paste` | 1.0.15 | build.rs | macro token pasting; unmaintained (`RUSTSEC-2024-0436`), transitive under `pqcrypto-mldsa` |
| `zmij` | 1.0.21 | build.rs | float formatting |
| `icu_normalizer_data`, `icu_properties_data` | 2.2.0 | build.rs | Unicode data tables, transitive under the URL parser |

Every crate in this section performs compiler feature detection: the build
script emits `cfg` flags so the crate can compile against several Rust
versions. None fetches anything at build time. Removing any of them is not
possible without removing `serde`, `reqwest` or the derive macros.

## Pinning

All three ecosystems are pinned by exact version and cryptographic digest, and
each of the three enforces that on install:

| ecosystem | manifest | digest form | enforced by |
| --- | --- | --- | --- |
| PyPI | `requirements.lock` | `--hash=sha256:` per artifact | `pip install --require-hashes` |
| crates.io | `aegis_rust_v2/Cargo.lock`, `connectors/envoy-wasm/Cargo.lock` | `checksum` per package | `cargo build --locked` |
| npm | `sdk/typescript/package-lock.json`, `dashboard/package-lock.json` | `integrity` (SRI) per package | `npm ci` |

**[MEASURED]** Every entry in `sdk/typescript/package-lock.json` that carries a
`resolved` URL also carries an `integrity` hash — zero exceptions — and plain
`npm ci` reproduces the tree from it.

## Software bill of materials

CycloneDX 1.5 documents for all five dependency trees are generated into
`evidence/sbom/4.3.0/`:

| file | tree | components |
| --- | --- | --- |
| `aegis-gateway-python-cyclonedx-1.5.json` | `requirements.lock` | 34 |
| `aegis-rust-cyclonedx-1.5.json` | `aegis_rust_v2` | 179 |
| `aegis-envoy-wasm-cyclonedx-1.5.json` | `connectors/envoy-wasm` | 6 |
| `aegis-typescript-npm-cyclonedx-1.5.json` | `sdk/typescript` | 55 |
| `aegis-dashboard-npm-cyclonedx-1.5.json` | `dashboard` | 247 |

Generated with `cyclonedx-py requirements` (`--output-reproducible`),
`cargo-cyclonedx`, and `npm sbom --sbom-format cyclonedx`.

The Python SBOM is built from `requirements.lock` rather than from the ambient
virtual environment, so it describes what a released image installs rather than
what a developer happens to have.

### What is not produced

- **`[BLOCKED: syft is not installed and cannot be fetched — the GitHub
  releases API returns 403 through this environment's proxy, which is scoped to
  a single repository.]`** SPDX 2.3 documents are therefore **not** generated.
  Only CycloneDX 1.5 exists. The brief asked for both; one is present.
- **`[BLOCKED: cosign is not installed and cannot be fetched, for the same
  reason. No Sigstore keyless signing identity is available in this
  environment.]`** The SBOMs are consequently **unsigned**, and no in-toto
  attestation or SLSA provenance is produced. Nothing in `evidence/sbom/4.3.0/`
  should be described as attested, signed, or SLSA-anything; it is a generated
  inventory with no provenance binding it to a build.
