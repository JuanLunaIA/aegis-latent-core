# Repository Map — Aegis Latent Core

**Last verified:** 2026-08-27 UTC
**Release baseline:** four-layer truth model
**Source baseline:** checked-out source metadata is synchronized at `v4.1.1`
**Immutable comparison source:** `fdace8844568eb788216740b2cb5daf187d99d3b` retains the historical `4.0.0` comparison anchors documented by [`evidence/v4_0_0_post_merge_release_readiness_2026-08-25.md`](../evidence/v4_0_0_post_merge_release_readiness_2026-08-25.md)
**External lifecycle boundary:** source metadata does not prove a tag, GitHub Release, registry package, OCI image, deployment, or acceptance; verify each surface by external readback
**Historical evidence baseline:** previously published `v3.1.0` artifacts and retained measurements remain historical

Read the root [`README.md`](../README.md) first. Paths below describe the checked-out `v4.1.1` source baseline unless a row is explicitly historical. Source paths and version metadata do not imply that corresponding packages or images are available from a public registry or that an OCI image has been published.

## Runtime and product surfaces

| Path | Role | Review focus |
|---|---|---|
| `aegis/proxy/app.py` | Primary FastAPI gateway, `create_app()`, module-level `app`, and installed `aegis`/`aegis-server` CLI target | Authentication, request bounds, provider forwarding, durable evidence, streaming, and failure paths |
| `aegis/config.py` | `AegisSettings` environment contract | Strict versus development mode, secrets, storage, Redis, kernel controls, and bounds |
| `aegis/core/crypto_audit.py` | Authoritative JSONL hash chain and WAL | Canonical records, signature metadata, flush/`fsync`, replay, rotation, and integrity |
| `aegis/proxy/streaming.py` | Bounded SSE transformation | Per-stream queue/event/byte/window/output/duration limits and terminal evidence ordering |
| `aegis/core/mmr.py` | MMR state and portable proof generation | Retained-state availability, shared schema, and trusted-root boundary |
| `aegis/core/forensic_bundle.py` | Bounded retained-window ZIP export | Contract contents, digest checks, acquisition limits, and custody/authenticity limits |
| `aegis/auth/`, `aegis/storage/`, `aegis/telemetry/` | v4 source authentication, archival, and telemetry modules | Deployment dependencies and explicit acceptance gaps |
| `aegis_server/` | Separate legacy/enterprise server surface | Do not assume parity with the primary gateway's current auth or tenant contract |
| `dashboard/` | Private Next.js audit UI source | Server-only credential handling, real-data states, build/test boundaries; no deployment claim |

## Package and import names

| Source path | Build/distribution name | Import or package name | Availability boundary |
|---|---|---|---|
| repository root | Python distribution metadata `aegis-latent-core` | Python package `aegis`; CLIs `aegis`, `aegis-server` | Install from the clone for this baseline; no current registry availability is asserted. |
| `sdk/python/` | Python distribution metadata `aegis-latent-sdk` | Python package `aegis_sdk` | Install with `python -m pip install -e './sdk/python[dev]'`; no PyPI publication is asserted. |
| `sdk/typescript/` | npm package metadata `aegis-latent-sdk` | Exports declared by that local package | Use `npm ci` in the source directory; no npm publication is asserted. |
| `aegis_rust_v2/` | Cargo crate/library `aegis_rust`; Python wheel distribution `aegis-rust` | Python import module `aegis_rust` | `aegis_rust_v2` is only the legacy source-directory name; build locally with Cargo/maturin. |
| `dashboard/` | private package `aegis-audit-dashboard` | not a reusable public import | Private source application; no registry or deployment claim. |

## Tests and verification

| Path | Role |
|---|---|
| `tests/test_health.py` | Offline application-factory health test |
| `tests/test_p0_release_gates.py` | Strict-runtime and blocking durable-evidence regressions |
| `tests/test_enterprise_durable_evidence.py` | Governed success and failure-path evidence tests |
| `tests/test_proxy_streaming.py` | Bounded SSE and terminal-ordering tests |
| `tests/test_mmr_portable.py` | Portable proof generation, tamper rejection, and schema tests |
| `sdk/python/tests/`, `sdk/typescript/tests/` | SDK provider and proof contracts |
| `dashboard/tests/` | UI contract, state, and no-fabrication tests |
| `tools/docs/verify_documentation.py` | Required-document, relative-link, table, metadata, and claim-boundary verifier |
| `scripts/verify_release_contract.py` | Source/version contract; passing it is not publication evidence |

## Evidence and historical results

[`evidence/INDEX.md`](../evidence/INDEX.md) is the evidence entry point. The 2026-08-20 through 2026-08-22 benchmark, security, GitHub-status, remediation, and documentation-audit collections are preserved as historical v3.1.0-era observations. The 2026-08-24 candidate/no-go records are superseded for current source-state identification by the 2026-08-25 post-merge audit, while retaining their historical results and decision context.

## Change-impact checklist

A change touching gateway admission, evidence commit, signer code, WAL persistence, SDK proof verification, Rust bindings, deployment manifests, or public claims requires a scoped regression test and claim review. Record the exact source revision and environment for new evidence; never overwrite historical artifacts or silently apply their results to a newer baseline.

## Related documents

- [`docs/README.md`](README.md)
- [`docs/DEVELOPER_QUICKSTART.md`](DEVELOPER_QUICKSTART.md)
- [`docs/architecture/ARCHITECTURE.md`](architecture/ARCHITECTURE.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
- [`docs/RUST_BUILD.md`](RUST_BUILD.md)
- [`evidence/INDEX.md`](../evidence/INDEX.md)
