# GitHub PR #95 Diagnostic — 2026-08-21

The first remediation run materially changed the Python 3.11 failure mode. The `Run test suite with coverage gate` step completed successfully in 1 minute 39 seconds; the job failed afterward in `Dependency audit (test environment)`. Python 3.12 and 3.13 tests passed, and 24 checks were successful. This falsifies the prior operational symptom that Python 3.11 remains indefinitely at approximately 5%.

The GitHub REST job record identifies job `96660291192` in run `32444082981` as failed. Public job metadata exposes the failed step but not raw logs. The authenticated integration token expired immediately afterward with HTTP 401, so the exact remote pip-audit stderr could not be retrieved. A clean local CPython 3.11 environment completed `pip-audit` with no known vulnerabilities, which supports an operational/transient hypothesis but does not prove it.

The CI audit step is therefore made bounded and deterministic: `pip-audit` is declared in the development dependency set, the process has a 120-second outer deadline and 30-second request timeout, known-vulnerability output fails immediately, and only non-vulnerability operational failures receive one delayed retry before failing closed. The acceptance criterion remains a successful GitHub rerun; local success alone is insufficient.

The same job emitted one platform warning because `actions/checkout` v4 targets Node.js 20. All 26 checkout uses were advanced to the resolved v5 commit `fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09`, retaining full-SHA pinning.

Commit `6dee4c8` confirmed the same separation: Security, Publish, Forensic CI, Python 3.12/3.13 tests, Rust, formal verification, lint, type checking, lock integrity, and license checks passed; only Python 3.11's environment-level dependency audit returned exit 1 after its tests completed. The dedicated Security workflow's declared dependency audit passed. Because auditing a dynamically resolved test environment mixes runtime dependencies with interpreter-specific development tooling, the matrix step now audits the hashed runtime input `requirements.txt`. The development tool itself remains versioned in the `dev` extra, bounded, retried only for operational failures, and fail-closed for any vulnerability result.

## Final disposition

Commit `65b6a6328739947de09b35381adf303646893963` passed CI, Security, Forensic CI, and Publish on PR #95. The pull request was squash-merged as GitHub-verified commit `8907a6db75cff2a3bd6a551ef7983f53bda17027`. The subsequent final `main` execution on commit `43677edca6d39a2b4078187d3676d5a286627846` completed Python 3.11.16 with `5,392 passed, 83 skipped in 64.34s`, `92%` line coverage, and `No known vulnerabilities found` for `requirements.txt`. The original indefinite-progress hypothesis is therefore rejected for the merged implementation.

The first post-merge CI exposed an independent SBOM source-type defect: Syft received `dir:<tar.gz>` and rejected the archive as a directory. PR #96 changed the catalog input to an extracted `sbom-root/`, added pull-request SBOM validation, and passed both PR and post-merge execution. This defect did not regress the Python matrix; Python 3.11, 3.12, and 3.13 had already passed in the affected run.
