# GitHub PR #95 Diagnostic — 2026-08-21

The first remediation run materially changed the Python 3.11 failure mode. The `Run test suite with coverage gate` step completed successfully in 1 minute 39 seconds; the job failed afterward in `Dependency audit (test environment)`. Python 3.12 and 3.13 tests passed, and 24 checks were successful. This falsifies the prior operational symptom that Python 3.11 remains indefinitely at approximately 5%.

The GitHub REST job record identifies job `96660291192` in run `32444082981` as failed. Public job metadata exposes the failed step but not raw logs. The authenticated integration token expired immediately afterward with HTTP 401, so the exact remote pip-audit stderr could not be retrieved. A clean local CPython 3.11 environment completed `pip-audit` with no known vulnerabilities, which supports an operational/transient hypothesis but does not prove it.

The CI audit step is therefore made bounded and deterministic: `pip-audit` is declared in the development dependency set, the process has a 120-second outer deadline and 30-second request timeout, known-vulnerability output fails immediately, and only non-vulnerability operational failures receive one delayed retry before failing closed. The acceptance criterion remains a successful GitHub rerun; local success alone is insufficient.

The same job emitted one platform warning because `actions/checkout` v4 targets Node.js 20. All 26 checkout uses were advanced to the resolved v5 commit `fbc6f3992d24b796d5a048ff273f7fcc4a7b6c09`, retaining full-SHA pinning.
