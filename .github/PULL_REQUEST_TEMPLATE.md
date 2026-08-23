## Change summary

Describe the mechanism-level change and the affected trust boundary.

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Security fix
- [ ] Documentation update
- [ ] Refactor / code quality

## Evidence contract

- [ ] I updated `docs/CLAIMS_MATRIX.md` for every new or changed public claim.
- [ ] I identified the exact artifact, test, log, or benchmark supporting the claim.
- [ ] I stated what the evidence does **not** establish.
- [ ] I did not include credentials, customer payloads, private endpoints, or synthetic telemetry presented as runtime evidence.

## Verification

- [ ] `pytest` passes for the affected scope.
- [ ] `ruff check .` passes.
- [ ] `ruff format --check .` passes.
- [ ] `bandit -r aegis aegis_server -lll` passes or a reviewed exception is documented.
- [ ] `pip-audit` and relevant lockfile checks pass.
- [ ] If `sdk/python/**` changed: SDK Ruff, strict mypy, pytest and package build pass.
- [ ] If `sdk/typescript/**` changed: `npm ci`, typecheck, tests, build, audit and pack dry-run pass.
- [ ] If `dashboard/**` changed: TypeScript SDK build, dashboard typecheck, tests, production build and audit pass.
- [ ] Rust, Helm, container, or benchmark gates were run when affected.
- [ ] Raw artifacts are attached or linked for performance/security measurements.

## Security and operations

- [ ] Threat model and residual risk are updated.
- [ ] Failure behavior is fail-closed where the evidence boundary requires it.
- [ ] Rollback, blast radius, observability, and kill criteria are documented.
- [ ] New secrets and sensitive data are absent from the diff.

## Release impact

- [ ] Version and changelog updates are included when behavior or public claims change.
- [ ] Commercial and buyer-facing language does not imply certification, SLO, legal admissibility, or customer references without evidence.
- [ ] Human reviewer/owner: `@JuanLunaIA`

## Test plan

List the exact commands run and link retained artifacts.
