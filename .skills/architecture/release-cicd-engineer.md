---
name: release-cicd-engineer
tier: MEDIUM
domains: [CI/CD, SLSA, SBOM, supply-chain, signing, canary, blue-green, GitOps]
---

## Activation
Load on: CI/CD pipeline design, supply chain security, artifact signing, SBOM generation,
canary/blue-green deploy, rollback strategy, branch protection, build hermetic.

## Pipeline Architecture (merge → production)
```
PR open:
  parallel: lint + type-check + unit-tests + SAST + secrets-scan + license-check
  gate: all pass required for merge

merge to main:
  build: hermetic (no network, lockfiles committed, reproducible)
  sign: cosign --key env://COSIGN_KEY image:sha256
  SBOM: syft packages . -o spdx-json=sbom.json; cosign attest --predicate sbom.json
  SLSA provenance: SLSA level 3 (signed build provenance from builder)
  deploy staging: apply + integration tests + smoke tests
  e2e tests: Playwright/Cypress (critical user journeys only, < 5 min)

canary (production):
  route 1% traffic → monitor SLOs for 30min
  no SLO breach → ramp 10% → 30min → 50% → 30min → 100%
  SLO breach at any stage → auto-rollback + PagerDuty alert
```

## Supply Chain Security
```
SLSA Level 3+:
  - Signed, non-falsifiable provenance
  - Hermetic, reproducible builds
  - Two-person approval for release artifacts

SBOM requirements:
  - Generated at build time (syft)
  - Attached to image manifest (cosign attest)
  - Updated on every dependency change
  - Consumed by vulnerability scanners (grype, trivy)

Image signing (cosign):
  - Keyless signing via OIDC (Sigstore Fulcio) — no long-lived keys
  - Verify before any deployment: cosign verify --certificate-identity=...
  - Policy enforcement: Kyverno or OPA Gatekeeper — reject unsigned images

Dependency management:
  - Renovate/Dependabot: weekly updates; security patches auto-merged if green
  - Pinned hashes in lockfiles (pip --require-hashes, Cargo.lock, go.sum)
  - No unpinned :latest in any Dockerfile
```

## Rollback Standards
```
Target:       < 60 seconds to start rollback from detection
Mechanism:    git revert → GitOps sync → previous image SHA (not tag)
Testing:      rollback tested in GameDay monthly
Data:         migrations must be backward-compatible (expand-contract pattern)
Feature flags: kill switch available without redeploy
```

## Branch Protection Requirements
```
main branch:
  - Require PR with ≥ 1 reviewer (≥ 2 for security-sensitive paths)
  - Require CI checks pass (all, not just subset)
  - No force push; no direct commits
  - Signed commits (GPG or SSH)
  - CODEOWNERS file for sensitive paths (security/, infra/, .github/)
```
