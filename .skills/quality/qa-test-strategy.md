---
name: qa-test-strategy
tier: HIGH
domains: [test-strategy, test-pyramid, E2E, contract-testing, mutation, coverage, QA]
---
## Activation
Load on: test strategy design, test pyramid, E2E architecture, contract testing,
mutation testing, coverage strategy, QA process, release testing, regression suite.

## Test Pyramid (allocation by cost/value)
```
        /\         E2E (5%)      — critical user journeys; slow, brittle, high-value
       /  \        Integration (15%) — service + real deps (testcontainers)
      /    \       Contract (10%)   — API producer/consumer (Pact)
     /------\      Component (20%)  — UI components, modules in isolation
    /        \     Unit (50%)       — pure logic, fast, deterministic

Anti-pattern: ice cream cone (mostly E2E) → slow, flaky, expensive to maintain
```

## What to Test at Each Level
```
Unit:          business rules, calculations, transformations, edge cases, error paths
Component:     UI states, props variations, user interactions (Testing Library)
Contract:      API schema compatibility between services (consumer-driven, Pact)
Integration:   service + DB + cache; data persistence; transaction boundaries
E2E:           ONLY critical revenue/safety paths: signup, checkout, payment, core flow
```

## Test Strategy Document Template
```markdown
## Test Strategy: [Feature/System]
### Risk Assessment
| Component | Failure Impact | Likelihood | Test Priority |
|---|---|---|---|
| Payment flow | Revenue loss + legal | Medium | E2E + integration + unit |
| Profile photo | Minor UX | Low | Unit only |

### Coverage Targets
- Critical paths (payment, auth, data mutation): 100% branch
- Business logic: 90% branch
- Glue/adapters: 70% (integration-covered)

### Test Types
- Unit: [scope] via [framework]
- Integration: [scope] via testcontainers
- E2E: [critical journeys only] via Playwright
- Contract: [service boundaries] via Pact
- Load: [SLO validation] via k6 at 3× peak
- Security: [injection, authz] in CI

### Regression Strategy
- Automated suite runs on every PR
- Flaky test policy: quarantine + fix within 1 sprint or delete
- Test data: factories (not fixtures); isolated per test; rollback after
```

## Contract Testing (microservices)
```
Consumer-driven (Pact):
  1. Consumer defines expected interactions (request → expected response)
  2. Contract published to broker
  3. Provider verifies it satisfies all consumer contracts in CI
  4. Breaking change = provider CI fails BEFORE deploy → no integration surprise

Without contract tests: integration breaks discovered in staging/prod (too late)
```

## Mutation Testing (test quality validation)
```
Tool:        mutmut (Python) / Stryker (JS/Java) / cargo-mutants (Rust)
Concept:     inject bugs (mutations); tests should catch them; surviving mutants = weak tests
Target:      mutation score > 80% on critical modules
When:        on critical business logic where coverage % is misleading
```

## Flaky Test Protocol
```
Detection:    track pass/fail across runs; flag tests with intermittent failures
Quarantine:   move flaky test out of blocking suite (still runs, doesn't block)
Root cause:   timing (add proper waits, not sleep), order-dependence (isolate state),
              external dependency (mock it), race condition (fix the actual bug)
Policy:       fix within 1 sprint or delete — flaky tests erode trust in the suite
```
