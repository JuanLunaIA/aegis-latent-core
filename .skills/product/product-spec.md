---
name: product-spec
tier: MEDIUM
domains: [PRD, spec, requirements, user-stories, acceptance-criteria, scoping]
---
## Activation
Load on: PRD writing, feature spec, requirements doc, scoping, user stories,
acceptance criteria, "spec out X", turning idea into structured requirements.

## PRD Template (lean, decision-oriented)
```markdown
## [Feature Name] — PRD
Author: | Status: Draft/Review/Approved | Last updated: YYYY-MM-DD

### Problem
[What user problem are we solving? Evidence it's real (data, research, support tickets).
NOT a solution disguised as a problem.]

### Why Now
[Why is this worth doing now vs other priorities? Strategic/competitive/cost driver.]

### Goals (measurable)
- Primary: [metric + target, e.g. "reduce checkout abandonment from 30% to 22%"]
- Secondary: [supporting metrics]

### Non-Goals (explicit scope boundaries)
- [What this does NOT do — prevents scope creep]

### User Stories
As a [persona], I want to [action] so that [outcome].
Acceptance criteria:
  Given [context], When [action], Then [observable result].

### Solution Overview
[High-level approach. Not implementation detail — that's the eng design doc.]

### Success Metrics
| Metric | Baseline | Target | Measurement method |
|---|---|---|---|

### Rollout Plan
[Phases: internal → beta → % rollout → GA. Kill criteria per phase.]

### Risks & Open Questions
- [Risk]: [mitigation]
- [Open question]: [owner + resolution date]

### Out of Scope / Future
[Deferred items — captured so they're not lost, explicitly not in this version]
```

## Acceptance Criteria (Gherkin)
```gherkin
Feature: Password reset
  Scenario: Successful reset with valid token
    Given a user with a valid reset token
    When they submit a new password meeting policy
    Then the password is updated
    And all existing sessions are invalidated
    And a confirmation email is sent

  Scenario: Expired token
    Given a reset token older than 1 hour
    When the user attempts to reset
    Then they see "token expired"
    And no password change occurs
```

## Scoping Discipline
```
MVP test:        what's the smallest thing that validates the core hypothesis?
Cut ruthlessly:  every feature = maintenance cost forever; default to NO
Phasing:         v1 (core value) → v2 (table stakes) → v3 (delight)
RICE prioritize: (Reach × Impact × Confidence) / Effort — for feature ranking
Anti-pattern:    "while we're at it" additions; gold-plating before validation
```

## Quality Bar for a Spec
```
[ ] Problem is a problem, not a solution in disguise
[ ] Goals are measurable (number + target + how measured)
[ ] Non-goals explicit (scope boundary defined)
[ ] Acceptance criteria testable (QA can write tests from them)
[ ] Success metrics defined BEFORE build (not retrofitted)
[ ] Rollout has kill criteria (when do we roll back?)
[ ] Risks surfaced honestly (not hidden to get approval)
```
