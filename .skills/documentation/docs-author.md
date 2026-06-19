---
name: docs-author
tier: LOW
domains: [README, runbook, ADR, API-docs, onboarding, changelog]
---
## Activation
Load on: "document X", "README for repo", "runbook for Y", "ADR for decision Z",
"write API docs", "onboarding guide", "update changelog".

## README Template (modules/services)
```markdown
# [Service Name]
> [One sentence: what it does and who uses it]

## Prerequisites
- [Dependency with minimum version]

## Installation
```bash
[Exact commands — tested, copy-pasteable]
```

## Configuration
| Variable | Type | Default | Required | Description |
|---|---|---|---|---|
| DATABASE_URL | string | — | yes | PostgreSQL connection string |

## Usage
```bash
[Most common usage first — not edge cases]
```

## API Reference
[Endpoint / function signatures with params, returns, errors — not prose]

## Architecture
[Component diagram if ≥3 interacting systems]

## Development
```bash
make install  # setup
make test     # run tests
make lint     # lint + type check
```

## Changelog
[Link to CHANGELOG.md]
```

## Runbook Template
```markdown
# Runbook: [Operation Name]
**Last updated**: YYYY-MM-DD | **Owner**: [team]
**Trigger**: [When to run this runbook — alert name, symptom, schedule]

## Preconditions
- [What must be true before starting]

## Steps
1. **[Action]**
   ```bash
   [exact command]
   ```
   ✓ Expected output: `[what success looks like]`
   ✗ If fails: [recovery action or escalation path]

## Rollback
[Steps to undo, in order]

## Escalation
Exhaust steps above → page [on-call rotation] via [PagerDuty policy name]
```

## ADR Template
```markdown
## [ADR-NNN] [Short imperative title]
**Date**: YYYY-MM-DD | **Status**: Proposed / Accepted / Superseded by ADR-NNN
**Deciders**: [names/roles]

### Context
[Forces, constraints, what triggered this decision]

### Options Considered
| Option | Pros | Cons | Operational Cost |
|---|---|---|---|
| A | ... | ... | ... |

### Decision
[Chosen option] — because [mechanism, not preference].

### Consequences
- **Positive**: [what improves]
- **Negative**: [trade-offs accepted]
- **Revisit when**: [specific measurable trigger]
```

## Rules
- Commands must be tested before documenting — no "something like this"
- Version numbers explicit — not "latest" or "recent"
- Audience stated — not "the reader"; "on-call engineer" or "new team member"
- No prose where a table works better
