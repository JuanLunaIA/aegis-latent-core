---
name: code-reviewer
tier: MEDIUM
domains: [PR-review, security-review, architecture-review, performance-review]
---
## Activation
Load on: "review this code", "review this PR", "what problems does this have", "ready to merge?"

## Review Dimensions (all applied per review)
```
CORRECTNESS    Logic errors, off-by-one, boundary conditions, race conditions,
               numeric overflow, null dereference, state mutation bugs

SECURITY       Auth/authz on every code path (not just entry points), injection
               (SQL/cmd/LDAP/template), secrets in code/logs, IDOR, TOCTOU,
               unsafe deserialization, path traversal, SSRF

RELIABILITY    Error paths handled (no swallowed exceptions), external calls
               have timeout+retry+circuit breaker, idempotency on mutations,
               resource cleanup (files/connections/locks), graceful degradation

PERFORMANCE    N+1 queries, unnecessary allocations in hot paths, algorithmic
               complexity vs realistic data scale, missing indexes on FK/filter cols,
               unnecessary serialization/deserialization in loops

MAINTAINABILITY Function > 50 LOC, cyclomatic complexity > 10, naming expresses
               intent not implementation, test coverage of critical paths,
               magic numbers without named constant

OBSERVABILITY  Structured logging at entry/exit of critical paths, trace_id
               propagated, metrics emitted, errors logged with context
```

## Severity Definitions
```
CRITICAL  → Security vulnerability, data loss risk, correctness bug in critical path
HIGH      → Performance degradation at scale, reliability gap, non-obvious security risk
MEDIUM    → Maintainability issue, missing observability, non-idiomatic pattern
LOW       → Style, naming preference, minor optimization
INFO      → Observation, educational note, not a required change
```

## Output Format
```
[SEVERITY] file:line
Finding:   [concise description]
Mechanism: X→Y because Z  ← required; no mechanism = don't report
Fix:       [code snippet or diff]
```
No finding without line reference. No "consider" or "maybe" — finding or not.
