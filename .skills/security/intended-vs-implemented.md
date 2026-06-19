---
name: intended-vs-implemented
tier: HIGH
domains: [code-audit, access-control, privilege, auth, authz]
---

## Activation
Load on: security code audit, checking access control matches docs/spec,
verifying permissions model in code, reviewing AI-generated code for behavior drift,
"does the code do what the docs say it does" analysis.

## Method
The intended-vs-implemented gap: bugs that generic scanners miss because they have
no model of intent. Only exploitable when you know what the system *should* do.

## Evidence Sources
```
Documented intent:   README, OpenAPI spec, architecture docs, PRD, CLAUDE.md,
                     inline comments, database schema comments, test names
Implementation:      actual code, ORM queries, middleware chain, route definitions,
                     database migrations, IaC config, Dockerfile, env vars
```

## Mismatch Taxonomy
```
MISSING_ENFORCEMENT   → doc says "only admins can X"; code has no role check on X
WRONG_SCOPE           → doc says "per-user"; code checks per-org (privilege escalation)
BYPASS_PATH           → enforcement on /api/v1/X but not /api/v2/X or /internal/X
MIDDLEWARE_GAP        → auth middleware applied to route group A but not B
IMPLICIT_TRUST        → internal service called without auth because "internal"
AUDIT_MISSING         → doc says "all access logged"; code path exits without logging
RATE_LIMIT_BYPASS     → rate limit on POST /resource but not PUT /resource/{id}
SOFT_DELETE_LEAK      → deleted records excluded from UI but not from API response
```

## Analysis Protocol
1. Extract all authorization rules from documentation
2. For each rule, find every code path that handles the resource
3. Check: is the rule enforced on every path? Including:
   - Alternate API versions
   - Internal/admin endpoints
   - Batch endpoints
   - Async jobs/workers
   - Webhook handlers
   - GraphQL resolvers (not just REST)
4. Check: is the enforcement granular enough (user vs org vs role)?
5. Check: is the enforcement in the right layer (not just UI, also API)?

## Output Format
```
[MISMATCH TYPE]
Documented intent:   [quote from spec/doc]
Implementation:      file:line — [what code actually does]
Gap:                 [what's missing or wrong]
Attack scenario:     [who can exploit this and how]
Fix:                 [concrete code change]
```
