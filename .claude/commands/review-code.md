---
description: Code review de producción con severidad y remediation. Ejemplo: /review-code src/api/routes.py
---

Revisá el código en: $ARGUMENTS

**Checklist de review (reportar solo hallazgos reales con evidencia de línea):**

```
CORRECTNESS
□ Logic errors, off-by-one, boundary conditions
□ Race conditions, TOCTOU, shared mutable state
□ Numeric overflow / underflow / precision loss
□ Null/None dereference paths

SECURITY  
□ Input validation antes de business logic
□ Auth/authz en cada endpoint (no solo happy path)
□ Secrets en código, logs, o error messages
□ Injection: SQL, command, LDAP, XPath, template
□ Unsafe deserialization

RELIABILITY
□ Error paths manejados (no bare except, no swallowed errors)
□ External calls: timeout + retry + circuit breaker
□ Resource cleanup: context managers, file handles, DB connections
□ Idempotency en operaciones que deben serlo

PERFORMANCE
□ N+1 queries (ORM loops sin prefetch)
□ Unnecessary allocations en hot paths
□ Algorithmic complexity vs data size real
□ Missing indexes en queries frecuentes

MAINTAINABILITY
□ Naming: nombres que expresan intent, no implementación
□ Function size > 50 LOC sin justificación
□ Cyclomatic complexity > 10 sin justificación
□ Test coverage de paths críticos
```

**Output format:**
```
[CRITICAL|HIGH|MEDIUM|LOW|INFO] file:line
Finding: descripción concisa
Mechanism: X→Y porque Z
Fix: código concreto o patch diff
```

Sin mecanismo = no emitir finding. No mencionar style preferences como HIGH.
