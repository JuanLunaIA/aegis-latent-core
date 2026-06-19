---
description: Pre-deployment checklist antes de hacer push a producción. Ejemplo: /deploy-check v2.3.1
---

Pre-deployment verification para: $ARGUMENTS

**Ejecutar checks en orden. HALT si CRITICAL falla.**

```bash
# 1. TEST SUITE — Debe pasar al 100%
pytest --tb=short -q
echo "Exit code: $?"

# 2. TYPE CHECK
mypy src/ --strict --ignore-missing-imports
echo "Exit code: $?"

# 3. LINTING
ruff check src/
echo "Exit code: $?"

# 4. SECURITY SCAN
bandit -r src/ -ll -q
pip-audit --require-hashes --progress-spinner off
echo "Exit code: $?"

# 5. DEPENDENCY HASH VERIFICATION
pip-compile --generate-hashes requirements.in > /dev/null
echo "Exit code: $?"
```

**Checklist manual:**

```
CRÍTICO (no deployar si falla):
□ Migrations reversibles: alembic downgrade funciona en staging
□ Secrets en vault/env, no en código ni en git history
□ Feature flags para rollback sin redeploy
□ Health check endpoint responde /health con 200
□ DB connection pool configurado (no default ilimitado)

ALTO (documentar excepción si se saltea):
□ Rate limiting activo en endpoints públicos
□ Logging estructurado con trace IDs
□ Alertas configuradas para error rate > baseline
□ Rollback plan documentado (tiempo estimado + responsable)

MEDIO:
□ CHANGELOG.md actualizado
□ API version bumpeada si hay breaking changes
□ Runbook actualizado si hay nueva dependencia operacional
```

**Output esperado:**
```
[PASS/FAIL] Tests: N passed, N failed
[PASS/FAIL] Types: N errors
[PASS/FAIL] Lint: N issues
[PASS/FAIL] Security: N issues (CRITICAL/HIGH/MEDIUM)
[PASS/FAIL] Dependencies: N vulnerabilities

DEPLOY STATUS: GO / NO-GO
Blocker (si NO-GO): [lista de items que deben resolverse]
```
