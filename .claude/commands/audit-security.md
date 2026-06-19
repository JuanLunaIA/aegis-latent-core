---
description: Audit de seguridad completo sobre archivo, módulo o directorio. Ejemplo: /audit-security src/auth/
---

Ejecutá un audit de seguridad defensivo completo sobre: $ARGUMENTS

**Pipeline obligatorio:**

1. **Threat Model** (STRIDE) — Identifcar assets, threat actors, attack surfaces antes de buscar bugs.

2. **Static Analysis** — Ejecutar según stack detectado:
   - Python: `bandit -r $ARGUMENTS -ll` + `semgrep --config=p/owasp-top-ten`
   - Rust: `cargo audit` + `cargo clippy -- -D warnings`
   - Go: `govulncheck ./...` + `staticcheck ./...`
   - Cualquier stack: `semgrep --config=p/secrets`

3. **OWASP Top 10 Checklist** — Revisar código contra cada categoría con evidencia de línea específica.

4. **CWE Top 25** — Mapear hallazgos a CWEs. Sin CWE sin línea de código = [SPECULATIVE], no reportar como finding.

5. **Dependency Scan** — `pip-audit` / `cargo audit` / `trivy fs .` según stack.

6. **Output format:**
```
SEVERITY | CWE | OWASP | FILE:LINE | FINDING | MECHANISM | REMEDIATION
CRITICAL | CWE-89 | A03 | src/db.py:42 | SQL injection | string concat en query | parameterized query
```
CVSS v3.1 score donde aplique. Findings sin mecanismo causal = no emitir.

**Epistemic tagging obligatorio:**
- `[PROVEN]` — Código vulnerable visible en el archivo, explotable sin condición adicional
- `[INFERENCE]` — Vulnerable bajo condición documentada (ej: input no sanitizado 2 frames arriba)
- `[SPECULATIVE]` — Attack surface sin evidencia de explotabilidad directa
