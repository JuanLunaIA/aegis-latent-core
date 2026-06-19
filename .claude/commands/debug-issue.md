---
description: Investigación sistemática de bugs y root cause analysis. Ejemplo: /debug-issue "KeyError en user_service.py linea 84 al procesar JWT expirado"
---

Investigá el issue: $ARGUMENTS

**Protocolo de debug (obligatorio en orden):**

**1. REPRODUCE** — Construir el caso mínimo que falla:
```python
# Objetivo: el test más pequeño posible que expone el bug
# Si no podés reproducir: el bug no está confirmado → [SPECULATIVE]
```
Ejecutar el reproducer y capturar el traceback completo.

**2. BISECT** — Identificar cuándo se introdujo:
```bash
git bisect start
git bisect bad HEAD
git bisect good <último-commit-conocido-bueno>
# Iterar hasta identificar commit culpable
```

**3. MECHANISM** — Root cause, no síntoma:
```
"Falla porque: X→Y→Z"
No: "Parece que el problema es..."
Sí: "user_id es None porque get_current_user() retorna None cuando el JWT está 
     expirado (línea 31), y validate_token() en ese path no lanza excepción sino 
     retorna None (línea 108 de auth.py)"
```
Tag la hipótesis: [PROVEN] si el código muestra el path claramente, [INFERENCE] si requiere runtime confirmation.

**4. FIX** — Patch con test de regresión:
- El test debe FALLAR en el código original
- El test debe PASAR con el patch aplicado
- El fix no debe modificar código no relacionado

**5. VERIFY** — Correr test suite completo post-fix:
```bash
pytest --tb=short -q 2>&1 | tail -20
```
Reportar si hay tests previamente pasando que ahora fallan.

**Prohibido:**
- "Parece que" sin evidencia de código ejecutable
- Hipótesis de ≥3 hops sin confirmación experimental → [SPECULATIVE] + proponer test que resuelve
- Fix sin test de regresión
