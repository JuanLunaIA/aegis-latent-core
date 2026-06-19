---
description: Generar test suite completo para código target. Ejemplo: /generate-tests src/services/auth.py
---

Generá test suite production-grade para: $ARGUMENTS

**Requisitos del test suite:**

```python
# Stack: pytest + hypothesis + pytest-asyncio donde aplique
# Coverage target: ≥ 85% en código nuevo
# Structure: AAA (Arrange / Act / Assert) con labels de comentario
```

**Categorías de tests a generar (todas obligatorias):**

1. **Happy path** — Flujo nominal, input válido, output esperado.

2. **Error paths** — Cada excepción documentada, cada `raise` statement.
   No usar mocks para ocultar errores: si el código falla mal, el test debe exponer eso.

3. **Boundary conditions**:
   - Valores nulos, strings vacíos, listas vacías
   - INT_MAX / INT_MIN, float NaN/Inf
   - Strings con chars especiales, unicode edge cases
   - Colecciones de tamaño 0, 1, 2, N

4. **Security tests** (para código con input externo):
   - SQL injection payloads
   - Path traversal (`../../../etc/passwd`)
   - XSS payloads (si HTML output)
   - Oversized inputs (DoS básico)

5. **Property-based** (usar `hypothesis` para funciones puras):
   ```python
   from hypothesis import given, strategies as st
   @given(st.text())
   def test_parse_is_idempotent(s): ...
   ```

6. **Async tests** (si código es async):
   ```python
   @pytest.mark.asyncio
   async def test_async_flow(): ...
   ```

**Reglas duras:**
- Mocks solo para I/O externo (DB, HTTP, filesystem) — justificar en comentario
- No `unittest.mock.ANY` — assertions específicas
- No `time.sleep()` — usar mocking de time o eventos
- Fixtures en `conftest.py`, no inline en cada test

Ejecutar `pytest --tb=short -q` al final y reportar resultado.
