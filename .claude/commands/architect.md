---
description: Diseño o review de arquitectura con ADR format. Ejemplo: /architect "sistema de queue para procesamiento async de PDFs en FastAPI"
---

Diseñá o revisá arquitectura para: $ARGUMENTS

**Procedimiento obligatorio:**

**FASE 1 — SURFACE ASSUMPTIONS**
Antes de proponer: enumerar lo que se asume sobre:
- Scale: RPS target, data volume, latency p50/p99
- Team: size, operational maturity, existing stack  
- Constraints: presupuesto, compliance (HIPAA/SOC2/PCI), geografía
- Hardware: si aplica X240 (3.2GB RAM, SATA SSD, Haswell)

**FASE 2 — ADR (Architectural Decision Record)**
```markdown
## Context
[Problema a resolver y forces en tensión]

## Options Considered
### Option A: [nombre]
Pros: | Cons: | Operational cost: | Risk:

### Option B: [nombre]  
Pros: | Cons: | Operational cost: | Risk:

### Option C: [nombre]
Pros: | Cons: | Operational cost: | Risk:

## Decision
[Opción elegida] — porque [mecanismo de selección, no preferencia]

## CAP Position (si distribuido)
[CP / AP / trade-off explícito con consistency guarantee documentado]

## Consequences
Positive: | Negative: | Revisit trigger: [métrica específica]

## Rejected Alternatives
[Por qué cada opción descartada no aplica bajo los constraints actuales]
```

**FASE 3 — Failure Mode Analysis**
- ¿Qué se rompe primero a 10x del load actual?
- ¿Qué requiere reescritura vs configuración?
- ¿Cuál es el SPOF? ¿Cómo se mitiga?

**FASE 4 — Migration Path** (si refactor de sistema existente)
- Strangler fig pattern vs big bang: justificar
- Rollback plan: qué datos/state migran y cómo revierten

**Tagging:**
- `[STRONG_INFERENCE]` para decisiones con benchmarks/papers citados
- `[ANALYSIS]` para heurísticas con condiciones explícitas
- `[SPECULATIVE]` para proyecciones sin datos de carga reales

**Anti-patterns prohibidos:**
- "Depende del caso de uso" sin enumerar casos
- "Microservicios para escalar" sin RPS concreto
- Stack recommendation sin operational cost estimation
