---
description: "Coordinación de incidente activo P0/P1. Ejemplo: /incident-response P0 checkout-flow down 15%"
---

Iniciando respuesta a incidente: $ARGUMENTS

**Acción inmediata — ejecutar en orden:**

```bash
# 1. Snapshot del estado actual
date -u  # timestamp de inicio
# Capturar métricas actuales antes de cualquier cambio
```

**PASO 1 — DECLARAR (< 2 min)**
```
#incidents: "🔴 P[N] DECLARED — [síntoma] — IC: @[vos] — Bridge: [link]"
Status page: update a "Investigating"
```

**PASO 2 — MITIGAR PRIMERO (< 10 min)**
¿Hay rollback disponible? → hacerlo ANTES de diagnosticar si es P0.
```bash
# Rollback deploy (GitOps)
git revert HEAD && git push
# O rollback image directa:
kubectl set image deployment/api api=image:sha256-[prev-sha]
# Feature flag off:
# launchdarkly/unleash kill switch para la feature afectada
```

**PASO 3 — DIAGNÓSTICO (paralelo a mitigación)**
```bash
# Error rate últimos 15 min
# Latency p99 por servicio
# Recent deploys en la ventana de inicio del incidente
# DB connections, lock waits, replication lag
# External dependency status (pagerduty.com/status)
```

**Formato de actualización cada 15 min:**
```
[HH:MM UTC] Status: [Investigating/Identified/Monitoring/Resolved]
Impact: ~[N] users | Error rate: [X]% | Started: [HH:MM UTC]
Current action: [qué se está haciendo ahora]
Next update: [HH:MM UTC]
```

**Template incidente doc (abrir ahora):**
```
IC: @[nombre] | Comms: @[nombre] | Tech: @[nombre]
Timeline: [HH:MM] — Incident declared
Hypotheses: [ ] [hip1] | [ ] [hip2]
Actions: [HH:MM] — @who did what → result
```
