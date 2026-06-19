---
description: "Profiling y análisis de performance. Ejemplo: /perf-profile src/services/order.py"
---

Analizá performance de: $ARGUMENTS

**1. BASELINE — medir antes de cualquier cambio**
```bash
# Python CPU profile
python -m cProfile -o /tmp/profile.out $ARGUMENTS
python -c "import pstats; p = pstats.Stats('/tmp/profile.out'); p.sort_stats('cumulative'); p.print_stats(20)"

# O py-spy (production-safe, no instrumentation needed)
py-spy record -o /tmp/flamegraph.svg -- python $ARGUMENTS
echo "Flamegraph: /tmp/flamegraph.svg"

# Memory
python -c "
import tracemalloc
tracemalloc.start()
# [run the code]
snapshot = tracemalloc.take_snapshot()
for stat in snapshot.statistics('lineno')[:10]:
    print(stat)
"
```

**2. DB QUERIES — capturar todas las queries en la operación target**
```python
# Django/SQLAlchemy: enable query logging
import logging
logging.getLogger('sqlalchemy.engine').setLevel(logging.INFO)

# PostgreSQL: pg_stat_statements top queries
# SELECT query, calls, total_exec_time/calls as avg_ms, rows/calls as avg_rows
# FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 20;
```

**3. ANÁLISIS**
Reportar:
- Top 5 funciones por tiempo acumulado (con % del total)
- Queries más lentas (> 100ms) con EXPLAIN ANALYZE
- Allocations más grandes (si memory issue)
- Event loop lag si es async (aiomonitor)

**4. HIPÓTESIS**
Para cada bottleneck: `[INFERENCE] X es bottleneck porque Y→Z`
Proponer fix concreto. Implementar UNO, medir, iterar.

**5. TARGET**
¿Cuál es el SLO de latencia? Optimizar hasta SLO, no hasta el límite teórico.
