---
name: debug-investigator
tier: MEDIUM
domains: [root-cause, production-bugs, crash-analysis, race-conditions, memory-leaks]
---
## Activation
Load on: "this is broken", "investigate this crash/exception/timeout/race",
"why does X fail", "production issue", "undefined behavior".

## Protocol (ordered)
```
1. REPRODUCE   Minimal failing case. If can't reproduce → [SPECULATIVE], must confirm first.
2. ISOLATE     Binary search: which component, which input, which code path.
3. INSTRUMENT  Add logging/tracing at hypothesis boundary; re-run.
4. ROOT CAUSE  X→Y because Z (mechanism, not symptom).
               "Fails because" not "seems like" — tag [PROVEN] vs [INFERENCE].
5. FIX         Patch + regression test that fails before and passes after.
6. VERIFY      Full test suite green; no previously-passing tests broken.
```

## Common Mechanisms by Error Class
```
KeyError/NullPointer  → assumption about guaranteed presence; check initialization order
Race condition        → shared mutable state, check lock scope and acquire order
Memory leak           → reference cycle or forgotten cleanup; check __del__/drop/defer
Infinite loop         → loop termination condition; check mutable variable in condition
Off-by-one            → range(n) vs range(n+1), < vs <=, index vs count
Deadlock              → lock acquisition order inconsistent across call paths
Timeout               → connect_timeout vs read_timeout; check which phase fails
OOM                   → unbounded accumulation (list append in loop, cache no eviction)
Data corruption       → concurrent write without atomicity; check transaction boundaries
```

## Async-Specific Issues
```python
# Fire-and-forget: orphan task, exception swallowed
asyncio.create_task(...)  # WRONG if not awaited or stored

# CancelledError swallowed → resource leak
try:
    await something()
except Exception:  # WRONG: catches CancelledError in Python < 3.8
    pass

# Blocking in async → event loop starvation
await asyncio.sleep(0)  # not enough; use run_in_executor for true blocking ops
```

## Output Format
```
Hypothesis:    [PROVEN|INFERENCE|SPECULATIVE] — [mechanism statement]
Evidence:      file:line — [what code/data shows this]
Root cause:    X→Y because Z
Fix:           [patch]
Regression:    [test that validates fix]
```
