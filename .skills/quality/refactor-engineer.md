---
name: refactor-engineer
tier: MEDIUM
domains: [refactoring, dead-code, module-extraction, rename, dependency-upgrade]
---
## Activation
Load on: "rename X across codebase", "clean this module", "extract Y to its own module",
"upgrade library Z", behavior-preserving transformation requests.

## Invariant: Behavior Preservation
```
Refactor contract:
  - diff(tests before) == diff(tests after) = ∅   (same tests pass)
  - diff(code shape) ≠ ∅                           (structure changed)
If tests break: not a refactor, it's a bug. Stop and fix.
```

## Safe Refactor Sequence
```
1. Ensure tests cover the code being refactored (if not: add tests first, then refactor)
2. Make ONE logical change per commit
3. Run full test suite after each commit
4. Never refactor and fix bugs in the same commit
5. Never refactor and add features in the same commit
```

## Rename Protocol
```bash
# Python — use rope or semgrep, not sed
python -m rope rename src/ OldName NewName
# Verify: no partial matches, no string literals that should stay
grep -r "OldName" src/ --include="*.py"  # should be zero

# Go — gorename
gorename -from "pkg.OldFunc" -to "NewFunc"

# Rust — cargo check after rename confirms all usages
```

## Module Extraction
```
Trigger:   file > 300 LOC OR multiple distinct responsibilities in one file
Process:
  1. Identify cohesive group of functions/classes (single responsibility)
  2. Create new module file
  3. Move functions — check all imports compile
  4. Update __init__.py / mod.rs / package exports
  5. Run tests — must be green before next step
  6. Delete original code — run tests again
```

## Dependency Upgrade Protocol
```bash
# Python
pip-compile --upgrade requirements.in  # update lockfile
pytest -x -q                           # fail fast on first break
# If tests break: check CHANGELOG for breaking changes, adapt code

# Rust
cargo update && cargo test

# Node
npx npm-check-updates -u && npm install && npm test
```
