TODO / FIXME Triage
==================

This file summarizes actionable TODOs and FIXMEs found during the forensic audit. Use this as a backlog to create focused PRs.

How to refresh the list:

```bash
# list all TODO/FIXME occurrences
rg "\bTODO\b|\bFIXME\b" -n --hidden --glob "!aegis_rust_v2/target/**" || true
```

Priority (suggested):

1. Security-critical (exec/eval/pickle/secret handling) — fix or isolate immediately.
2. Chain-of-custody / MMR blockers — ensure add_leaf correctness and persistence.
3. CI & build reproducibility — ensure maturin + python matrix builds in GH Actions.
4. Docs & procurement artifacts — SOW, SLA templates, and compliance export examples.

Initial findings (automated):

- See tools/forensic/report.json for pattern matches (exec/eval/pickle hints).
- See SECURITY_AUDIT_REPORT.md for a high-level summary and remediation guidance.

Suggested PRs to open now:

- PR: "security/pickling-hardening" — introduce aegis/core/safe_serialization.py and replace direct pickle.load usage in high-risk paths.
- PR: "build/rust-helper-and-docs" — add scripts/build_rust.sh and update docs/RUST_BUILD.md (already present).
- PR: "docs/enterprise-procurement" — extend COMMERCIAL.md with SOW and SLA templates.
