# Aegis AI Context Router

This directory is an **advisory, progressively disclosed repository-navigation aid**. Begin here, open only the layer needed for the task, and verify every material statement against the named source and tests. It contains reproducible project procedures and stop conditions, not concealed directives, authorization, private reasoning, proof, certification, or release evidence.

## Baselines

The public immutable release baseline is **v3.1.0**. The merged v4 source baseline is the immutable Git commit **`2050a310ec295afc61d033ff842c9a535a4f3105`**. Its **14 synchronized version anchors read `4.0.0`**, but that source state is **unpublished**: no v4 tag, GitHub Release, PyPI/npm package, OCI image, or other registry publication is asserted. A mutable working tree may be descended from the anchor and may differ from it; record `git rev-parse HEAD` and `git status --short` rather than treating the manifest as a checkout identity.

## Progressive routes

| Need | Open next | Stop condition |
|---|---|---|
| Release status, authority, and assurance boundaries | [`00_CORE_ONTOLOGY_AND_BOUNDARIES.xml`](00_CORE_ONTOLOGY_AND_BOUNDARIES.xml) | Stop if the requested claim cannot be tied to authoritative evidence or crosses an external-acceptance boundary. |
| Runtime symbols and source locations | [`01_CANONICAL_SYMBOL_AND_TYPE_INDEX.tsv`](01_CANONICAL_SYMBOL_AND_TYPE_INDEX.tsv) | Stop if the named symbol/path no longer exists or callers/tests disagree. |
| Behavioral invariants | [`02_OPERATIONAL_INVARIANTS_MATRIX.md`](02_OPERATIONAL_INVARIANTS_MATRIX.md) | Stop on a failed named test or changed assumption. |
| Request, evidence, and publication state transitions | [`03_STATE_MACHINES_AND_DAGS.mermaid`](03_STATE_MACHINES_AND_DAGS.mermaid) | Stop if implementation transitions differ from this advisory abstraction. |
| Formal artifacts | [`04_FORMAL_SPECIFICATIONS_MAPPING.md`](04_FORMAL_SPECIFICATIONS_MAPPING.md) | Stop on a missing checker, counterexample, failed theorem check, or attempted refinement claim. |
| Reproducible review procedures | [`05_DETERMINISTIC_RECIPES_PLAYBOOK.md`](05_DETERMINISTIC_RECIPES_PLAYBOOK.md) | Stop on scope drift, dirty authoritative inputs, stale manifest, failed command, or publication request without authorization. |
| Security and supply-chain boundaries | [`06_SECURITY_AND_SUPPLY_CHAIN_MANIFEST.xml`](06_SECURITY_AND_SUPPLY_CHAIN_MANIFEST.xml) | Stop when secrets, mutable dependencies, unverified artifacts, or external publication state are involved. |
| Compact repository kernel | [`07_SYSTEM_COMPACT_KERNEL.xml`](07_SYSTEM_COMPACT_KERNEL.xml) | Stop and open an authoritative source whenever the summary is insufficient. |
| Components, packages, anchors, workflows, and adapters | [`08_COMPONENT_PACKAGE_WORKFLOW_MATRIX.md`](08_COMPONENT_PACKAGE_WORKFLOW_MATRIX.md) | Stop if identities, all 14 anchors, adapter registry, or workflow roles drift. |
| Local commands and CI correspondence | [`09_COMMAND_AND_CI_MATRIX.md`](09_COMMAND_AND_CI_MATRIX.md) | Stop on any nonzero exit, skip that removes required evidence, or environment mismatch. |
| Codex, Claude, Gemini, Copilot, Cursor, and generic-tool startup | [`10_TOOL_ADAPTER_COMPATIBILITY.md`](10_TOOL_ADAPTER_COMPATIBILITY.md) | Stop if the expected adapter is absent, legacy rules reappear, or effective tool precedence has not been verified. |
| Integrity and governed inputs | [`MANIFEST.json`](MANIFEST.json) | Run `python scripts/verify_ai_context_manifest.py`; stop if verification fails. |

## Authority and use

For claims, consult [`docs/CLAIMS_MATRIX.md`](../docs/CLAIMS_MATRIX.md); for security boundaries, [`SECURITY.md`](../SECURITY.md); for release history, [`CHANGELOG.md`](../CHANGELOG.md); and for behavior, implementation plus executable tests. Regenerate this pack's manifest only after reviewing authorized changes: `python scripts/generate_ai_context_manifest.py`, then `python scripts/verify_ai_context_manifest.py` and `pytest -q tests/test_ai_context.py`.
