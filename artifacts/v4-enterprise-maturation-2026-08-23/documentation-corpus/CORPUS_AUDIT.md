# Documentation Corpus Audit

**Status:** PASS
**Source commit:** `7647fad798b3b79a98cc15323299f40d185b7b4c`
**Source worktree dirty:** `true`
**Tracked patch SHA-256:** `7891a83ca80e1e4eb522d24eab589d5d3a2d5117ace7cfbd7ee2d572c64bc2d2`
**Scope:** Git-tracked and untracked, non-ignored repository files present at execution time.

## Deterministic counts

| Metric | Count |
|---|---:|
| Files | 757 |
| UTF-8 text files | 660 |
| Markdown files | 77 |
| Institutional files | 10 |
| Exact duplicate groups | 10 |
| Repeated heading groups | 4 |
| UTF-8 decode failures in declared text types | 0 |
| Non-NFC text files | 0 |
| CRLF-containing text files | 0 |
| Placeholder markers in institutional documents | 0 |
| Post-write hash mismatches | 0 |

## Interpretation boundary

Exact-byte duplication and repeated headings are discovery signals, not automatic defects. Repeated operational headings such as Preconditions or Rollback are expected across independent runbooks. Semantic contradiction and regulatory accuracy require claim-level review and are recorded separately in `docs/institutional/CLAIM_EVIDENCE_GRAPH.md` and `docs/institutional/UNSUPPORTED_CLAIMS.md`.

## Falsification criterion

This audit passes only if every declared text file is inventory-addressable and unchanged through report emission, and the institutional suite contains no `TODO`, `FIXME`, `TBD`, `PLACEHOLDER`, or literal ellipsis marker. Re-running `python scripts/audit_documentation_corpus.py --output-dir <new-or-current-audit-directory>` must reproduce the same file hashes and tracked-patch digest when repository bytes are unchanged.
