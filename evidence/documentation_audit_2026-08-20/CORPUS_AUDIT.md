# Documentation Corpus Audit

**Status:** PASS
**Source commit:** `3f84245c5d62132d0aee68755009e021b3138415`
**Scope:** Git-tracked and untracked, non-ignored repository files present at execution time.

## Deterministic counts

| Metric | Count |
|---|---:|
| Files | 609 |
| UTF-8 text files | 557 |
| Markdown files | 64 |
| Institutional files | 10 |
| Exact duplicate groups | 5 |
| Repeated heading groups | 4 |
| UTF-8 decode failures in declared text types | 0 |
| Non-NFC text files | 0 |
| CRLF-containing text files | 0 |
| Placeholder markers in institutional documents | 0 |

## Interpretation boundary

Exact-byte duplication and repeated headings are discovery signals, not automatic defects. Repeated operational headings such as Preconditions or Rollback are expected across independent runbooks. Semantic contradiction and regulatory accuracy require claim-level review and are recorded separately in `docs/institutional/CLAIM_EVIDENCE_GRAPH.md` and `docs/institutional/UNSUPPORTED_CLAIMS.md`.

## Falsification criterion

This audit passes only if every declared text file is inventory-addressable and the institutional suite contains no `TODO`, `FIXME`, `TBD`, `PLACEHOLDER`, or literal ellipsis marker. Re-running `python scripts/audit_documentation_corpus.py` must reproduce the same file hashes when repository bytes are unchanged.
