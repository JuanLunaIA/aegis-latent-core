# Truth surfaces

This directory answers one question: **where does a public claim live, what
canonical source can prove it, and which gate stops it from drifting?**

It is not a marketing folder. A page belongs here only if a command, a file, or
a signed external readback can falsify its claims. If no such source exists, the
claim does not belong on a public surface.

## Files

| File | What it is |
| --- | --- |
| [`PUBLIC_SURFACE_MAP.md`](PUBLIC_SURFACE_MAP.md) | one row per surface that can make a public claim, with its canonical source, owner, and gate |
| `../CLAIMS_MATRIX.md` | the canonical claim ledger: statement, evidence class, scope, and status |
| `../commercial/CLAIM_LEDGER.md` | commercial claims with the exact artifact that supports each one |
| `../institutional/UNSUPPORTED_CLAIMS.md` | claims that are explicitly **not** made, and why |
| `../assurance/ASSURANCE_STATUS.md` | per-assurance-item state; no item is complete without evidence |

## Rules

1. **One claim, one canonical source.** A surface may restate a number; it may
   not invent one. The source column in `PUBLIC_SURFACE_MAP.md` is mandatory.
2. **A gate that cannot fail is not a gate.** Every row names a command or a
   review record. "Manual review" is allowed only when a named reviewer and a
   dated record exist.
3. **Historical surfaces are frozen.** `evidence/`, `investor_packs/` and
   `site/` keep the text they shipped with. They are not current claims and must
   not be edited to look current.
4. **Absence is a claim.** "No SOC 2 report", "no ISO certificate", "no
   FedRAMP authorization" and "no independent pen test" are true statements.
   They are allowed and required where a buyer would otherwise infer assurance.
5. **Withdrawn claims stay withdrawn.** If a claim was removed because it could
   not be proved, do not reintroduce it under a synonym. Add it to
   `UNSUPPORTED_CLAIMS.md` first.
