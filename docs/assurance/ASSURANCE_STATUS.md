<!--
Copyright (c) 2026 Juan Luna.
SPDX-License-Identifier: Apache-2.0
Licensed under the Apache License, Version 2.0; see LICENSE and NOTICE.
-->

# Assurance Status

**Audience:** anyone about to write a sentence about the product's independent assurance, and any buyer asking for it.
**Scope:** one place that states, per assurance item, where it stands and the exact wording that state allows. The machine-readable copy is [`ASSURANCE_STATUS.json`](ASSURANCE_STATUS.json); `tests/test_assurance_tools.py` checks it.
**Boundary:** a status page, not evidence. As of 2026-09-29 (Mission XVI, Phase 4), **no independent assurance exists**. Every item below is `NOT_STARTED` or `DRAFTED`, and none is `COMPLETE`. A state changes only when the evidence path listed for it exists.

## States

`NOT_STARTED`, `DRAFTED` (documents prepared, nothing engaged), `ENGAGED` (a contract is signed), `IN_PROGRESS` (work under way), `COMPLETE` (evidence exists and is linked).

## Items

| Item | Register | State | Prepared | Target | Allowed wording |
| --- | --- | --- | --- | --- | --- |
| Independent penetration test | `REG-H01` | `DRAFTED` | [SOW draft](PENTEST_SOW_DRAFT.md) | SOW 2027-03-31; report 2027-06-30 (`M`) | "No independent penetration test has been performed; a scope is drafted." |
| SOC 2 Type I | `REG-H02` | `DRAFTED` | [Readiness](SOC2_READINESS.md) | Auditor engaged 2027-08-31; report 2027-12-31 (`M`) | "No SOC 2 report exists; none is in progress with an auditor." |
| Escrow | `REG-H03` | `DRAFTED` | [Plan](ESCROW_EXECUTION_PLAN.md), [term sheet](../legal/ESCROW_TERM_SHEET.md), manifest tool | 2027-03-31 (`M`) | "No escrow agreement is executed and nothing is deposited." |
| Second maintainer | `REG-H05` | `NOT_STARTED` | none | 2027-02-28 (`M`) | "The project has one maintainer." |
| Constant-time review of the post-quantum signer | `REG-041`, `UC-012` | `NOT_STARTED` | [PQC timing note](../security/PQC_CONSTANT_TIME.md) | not scheduled | "A timing sample exists; no constant-time claim is made." |
| Target-environment acceptance (HA, storage, failover) | `UC-005` | `NOT_STARTED` | [Audit readiness](../compliance/AUDIT_READINESS.md) | per customer | "HA is tested locally and in CI, not on customer infrastructure." |

## Wording that is not allowed until the state changes

| While | Do not write |
| --- | --- |
| Penetration test is not `COMPLETE` | "penetration-tested", "externally assessed", "independently reviewed" |
| SOC 2 is not `COMPLETE` | "SOC 2 compliant", "SOC 2 certified", "SOC 2 attested", "SOC 2 ready" as a status |
| Escrow is not `COMPLETE` | "software escrow is in place", "continuity is guaranteed" |

The claims register and `docs/institutional/UNSUPPORTED_CLAIMS.md` hold the full refusals.

## Reproduce

```bash
python -m pytest tests/test_assurance_tools.py -q
python tools/assurance/escrow_manifest.py build --ref v5.0.1
```
