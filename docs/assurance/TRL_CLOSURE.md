<!--
Copyright (c) 2026 Juan Luna. All rights reserved.
Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.
-->

# TRL Closure: Evidence Gathered Against Each Gap

**Audience:** the owner, an investor reading the maturity matrix in the investor pack (D2), and a reviewer deciding what to believe.
**Scope:** for six components, the gap the pack names, what was run on 2026-09-29 against it, the result, and what is still open. Prepared under Mission XVI, Phase 5.
**Boundary:** evidence, not a promotion. This page **does not change any TRL number**; the levels are the pack's planning construct and stay as published. Every run was local, on one shared container, with no customer workload and no spend on cloud resources. A local pass does not close a gap that asks for target hardware, a pilot or a third party.

## Summary

| Component | Gap named in the pack | Run today | Result | Still open |
| --- | --- | --- | --- | --- |
| WAL + group commit | 30-day soak and power-loss test on target storage | 60 rounds of kill and recover | 27,735 acknowledged commits, 0 lost, chain valid in every round | The 30-day soak and a real power cut on target storage |
| SDK verifiers | External auditor runs the verifier in a pilot | Deterministic verifier kit and a test that runs it stand-alone | Builds byte-identically; demo passes from the extracted kit | An external auditor using it in a pilot |
| HA lease + global sequence | Partition and failover chaos tests | 45 existing HA tests against real Redis 7.0.15 and PostgreSQL 16, plus two new fault-injection tests | All pass; one **finding** on Redis data loss, fixed on 2026-09-30 (`REG-D91`) | Real network partitions, PostgreSQL failover, storage classes, a pilot |
| WAF L1/L2 | Published adversarial evaluation and pen-test coverage | The pinned 23-case corpus | 0 bypasses, 0 false positives; the 95% upper bound on the bypass rate is 20.4% | An independent, larger corpus; the pen test |
| HSM / PQC signing | Key Vault Premium HSM-backed integration test | The adapter against a real PKCS#11 token (SoftHSM 2.6.1) | **Two defects found and fixed**; signatures verify independently | A hardware or cloud HSM, which costs money |
| OTel / metrics | Pilot dashboards and an exercised alert runbook | Alert rules and a dashboard built from exported metrics | Every metric name checked against the code | Loading into a live stack; a pilot exercising the alerts |

## WAL: kill and recover

`tools/qualification/wal_crash_soak.py` starts a committing process, kills it with `SIGKILL` at a random moment, reopens the ledger and checks the chain verifies and that every commit the process had acknowledged is present. Sixty rounds, seed 42, 223 seconds, retained as `evidence/qualification/wal_crash_soak_2026-09-29.json`: 27,735 acknowledged commits, none lost, no duplicates, integrity valid after each round. A kill that lands inside a write leaves a torn last line, which the harness now repairs with `tools/wal_repair.py` between rounds and counts as `torn_tails_repaired`; that run predates the repair step and does not record the count.

**What this is not.** `SIGKILL` ends the process but leaves the operating system's page cache intact, so this exercises replay and torn-tail handling, not the storage stack or `fsync` honesty. It is not a power-loss test and 223 seconds is not a 30-day soak. Both need the target host: `python tools/qualification/wal_crash_soak.py --hours 720 --wal /mnt/target/aegis.wal.jsonl`.

## HA: fault injection against a real Redis

The existing HA suite passed against real backends: 45 passed and 4 skipped (Helm is not installed here). Two new tests, `tests/ha/test_ha_chaos.py`, inject faults:

- **Partition.** The holder's connection to Redis goes through a forwarder that is then cut while a standby stays connected. Sampling every 50 ms, the two replicas were never both holding the lease; the holder stopped admitting within its 2-second TTL; the standby took over with epoch 2; the healed old holder could not renew. Three runs, three passes.
- **Redis restart without persistence.** Every holder is fenced, which is right. But the epoch counter is lost with the data, so the next holder draws epoch 1 again, below one already sequenced. The sequence fence refuses a writer older than its last entry, so the chain **stops admitting** rather than forking: fail-closed, and an availability incident.

**Finding.** The second result is a real operational risk that the HA documentation did not state. It is recorded in `docs/operations/HIGH_AVAILABILITY.md` §4 with the operator action (keep the epoch counter durable). A code fix, seeding the epoch above the highest sequenced value when a lease is drawn, is a change to a governed path and is **not made here**; it needs the maintainer's decision and a registry entry.

**Closed 2026-09-30 (`REG-D91`, `CLM-116`).** The owner directed that the recorded items be resolved. A replica now lifts its lease epoch above the highest `ha-lease-<chain>-<epoch>` handover its WAL records before it writes its own handover, in one Lua script that re-checks holder and epoch and is serialised with renewal and release (`ChainLease.raise_epoch_above`). `tests/ha/test_ha_chaos.py` now restarts a real Redis without persistence and shows the new holder drawing epoch 1, being refused by the sequence store, lifting to 3 above the recorded 2, being accepted, and the next holder drawing 4. The floor is what the replica's own WAL records: a WAL restored from a backup older than the sequence still meets the fence, which stays fail-closed. The paragraph above is kept as written.

## HSM: two defects found by using a real token

`tests/test_hsm.py` injects fake PKCS#11 objects. Running the adapter against SoftHSM 2.6.1 with the real `python-pkcs11` library showed the mock hid two defects:

1. **RSA-PSS signing failed on every real token.** The code called `pkcs11.mechanisms.RSA_PKCS_PSS_PARAMS`, which exists only in the test mock. The real library takes a `(hash, mgf, salt length)` tuple. Fixed.
2. **ECDSA failed on tokens without `CKM_ECDSA_SHA256`.** SoftHSM offers only raw `CKM_ECDSA`. The adapter now falls back to hashing on the host and signing the digest, which yields the same `r||s` signature. Fixed.

`tests/test_hsm_softhsm.py` signs through the repository's adapter on each path and verifies independently with `cryptography` in a clean interpreter, including rejecting a tampered message. The RSA path failed closed before the fix (it raised), so no unsigned or wrongly signed record was produced. This shows the adapter works against one **software** token. It says nothing about hardware or cloud HSM interoperability, key non-exportability or any certification.

## WAF: what a 23-case corpus can and cannot say

`tools/security/run_waf_corpus.py` on `tests/data/waf_corpus_v1.json`, retained as `evidence/qualification/waf_corpus_report_2026-09-29.json`: 15 malicious and 8 benign cases, 0 bypasses, 0 false positives. With 15 malicious cases the Wilson 95% upper bound on the bypass rate is 20.4%, so the result is compatible with a WAF that misses a fifth of attacks. It shows the corpus behaves as written. It does not close a gap that asks for a published adversarial evaluation, and the WAF remains bounded pattern detection (`UC-042`).

## Observability

`deploy/observability/` holds fourteen alert rules (eleven from the operations guide, three marked extra) and a twelve-panel dashboard. `tests/test_observability_assets.py` fails if any alert or panel references a metric the gateway does not export, and if a documented alert is missing from the shipped file. Neither asset has been loaded into a live Prometheus or Grafana, and no threshold has been tuned.

## Deferrals

| Item | Pack figure | Decision | Revisit when |
| --- | --- | --- | --- |
| Zero-knowledge circuit audit | 12 engineer-weeks, $40k (`M`) | Deferred. The circuit is a preview behind a guard and is not on the request path | A customer needs the proof system on the request path |
| Raft / consensus | 0 weeks | Not on the roadmap. The module is orphaned and superseded by the lease design (`AD-17`) | Never for the current design |
| Azure Managed HSM | $3.20 per hour, $2,342.40 per month (`V`) | Excluded by design. It would spend the whole $200 credit in about 62.5 hours | A funded deployment that needs a dedicated managed HSM |

## Not done in this phase

No Azure resource was created and nothing was spent. The Key Vault Premium test, a run of `phase0_guardrails.sh` end to end and a second-region repeat all spend money, so they wait for the owner. The script `deploy/azure/phase0/00_query_prices.sh` still does not exist.

## Reproduce

```bash
python tools/qualification/wal_crash_soak.py --rounds 60 --json out.json
AEGIS_TEST_REQUIRE_HA_BACKENDS=1 AEGIS_TEST_POSTGRES_DSN=postgresql://… python -m pytest tests/ha -q
PYTHONPATH=. python tools/security/run_waf_corpus.py --corpus tests/data/waf_corpus_v1.json --output waf.json
python -m pytest tests/test_hsm_softhsm.py tests/test_observability_assets.py -q
python tools/sales/build_verifier_kit.py --out aegis-verifier-kit.zip
```
