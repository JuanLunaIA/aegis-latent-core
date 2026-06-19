# Aegis Examples

Runnable, reproducible examples. Each one is self-contained and exits non-zero
on failure, so they double as smoke tests.

## `demo.py` — end-to-end value demo (< 1 minute)

```bash
pip install -e ".[storage-sqlite]"
python -m examples.demo
```

No provider API key, no external network, no real secrets. The demo boots the
Aegis proxy in-process against a mock OpenAI-compatible upstream and walks
through the whole value proposition, printing `PASS`/`FAIL` with evidence at
each step:

| Step | What it proves | How |
|---|---|---|
| 1 | The proxy boots and forwards transparently | `GET /health` → 200; OpenAI-format requests return 200 |
| 2 | Every request appends exactly one signed node | `chain length` grows 1 → 5, one per request |
| 3 | The full chain verifies | `GET /v1/audit/integrity` → `valid=true` |
| 4 | Tampering is detected | mutate one node field → `verify_integrity()` flags the exact index |
| 5 | Compliance export is real and re-verifiable | seal a SOC2/HIPAA bundle, then `verify_bundle()` re-checks `chain_hash` + signature |

Expected final line:

```
RESULTADO: 5/5 verificaciones OK — demo exitosa.
```

### Notes

- **Why two in-process servers?** The demo starts the mock upstream and the Aegis
  proxy as real `uvicorn` servers in daemon threads so their full ASGI lifespans
  run (the forwarder's HTTP client and the audit ledger initialize exactly as in
  production). `httpx.ASGITransport` is deliberately *not* used because it skips
  lifespan.
- **`HERMES_SANDBOX=true`** is set by the demo to skip real seccomp/LSM
  enforcement — production hardening that does not apply to an ephemeral demo
  process. Do **not** set it in production.
- **Isolated WAL.** Each run writes to a fresh temp WAL so it never loads nodes
  signed by a previous run's key.
- The audit-chain step uses the public HTTP API; the compliance step reads the
  in-process ledger directly and feeds the real `ComplianceExporter` over a
  temporary SQLite store. Both temp directories are left in `/tmp` for inspection.
