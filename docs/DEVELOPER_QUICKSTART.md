# Developer Quickstart — Aegis Latent Core v3.1.0

This guide is for developers who need to clone Aegis, run the local evaluation path, inspect the evidence lifecycle, and extend the repository without weakening the durable evidence contract. It describes local development, not a production deployment or a regulatory result.

**Last verified:** 2026-08-22 UTC
**Release baseline:** `v3.1.0`
**Current main verified:** `45d95188d40792639fdd654369765a7233bef09a` (post-release; not the `v3.1.0` tag)
**Audience:** Application, platform, and security engineers
**Root entry point:** [`README.md`](../README.md)

## Evaluation target

Aegis exposes OpenAI-compatible `/v1/chat/completions` and, when `AEGIS_PROVIDER=anthropic`, native Anthropic `/v1/messages`. The local path lets a developer inspect policy, WAF, egress, signing, WAL persistence, portable MMR proofs, integrity verification, and failure-path behavior. The local path does not prove target filesystem semantics, secret-manager behavior, upstream availability, kernel enforcement, HTTP/2 ingress behavior, or production capacity.

## Clone and install

```bash
git clone https://github.com/JuanLunaIA/aegis-latent-core.git
cd aegis-latent-core
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --require-hashes -r requirements.lock
python -m pip install -e ".[dev]"
python -m compileall -q aegis aegis_server
```

The lockfile is the controlled runtime dependency input. The development extras are currently minimum-version ranges rather than a hash-locked test-toolchain input; record the resolved environment when reproducing test evidence. Do not replace the runtime lockfile with an unpinned install.

## Run the release tests

```bash
pytest -q
pytest -q tests/test_p0_release_gates.py
pytest -q tests/test_enterprise_durable_evidence.py
pytest -q tests/test_keyring_rotation.py
pytest -q tests/test_market_hardening_gates.py
```

The final v3.1.0 release run recorded 5,442 passed, 37 skipped and 47 warnings. The retained log and release-gate artifact are outside the source tree. A fresh local run can differ by Python version, native extension availability, filesystem, operating system and optional services.

## Run the bounded formal models

The formal gate requires Z3, Lean 4.33.0, Java 21, and a TLA+ Tools JAR at `.tools/tla2tools.jar` whose manifest identifies source revision `0894c3407f4717fec7cc18bde3bf3c857fa47333`. CI checks out that exact Git object, builds the JAR, and verifies its manifest; it does not trust the mutable upstream release-asset URL. With those prerequisites installed, run:

```bash
scripts/verify_formal_artifacts.sh
```

The gate checks a QF_BV token-bucket contradiction with Z3, proves the durable-emission transition invariant inductively with Lean, and exhaustively explores finite TLC models for commit-before-emission, append-only ledger prefixes, and session-to-ledger binding. These are bounded abstractions: they do not prove filesystem durability, cryptographic constant-time behavior, Python/Rust refinement, multi-process ordering, or the absence of implementation defects outside the modeled transitions.

## Start a local evaluation gateway

The exact configuration surface is defined by the settings model and `.env.example`. A minimal evaluation must use a mock or disposable upstream. Never put provider keys, signing keys, client secrets, customer prompts or WAL data in source control.

```bash
export AEGIS_SECURITY_ENFORCEMENT_MODE=permissive
export AEGIS_DEBUG_MODE=true
export AEGIS_BACKEND_URL=http://127.0.0.1:9001/v1
export AEGIS_WAL_PATH=/tmp/aegis-evaluation.wal.jsonl
uvicorn aegis.main:app --host 127.0.0.1 --port 8000
```

Strict mode is the deployment path. It requires authentication, durable evidence, strong signing, bounded request bodies, distributed rate limiting and the configured kernel controls. See [`DEPLOYMENT_GUIDE.md`](../DEPLOYMENT_GUIDE.md) before using a real provider.

## Inspect the evidence lifecycle

The relevant implementation path is distributed across `aegis/proxy/`, `aegis/core/crypto_audit.py`, and `aegis_server/main.py`. The lifecycle is:

1. Authenticate and assign a request ID.
2. Read the bounded request body and canonicalize the representation.
3. Apply WAF, session, egress and rate-limit controls.
4. Call the configured upstream only after admission.
5. For non-streaming traffic, capture the response, then hash, sign, append, flush and `fsync` the evidence before emission.
6. For SSE, pass canonical events through `BoundedStreamProxy`: a queue bounded by items and bytes, incremental SHA-256 over emitted bytes, and finite de-identification holdback. The implementation does not retain the complete response.
7. Start SSE with `X-Aegis-Evidence-Status: pending-terminal` and `X-Aegis-Proof-Status: pending-terminal`; commit exactly one terminal summary before emitting `[DONE]` or Anthropic `message_stop`.
8. On a byte, event-size or duration limit, close upstream immediately, commit the failure outcome once, and omit the success terminal marker.
9. Enqueue optional response enrichment after the authoritative record exists.

The P0 failure-path tests are the executable contract for this sequence. A background analyzer is not the authoritative evidence commit.

## Use the provider-native SDKs

The Python wrappers subclass the official provider clients, and the TypeScript wrappers subclass their installed peer dependencies. They preserve native resources, overloads, stream iterators, errors and response types while changing gateway routing and Aegis headers.

```python
from aegis_sdk.openai import OpenAI
from aegis_sdk.anthropic import Anthropic

openai_client = OpenAI(
    aegis_api_key="dev-key",
    gateway_url="http://127.0.0.1:8000",
    tenant_id="dev-tenant",
)
openai_response = openai_client.chat.completions.create(
    model="gpt-4o-mini", messages=[{"role": "user", "content": "hello"}]
)

# Requires the gateway itself to use AEGIS_PROVIDER=anthropic.
anthropic_client = Anthropic(
    aegis_api_key="dev-key",
    gateway_url="http://127.0.0.1:8000",
    tenant_id="dev-tenant",
)
anthropic_response = anthropic_client.messages.create(
    model="claude-3-5-sonnet-latest",
    max_tokens=64,
    messages=[{"role": "user", "content": "hello"}],
)
```

```typescript
import OpenAI from "aegis-latent-sdk/openai";
import Anthropic from "aegis-latent-sdk/anthropic";

const openai = new OpenAI({
  aegisApiKey: "dev-key",
  gatewayUrl: "http://127.0.0.1:8000",
  tenantId: "dev-tenant",
});
const anthropic = new Anthropic({
  aegisApiKey: "dev-key",
  gatewayUrl: "http://127.0.0.1:8000",
  tenantId: "dev-tenant",
});
```

Durable non-streaming replies expose portable `aegis-mmr-inclusion-v1` headers. SSE starts with pending-terminal headers and a `Link` to `GET /v1/audit/proofs/{request_id}`; perform that authenticated lookup after termination rather than treating initial headers as a durable proof.

## Exercise key rotation locally

```bash
PYTHONPATH=. .venv/bin/python tools/benchmarks/run_key_rotation.py \
  --output evidence/key_rotation_report.json
pytest -q tests/test_keyring_rotation.py
```

The retained v3.1.0 evidence covers three independent local signer instances, atomic keyring replacement, old/new key IDs, zero failed local commits and zero unverifiable records. It does not prove secret-manager propagation, orchestrator restart behavior, clock-skew tolerance or multi-region storage.

## Exercise WAF and backpressure

```bash
PYTHONPATH=. .venv/bin/python tools/security/run_waf_corpus.py \
  --corpus tests/data/waf_corpus_v1.json \
  --output evidence/waf_corpus_report.json

PYTHONPATH=. .venv/bin/python tools/benchmarks/run_backpressure_stall.py \
  --duration-s 0.25 --offered-rps 10000 --fsync-delay-ms 2 --max-workers 64 \
  --output evidence/backpressure_stall_report.json
```

The WAF corpus is 15 malicious and 8 benign cases. The retained run observed zero bypasses and zero false positives, but its confidence interval is wide. The backpressure run preserved 10,000 records but observed p99 commit latency of 1,189.89 ms. Neither result is a universal security or capacity claim.

## Extend code without breaking the contract

A change that affects admission, response emission, signing, WAL persistence, key rotation, failure handling, or public claims requires a regression test and a claims-matrix update. Keep the durable evidence gate on the authoritative path. Optional analysis may be bounded or rejected; it must not turn an accepted governed response into an unrecorded response.

Use the repository's existing style and run:

```bash
ruff check .
ruff format --check .
bandit -r aegis aegis_server -lll
git diff --check
```

## Related documents

- [`README.md`](../README.md)
- [`docs/PLATFORM_OPERATOR_GUIDE.md`](PLATFORM_OPERATOR_GUIDE.md)
- [`docs/CLAIMS_MATRIX.md`](CLAIMS_MATRIX.md)
- [`docs/benchmarks/README.md`](benchmarks/README.md)
- [`docs/security/THREAT_MODEL.md`](security/THREAT_MODEL.md)
- [`CONTRIBUTING.md`](../CONTRIBUTING.md)

## Verification references

- [`tests/test_p0_release_gates.py`](../tests/test_p0_release_gates.py)
- [`tests/test_enterprise_durable_evidence.py`](../tests/test_enterprise_durable_evidence.py)
- [`tests/test_keyring_rotation.py`](../tests/test_keyring_rotation.py)
- [`tools/benchmarks/run_backpressure_stall.py`](../tools/benchmarks/run_backpressure_stall.py)
- [`tools/security/run_waf_corpus.py`](../tools/security/run_waf_corpus.py)
