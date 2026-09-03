# Aegis Python SDK

**Audience:** developers integrating an application with an Aegis gateway.
**Scope:** installation, gateway configuration, provider clients, and inclusion-proof verification.
**Boundary:** the SDK talks to a gateway and verifies proofs. It establishes nothing about the gateway's trustworthiness — see [§ Proof verification](#proof-verification), which is the section that matters most.

---

## Install

**From this source tree** — the supported path while registry versions lag:

```bash
pip install -e ./sdk/python
```

> **Registry caution.** PyPI carries `aegis-latent-sdk` at `4.0.0`; this source tree is `4.1.2`. Installing from PyPI gets you different code from what this document describes. See [Release Status](../../docs/RELEASE_STATUS.md).

Requires Python 3.11 or newer.

## Configure a gateway

```python
from aegis_sdk import build_headers, normalize_gateway_url

base_url = normalize_gateway_url("http://127.0.0.1:8080")
headers = build_headers(api_key="your-proxy-key", session_id="session-1")
```

`normalize_gateway_url` rejects malformed and unsafe URL forms rather than passing them through. `build_headers` assembles the session and authorization headers the gateway expects.

## Provider clients

Drop-in wrappers that route through the gateway:

```python
from aegis_sdk import OpenAI

client = OpenAI(
    aegis_base_url="http://127.0.0.1:8080",
    aegis_api_key="your-proxy-key",
    session_id="session-1",
)

response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "Hello, Aegis."}],
)
```

`AsyncOpenAI`, `Anthropic` and `AsyncAnthropic` follow the same shape.

**Compatibility is bounded by the SDK's tests.** It covers the provider surfaces and dependency ranges those tests exercise, not every provider version or endpoint.

## Proof verification

This is the part that is easy to get wrong, and getting it wrong makes the verification meaningless.

```python
from aegis_sdk import verify_proof_headers, require_trusted_root

# The root MUST come from a channel independent of the gateway that
# served the response. A root read from the same response proves nothing.
trusted_root = require_trusted_root(load_root_from_your_own_anchor())

ok = verify_proof_headers(response.headers, trusted_root=trusted_root)
```

> **A proof verified against a root supplied by the gateway that produced it establishes internal consistency and nothing more.** The system would be attesting to itself. `require_trusted_root` exists to make the input explicit; it cannot tell whether the root you passed is genuinely independent, because a root is a root.

Lower-level entry points, when you hold the proof rather than the headers:

| Function | Use |
| --- | --- |
| `decode_proof_header` | Parse the `X-Aegis-MMR-Proof` header |
| `canonical_proof_json` | Canonical form for hashing or storage |
| `verify_inclusion` | Verify a parsed `InclusionProof` |
| `verify_inclusion_hash` | Verify from a leaf hash |

Schema and semantics: [MMR Proof v1](../../docs/api/MMR_PROOF_V1.md).

## Streaming

A stream reports evidence as `pending-terminal` until its terminal summary commits, and no inclusion proof exists before then.

**Check for the terminal marker.** A client that treats connection close as success will silently accept a stream whose terminal commit failed — the gateway withholds the marker precisely so you can tell, and it cannot make you look.

## Errors

| Exception | Raised when |
| --- | --- |
| `AegisProofError` | A proof is malformed, fails schema validation, or does not verify against the supplied root |
| `ValueError` | A gateway URL or header input is rejected as malformed |

`AegisProofError` on a well-formed proof means the proof did not verify. Treat that as a security event, not a retryable failure.

## Secure defaults

- Never hard-code an API key. Read it from your environment or secret manager.
- Never log a key, a raw proof payload, or governed content.
- Verify proofs against an independently obtained root, always.
- Pin the SDK to an exact commit or version.
- Use HTTPS for any gateway that is not on localhost.

## Develop

```bash
cd sdk/python
pip install -e ".[dev]"
ruff check src tests
mypy --config-file pyproject.toml
pytest -q
```

---

**Related:** [Integrations Guide](../../docs/DEVELOPER_INTEGRATIONS_GUIDE.md) · [MMR Proof v1](../../docs/api/MMR_PROOF_V1.md) · [Audit Endpoints](../../docs/api/AUDIT_ENDPOINTS.md) · [Boundaries](../../docs/BOUNDARIES.md)
