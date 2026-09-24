# Aegis Python SDK

**Audience:** developers integrating an application with an Aegis gateway.
**Scope:** installation, gateway configuration, provider clients, inclusion-proof verification, and the `aegis-sdk` command line (offline bundle verification, gateway audit status).
**Boundary:** the SDK talks to a gateway and verifies proofs. It establishes nothing about the gateway's trustworthiness — see [§ Proof verification](#proof-verification), which is the section that matters most.

---

## Install

**From this source tree** — the supported path while registry versions lag:

```bash
pip install -e ./sdk/python
```

> **Registry caution.** PyPI carries `aegis-latent-sdk` at `5.0.0`; this source tree's SDK says `5.0.1`, which is not published anywhere yet, so an SDK installed from PyPI is not the code in this repository. The *gateway* distribution on PyPI (`aegis-latent-core`) is still `4.1.2`. See [Release Status](../../docs/RELEASE_STATUS.md).

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

## Command line: `aegis-sdk`

Installed with the package. It is called `aegis-sdk`, not `aegis`, because the gateway distribution already installs `aegis` and `aegis-server`. `python -m aegis_sdk` works too.

### `aegis-sdk verify <bundle.zip>` — offline

Checks a forensic bundle exported by the gateway without contacting it: every member is one the format defines, `manifest.json` is canonical and its self-seal matches, each evidence file matches its size and SHA-256, the ledger slice matches its CID, and every MMR inclusion proof verifies against the root recorded with it. Digests, CIDs and proofs use only the standard library.

```bash
pip install -e "./sdk/python[verify]"     # adds `cryptography`, for the signature step only
aegis-sdk verify bundle.zip --public-key operator-ed25519.pub.pem
aegis-sdk verify bundle.zip --public-key operator-ed25519.pub.pem --trusted-root <64-hex> --json
```

| Exit | Result | Meaning |
| --- | --- | --- |
| `0` | `VERIFIED` | Nothing failed **and** `manifest.json`'s Ed25519 signature verifies against the key you supplied |
| `3` | `INCOMPLETE` | Nothing failed, but the signature was not checked — unsigned bundle, no `--public-key`, or `cryptography` not installed |
| `1` | `FAILED` | A check failed; the output names it |
| `2` | — | Unusable input: missing file, malformed key or root |

> **`INCOMPLETE` is not a pass.** Without the signature, the digests detect corruption, not tampering: whoever can rewrite a record can rewrite the manifest beside it. The public key must reach you **out of band** — the bundle deliberately does not carry it, since a key read from the archive being checked authenticates nothing. Supplying a key to a bundle that has no signature fails, so a stripped signature cannot pass.

Not checked: per-node signatures, the CBOR slice and PDF beyond their digests, and whether a root is one you should trust — `--trusted-root` compares the terminal root with one you already hold.

### `aegis-sdk audit <gateway_url>`

Prints `/v1/audit/health` (and `/v1/audit/integrity` with `--integrity`) as sorted JSON; exits `0` when the gateway reports `status: ok` (and `valid: true`), `1` otherwise, `2` if it cannot be queried. This is the gateway's report about itself, not independent evidence. The audit key is read from `AEGIS_AUDIT_API_KEY` (or `--api-key-env NAME`), never from the command line. It refuses to send a key over plain HTTP to a non-loopback host, never follows redirects (which would re-send the key), and caps the response at 1 MiB.

## Streaming

A stream reports evidence as `pending-terminal` until its terminal summary commits, and no inclusion proof exists before then.

**Check for the terminal marker.** A client that treats connection close as success will silently accept a stream whose terminal commit failed — the gateway withholds the marker precisely so you can tell, and it cannot make you look.

## Errors

| Exception | Raised when |
| --- | --- |
| `AegisProofError` | A proof is malformed, fails schema validation, or does not verify against the supplied root |
| `ValueError` | A gateway URL or header input is rejected as malformed |
| `aegis_sdk.bundle.BundleInputError` | `verify_bundle` cannot read the bundle, or a key or root argument is malformed (a bundle that fails a check is a `failed` report, not an exception) |
| `aegis_sdk.audit.GatewayAuditError` | `fetch_audit_status` refused to send, was redirected, or got an error, oversized or non-JSON answer |

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
