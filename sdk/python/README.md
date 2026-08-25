# Aegis Python SDK

`aegis-latent-sdk` supplies typed subclasses of the official OpenAI and Anthropic clients plus a stateless verifier for `aegis-mmr-inclusion-v1` proofs.

## Develop from a clean checkout

The v4 distribution is named **`aegis-latent-sdk`** (its Python import package is
`aegis_sdk`). It is not published to PyPI; install it from this checkout rather
than using a registry package. Run these commands from the repository root:

```bash
cd sdk/python
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest
python -m ruff check src tests
python -m mypy
python -m pip wheel . --no-deps --wheel-dir dist
```

The `cd sdk/python` step is required: `pyproject.toml`, the SDK tests, and the
resulting `dist/` directory are component-relative. See the
[repository overview](../../README.md), [developer quickstart](../../docs/DEVELOPER_QUICKSTART.md),
and [integration guide](../../docs/DEVELOPER_INTEGRATIONS_GUIDE.md) for the
canonical project documentation.

```python
from aegis_sdk.openai import OpenAI

client = OpenAI(
    aegis_api_key="proxy-key",
    gateway_url="https://gateway.example",
    tenant_id="tenant-1",
)
response = client.chat.completions.create(
    model="gpt-4o-mini",
    messages=[{"role": "user", "content": "hello"}],
)
```

The wrapper changes constructor defaults only. Native resource methods, parsed return models, raw-response surfaces, and streaming types remain those of the installed official SDK. The Aegis gateway currently implements only the routes documented by its server; subclassing does not make unsupported vendor routes available.

Set `verify_proof=True` and supply a pinned `trusted_mmr_root` to require and verify the `X-Aegis-MMR-Leaf`, `X-Aegis-MMR-Proof`, and `X-Aegis-MMR-Root` response headers. `X-Aegis-MMR-Leaf` is a lowercase SHA-256 digest, not raw request or response material. The root is public integrity state, not a signing key. Root rotation must be managed by the caller's independent trust policy; copying the root from the same untrusted response is not an independent anchor.

The Anthropic subclass preserves the official client surface and uses bearer authentication. Aegis exposes native `POST /v1/messages` when the deployment sets `AEGIS_PROVIDER=anthropic`; the upstream and downstream bodies retain Anthropic Messages wire types. A deployment configured for a different provider rejects native Anthropic ingress rather than pretending that an OpenAI-shaped response is an `anthropic.types.Message`.

Streaming responses begin before the terminal evidence record exists, so their initial headers intentionally do not contain a completed proof. Use the returned proof `Link` after the stream terminates. Automatic header verification applies to non-streaming responses only.
