# Licensed under the GNU Affero General Public License v3 (AGPLv3) OR under a
# Proprietary Commercial License. See LICENSE and COMMERCIAL.md for terms.

import asyncio
import json
import os
from unittest.mock import AsyncMock, MagicMock

import httpx
import pytest

from aegis.config import AegisSettings
from aegis.core.crypto_audit import CryptographicAuditLedger
from aegis.proxy.app import create_app


@pytest.mark.asyncio
async def test_ledger_integration_via_proxy():
    """
    Verifies that the ledger correctly persists and reconstructs
    after a successful proxy request.
    """
    wal_path = "/tmp/aegis_integration_test.wal"
    if os.path.exists(wal_path):
        os.remove(wal_path)

    api_key_val = "test-proxy-key"

    settings = AegisSettings(
        backend_api_key="test-backend-key",
        api_keys=api_key_val,
        wal_path=wal_path,
        waf_strict_mode=False,
    )

    app = create_app(settings)

    # Mock the LLMForwarder to simulate a successful upstream response
    mock_forwarder = AsyncMock()

    # Use plain dictionaries for logprobs to avoid JSON serialization issues
    # Structure: content -> list of dicts where each dict has 'token' and 'top_logprobs'
    # 'top_logprobs' -> list of dicts where each dict has 'logprob'

    logprobs_content = [
        {"token": "Hello", "top_logprobs": [{"logprob": -0.1}, {"logprob": -0.5}]},
        {"token": " world", "top_logprobs": [{"logprob": -0.2}, {"logprob": -0.8}]},
        {"token": "!", "top_logprobs": [{"logprob": -0.05}, {"logprob": -0.9}]},
    ]

    resp_data = {
        "choices": [
            {"message": {"content": "Hello world!"}, "logprobs": {"content": logprobs_content}}
        ]
    }

    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = resp_data
    mock_response.content = json.dumps(resp_data).encode("utf-8")

    mock_forwarder.forward_json.return_value = mock_response
    mock_forwarder.stream_sse.return_value = []
    mock_forwarder.start = AsyncMock()
    mock_forwarder.stop = AsyncMock()

    app.state.aegis.forwarder = mock_forwarder

    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=app), base_url="http://test"
    ) as client:
        payload = {"messages": [{"role": "user", "content": "Hello, Aegis!"}]}
        headers = {"Authorization": "Bearer test-proxy-key", "x-session-id": "integration-session"}

        response = await client.post("/v1/chat/completions", json=payload, headers=headers)

        assert response.status_code == 200

        # Wait for the background audit task to complete
        await asyncio.sleep(1)

        # 2. Verify persistence
        assert os.path.exists(wal_path)

        new_ledger = CryptographicAuditLedger(persistence_path=wal_path)
        assert len(new_ledger.chain) >= 1

        # 3. Verify Integrity
        is_valid, error_idx = new_ledger.verify_integrity()
        assert is_valid is True

    # Cleanup
    if os.path.exists(wal_path):
        os.remove(wal_path)


if __name__ == "__main__":
    import asyncio
    import os

    asyncio.run(test_ledger_integration_via_proxy())
